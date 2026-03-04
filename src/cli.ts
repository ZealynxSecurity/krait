#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { readFileSync } from 'fs';
import { resolve, basename, join } from 'path';
import { resolveConfig } from './core/config.js';
import { discoverFiles, detectDomain } from './core/file-discovery.js';
import { PatternLoader } from './knowledge/pattern-loader.js';
import { AIAnalyzer } from './analysis/ai-analyzer.js';
import { deduplicateFindings } from './analysis/deduplicator.js';
import { postProcessFindings } from './analysis/post-processor.js';
import {
  buildSummary,
  generateJsonReport,
  writeMarkdownReport,
  generateMarkdownReport,
} from './core/reporter.js';
import { Finding, Report, Domain } from './core/types.js';
import {
  parseOfficialFindings,
  loadKraitReport,
  compareFindings,
  compareFindingsAI,
  formatCompareResults,
} from './core/comparator.js';
import {
  CONTEST_REGISTRY,
  getContestById,
  listContests,
} from './shadow/registry.js';
import { runShadowAudit, runBatchShadowAudit } from './shadow/runner.js';
import { generateFeedback, writeFeedbackReport } from './shadow/feedback.js';
import { updateDashboard, loadDashboard, formatDashboard } from './shadow/dashboard.js';
import { gatherProjectContext, formatContextForPrompt } from './analysis/context-gatherer.js';

const VERSION = '0.1.0';

const program = new Command();

program
  .name('krait')
  .description('AI-first security auditor powered by Claude')
  .version(VERSION);

program
  .command('audit')
  .description('Run a security audit on a project directory')
  .argument('<path>', 'Path to the project to audit')
  .option('--quick', 'Quick mode: Sonnet only, no cross-contract analysis')
  .option('--api-key <key>', 'Anthropic API key')
  .option('--model <model>', 'Model to use for analysis')
  .option('--output <path>', 'Output directory for reports', '.')
  .option('--format <format>', 'Output format: json, markdown, both', 'both')
  .option('-v, --verbose', 'Verbose output')
  .option('--patterns-dir <path>', 'Path to patterns directory')
  .option('--min-lines <n>', 'Skip files with fewer lines than this', '20')
  .action(async (targetPath: string, options: Record<string, unknown>) => {
    const startTime = Date.now();

    try {
      const config = resolveConfig({
        apiKey: options.apiKey as string | undefined,
        model: options.model as string | undefined,
        quick: options.quick as boolean | undefined,
        verbose: options.verbose as boolean | undefined,
        outputFormat: options.format as 'json' | 'markdown' | 'both' | undefined,
        patternsDir: options.patternsDir as string | undefined,
        minLines: options.minLines ? parseInt(options.minLines as string, 10) : undefined,
      });

      const projectPath = resolve(targetPath);
      const projectName = inferProjectName(projectPath);

      console.log(chalk.bold.cyan('\n  🐍 Krait Security Auditor v' + VERSION));
      console.log(chalk.gray(`  Analyzing: ${projectPath}\n`));

      // Step 1: Load patterns
      const patternsDir = resolve(config.patternsDir);
      const spinner = ora('Loading vulnerability patterns...').start();
      const loader = new PatternLoader(patternsDir);
      const allPatterns = loader.load();
      spinner.succeed(`Loaded ${allPatterns.length} vulnerability patterns`);

      // Step 2: Discover files
      spinner.start('Discovering source files...');
      const files = await discoverFiles(projectPath, config.excludePatterns, config.maxFileSizeKb, config.minLines);
      if (files.length === 0) {
        spinner.fail('No source files found');
        process.exit(1);
      }
      const totalLOC = files.reduce((sum, f) => sum + f.lines, 0);
      spinner.succeed(`Found ${files.length} source files (${totalLOC.toLocaleString()} LOC)`);

      // Step 3: Gather project context
      spinner.start('Gathering project context...');
      const projectContext = await gatherProjectContext(projectPath, files);
      const contextParts: string[] = [];
      if (projectContext.protocolName) contextParts.push(projectContext.protocolName);
      if (projectContext.protocolType) contextParts.push(projectContext.protocolType);
      if (projectContext.compilerVersion) contextParts.push(`Solidity ${projectContext.compilerVersion}`);
      if (projectContext.dependencies.length > 0) contextParts.push(projectContext.dependencies.join(', '));
      spinner.succeed(`Project context: ${contextParts.join(' | ') || 'minimal'}`);
      if (projectContext.contractRoles.size > 0) {
        console.log(chalk.gray(`  Contract roles: ${projectContext.contractRoles.size} contracts documented`));
      }
      if (projectContext.interfaceSignatures.size > 0) {
        console.log(chalk.gray(`  Interfaces: ${projectContext.interfaceSignatures.size} interfaces extracted`));
      }

      // Step 4: Select domain and patterns
      const domain = detectDomain(files) as Domain;
      const domainPatterns = loader.getPatternsByDomain(domain);
      console.log(chalk.gray(`  Domain: ${domain} (${domainPatterns.length} domain patterns)`));

      // Step 5: Analyze files
      const analyzer = new AIAnalyzer(config);
      analyzer.setProjectContext(projectContext);
      const allFindings: Finding[] = [];
      const fileContentsMap = new Map<string, string>();

      console.log(chalk.bold('\n  Analyzing files...'));
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const fileSpinner = ora(`  [${i + 1}/${files.length}] ${file.relativePath}`).start();
        try {
          const content = readFileSync(file.path, 'utf-8');
          fileContentsMap.set(file.relativePath, content);
          const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
          const patternContext = loader.formatForPrompt(filePatterns);
          const findings = await analyzer.analyzeFile(file, content, patternContext);
          allFindings.push(...findings);
          const findingText = findings.length > 0
            ? chalk.yellow(` (${findings.length} findings)`)
            : chalk.green(' (clean)');
          fileSpinner.succeed(`  [${i + 1}/${files.length}] ${file.relativePath}${findingText}`);
        } catch (err) {
          fileSpinner.fail(`  [${i + 1}/${files.length}] ${file.relativePath} — error`);
          if (config.verbose) {
            console.error(chalk.red(`    ${err}`));
          }
        }
      }

      // Step 5: Cross-contract analysis (unless quick mode)
      if (!config.quick && files.length > 1) {
        const crossSpinner = ora('  Running cross-contract analysis...').start();
        try {
          const fileContents = files.map(f => ({
            file: f,
            content: readFileSync(f.path, 'utf-8'),
          }));
          const crossPatternContext = loader.formatForPrompt(domainPatterns);
          const crossFindings = await analyzer.analyzeCrossContract(
            fileContents,
            allFindings,
            crossPatternContext
          );
          allFindings.push(...crossFindings);
          crossSpinner.succeed(
            `  Cross-contract analysis complete (${crossFindings.length} findings)`
          );
        } catch (err) {
          crossSpinner.fail('  Cross-contract analysis failed');
          if (config.verbose) console.error(chalk.red(`    ${err}`));
        }
      }

      // Step 6: Post-processing — deduplicate, adjust confidence, filter FPs
      const dedupFindings = deduplicateFindings(allFindings);
      if (config.verbose && dedupFindings.length < allFindings.length) {
        console.log(chalk.gray(`\n  Dedup: ${allFindings.length} → ${dedupFindings.length} findings`));
      }

      const processedFindings = postProcessFindings(dedupFindings, files, fileContentsMap);
      if (config.verbose && processedFindings.length < dedupFindings.length) {
        console.log(chalk.gray(`  Post-process: ${dedupFindings.length} → ${processedFindings.length} findings`));
      }

      const rawCount = processedFindings.length;
      const filteredFindings = processedFindings.filter(f => {
        // Drop low-confidence findings unless they're critical/high severity
        if (f.confidence === 'low' && !['critical', 'high'].includes(f.severity)) {
          return false;
        }
        // Drop info-level findings unless verbose
        if (f.severity === 'info' && !config.verbose) {
          return false;
        }
        return true;
      });

      if (rawCount !== filteredFindings.length && config.verbose) {
        console.log(chalk.gray(`\n  Filtered: ${rawCount - filteredFindings.length} low-confidence/info findings removed`));
      }

      // Step 7: Build report
      const duration = Date.now() - startTime;
      const summary = buildSummary(filteredFindings, files.length, totalLOC);
      const report: Report = {
        projectName,
        projectPath,
        timestamp: new Date().toISOString(),
        duration,
        summary,
        findings: filteredFindings,
        filesAnalyzed: files,
        patternsUsed: domainPatterns.length,
        model: config.model,
      };

      // Step 7: Output
      const outputDir = resolve(options.output as string || '.');
      const format = config.outputFormat;

      if (format === 'json' || format === 'both') {
        const jsonPath = join(outputDir, `krait-report-${projectName}.json`);
        generateJsonReport(report, jsonPath);
        console.log(chalk.gray(`\n  JSON report: ${jsonPath}`));
      }

      if (format === 'markdown' || format === 'both') {
        const mdPath = join(outputDir, `krait-report-${projectName}.md`);
        writeMarkdownReport(report, mdPath);
        console.log(chalk.gray(`  Markdown report: ${mdPath}`));
      }

      // Print summary
      console.log(chalk.bold('\n  Results:'));
      if (summary.critical > 0) console.log(chalk.red(`    Critical: ${summary.critical}`));
      if (summary.high > 0) console.log(chalk.red(`    High:     ${summary.high}`));
      if (summary.medium > 0) console.log(chalk.yellow(`    Medium:   ${summary.medium}`));
      if (summary.low > 0) console.log(chalk.blue(`    Low:      ${summary.low}`));
      if (summary.info > 0) console.log(chalk.gray(`    Info:     ${summary.info}`));
      console.log(chalk.bold(`    Total:    ${summary.totalFindings}`));
      console.log(chalk.gray(`\n  Duration: ${(duration / 1000).toFixed(1)}s\n`));

    } catch (err) {
      console.error(chalk.red(`\nError: ${err instanceof Error ? err.message : err}`));
      process.exit(1);
    }
  });

program
  .command('patterns')
  .description('List loaded patterns and stats')
  .option('--patterns-dir <path>', 'Path to patterns directory', 'patterns')
  .action((options: Record<string, unknown>) => {
    const patternsDir = resolve(options.patternsDir as string);
    const loader = new PatternLoader(patternsDir);
    const stats = loader.getStats();

    console.log(chalk.bold.cyan('\n  🐍 Krait — Pattern Database'));
    console.log(chalk.bold(`\n  Total patterns: ${stats.total}\n`));

    console.log(chalk.bold('  By domain:'));
    for (const [domain, count] of Object.entries(stats.byDomain)) {
      console.log(`    ${domain}: ${count}`);
    }

    console.log(chalk.bold('\n  By severity:'));
    for (const [sev, count] of Object.entries(stats.bySeverity)) {
      console.log(`    ${sev}: ${count}`);
    }
    console.log('');
  });

program
  .command('compare')
  .description('Compare Krait report against official contest findings')
  .argument('<report>', 'Path to Krait JSON report')
  .argument('<findings>', 'Path to contest findings directory (with report.md)')
  .option('--json', 'Output results as JSON')
  .option('--ai-match', 'Use AI-assisted matching (more accurate)')
  .option('--api-key <key>', 'Anthropic API key (for --ai-match)')
  .action(async (reportPath: string, findingsPath: string, options: Record<string, unknown>) => {
    try {
      const absReport = resolve(reportPath);
      const absFindings = resolve(findingsPath);

      const log = options.json ? console.error.bind(console) : console.log.bind(console);

      log(chalk.bold.cyan('\n  🐍 Krait — Shadow Audit Comparison'));

      // Load Krait report
      const kraitFindings = loadKraitReport(absReport);
      log(chalk.gray(`  Krait report: ${kraitFindings.length} findings`));

      // Parse official findings from report.md
      const reportMd = join(absFindings, 'report.md');
      const officialFindings = parseOfficialFindings(reportMd);
      log(chalk.gray(`  Official findings: ${officialFindings.length} (H/M)`));

      if (officialFindings.length === 0) {
        console.log(chalk.yellow('\n  No official H/M findings found in report.md'));
        process.exit(1);
      }

      // Compare
      const contestName = basename(absFindings);
      let result;
      if (options.aiMatch) {
        log(chalk.gray('  Using AI-assisted matching...'));
        result = await compareFindingsAI(
          contestName, officialFindings, kraitFindings,
          options.apiKey as string | undefined,
          (msg: string) => log(chalk.gray(msg))
        );
      } else {
        result = compareFindings(contestName, officialFindings, kraitFindings);
      }

      if (options.json) {
        const output = {
          contest: result.contestName,
          precision: result.precision,
          recall: result.recall,
          f1: result.f1,
          truePositives: result.truePositives,
          falseNegatives: result.falseNegatives,
          falsePositives: result.falsePositives,
          byRisk: result.byRisk,
          matches: result.matches.map(m => ({
            official: m.official.id,
            officialTitle: m.official.title,
            matched: m.matched?.id || null,
            matchedTitle: m.matched?.title || null,
            score: m.matchScore,
            reason: m.matchReason,
          })),
        };
        console.log(JSON.stringify(output, null, 2));
      } else {
        console.log(formatCompareResults(result));
      }

    } catch (err) {
      console.error(chalk.red(`\nError: ${err instanceof Error ? err.message : err}`));
      process.exit(1);
    }
  });

program
  .command('shadow-audit')
  .description('Run shadow audits against known contest results')
  .option('--contest <id>', 'Run a specific contest by ID')
  .option('--difficulty <level>', 'Run contests of a specific difficulty: small, medium, large')
  .option('--all', 'Run all contests in registry')
  .option('--work-dir <path>', 'Working directory for cloned repos and results', 'shadow-results')
  .option('--quick', 'Quick mode: Sonnet only, no cross-contract')
  .option('--dry-run', 'Show what would happen without running audits')
  .option('--skip-clone', 'Use already-cloned repos in work dir')
  .option('--ai-match', 'Use AI-assisted matching for comparison scoring (more accurate, costs ~$0.01/contest)')
  .option('--api-key <key>', 'Anthropic API key')
  .option('--patterns-dir <path>', 'Path to patterns directory', 'patterns')
  .option('-v, --verbose', 'Verbose output')
  .action(async (options: Record<string, unknown>) => {
    try {
      console.log(chalk.bold.cyan('\n  🐍 Krait — Shadow Audit Pipeline'));

      // Determine which contests to run
      let contests = listContests();

      if (options.contest) {
        const c = getContestById(options.contest as string);
        if (!c) {
          console.error(chalk.red(`\n  Contest not found: ${options.contest}`));
          console.log(chalk.gray('  Available contests:'));
          for (const entry of contests) {
            console.log(chalk.gray(`    ${entry.id} — ${entry.name} (${entry.difficulty})`));
          }
          process.exit(1);
        }
        contests = [c];
      } else if (options.difficulty) {
        contests = contests.filter(c =>
          c.difficulty === (options.difficulty as string)
        );
      } else if (!options.all) {
        // Default: small + medium
        contests = contests.filter(c => c.difficulty !== 'large');
      }

      if (contests.length === 0) {
        console.log(chalk.yellow('  No contests matched the filter.'));
        process.exit(1);
      }

      console.log(chalk.gray(`  Contests: ${contests.length}`));
      for (const c of contests) {
        console.log(chalk.gray(`    ${c.id} — ${c.name} (${c.difficulty}, ~${c.estimatedLOC} LOC)`));
      }
      console.log('');

      const workDir = resolve(options.workDir as string || 'shadow-results');
      const patternsDir = resolve(options.patternsDir as string || 'patterns');

      const auditOptions = {
        workDir,
        patternsDir,
        apiKey: options.apiKey as string | undefined,
        quick: options.quick as boolean | undefined,
        verbose: options.verbose as boolean | undefined,
        dryRun: options.dryRun as boolean | undefined,
        skipClone: options.skipClone as boolean | undefined,
        aiMatch: options.aiMatch as boolean | undefined,
      };

      const results = await runBatchShadowAudit(
        contests,
        auditOptions,
        (msg: string) => console.log(msg)
      );

      // Generate feedback for missed findings
      const successResults = results.filter(r => !r.error);
      for (const result of successResults) {
        const contest = getContestById(result.contestId);
        if (!contest) continue;

        const findingsDir = join(workDir, basename(contest.findingsRepo));
        const suggestions = generateFeedback(result.comparison, findingsDir);
        if (suggestions.length > 0) {
          const feedbackPath = writeFeedbackReport(suggestions, workDir, result.contestId);
          console.log(chalk.gray(`  Feedback: ${feedbackPath} (${suggestions.length} suggestions)`));
        }
      }

      // Update dashboard
      if (successResults.length > 0 && !options.dryRun) {
        const model = options.model as string || 'claude-sonnet-4-20250514';
        const dashboard = updateDashboard(workDir, successResults, model);
        console.log(chalk.bold('\n  Dashboard:'));
        console.log(formatDashboard(dashboard));
      }

      // Summary
      console.log(chalk.bold('\n  Summary:'));
      for (const result of results) {
        if (result.error) {
          console.log(chalk.red(`    ${result.contestName}: ERROR — ${result.error}`));
        } else {
          const c = result.comparison;
          const status = c.recall >= 0.3 ? chalk.green('PASS') : chalk.yellow('NEEDS WORK');
          console.log(`    ${result.contestName}: P=${(c.precision * 100).toFixed(0)}% R=${(c.recall * 100).toFixed(0)}% F1=${(c.f1 * 100).toFixed(0)}% ${status}`);
        }
      }

      console.log('');
    } catch (err) {
      console.error(chalk.red(`\nError: ${err instanceof Error ? err.message : err}`));
      process.exit(1);
    }
  });

program
  .command('dashboard')
  .description('Show shadow audit performance dashboard')
  .option('--work-dir <path>', 'Directory containing dashboard data', 'shadow-results')
  .action((options: Record<string, unknown>) => {
    const workDir = resolve(options.workDir as string || 'shadow-results');
    const dashboard = loadDashboard(workDir);

    console.log(chalk.bold.cyan('\n  🐍 Krait — Performance Dashboard\n'));
    console.log(formatDashboard(dashboard));
    console.log('');
  });

program
  .command('contests')
  .description('List available contests in the registry')
  .action(() => {
    console.log(chalk.bold.cyan('\n  🐍 Krait — Contest Registry\n'));
    const contests = listContests();
    for (const c of contests) {
      const findings = `${c.expectedHighs}H/${c.expectedMediums}M`;
      console.log(`  ${chalk.bold(c.id.padEnd(25))} ${c.name.padEnd(22)} ${c.difficulty.padEnd(8)} ~${String(c.estimatedLOC).padEnd(6)} LOC  ${findings}`);
    }
    console.log(chalk.gray(`\n  Total: ${contests.length} contests\n`));
  });

/**
 * Infer a meaningful project name from the audit path.
 * Avoids generic names like "src", "contracts", "solidity".
 */
function inferProjectName(projectPath: string): string {
  const genericNames = new Set(['src', 'contracts', 'solidity', 'core', 'lib', 'app', 'packages']);
  const parts = projectPath.split('/').filter(p => p.length > 0);

  // Walk from the leaf upward until we find a non-generic name
  for (let i = parts.length - 1; i >= 0; i--) {
    if (!genericNames.has(parts[i])) {
      return parts[i];
    }
  }

  return parts[parts.length - 1] || 'project';
}

program.parse();
