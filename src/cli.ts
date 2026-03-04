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
import {
  buildSummary,
  generateJsonReport,
  writeMarkdownReport,
  generateMarkdownReport,
} from './core/reporter.js';
import { Finding, Report, Domain } from './core/types.js';

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
      });

      const projectPath = resolve(targetPath);
      const projectName = basename(projectPath);

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
      const files = await discoverFiles(projectPath, config.excludePatterns, config.maxFileSizeKb);
      if (files.length === 0) {
        spinner.fail('No source files found');
        process.exit(1);
      }
      const totalLOC = files.reduce((sum, f) => sum + f.lines, 0);
      spinner.succeed(`Found ${files.length} source files (${totalLOC.toLocaleString()} LOC)`);

      // Step 3: Select domain and patterns
      const domain = detectDomain(files) as Domain;
      const domainPatterns = loader.getPatternsByDomain(domain);
      console.log(chalk.gray(`  Domain: ${domain} (${domainPatterns.length} domain patterns)`));

      // Step 4: Analyze files
      const analyzer = new AIAnalyzer(config);
      const allFindings: Finding[] = [];

      console.log(chalk.bold('\n  Analyzing files...'));
      for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const fileSpinner = ora(`  [${i + 1}/${files.length}] ${file.relativePath}`).start();
        try {
          const content = readFileSync(file.path, 'utf-8');
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

      // Step 6: Build report
      const duration = Date.now() - startTime;
      const summary = buildSummary(allFindings, files.length, totalLOC);
      const report: Report = {
        projectName,
        projectPath,
        timestamp: new Date().toISOString(),
        duration,
        summary,
        findings: allFindings,
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

program.parse();
