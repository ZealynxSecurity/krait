/**
 * Shadow audit runner — automated pipeline for benchmarking Krait
 * against known public contest results.
 *
 * Pipeline: Clone repo → Run Krait audit → Clone findings → Compare → Score
 */

import { execSync } from 'child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { resolve, join, basename } from 'path';
import { ContestEntry } from './registry.js';
import { resolveConfig } from '../core/config.js';
import { discoverFiles, detectDomain } from '../core/file-discovery.js';
import { PatternLoader } from '../knowledge/pattern-loader.js';
import { AIAnalyzer } from '../analysis/ai-analyzer.js';
import { gatherProjectContext } from '../analysis/context-gatherer.js';
import { deduplicateFindings } from '../analysis/deduplicator.js';
import { postProcessFindings, validateWithSolodit } from '../analysis/post-processor.js';
import { SoloditClient } from '../knowledge/solodit-client.js';
import { buildSummary, generateJsonReport } from '../core/reporter.js';
import {
  parseOfficialFindings,
  compareFindings,
  compareFindingsAI,
  CompareResult,
} from '../core/comparator.js';
import { Finding, FileInfo, Report, Domain, KraitConfig } from '../core/types.js';

export interface ShadowAuditResult {
  contestId: string;
  contestName: string;
  timestamp: string;
  duration: number;
  comparison: CompareResult;
  reportPath: string;
  error?: string;
}

export interface ShadowAuditOptions {
  workDir: string;       // Where to clone repos and store results
  patternsDir: string;   // Path to patterns directory
  apiKey?: string;       // Anthropic API key (or env var)
  model?: string;        // Model override
  deepModel?: string;    // Model for deep analysis / cross-contract
  quick?: boolean;       // Quick mode (Sonnet only)
  verbose?: boolean;
  dryRun?: boolean;      // Just clone and show what would happen
  skipClone?: boolean;   // Use existing repos (already cloned)
  aiMatch?: boolean;     // Use AI-assisted matching for comparison
  soloditApiKey?: string; // Solodit API key for enrichment
}

/**
 * Run a shadow audit against a single contest.
 */
export async function runShadowAudit(
  contest: ContestEntry,
  options: ShadowAuditOptions,
  log: (msg: string) => void = console.log
): Promise<ShadowAuditResult> {
  const startTime = Date.now();
  const workDir = resolve(options.workDir);

  if (!existsSync(workDir)) {
    mkdirSync(workDir, { recursive: true });
  }

  const sourceDir = join(workDir, basename(contest.sourceRepo));
  const findingsDir = join(workDir, basename(contest.findingsRepo));

  try {
    // Step 1: Clone source repo (if needed)
    if (!options.skipClone) {
      if (!existsSync(sourceDir)) {
        log(`  Cloning source: ${contest.sourceRepo}`);
        execSync(`git clone --depth 1 ${contest.sourceRepo} ${sourceDir}`, {
          stdio: options.verbose ? 'inherit' : 'pipe',
          timeout: 120000,
        });
      } else {
        log(`  Source already cloned: ${sourceDir}`);
      }

      // Step 2: Clone findings repo (if needed)
      if (!existsSync(findingsDir)) {
        log(`  Cloning findings: ${contest.findingsRepo}`);
        execSync(`git clone --depth 1 ${contest.findingsRepo} ${findingsDir}`, {
          stdio: options.verbose ? 'inherit' : 'pipe',
          timeout: 120000,
        });
      } else {
        log(`  Findings already cloned: ${findingsDir}`);
      }
    }

    // Verify repos exist
    if (!existsSync(sourceDir)) {
      throw new Error(`Source directory not found: ${sourceDir}`);
    }
    if (!existsSync(findingsDir)) {
      throw new Error(`Findings directory not found: ${findingsDir}`);
    }

    // Step 3: Verify findings report.md exists
    const reportMd = join(findingsDir, 'report.md');
    if (!existsSync(reportMd)) {
      throw new Error(`No report.md found in ${findingsDir}`);
    }

    // Parse official findings
    const officialFindings = parseOfficialFindings(reportMd);
    log(`  Official findings: ${officialFindings.length} (H/M)`);

    if (officialFindings.length === 0) {
      throw new Error('No official H/M findings found in report.md');
    }

    if (options.dryRun) {
      log(`  [DRY RUN] Would audit: ${join(sourceDir, contest.sourcePath)}`);
      log(`  [DRY RUN] Would compare against ${officialFindings.length} official findings`);
      return {
        contestId: contest.id,
        contestName: contest.name,
        timestamp: new Date().toISOString(),
        duration: Date.now() - startTime,
        comparison: {
          contestName: contest.name,
          officialFindings,
          kraitFindings: [],
          matches: [],
          truePositives: 0,
          falseNegatives: officialFindings.length,
          falsePositives: 0,
          precision: 0,
          recall: 0,
          f1: 0,
          byRisk: {
            high: { tp: 0, fn: 0, total: 0, recall: 0 },
            medium: { tp: 0, fn: 0, total: 0, recall: 0 },
          },
        },
        reportPath: '',
      };
    }

    // Step 4: Run Krait audit
    const auditPath = join(sourceDir, contest.sourcePath);
    if (!existsSync(auditPath)) {
      throw new Error(`Source path not found: ${auditPath}`);
    }

    log(`  Running Krait audit on: ${auditPath}`);
    const { findings, report, reportPath } = await runAudit(
      auditPath, contest, options, log
    );

    // Step 5: Compare (only medium+ findings — official findings are H/M only)
    const comparableFindings = findings.filter(f =>
      ['critical', 'high', 'medium'].includes(f.severity)
    );
    log(`  Comparing ${comparableFindings.length} Krait findings (${findings.length} total, ${findings.length - comparableFindings.length} low/info filtered) vs ${officialFindings.length} official`);

    let comparison: CompareResult;
    if (options.aiMatch) {
      log(`  Using AI-assisted matching...`);
      comparison = await compareFindingsAI(
        contest.name, officialFindings, comparableFindings,
        options.apiKey, log
      );
    } else {
      comparison = compareFindings(contest.name, officialFindings, comparableFindings);
    }

    const result: ShadowAuditResult = {
      contestId: contest.id,
      contestName: contest.name,
      timestamp: new Date().toISOString(),
      duration: Date.now() - startTime,
      comparison,
      reportPath,
    };

    // Save result
    const resultPath = join(workDir, `shadow-result-${contest.id}.json`);
    writeFileSync(resultPath, JSON.stringify(result, null, 2));
    log(`  Result saved: ${resultPath}`);

    return result;

  } catch (err) {
    const errorMsg = err instanceof Error ? err.message : String(err);
    log(`  ERROR: ${errorMsg}`);
    return {
      contestId: contest.id,
      contestName: contest.name,
      timestamp: new Date().toISOString(),
      duration: Date.now() - startTime,
      comparison: {
        contestName: contest.name,
        officialFindings: [],
        kraitFindings: [],
        matches: [],
        truePositives: 0,
        falseNegatives: 0,
        falsePositives: 0,
        precision: 0,
        recall: 0,
        f1: 0,
        byRisk: {
          high: { tp: 0, fn: 0, total: 0, recall: 0 },
          medium: { tp: 0, fn: 0, total: 0, recall: 0 },
        },
      },
      reportPath: '',
      error: errorMsg,
    };
  }
}

/**
 * Run the actual Krait audit pipeline (same logic as CLI audit command).
 */
async function runAudit(
  projectPath: string,
  contest: ContestEntry,
  options: ShadowAuditOptions,
  log: (msg: string) => void
): Promise<{ findings: Finding[]; report: Report; reportPath: string }> {
  const config = resolveConfig({
    apiKey: options.apiKey,
    model: options.model,
    deepModel: options.deepModel,
    quick: options.quick,
    verbose: options.verbose,
    patternsDir: options.patternsDir,
  });

  // Load patterns
  const patternsDir = resolve(config.patternsDir);
  const loader = new PatternLoader(patternsDir);
  loader.load();

  // Discover files
  const files = await discoverFiles(
    projectPath, config.excludePatterns, config.maxFileSizeKb, config.minLines
  );
  if (files.length === 0) {
    throw new Error('No source files found');
  }
  const totalLOC = files.reduce((sum, f) => sum + f.lines, 0);
  log(`  Found ${files.length} files (${totalLOC.toLocaleString()} LOC)`);

  // Gather project context
  const projectContext = await gatherProjectContext(projectPath, files);
  if (projectContext.protocolName) {
    log(`  Protocol: ${projectContext.protocolName} (${projectContext.protocolType || 'unknown type'})`);
  }

  // Domain & patterns
  const domain = detectDomain(files) as Domain;
  const domainPatterns = loader.getPatternsByDomain(domain);

  // Analyze
  const analyzer = new AIAnalyzer(config);
  analyzer.setProjectContext(projectContext);

  // Solodit enrichment (always-on, graceful fallback)
  const soloditKey = options.soloditApiKey || process.env.SOLODIT_API_KEY;
  let soloditClient: SoloditClient | null = null;
  if (soloditKey) {
    try {
      soloditClient = new SoloditClient(soloditKey, options.verbose);
      const enrichmentFindings = await soloditClient.getEnrichmentFindings(
        projectContext.protocolType || '',
        projectContext.dependencies || []
      );
      const soloditContext = soloditClient.formatForPrompt(enrichmentFindings);
      if (soloditContext) analyzer.setSoloditContext(soloditContext);
      log(`    Solodit enrichment: ${enrichmentFindings.length} examples loaded`);
    } catch (err) {
      soloditClient = null;
      log(`    Solodit unavailable, continuing without: ${err instanceof Error ? err.message : err}`);
    }
  }

  const allFindings: Finding[] = [];
  const fileContentsMap = new Map<string, string>();

  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    try {
      const content = readFileSync(file.path, 'utf-8');
      fileContentsMap.set(file.relativePath, content);
      const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
      const patternContext = loader.formatForPrompt(filePatterns);
      const findings = await analyzer.analyzeFile(file, content, patternContext);
      allFindings.push(...findings);
      log(`    [${i + 1}/${files.length}] ${file.relativePath} (${findings.length} findings)`);
    } catch (err) {
      log(`    [${i + 1}/${files.length}] ${file.relativePath} — error`);
    }
  }

  // Deep analysis pass (unless quick) — second pass on files that had findings
  if (!config.quick) {
    const filesWithFindings = new Map<string, { file: FileInfo; content: string; findings: Finding[] }>();
    for (const finding of allFindings) {
      const file = files.find(f => f.relativePath === finding.file);
      if (file && !filesWithFindings.has(file.relativePath)) {
        const content = fileContentsMap.get(file.relativePath) || readFileSync(file.path, 'utf-8');
        filesWithFindings.set(file.relativePath, {
          file,
          content,
          findings: allFindings.filter(f => f.file === file.relativePath),
        });
      }
    }

    if (filesWithFindings.size > 0) {
      // Rank by finding count + file size, take top 8 most interesting files
      const ranked = [...filesWithFindings.entries()]
        .sort((a, b) => {
          const scoreA = a[1].findings.length * 2 + a[1].file.lines / 100;
          const scoreB = b[1].findings.length * 2 + b[1].file.lines / 100;
          return scoreB - scoreA;
        })
        .slice(0, 8);
      log(`    Deep analysis: ${ranked.length} files (of ${filesWithFindings.size} with findings)...`);
      for (const [relPath, { file, content, findings }] of ranked) {
        try {
          const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
          const patternContext = loader.formatForPrompt(filePatterns);
          const deepFindings = await analyzer.analyzeDeep(file, content, findings, patternContext);
          allFindings.push(...deepFindings);
          log(`    Deep: ${relPath} (+${deepFindings.length} findings)`);
        } catch {
          log(`    Deep: ${relPath} — error`);
        }
      }
    }
  }

  // Cross-contract (unless quick)
  if (!config.quick && files.length > 1) {
    try {
      const fileContents = files.map(f => ({
        file: f,
        content: readFileSync(f.path, 'utf-8'),
      }));
      const crossPatternContext = loader.formatForPrompt(domainPatterns);
      const crossFindings = await analyzer.analyzeCrossContract(
        fileContents, allFindings, crossPatternContext
      );
      allFindings.push(...crossFindings);
      log(`    Cross-contract: ${crossFindings.length} findings`);
    } catch {
      log(`    Cross-contract analysis failed`);
    }
  }

  // Post-process
  const dedupFindings = deduplicateFindings(allFindings);
  let processedFindings = postProcessFindings(dedupFindings, files, fileContentsMap, projectContext);

  // Solodit validation (injection point 2)
  if (soloditClient) {
    try {
      processedFindings = await validateWithSolodit(processedFindings, soloditClient);
      const refsCount = processedFindings.filter(f => f.soloditRefs?.length).length;
      log(`    Solodit validation: ${refsCount} findings corroborated`);
    } catch {
      // Non-fatal
    }
  }

  // Solodit gap analysis (injection point 3)
  if (soloditClient && !config.quick) {
    try {
      const existingCategories = [...new Set(processedFindings.map(f => f.category))];
      const gapFindings = await soloditClient.getGapFindings(
        projectContext.protocolType || '',
        existingCategories
      );
      if (gapFindings.length > 0) {
        const gapContext = soloditClient.formatForPrompt(gapFindings, 10);
        const fileContents = files
          .sort((a, b) => b.lines - a.lines)
          .slice(0, 5)
          .map(f => ({
            file: f,
            content: fileContentsMap.get(f.relativePath) || readFileSync(f.path, 'utf-8'),
          }));
        const gapResults = await analyzer.analyzeGaps(gapContext, fileContents, processedFindings);
        if (gapResults.length > 0) {
          const dedupGap = deduplicateFindings([...processedFindings, ...gapResults]);
          processedFindings = postProcessFindings(dedupGap, files, fileContentsMap, projectContext);
          log(`    Gap analysis: +${gapResults.length} new findings`);
        }
      }
    } catch {
      // Non-fatal
    }
  }

  const filteredFindings = processedFindings.filter(f => {
    if (f.confidence === 'low' && !['critical', 'high'].includes(f.severity)) return false;
    if (f.severity === 'info') return false;
    return true;
  });

  // Build report
  const projectName = contest.id;
  const summary = buildSummary(filteredFindings, files.length, totalLOC);
  const report: Report = {
    projectName,
    projectPath,
    timestamp: new Date().toISOString(),
    duration: 0,
    summary,
    findings: filteredFindings,
    filesAnalyzed: files,
    patternsUsed: domainPatterns.length,
    model: config.model,
  };

  // Save report
  const reportPath = join(options.workDir, `krait-report-${contest.id}.json`);
  generateJsonReport(report, reportPath);

  return { findings: filteredFindings, report, reportPath };
}

/**
 * Run shadow audits against multiple contests.
 */
export async function runBatchShadowAudit(
  contests: ContestEntry[],
  options: ShadowAuditOptions,
  log: (msg: string) => void = console.log
): Promise<ShadowAuditResult[]> {
  const results: ShadowAuditResult[] = [];

  for (const contest of contests) {
    log(`\n━━━ ${contest.name} (${contest.id}) ━━━`);
    const result = await runShadowAudit(contest, options, log);
    results.push(result);

    if (!result.error) {
      const c = result.comparison;
      log(`  Precision: ${(c.precision * 100).toFixed(1)}% | Recall: ${(c.recall * 100).toFixed(1)}% | F1: ${(c.f1 * 100).toFixed(1)}%`);
    }
  }

  return results;
}
