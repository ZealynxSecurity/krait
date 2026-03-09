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
import { runArchitecturePass } from '../analysis/architecture-pass.js';
import { summarizeContract } from '../analysis/contract-summarizer.js';
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
import { Finding, FileInfo, Report, Domain, KraitConfig, ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { scoreFileComplexity, batchSmallFiles } from '../core/file-scorer.js';
import { runMultiAgentPipeline } from '../agents/multi-agent.js';

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
  noCache?: boolean;     // Disable response caching
  soloditApiKey?: string; // Solodit API key for enrichment
  multiAgent?: boolean;  // Use multi-agent pipeline (default: true)
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

  // Attach cache unless disabled
  let cache: ResponseCache | null = null;
  if (!options.noCache) {
    cache = new ResponseCache(projectPath);
    analyzer.setCache(cache);
    if (cache.size() > 0) {
      log(`    Cache: ${cache.size()} entries from previous runs`);
    }
  }

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

  // Architecture pass (unless quick mode)
  let architectureContext: ArchitectureAnalysis | null = null;
  if (!config.quick) {
    try {
      const Anthropic = (await import('@anthropic-ai/sdk')).default;
      const archClient = new Anthropic({ apiKey: config.apiKey });
      const fileContentsForArch = new Map<string, string>();
      for (const file of files) {
        fileContentsForArch.set(file.relativePath, readFileSync(file.path, 'utf-8'));
      }
      const summaries = files.map(f => {
        const content = fileContentsForArch.get(f.relativePath)!;
        return summarizeContract(f, content);
      });

      architectureContext = await runArchitecturePass(
        archClient, files, fileContentsForArch, summaries,
        config.model, cache, options.verbose
      );

      if (architectureContext.protocolSummary) {
        analyzer.setArchitectureContext(architectureContext);
        log(`    Architecture: ${architectureContext.protocolSummary.slice(0, 60)}...`);
        log(`    Fund flows: ${architectureContext.fundFlows.length}, Invariants: ${architectureContext.invariants.length}`);
      }
    } catch (err) {
      log(`    Architecture pass failed (continuing without): ${err instanceof Error ? err.message : err}`);
    }
  }

  const allFindings: Finding[] = [];
  const fileContentsMap = new Map<string, string>();
  for (const file of files) {
    fileContentsMap.set(file.relativePath, readFileSync(file.path, 'utf-8'));
  }

  // Score files for analysis strategy
  const fileScores = files.map(file => {
    const content = fileContentsMap.get(file.relativePath)!;
    return scoreFileComplexity(file, content);
  });

  const analyzeFiles = fileScores.filter(s => s.decision === 'analyze');
  const skipFiles = fileScores.filter(s => s.decision === 'skip');
  const batchFileScores = fileScores.filter(s => s.decision === 'batch');
  const batches = batchSmallFiles(batchFileScores.map(s => s.file), fileContentsMap);

  if (skipFiles.length > 0) {
    log(`    Skipped: ${skipFiles.length} files`);
  }
  if (batches.length > 0) {
    log(`    Batched: ${batchFileScores.length} small files into ${batches.length} groups`);
  }

  const useMultiAgent = options.multiAgent !== false;

  if (useMultiAgent) {
    // ─── Multi-Agent Pipeline ───
    log(`    Multi-agent pipeline: Detector → Reasoner → Critic → Ranker`);
    const analyzableFiles = fileScores
      .filter(s => s.decision !== 'skip')
      .map(s => s.file);

    const Anthropic = (await import('@anthropic-ai/sdk')).default;
    const maClient = new Anthropic({ apiKey: config.apiKey });

    try {
      const { findings: maFindings, stats } = await runMultiAgentPipeline(
        maClient,
        analyzableFiles,
        fileContentsMap,
        loader,
        domainPatterns,
        config.model,
        cache,
        {
          architectureContext,
          projectContext,
          soloditContext: soloditClient ? undefined : undefined,
          verbose: options.verbose,
          config,
        },
      );
      allFindings.push(...maFindings);
      log(`    Multi-agent: ${stats.detectCandidates} candidates → ${stats.reasonerExploitable} exploitable → ${stats.finalFindings} findings`);
    } catch (err) {
      log(`    Multi-agent pipeline failed: ${err instanceof Error ? err.message : err}`);
      // Fall back to legacy per-file analysis
      log(`    Falling back to legacy per-file analysis...`);
      const fallbackAnalyzer = new AIAnalyzer(config);
      fallbackAnalyzer.setProjectContext(projectContext);
      if (architectureContext) fallbackAnalyzer.setArchitectureContext(architectureContext);
      if (cache) fallbackAnalyzer.setCache(cache);

      for (const file of analyzableFiles) {
        try {
          const content = fileContentsMap.get(file.relativePath)!;
          const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
          const patternContext = loader.formatForPrompt(filePatterns);
          const findings = await fallbackAnalyzer.analyzeFile(file, content, patternContext);
          allFindings.push(...findings);
        } catch {
          // continue
        }
      }
      log(`    Legacy fallback: ${allFindings.length} findings`);
    }
  } else {
    // ─── Legacy Single-Pass Pipeline ───
    // Analyze individual files
    for (let i = 0; i < analyzeFiles.length; i++) {
      const { file } = analyzeFiles[i];
      try {
        const content = fileContentsMap.get(file.relativePath)!;
        const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
        const patternContext = loader.formatForPrompt(filePatterns);
        const findings = await analyzer.analyzeFile(file, content, patternContext);
        allFindings.push(...findings);
        log(`    [${i + 1}/${analyzeFiles.length + batches.length}] ${file.relativePath} (${findings.length} findings)`);
      } catch (err) {
        log(`    [${i + 1}/${analyzeFiles.length + batches.length}] ${file.relativePath} — error`);
      }
    }

    // Analyze batched files
    for (let i = 0; i < batches.length; i++) {
      const batch = batches[i];
      try {
        const patternContext = loader.formatForPrompt(domainPatterns);
        const findings = await analyzer.analyzeBatch(batch, patternContext);
        allFindings.push(...findings);
        log(`    [${analyzeFiles.length + i + 1}/${analyzeFiles.length + batches.length}] batch (${findings.length} findings)`);
      } catch {
        log(`    [${analyzeFiles.length + i + 1}/${analyzeFiles.length + batches.length}] batch — error`);
      }
    }

    // Deep analysis pass (unless quick) — uses file scores
    if (!config.quick) {
      const analyzedScores = fileScores.filter(s => s.decision !== 'skip');
      const allFileData = analyzedScores.map(s => {
        const content = fileContentsMap.get(s.file.relativePath)!;
        const findings = allFindings.filter(f => f.file === s.file.relativePath);
        const deepScore = s.score + findings.length * 3;
        return { file: s.file, content, findings, score: deepScore };
      });

      const deepLimit = analyzedScores.length <= 8 ? analyzedScores.length : 5;
      const ranked = allFileData
        .sort((a, b) => b.score - a.score)
        .slice(0, deepLimit);

      if (ranked.length > 0) {
        log(`    Deep analysis: ${ranked.length} files (top by complexity)...`);
        for (const { file, content, findings } of ranked) {
          try {
            const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
            const patternContext = loader.formatForPrompt(filePatterns);
            const deepFindings = await analyzer.analyzeDeep(file, content, findings, patternContext);
            allFindings.push(...deepFindings);
            log(`    Deep: ${file.relativePath} (+${deepFindings.length} findings)`);
          } catch {
            log(`    Deep: ${file.relativePath} — error`);
          }
        }
      }
    }

    // Flow-based analysis or cross-contract fallback (unless quick)
    if (!config.quick && files.length > 1) {
      const fileContents = files.map(f => ({
        file: f,
        content: fileContentsMap.get(f.relativePath) || readFileSync(f.path, 'utf-8'),
      }));

      if (architectureContext && architectureContext.fundFlows.length > 0) {
        try {
          const crossPatternContext = loader.formatForPrompt(domainPatterns);
          const flowFindings = await analyzer.analyzeFlows(
            architectureContext.fundFlows, fileContents, allFindings,
            architectureContext, crossPatternContext
          );
          allFindings.push(...flowFindings);
          log(`    Flow analysis: ${flowFindings.length} findings from ${Math.min(3, architectureContext.fundFlows.length)} flows`);
        } catch {
          log(`    Flow analysis failed`);
        }
      } else {
        try {
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
    // Drop low-confidence LOW/INFO
    if (f.confidence === 'low' && ['low', 'info'].includes(f.severity)) return false;
    if (f.severity === 'info') return false;
    // For larger codebases (>10 files), require medium+ confidence for medium severity
    // This prevents death-by-a-thousand-cuts FP flooding
    if (files.length > 10 && f.confidence === 'low' && f.severity === 'medium') return false;
    return true;
  });

  // Reassign sequential IDs after all filtering
  for (let i = 0; i < filteredFindings.length; i++) {
    filteredFindings[i].id = `KRAIT-${String(i + 1).padStart(3, '0')}`;
  }

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

  // Log cache stats
  if (cache) {
    const cacheStats = cache.getStats();
    if (cacheStats.hits > 0 || cacheStats.misses > 0) {
      log(`    Cache: ${cacheStats.hits} hits, ${cacheStats.misses} misses`);
    }
  }

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
