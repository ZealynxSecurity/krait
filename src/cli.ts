#!/usr/bin/env node

import { Command } from 'commander';
import chalk from 'chalk';
import ora from 'ora';
import { readFileSync, existsSync } from 'fs';
import { resolve, basename, join } from 'path';

// Load .env file (no dependency — just read and parse)
function loadEnv(): void {
  // Look for .env in CWD first, then next to the compiled JS
  const candidates = [
    resolve(process.cwd(), '.env'),
    resolve(import.meta.dirname || '.', '..', '.env'),
  ];
  const envPath = candidates.find(p => existsSync(p));
  if (!envPath) return;
  try {
    const content = readFileSync(envPath, 'utf-8');
    for (const line of content.split('\n')) {
      const trimmed = line.trim();
      if (!trimmed || trimmed.startsWith('#')) continue;
      const eqIdx = trimmed.indexOf('=');
      if (eqIdx === -1) continue;
      const key = trimmed.slice(0, eqIdx).trim();
      const value = trimmed.slice(eqIdx + 1).trim();
      if (!process.env[key]) process.env[key] = value;
    }
  } catch { /* ignore */ }
}
loadEnv();
import { resolveConfig } from './core/config.js';
import { discoverFiles, detectDomain } from './core/file-discovery.js';
import { PatternLoader } from './knowledge/pattern-loader.js';
import { AIAnalyzer } from './analysis/ai-analyzer.js';
import { runArchitecturePass } from './analysis/architecture-pass.js';
import { summarizeContract } from './analysis/contract-summarizer.js';
import { deduplicateFindings } from './analysis/deduplicator.js';
import { postProcessFindings, validateWithSolodit } from './analysis/post-processor.js';
import {
  buildSummary,
  generateJsonReport,
  writeMarkdownReport,
  generateMarkdownReport,
} from './core/reporter.js';
import { Finding, Report, Domain, ArchitectureAnalysis } from './core/types.js';
import { ResponseCache } from './core/cache.js';
import { scoreFileComplexity, batchSmallFiles, FileScore, BatchGroup } from './core/file-scorer.js';
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
import { generatePatternsFromSolodit } from './knowledge/pattern-generator.js';
import { SoloditClient } from './knowledge/solodit-client.js';
import { runMultiAgentPipeline } from './agents/multi-agent.js';

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
  .option('--deep-model <model>', 'Model for deep analysis and cross-contract passes')
  .option('--output <path>', 'Output directory for reports', '.')
  .option('--format <format>', 'Output format: json, markdown, both', 'both')
  .option('-v, --verbose', 'Verbose output')
  .option('--patterns-dir <path>', 'Path to patterns directory')
  .option('--min-lines <n>', 'Skip files with fewer lines than this', '20')
  .option('--no-cache', 'Disable response caching')
  .option('--dry-run', 'Show analysis plan without making API calls')
  .option('--multi-agent', 'Use multi-agent pipeline: Detector → Reasoner → Critic → Ranker (default)')
  .option('--no-multi-agent', 'Use legacy single-pass analysis')
  .option('--solodit-key <key>', 'Solodit API key for enrichment (or set SOLODIT_API_KEY)')
  .action(async (targetPath: string, options: Record<string, unknown>) => {
    const startTime = Date.now();

    try {
      const config = resolveConfig({
        apiKey: options.apiKey as string | undefined,
        model: options.model as string | undefined,
        deepModel: options.deepModel as string | undefined,
        quick: options.quick as boolean | undefined,
        verbose: options.verbose as boolean | undefined,
        outputFormat: options.format as 'json' | 'markdown' | 'both' | undefined,
        patternsDir: options.patternsDir as string | undefined,
        minLines: options.minLines ? parseInt(options.minLines as string, 10) : undefined,
        noCache: options.cache === false,  // Commander's --no-cache sets cache=false
        dryRun: options.dryRun as boolean | undefined,
        soloditApiKey: options.soloditKey as string | undefined,
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

      // Step 4b: Solodit enrichment (always-on, graceful fallback)
      let soloditClient: SoloditClient | null = null;
      let soloditContextStr = '';
      if (config.soloditApiKey) {
        try {
          soloditClient = new SoloditClient(config.soloditApiKey, config.verbose);
          const soloditSpinner = ora('Fetching Solodit enrichment...').start();
          const enrichmentFindings = await soloditClient.getEnrichmentFindings(
            projectContext.protocolType || '',
            projectContext.dependencies || []
          );
          soloditContextStr = soloditClient.formatForPrompt(enrichmentFindings);
          soloditSpinner.succeed(`Solodit enrichment: ${enrichmentFindings.length} real-world examples loaded`);
        } catch (err) {
          soloditClient = null; // Disable downstream Solodit features
          console.log(chalk.yellow(`  Solodit unavailable, continuing without enrichment: ${err instanceof Error ? err.message : err}`));
        }
      } else {
        console.log(chalk.yellow('  No SOLODIT_API_KEY found — running without Solodit enrichment'));
      }

      // Step 4c: Score files for analysis strategy
      const fileContentsMap = new Map<string, string>();
      for (const file of files) {
        fileContentsMap.set(file.relativePath, readFileSync(file.path, 'utf-8'));
      }

      const fileScores = files.map(file => {
        const content = fileContentsMap.get(file.relativePath)!;
        return scoreFileComplexity(file, content);
      });

      const analyzeFiles = fileScores.filter(s => s.decision === 'analyze');
      const skipFiles = fileScores.filter(s => s.decision === 'skip');
      const batchFiles = fileScores.filter(s => s.decision === 'batch');
      const batches = batchSmallFiles(
        batchFiles.map(s => s.file),
        fileContentsMap
      );

      if (skipFiles.length > 0) {
        console.log(chalk.gray(`  Skipped: ${skipFiles.length} files (${skipFiles.map(s => s.skipReason).join(', ')})`));
        if (config.verbose) {
          for (const s of skipFiles) {
            console.log(chalk.gray(`    ${s.file.relativePath} — ${s.skipReason}`));
          }
        }
      }
      if (batches.length > 0) {
        console.log(chalk.gray(`  Batched: ${batchFiles.length} small files into ${batches.length} groups`));
      }

      // Dry-run: print analysis plan and exit
      if (config.dryRun) {
        console.log(chalk.bold('\n  Dry-Run Analysis Plan:'));
        console.log(chalk.bold('\n  Files to analyze individually:'));
        for (const s of analyzeFiles) {
          const content = fileContentsMap.get(s.file.relativePath)!;
          const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
          const hints = s.details;
          console.log(`    ${s.file.relativePath} (${s.file.lines} LOC, score=${s.score.toFixed(1)}, ${filePatterns.length} patterns)`);
        }

        if (batches.length > 0) {
          console.log(chalk.bold('\n  Batched files:'));
          for (let i = 0; i < batches.length; i++) {
            const b = batches[i];
            console.log(`    Batch ${i + 1}: ${b.files.map(f => f.relativePath).join(', ')} (${b.totalLOC} LOC)`);
          }
        }

        if (skipFiles.length > 0) {
          console.log(chalk.bold('\n  Skipped files:'));
          for (const s of skipFiles) {
            console.log(`    ${s.file.relativePath} — ${s.skipReason}`);
          }
        }

        // Estimate API calls and cost
        // Sonnet: ~$3/M input, ~$15/M output. Opus: ~$15/M input, ~$75/M output.
        // Rough estimate: 1 token ≈ 4 chars. System prompt ≈ 3K tokens, output ≈ 500 tokens/call.
        const SONNET_INPUT_PER_TOKEN = 3 / 1_000_000;
        const SONNET_OUTPUT_PER_TOKEN = 15 / 1_000_000;
        const OPUS_INPUT_PER_TOKEN = 15 / 1_000_000;
        const OPUS_OUTPUT_PER_TOKEN = 75 / 1_000_000;
        const SYSTEM_PROMPT_TOKENS = 3000;
        const OUTPUT_TOKENS_PER_CALL = 500;

        const isOpusDeep = config.deepModel?.includes('opus');

        let firstPassCost = 0;
        for (const s of analyzeFiles) {
          const contentTokens = Math.ceil((fileContentsMap.get(s.file.relativePath)?.length || 0) / 4);
          const inputTokens = SYSTEM_PROMPT_TOKENS + contentTokens;
          firstPassCost += inputTokens * SONNET_INPUT_PER_TOKEN + OUTPUT_TOKENS_PER_CALL * SONNET_OUTPUT_PER_TOKEN;
        }
        for (const b of batches) {
          const batchTokens = Math.ceil(b.totalLOC * 40 / 4); // ~40 chars/line average
          const inputTokens = SYSTEM_PROMPT_TOKENS + batchTokens;
          firstPassCost += inputTokens * SONNET_INPUT_PER_TOKEN + OUTPUT_TOKENS_PER_CALL * SONNET_OUTPUT_PER_TOKEN;
        }

        const firstPassCalls = analyzeFiles.length + batches.length;
        const analyzableCount = analyzeFiles.length + batchFiles.length;
        const deepPassFiles = config.quick ? 0 : Math.min(analyzableCount, analyzableCount <= 8 ? analyzableCount : 5);
        const crossContract = (!config.quick && files.length > 1) ? 1 : 0;

        let deepPassCost = 0;
        if (deepPassFiles > 0) {
          // Deep pass files are the largest/most complex ones
          const deepInputRate = isOpusDeep ? OPUS_INPUT_PER_TOKEN : SONNET_INPUT_PER_TOKEN;
          const deepOutputRate = isOpusDeep ? OPUS_OUTPUT_PER_TOKEN : SONNET_OUTPUT_PER_TOKEN;
          const sortedByScore = [...analyzeFiles].sort((a, b) => b.score - a.score);
          for (let i = 0; i < Math.min(deepPassFiles, sortedByScore.length); i++) {
            const contentTokens = Math.ceil((fileContentsMap.get(sortedByScore[i].file.relativePath)?.length || 0) / 4);
            deepPassCost += (SYSTEM_PROMPT_TOKENS + contentTokens) * deepInputRate + OUTPUT_TOKENS_PER_CALL * deepOutputRate;
          }
        }

        let crossContractCost = 0;
        if (crossContract) {
          const crossInputRate = isOpusDeep ? OPUS_INPUT_PER_TOKEN : SONNET_INPUT_PER_TOKEN;
          const crossOutputRate = isOpusDeep ? OPUS_OUTPUT_PER_TOKEN : SONNET_OUTPUT_PER_TOKEN;
          const totalContentTokens = Math.ceil(totalLOC * 40 / 4);
          crossContractCost = (SYSTEM_PROMPT_TOKENS + Math.min(totalContentTokens, 20000)) * crossInputRate + OUTPUT_TOKENS_PER_CALL * crossOutputRate;
        }

        const totalCalls = firstPassCalls + deepPassFiles + crossContract;
        const totalCost = firstPassCost + deepPassCost + crossContractCost;

        console.log(chalk.bold('\n  Estimated API calls:'));
        console.log(`    First pass: ${firstPassCalls} (${analyzeFiles.length} individual + ${batches.length} batched) ~$${firstPassCost.toFixed(2)}`);
        if (!config.quick) {
          console.log(`    Deep pass: ${deepPassFiles} files (${isOpusDeep ? 'Opus' : 'Sonnet'}) ~$${deepPassCost.toFixed(2)}`);
          console.log(`    Cross-contract: ${crossContract ? 'yes' : 'no'}${crossContract ? ` ~$${crossContractCost.toFixed(2)}` : ''}`);
        }
        console.log(`    Total: ~${totalCalls} calls`);
        console.log(chalk.bold(`    Estimated cost: ~$${totalCost.toFixed(2)}`));
        console.log('');
        process.exit(0);
      }

      // Step 4d: Architecture pass (unless quick mode or dry-run)
      let architectureContext: ArchitectureAnalysis | null = null;
      if (!config.quick && !config.dryRun) {
        const archSpinner = ora('Running architecture analysis...').start();
        try {
          const archClient = new (await import('@anthropic-ai/sdk')).default({ apiKey: config.apiKey });
          const summaries = files.map(f => {
            const content = fileContentsMap.get(f.relativePath)!;
            return summarizeContract(f, content);
          });

          // Create a temporary cache for the architecture pass
          let archCache: ResponseCache | null = null;
          if (!config.noCache) {
            archCache = new ResponseCache(projectPath);
          }

          architectureContext = await runArchitecturePass(
            archClient, files, fileContentsMap, summaries,
            config.model, archCache, config.verbose
          );

          const flowNames = architectureContext.fundFlows.map(f => f.name).join(', ');
          archSpinner.succeed(`Architecture: ${architectureContext.protocolSummary.slice(0, 80)}...`);
          if (config.verbose) {
            console.log(chalk.gray(`  Fund flows: ${flowNames || 'none identified'}`));
            console.log(chalk.gray(`  Invariants: ${architectureContext.invariants.length}`));
            console.log(chalk.gray(`  Contract roles: ${architectureContext.contractRoles.length}`));
          }
        } catch (err) {
          archSpinner.fail('Architecture analysis failed (continuing without)');
          if (config.verbose) console.error(chalk.red(`    ${err}`));
        }
      }

      // Step 5: Analyze files
      // Determine pipeline mode: multi-agent (default) or legacy
      const useMultiAgent = options.multiAgent !== false; // --no-multi-agent sets multiAgent=false

      // Attach cache
      let auditCache: ResponseCache | null = null;
      if (!config.noCache) {
        auditCache = new ResponseCache(projectPath);
        if (config.verbose && auditCache.size() > 0) {
          console.log(chalk.gray(`  Cache: ${auditCache.size()} entries from previous runs`));
        }
      }

      const allFindings: Finding[] = [];

      if (useMultiAgent) {
        // ─── Multi-Agent Pipeline: Detector → Reasoner → Critic → Ranker ───
        console.log(chalk.bold('\n  Multi-agent analysis pipeline...'));

        const analyzableFiles = fileScores
          .filter(s => s.decision !== 'skip')
          .map(s => s.file);

        const Anthropic = (await import('@anthropic-ai/sdk')).default;
        const maClient = new Anthropic({ apiKey: config.apiKey });

        const pipelineSpinner = ora('  Running Detector → Reasoner → Critic → Ranker...').start();
        try {
          const { findings: maFindings, stats } = await runMultiAgentPipeline(
            maClient,
            analyzableFiles,
            fileContentsMap,
            loader,
            domainPatterns,
            config.model,
            auditCache,
            {
              architectureContext,
              projectContext,
              soloditContext: soloditContextStr || undefined,
              verbose: config.verbose,
              config,
            },
          );
          allFindings.push(...maFindings);

          pipelineSpinner.succeed(
            `  Multi-agent: ${stats.detectCandidates} candidates → ${stats.reasonerExploitable} exploitable → ${stats.criticValid} valid + ${stats.criticUncertain} uncertain → ${stats.finalFindings} findings`
          );
        } catch (err) {
          pipelineSpinner.fail('  Multi-agent pipeline failed, falling back to legacy...');
          if (config.verbose) console.error(chalk.red(`    ${err}`));

          // Actually fall back to legacy per-file analysis
          const fallbackAnalyzer = new AIAnalyzer(config);
          fallbackAnalyzer.setProjectContext(projectContext);
          if (architectureContext) fallbackAnalyzer.setArchitectureContext(architectureContext);
          if (soloditContextStr) fallbackAnalyzer.setSoloditContext(soloditContextStr);
          if (auditCache) fallbackAnalyzer.setCache(auditCache);

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
          console.log(chalk.yellow(`    Legacy fallback: ${allFindings.length} findings`));
        }
      } else {
        // ─── Legacy Single-Pass Pipeline ───
        const analyzer = new AIAnalyzer(config);
        analyzer.setProjectContext(projectContext);
        if (architectureContext) analyzer.setArchitectureContext(architectureContext);
        if (soloditContextStr) analyzer.setSoloditContext(soloditContextStr);
        if (auditCache) analyzer.setCache(auditCache);

        console.log(chalk.bold('\n  Analyzing files (legacy mode)...'));

        // Analyze individual files
        for (let i = 0; i < analyzeFiles.length; i++) {
          const { file } = analyzeFiles[i];
          const fileSpinner = ora(`  [${i + 1}/${analyzeFiles.length + batches.length}] ${file.relativePath}`).start();
          try {
            const content = fileContentsMap.get(file.relativePath)!;
            const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
            const patternContext = loader.formatForPrompt(filePatterns);
            const findings = await analyzer.analyzeFile(file, content, patternContext);
            allFindings.push(...findings);
            const findingText = findings.length > 0
              ? chalk.yellow(` (${findings.length} findings)`)
              : chalk.green(' (clean)');
            fileSpinner.succeed(`  [${i + 1}/${analyzeFiles.length + batches.length}] ${file.relativePath}${findingText}`);
          } catch (err) {
            fileSpinner.fail(`  [${i + 1}/${analyzeFiles.length + batches.length}] ${file.relativePath} — error`);
            if (config.verbose) {
              console.error(chalk.red(`    ${err}`));
            }
          }
        }

        // Analyze batched files
        for (let i = 0; i < batches.length; i++) {
          const batch = batches[i];
          const batchLabel = batch.files.map(f => f.relativePath).join(', ');
          const idx = analyzeFiles.length + i + 1;
          const batchSpinner = ora(`  [${idx}/${analyzeFiles.length + batches.length}] batch: ${batchLabel}`).start();
          try {
            const patternContext = loader.formatForPrompt(domainPatterns);
            const findings = await analyzer.analyzeBatch(batch, patternContext);
            allFindings.push(...findings);
            const findingText = findings.length > 0
              ? chalk.yellow(` (${findings.length} findings)`)
              : chalk.green(' (clean)');
            batchSpinner.succeed(`  [${idx}/${analyzeFiles.length + batches.length}] batch: ${batchLabel}${findingText}`);
          } catch (err) {
            batchSpinner.fail(`  [${idx}/${analyzeFiles.length + batches.length}] batch: ${batchLabel} — error`);
            if (config.verbose) {
              console.error(chalk.red(`    ${err}`));
            }
          }
        }

        // Step 5a: Deep analysis pass (unless quick mode)
        if (!config.quick) {
          const analyzedFiles = fileScores.filter(s => s.decision !== 'skip');
          const allFileData = analyzedFiles.map(s => {
            const content = fileContentsMap.get(s.file.relativePath)!;
            const findings = allFindings.filter(f => f.file === s.file.relativePath);
            const deepScore = s.score + findings.length * 3;
            return { file: s.file, content, findings, score: deepScore };
          });

          const deepLimit = analyzedFiles.length <= 8 ? analyzedFiles.length : 5;
          const ranked = allFileData
            .sort((a, b) => b.score - a.score)
            .slice(0, deepLimit);

          if (ranked.length > 0) {
            const deepSpinner = ora(`  Deep analysis on ${ranked.length} files...`).start();
            let deepTotal = 0;
            for (const { file, content, findings } of ranked) {
              try {
                const filePatterns = loader.filterPatternsForFile(domainPatterns, content);
                const patternContext = loader.formatForPrompt(filePatterns);
                const deepFindings = await analyzer.analyzeDeep(file, content, findings, patternContext);
                allFindings.push(...deepFindings);
                deepTotal += deepFindings.length;
              } catch {
                // continue with other files
              }
            }
            deepSpinner.succeed(`  Deep analysis complete (+${deepTotal} findings)`);
          }
        }

        // Step 5b: Flow-based analysis or cross-contract fallback (unless quick mode)
        if (!config.quick && files.length > 1) {
          const fileContents = files.map(f => ({
            file: f,
            content: fileContentsMap.get(f.relativePath) || readFileSync(f.path, 'utf-8'),
          }));

          if (architectureContext && architectureContext.fundFlows.length > 0) {
            const flowSpinner = ora(`  Tracing ${Math.min(3, architectureContext.fundFlows.length)} critical fund flows...`).start();
            try {
              const crossPatternContext = loader.formatForPrompt(domainPatterns);
              const flowFindings = await analyzer.analyzeFlows(
                architectureContext.fundFlows,
                fileContents,
                allFindings,
                architectureContext,
                crossPatternContext
              );
              allFindings.push(...flowFindings);
              flowSpinner.succeed(
                `  Flow analysis complete (${flowFindings.length} findings from ${Math.min(3, architectureContext.fundFlows.length)} flows)`
              );
            } catch (err) {
              flowSpinner.fail('  Flow analysis failed');
              if (config.verbose) console.error(chalk.red(`    ${err}`));
            }
          } else {
            const crossSpinner = ora('  Running cross-contract analysis...').start();
            try {
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
        }
      }

      // Step 6: Post-processing — deduplicate, adjust confidence, filter FPs
      const dedupFindings = deduplicateFindings(allFindings);
      if (config.verbose && dedupFindings.length < allFindings.length) {
        console.log(chalk.gray(`\n  Dedup: ${allFindings.length} → ${dedupFindings.length} findings`));
      }

      let processedFindings = postProcessFindings(dedupFindings, files, fileContentsMap, projectContext);
      if (config.verbose && processedFindings.length < dedupFindings.length) {
        console.log(chalk.gray(`  Post-process: ${dedupFindings.length} → ${processedFindings.length} findings`));
      }

      // Step 6b: Solodit validation (precision boost)
      if (soloditClient) {
        try {
          const valSpinner = ora('Validating findings against Solodit...').start();
          processedFindings = await validateWithSolodit(processedFindings, soloditClient);
          const refsCount = processedFindings.filter(f => f.soloditRefs?.length).length;
          valSpinner.succeed(`Solodit validation: ${refsCount} findings corroborated`);
        } catch (err) {
          if (config.verbose) console.log(chalk.yellow(`  Solodit validation skipped: ${err instanceof Error ? err.message : err}`));
        }
      }

      // Step 6c: Solodit gap analysis (recall boost) — legacy mode only
      if (soloditClient && !config.quick && !useMultiAgent) {
        try {
          const gapAnalyzer = new AIAnalyzer(config);
          gapAnalyzer.setProjectContext(projectContext);
          if (architectureContext) gapAnalyzer.setArchitectureContext(architectureContext);
          if (soloditContextStr) gapAnalyzer.setSoloditContext(soloditContextStr);
          if (auditCache) gapAnalyzer.setCache(auditCache);

          const existingCategories = [...new Set(processedFindings.map(f => f.category))];
          const gapFindings = await soloditClient.getGapFindings(
            projectContext.protocolType || '',
            existingCategories
          );
          if (gapFindings.length > 0) {
            const gapSpinner = ora(`Gap analysis: checking ${gapFindings.length} missed patterns...`).start();
            const gapContext = soloditClient.formatForPrompt(gapFindings, 10);
            const fileContents = files
              .sort((a, b) => b.lines - a.lines)
              .slice(0, 5)
              .map(f => ({
                file: f,
                content: fileContentsMap.get(f.relativePath) || readFileSync(f.path, 'utf-8'),
              }));
            const gapResults = await gapAnalyzer.analyzeGaps(gapContext, fileContents, processedFindings);
            if (gapResults.length > 0) {
              const dedupGap = deduplicateFindings([...processedFindings, ...gapResults]);
              const newGapCount = dedupGap.length - processedFindings.length;
              processedFindings = postProcessFindings(dedupGap, files, fileContentsMap, projectContext);
              gapSpinner.succeed(`Gap analysis: +${newGapCount} new findings`);
            } else {
              gapSpinner.succeed('Gap analysis: no new findings');
            }
          }
        } catch (err) {
          if (config.verbose) console.log(chalk.yellow(`  Gap analysis skipped: ${err instanceof Error ? err.message : err}`));
        }
      }

      const rawCount = processedFindings.length;
      const filteredFindings = processedFindings.filter(f => {
        // Drop low-confidence LOW/INFO findings
        if (f.confidence === 'low' && ['low', 'info'].includes(f.severity)) {
          return false;
        }
        // Drop info-level findings unless verbose
        if (f.severity === 'info' && !config.verbose) {
          return false;
        }
        // For larger codebases (>10 files), require medium+ confidence for medium severity
        if (files.length > 10 && f.confidence === 'low' && f.severity === 'medium') {
          return false;
        }
        return true;
      });

      if (rawCount !== filteredFindings.length && config.verbose) {
        console.log(chalk.gray(`\n  Filtered: ${rawCount - filteredFindings.length} low-confidence/info findings removed`));
      }

      // Reassign sequential IDs after all filtering
      for (let i = 0; i < filteredFindings.length; i++) {
        filteredFindings[i].id = `KRAIT-${String(i + 1).padStart(3, '0')}`;
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
      console.log(chalk.gray(`\n  Duration: ${(duration / 1000).toFixed(1)}s`));

      // Show cache stats if cache was used
      if (auditCache) {
        const stats = auditCache.getStats();
        console.log(chalk.gray(`  Cache: ${stats.hits} hits, ${stats.misses} misses, ${stats.size} entries stored`));
      }
      console.log('');

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
  .option('--deep-model <model>', 'Model for deep analysis and cross-contract passes')
  .option('--dry-run', 'Show what would happen without running audits')
  .option('--skip-clone', 'Use already-cloned repos in work dir')
  .option('--multi-agent', 'Use multi-agent pipeline (default)')
  .option('--no-multi-agent', 'Use legacy single-pass analysis')
  .option('--ai-match', 'Use AI-assisted matching for comparison scoring (more accurate, costs ~$0.01/contest)')
  .option('--api-key <key>', 'Anthropic API key')
  .option('--solodit-key <key>', 'Solodit API key for enrichment (or set SOLODIT_API_KEY)')
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
        deepModel: options.deepModel as string | undefined,
        verbose: options.verbose as boolean | undefined,
        dryRun: options.dryRun as boolean | undefined,
        skipClone: options.skipClone as boolean | undefined,
        aiMatch: options.aiMatch as boolean | undefined,
        soloditApiKey: (options.soloditKey as string | undefined) || process.env.SOLODIT_API_KEY || undefined,
        multiAgent: options.multiAgent !== false,
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

program
  .command('ingest-solodit')
  .description('Ingest solodit audit reports and generate vulnerability patterns')
  .argument('<repo-path>', 'Path to cloned solodit/solodit_content repo')
  .option('--output <path>', 'Output directory for generated patterns', 'patterns')
  .option('--max-reports <n>', 'Maximum number of reports to process', '400')
  .option('--min-cluster-size <n>', 'Minimum findings per cluster', '3')
  .option('--dry-run', 'Show what would be generated without writing files')
  .option('--api-key <key>', 'Anthropic API key')
  .option('-v, --verbose', 'Verbose output')
  .action(async (repoPath: string, options: Record<string, unknown>) => {
    try {
      const absRepoPath = resolve(repoPath);
      const outputDir = resolve(options.output as string || 'patterns');

      console.log(chalk.bold.cyan('\n  🐍 Krait — Solodit Ingestion'));
      console.log(chalk.gray(`  Source: ${absRepoPath}`));
      console.log(chalk.gray(`  Output: ${outputDir}\n`));

      const apiKey = (options.apiKey as string) || process.env.ANTHROPIC_API_KEY;
      if (!apiKey) {
        console.error(chalk.red('  API key required for classification. Set ANTHROPIC_API_KEY or pass --api-key'));
        process.exit(1);
      }

      // Load existing patterns for dedup
      const patternsDir = resolve('patterns');
      const loader = new PatternLoader(patternsDir);
      const existingPatterns = loader.load();
      console.log(chalk.gray(`  Existing patterns: ${existingPatterns.length}`));

      const result = await generatePatternsFromSolodit(
        absRepoPath,
        outputDir,
        existingPatterns,
        apiKey,
        {
          maxReports: parseInt(options.maxReports as string || '400', 10),
          minClusterSize: parseInt(options.minClusterSize as string || '3', 10),
          dryRun: options.dryRun as boolean | undefined,
          verbose: options.verbose as boolean | undefined,
        },
        (msg) => console.log(msg)
      );

      console.log(chalk.bold('\n  Results:'));
      console.log(`    Total findings parsed: ${result.totalFindings}`);
      console.log(`    New patterns generated: ${result.generated}`);
      console.log(`    Duplicates skipped: ${result.skippedDuplicates}`);
      console.log('');

    } catch (err) {
      console.error(chalk.red(`\nError: ${err instanceof Error ? err.message : err}`));
      process.exit(1);
    }
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

program
  .command('version')
  .description('Show version number')
  .action(() => {
    console.log(VERSION);
  });

program.parse();
