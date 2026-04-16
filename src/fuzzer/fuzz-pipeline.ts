/**
 * Fuzz pipeline orchestrator.
 * Extract Invariants → Generate Tests → Run & Fix Loop → Collect Results
 *
 * Mirrors the structure of agents/multi-agent.ts.
 */

import Anthropic from '@anthropic-ai/sdk';
import { FileInfo, ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { ProjectContext } from '../analysis/context-gatherer.js';
import { scoreFileComplexity } from '../core/file-scorer.js';
import { runParallel } from '../core/parallel.js';
import {
  Invariant,
  FuzzTestFile,
  InvariantResult,
  FuzzPipelineStats,
  FuzzPipelineOptions,
  FoundryConfig,
  InvariantCounter,
  TestFileCounter,
} from './types.js';
import { extractInvariants, extractCrossContractInvariants } from './invariant-extractor.js';
import { generateTests } from './test-generator.js';
import { runTestWithRetry } from './test-runner.js';
import { checkFoundryInstalled, detectFoundryConfig, checkProjectCompiles } from './foundry-utils.js';

/**
 * Run the full invariant-based fuzzing pipeline.
 */
export async function runFuzzPipeline(
  client: Anthropic,
  files: FileInfo[],
  fileContentsMap: Map<string, string>,
  model: string,
  projectPath: string,
  cache?: ResponseCache | null,
  options?: FuzzPipelineOptions,
): Promise<{ results: InvariantResult[]; stats: FuzzPipelineStats }> {
  const verbose = options?.verbose ?? false;
  const fuzzRuns = options?.fuzzRuns ?? 1000;
  const maxIterations = options?.maxIterations ?? 3;
  const testOutputDir = options?.testOutputDir ?? '.audit/invariant-tests';
  const pipelineStart = Date.now();

  const stageTime = (label: string, start: number) => {
    if (verbose) console.error(`  [fuzz] ${label} (${((Date.now() - start) / 1000).toFixed(1)}s)`);
  };

  // ─── Pre-flight: Verify Foundry is installed ───
  const forgeVersion = checkFoundryInstalled();
  if (!forgeVersion) {
    throw new Error(
      'Foundry (forge) is not installed or not on PATH.\n' +
      'Install: curl -L https://foundry.paradigm.xyz | bash && foundryup'
    );
  }
  if (verbose) console.error(`  [fuzz] Foundry: ${forgeVersion}`);

  const foundryConfig = detectFoundryConfig(projectPath);
  if (verbose) {
    console.error(`  [fuzz] Solc: ${foundryConfig.solcVersion || 'default'}`);
    console.error(`  [fuzz] Remappings: ${foundryConfig.remappings.length}`);
    console.error(`  [fuzz] Source path: ${foundryConfig.srcPath}`);
  }

  // ─── Pre-flight: Verify project compiles ─��─
  const buildCheck = await checkProjectCompiles(projectPath, verbose);
  if (!buildCheck.success) {
    throw new Error(
      `Project does not compile. Run \`forge build\` to fix errors before fuzzing.\n${buildCheck.errors || ''}`
    );
  }
  if (verbose) console.error('  [fuzz] Project compiles successfully');

  const invCounter = new InvariantCounter();
  const testCounter = new TestFileCounter();

  // ─── Stage 1: EXTRACT INVARIANTS (parallel per-file) ───
  if (verbose) console.error(`\n  [fuzz] Stage 1: Extracting invariants from ${files.length} files...`);
  const extractStart = Date.now();

  const allInvariants: Invariant[] = [];
  const CONCURRENCY = 5;

  // Sort files by complexity (highest first)
  const scored = files
    .filter(f => fileContentsMap.has(f.relativePath))
    .map(f => ({
      file: f,
      score: scoreFileComplexity(f, fileContentsMap.get(f.relativePath)!).score,
    }))
    .sort((a, b) => b.score - a.score);

  const extractTasks = scored.map(({ file }) => async () => {
    const content = fileContentsMap.get(file.relativePath)!;
    try {
      const invariants = await extractInvariants(
        client, file, content, model, invCounter, cache,
        {
          architectureContext: options?.architectureContext,
          projectContext: options?.projectContext,
          verbose,
        },
      );
      if (verbose) {
        console.error(`    ${file.relativePath}: ${invariants.length} invariants`);
      }
      return invariants;
    } catch (err) {
      if (verbose) {
        console.error(`    ${file.relativePath}: error — ${err instanceof Error ? err.message : err}`);
      }
      return [];
    }
  });

  const extractResults = await runParallel(extractTasks, CONCURRENCY);
  for (const invariants of extractResults) {
    allInvariants.push(...invariants);
  }

  stageTime(`Extraction complete: ${allInvariants.length} invariants`, extractStart);

  // Cross-contract invariants pass
  if (files.length > 1) {
    if (verbose) console.error(`\n  [fuzz] Stage 1b: Cross-contract invariants...`);
    const crossStart = Date.now();

    try {
      const crossInvariants = await extractCrossContractInvariants(
        client, files, fileContentsMap, allInvariants, model, invCounter, cache,
        {
          architectureContext: options?.architectureContext,
          projectContext: options?.projectContext,
          verbose,
        },
      );
      allInvariants.push(...crossInvariants);
      stageTime(`Cross-contract: +${crossInvariants.length} invariants`, crossStart);
    } catch (err) {
      if (verbose) console.error(`  [fuzz] Cross-contract extraction failed: ${err}`);
    }
  }

  if (allInvariants.length === 0) {
    if (verbose) console.error(`  [fuzz] No invariants extracted — nothing to test.`);
    return {
      results: [],
      stats: emptyStats(Date.now() - pipelineStart),
    };
  }

  if (verbose) {
    console.error(`\n  [fuzz] Total invariants: ${allInvariants.length}`);
    const byCat = new Map<string, number>();
    for (const inv of allInvariants) {
      byCat.set(inv.category, (byCat.get(inv.category) || 0) + 1);
    }
    for (const [cat, count] of byCat) {
      console.error(`    ${cat}: ${count}`);
    }
  }

  // ─── Stage 2: GENERATE TESTS ───
  if (verbose) console.error(`\n  [fuzz] Stage 2: Generating Foundry invariant tests...`);
  const genStart = Date.now();

  // Group invariants by contract for test generation
  const byContract = new Map<string, Invariant[]>();
  for (const inv of allInvariants) {
    const key = inv.file === 'cross-contract' ? 'cross-contract' : inv.contractName;
    if (!byContract.has(key)) byContract.set(key, []);
    byContract.get(key)!.push(inv);
  }

  const allTestFiles: FuzzTestFile[] = [];

  for (const [contractName, invariants] of byContract) {
    try {
      const testFiles = await generateTests(
        client, invariants, fileContentsMap, model, testCounter, cache,
        {
          architectureContext: options?.architectureContext,
          foundryConfig,
          testOutputDir: `${projectPath}/${testOutputDir}`,
          verbose,
        },
      );
      // Fix file paths to be absolute
      for (const tf of testFiles) {
        tf.filePath = `${projectPath}/${testOutputDir}/${tf.fileName}`;
      }
      allTestFiles.push(...testFiles);

      if (verbose) {
        console.error(`    ${contractName}: ${testFiles.length} test file(s) generated`);
      }
    } catch (err) {
      if (verbose) {
        console.error(`    ${contractName}: test generation failed — ${err instanceof Error ? err.message : err}`);
      }
    }
  }

  stageTime(`Test generation complete: ${allTestFiles.length} files`, genStart);

  if (allTestFiles.length === 0) {
    if (verbose) console.error(`  [fuzz] No test files generated — cannot run fuzz campaign.`);
    return {
      results: allInvariants.map(inv => ({
        invariantId: inv.id,
        invariant: inv,
        status: 'INCONCLUSIVE' as const,
        testFileId: '',
        iterations: [],
        finalClassification: null,
        notes: 'Test generation failed',
      })),
      stats: emptyStats(Date.now() - pipelineStart),
    };
  }

  // ─── Stage 3: RUN & FIX LOOP (sequential per test file) ───
  if (verbose) console.error(`\n  [fuzz] Stage 3: Running forge tests (fuzz-runs=${fuzzRuns}, max-iterations=${maxIterations})...`);
  const runStart = Date.now();

  const allResults: InvariantResult[] = [];
  let totalForgeRuns = 0;
  let totalIterations = 0;

  // Build a map from test file to its invariants
  const testFileInvariantMap = new Map<string, Invariant[]>();
  for (const tf of allTestFiles) {
    const covered = allInvariants.filter(inv => tf.invariantIds.includes(inv.id));
    testFileInvariantMap.set(tf.id, covered);
  }

  for (const testFile of allTestFiles) {
    const covered = testFileInvariantMap.get(testFile.id) || [];
    if (covered.length === 0) continue;

    if (verbose) console.error(`\n    [fuzz] Running ${testFile.fileName} (${covered.length} invariants)...`);

    try {
      const { results, stats } = await runTestWithRetry(
        client, testFile, covered, fileContentsMap, model, cache,
        {
          fuzzRuns,
          maxIterations,
          projectPath,
          foundryConfig,
          verbose,
        },
      );
      allResults.push(...results);
      totalForgeRuns += stats.totalForgeRuns;
      totalIterations += stats.totalIterations;
    } catch (err) {
      if (verbose) {
        console.error(`    [fuzz] ${testFile.fileName} failed: ${err instanceof Error ? err.message : err}`);
      }
      // Mark all covered invariants as inconclusive
      for (const inv of covered) {
        allResults.push({
          invariantId: inv.id,
          invariant: inv,
          status: 'INCONCLUSIVE',
          testFileId: testFile.id,
          iterations: [],
          finalClassification: 'environment-issue',
          notes: `Test runner error: ${err instanceof Error ? err.message : err}`,
        });
      }
    }
  }

  stageTime(`Test execution complete`, runStart);

  // ─── Collect stats ───
  const stats: FuzzPipelineStats = {
    invariantsExtracted: allInvariants.length,
    testsGenerated: allTestFiles.length,
    testsCompiled: allResults.filter(r => r.iterations.some(i => i.runResult.compileSuccess)).length,
    testsPassed: allResults.filter(r => r.status === 'HOLDS').length,
    testsFailed: allResults.filter(r => r.status === 'VIOLATED').length,
    invariantsHold: allResults.filter(r => r.status === 'HOLDS').length,
    invariantsViolated: allResults.filter(r => r.status === 'VIOLATED').length,
    invariantsInconclusive: allResults.filter(r => r.status === 'INCONCLUSIVE').length,
    totalIterations,
    totalForgeRuns,
    duration: Date.now() - pipelineStart,
  };

  if (verbose) {
    console.error(`\n  [fuzz] ═══════════════════════════════════`);
    console.error(`  [fuzz] Results:`);
    console.error(`    Invariants: ${stats.invariantsExtracted} extracted`);
    console.error(`    HOLDS:       ${stats.invariantsHold}`);
    console.error(`    VIOLATED:    ${stats.invariantsViolated}`);
    console.error(`    INCONCLUSIVE:${stats.invariantsInconclusive}`);
    console.error(`    Forge runs:  ${stats.totalForgeRuns}`);
    console.error(`    Iterations:  ${stats.totalIterations}`);
    console.error(`    Duration:    ${(stats.duration / 1000).toFixed(1)}s`);
    console.error(`  [fuzz] ═══════════════════════════════════`);
  }

  return { results: allResults, stats };
}

function emptyStats(duration: number): FuzzPipelineStats {
  return {
    invariantsExtracted: 0,
    testsGenerated: 0,
    testsCompiled: 0,
    testsPassed: 0,
    testsFailed: 0,
    invariantsHold: 0,
    invariantsViolated: 0,
    invariantsInconclusive: 0,
    totalIterations: 0,
    totalForgeRuns: 0,
    duration,
  };
}
