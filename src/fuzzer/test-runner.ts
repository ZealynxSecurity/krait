/**
 * Test runner — iterative loop that runs forge tests and fixes broken tests.
 *
 * For each test file:
 *   1. Write test to disk
 *   2. Run forge test
 *   3. If all pass → invariants HOLD
 *   4. If failure → classify (real violation vs test bug)
 *   5. If test bug → fix and retry (up to maxIterations)
 *   6. If real violation → VIOLATED
 *   7. If max iterations exhausted → INCONCLUSIVE
 */

import Anthropic from '@anthropic-ai/sdk';
import { ResponseCache } from '../core/cache.js';
import {
  FuzzTestFile,
  Invariant,
  InvariantResult,
  IterationRecord,
  FoundryConfig,
  FixAction,
  FailureClassification,
} from './types.js';
import { writeTestFile, runForgeTest } from './foundry-utils.js';
import { classifyFailure } from './result-classifier.js';
import { fixTest } from './test-fixer.js';

export interface RunnerOptions {
  fuzzRuns: number;
  maxIterations: number;
  projectPath: string;
  foundryConfig: FoundryConfig;
  verbose?: boolean;
}

export interface RunnerStats {
  totalForgeRuns: number;
  totalIterations: number;
}

/**
 * Run a single test file through the iterative fix loop.
 * Returns an InvariantResult for each invariant covered by the test file.
 */
export async function runTestWithRetry(
  client: Anthropic,
  testFile: FuzzTestFile,
  invariants: Invariant[],
  sourceCode: Map<string, string>,
  model: string,
  cache: ResponseCache | null | undefined,
  options: RunnerOptions,
): Promise<{ results: InvariantResult[]; stats: RunnerStats }> {
  const { fuzzRuns, maxIterations, projectPath, foundryConfig, verbose } = options;
  const iterations: IterationRecord[] = [];
  let currentCode = testFile.solidityCode;
  let totalForgeRuns = 0;
  let totalIterations = 0;
  let lastClassification: FailureClassification | undefined;

  for (let iter = 0; iter < maxIterations; iter++) {
    totalIterations++;
    const action: FixAction = iter === 0 ? 'initial' : actionFromClassification(lastClassification!);

    // Write test file to disk
    writeTestFile(testFile.filePath, currentCode);

    // Run forge test
    if (verbose) console.error(`    [runner] Iteration ${iter + 1}/${maxIterations} for ${testFile.fileName}`);
    const runResult = await runForgeTest(projectPath, testFile.filePath, fuzzRuns, verbose);
    runResult.testFileId = testFile.id;
    totalForgeRuns++;

    // Record iteration
    const record: IterationRecord = {
      iteration: iter + 1,
      action,
      description: iter === 0 ? 'Initial run' : `Fix attempt #${iter}`,
      testCodeBefore: currentCode,
      testCodeAfter: currentCode,
      runResult,
    };

    // Check: did everything compile and pass?
    if (runResult.compileSuccess && runResult.results.length > 0 && runResult.results.every(r => r.passed)) {
      record.description = 'All tests passed';
      iterations.push(record);

      if (verbose) console.error(`    [runner] All tests PASSED — invariants HOLD`);

      return {
        results: buildResults(invariants, testFile, iterations, 'HOLDS', null),
        stats: { totalForgeRuns, totalIterations },
      };
    }

    // Classify the failure
    const { classification, reasoning } = await classifyFailure(
      client, testFile, runResult, invariants, sourceCode, model, cache, verbose,
    );

    if (verbose) console.error(`    [runner] Classification: ${classification} — ${reasoning}`);

    // Real violation: stop iterating
    if (classification === 'real-violation') {
      record.description = `Real invariant violation detected: ${reasoning}`;
      iterations.push(record);

      const counterexample = runResult.results
        .filter(r => !r.passed && r.counterexample)
        .map(r => `${r.testName}: ${r.counterexample}`)
        .join('\n') || undefined;

      if (verbose) console.error(`    [runner] VIOLATED — ${counterexample || 'no counterexample'}`);

      return {
        results: buildResults(invariants, testFile, iterations, 'VIOLATED', classification, counterexample),
        stats: { totalForgeRuns, totalIterations },
      };
    }

    // Environment issue: can't fix, mark inconclusive
    if (classification === 'environment-issue') {
      record.description = `Environment issue: ${reasoning}`;
      iterations.push(record);

      if (verbose) console.error(`    [runner] INCONCLUSIVE — environment issue`);

      return {
        results: buildResults(invariants, testFile, iterations, 'INCONCLUSIVE', classification, undefined, reasoning),
        stats: { totalForgeRuns, totalIterations },
      };
    }

    // Test bug: attempt to fix
    if (iter < maxIterations - 1) {
      record.description = `${classification}: ${reasoning} — attempting fix`;
      iterations.push(record);

      try {
        const { fixedCode, changeDescription } = await fixTest(
          client, testFile, runResult, classification, invariants, sourceCode, foundryConfig, model, cache, verbose,
        );

        if (verbose) console.error(`    [runner] Fix applied: ${changeDescription}`);
        currentCode = fixedCode;
        testFile.solidityCode = fixedCode;

        // Update the last iteration record with the fixed code
        iterations[iterations.length - 1].testCodeAfter = fixedCode;
        iterations[iterations.length - 1].description += ` → ${changeDescription}`;
      } catch (err) {
        if (verbose) console.error(`    [runner] Fix failed: ${err}`);
        iterations[iterations.length - 1].description += ' → Fix generation failed';
      }
    } else {
      record.description = `${classification}: ${reasoning} — max iterations reached`;
      iterations.push(record);
    }

    // Track last classification for the next iteration's action label
    lastClassification = classification;
  }

  // Exhausted iterations
  if (verbose) console.error(`    [runner] INCONCLUSIVE — max iterations (${maxIterations}) exhausted`);

  return {
    results: buildResults(
      invariants, testFile, iterations, 'INCONCLUSIVE', lastClassification || null,
      undefined, `Could not resolve test issues within ${maxIterations} iterations`,
    ),
    stats: { totalForgeRuns, totalIterations },
  };
}

function actionFromClassification(classification: FailureClassification): FixAction {
  switch (classification) {
    case 'compile-error': return 'fix-compile';
    case 'import-error': return 'fix-import';
    case 'test-setup-bug': return 'fix-setup';
    case 'assertion-bug': return 'fix-assertion';
    default: return 'fix-compile';
  }
}

function buildResults(
  invariants: Invariant[],
  testFile: FuzzTestFile,
  iterations: IterationRecord[],
  status: 'HOLDS' | 'VIOLATED' | 'INCONCLUSIVE',
  classification: FailureClassification | null,
  counterexample?: string,
  notes?: string,
): InvariantResult[] {
  // If there are specific per-test failures, try to map to specific invariants
  const lastRun = iterations[iterations.length - 1]?.runResult;

  if (status === 'VIOLATED' && lastRun) {
    // Map failed tests to invariants by matching function names
    const failedTestNames = new Set(lastRun.results.filter(r => !r.passed).map(r => r.testName));
    const passedTestNames = new Set(lastRun.results.filter(r => r.passed).map(r => r.testName));

    return invariants.map(inv => {
      // Try to match invariant to test function name
      const matchingFailed = Array.from(failedTestNames).find(name =>
        name.toLowerCase().includes(inv.id.toLowerCase().replace('-', '')) ||
        name.toLowerCase().includes(inv.contractName.toLowerCase())
      );
      const matchingPassed = Array.from(passedTestNames).find(name =>
        name.toLowerCase().includes(inv.id.toLowerCase().replace('-', '')) ||
        name.toLowerCase().includes(inv.contractName.toLowerCase())
      );

      if (matchingFailed) {
        const failResult = lastRun.results.find(r => r.testName === matchingFailed);
        return {
          invariantId: inv.id,
          invariant: inv,
          status: 'VIOLATED' as const,
          testFileId: testFile.id,
          iterations,
          finalClassification: classification,
          counterexample: failResult?.counterexample || counterexample,
          notes: notes || `Violated in test ${matchingFailed}`,
        };
      }

      if (matchingPassed) {
        return {
          invariantId: inv.id,
          invariant: inv,
          status: 'HOLDS' as const,
          testFileId: testFile.id,
          iterations,
          finalClassification: null,
          notes: `Holds — verified by ${matchingPassed}`,
        };
      }

      // Can't match — use the overall status
      return {
        invariantId: inv.id,
        invariant: inv,
        status,
        testFileId: testFile.id,
        iterations,
        finalClassification: classification,
        counterexample,
        notes: notes || '',
      };
    });
  }

  // For HOLDS or INCONCLUSIVE, all invariants in this test file get the same status
  return invariants.map(inv => ({
    invariantId: inv.id,
    invariant: inv,
    status,
    testFileId: testFile.id,
    iterations,
    finalClassification: classification,
    counterexample,
    notes: notes || '',
  }));
}
