/**
 * Result classifier — determines whether a forge test failure is a
 * real invariant violation or a test bug that needs fixing.
 *
 * Uses heuristics first, then Claude LLM for ambiguous cases.
 */

import Anthropic from '@anthropic-ai/sdk';
import { ResponseCache } from '../core/cache.js';
import { FailureClassification, TestRunResult, FuzzTestFile, Invariant } from './types.js';

const CLASSIFY_TOOL: Anthropic.Tool = {
  name: 'classify_failure',
  description: 'Classify whether a test failure represents a real invariant violation or a test bug.',
  input_schema: {
    type: 'object' as const,
    properties: {
      classification: {
        type: 'string',
        enum: ['real-violation', 'test-setup-bug', 'import-error', 'compile-error', 'assertion-bug', 'environment-issue'],
        description: 'The classification of the failure',
      },
      reasoning: {
        type: 'string',
        description: 'Explanation of why this classification was chosen',
      },
    },
    required: ['classification', 'reasoning'],
  },
};

export interface ClassifierResult {
  classification: FailureClassification;
  reasoning: string;
}

/**
 * Classify a test failure. Uses heuristics for obvious cases,
 * falls back to LLM for ambiguous assertion failures.
 */
export async function classifyFailure(
  client: Anthropic,
  testFile: FuzzTestFile,
  runResult: TestRunResult,
  invariants: Invariant[],
  sourceCode: Map<string, string>,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
): Promise<ClassifierResult> {
  // ─── Heuristic classification (no LLM call needed) ───

  const combined = runResult.rawStdout + '\n' + runResult.rawStderr;

  // Check for environment issues first
  if (combined.includes('forge: command not found') || combined.includes('not recognized')) {
    return { classification: 'environment-issue', reasoning: 'forge is not installed or not on PATH' };
  }

  // Compile errors
  if (!runResult.compileSuccess) {
    const errors = (runResult.compileErrors || []).join('\n').toLowerCase();

    // Import/path errors
    if (
      errors.includes('source not found') ||
      errors.includes('not found') ||
      errors.includes('file not found') ||
      errors.includes('import') ||
      errors.includes('cannot import')
    ) {
      return {
        classification: 'import-error',
        reasoning: `Compilation failed due to import/path errors: ${(runResult.compileErrors || []).slice(0, 3).join('; ')}`,
      };
    }

    return {
      classification: 'compile-error',
      reasoning: `Compilation failed: ${(runResult.compileErrors || []).slice(0, 3).join('; ')}`,
    };
  }

  // setUp() revert — all tests fail with setUp revert
  const allSetUpFail = runResult.results.length > 0 &&
    runResult.results.every(r => !r.passed && r.rawOutput.toLowerCase().includes('setup'));
  if (allSetUpFail) {
    return {
      classification: 'test-setup-bug',
      reasoning: 'All tests failed during setUp() — contract deployment or initialization is incorrect',
    };
  }

  // If all tests passed, this shouldn't be called — but handle gracefully
  if (runResult.results.every(r => r.passed)) {
    return { classification: 'real-violation', reasoning: 'All tests passed — no failure to classify' };
  }

  // ─── LLM classification for assertion failures with counterexamples ───

  const failedTests = runResult.results.filter(r => !r.passed);

  // If failures look like setUp issues (revert with no counterexample)
  const allRevertNoCounterexample = failedTests.every(
    r => !r.counterexample && r.revertReason && !r.revertReason.includes('Assertion')
  );
  if (allRevertNoCounterexample) {
    return {
      classification: 'test-setup-bug',
      reasoning: `Tests reverted without assertion failure or counterexample — likely setUp or state initialization issue. Reasons: ${failedTests.map(r => r.revertReason).join('; ')}`,
    };
  }

  // For assertion failures with counterexamples, use LLM to determine
  // if the counterexample represents a legitimate state
  return classifyWithLLM(client, testFile, runResult, invariants, sourceCode, model, cache, verbose);
}

async function classifyWithLLM(
  client: Anthropic,
  testFile: FuzzTestFile,
  runResult: TestRunResult,
  invariants: Invariant[],
  sourceCode: Map<string, string>,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
): Promise<ClassifierResult> {
  const failedTests = runResult.results.filter(r => !r.passed);

  // Build source code context for relevant files
  const relevantSource = invariants
    .map(inv => inv.file)
    .filter(f => sourceCode.has(f))
    .map(f => `### ${f}\n\`\`\`solidity\n${sourceCode.get(f)!.slice(0, 5000)}\n\`\`\``)
    .join('\n\n');

  const failureDetails = failedTests.map(r =>
    `Test: ${r.testName}\nReason: ${r.revertReason || 'unknown'}\nCounterexample: ${r.counterexample || 'none'}\nOutput:\n${r.rawOutput.slice(0, 2000)}`
  ).join('\n---\n');

  const invariantDescriptions = invariants
    .map(inv => `- ${inv.id}: ${inv.description} (formal: ${inv.formalExpression || 'N/A'})`)
    .join('\n');

  const systemPrompt = `You are classifying a Foundry invariant test failure. Your job is to determine: is this a REAL invariant violation in the source contract, or a BUG in the test itself?

## Classification Guide

- **real-violation**: The counterexample shows a legitimate sequence of function calls that breaks the invariant. The contract state is reachable through normal usage. This means the source contract has a real bug.

- **test-setup-bug**: The test's setUp() doesn't correctly deploy/initialize contracts. Common signs: constructor arguments wrong, missing initialization calls, wrong addresses, insufficient permissions.

- **assertion-bug**: The invariant assertion is wrong — it doesn't correctly express the invariant. Example: the test checks totalSupply == balances.length but the invariant says totalSupply == sum(balances).

- **environment-issue**: The test requires something not available (specific network state, external contracts).

Be conservative: if the counterexample looks like it could be a legitimate state, classify as **real-violation**. Only classify as a test bug if you can specifically identify what's wrong with the test.`;

  const userPrompt = `## Invariants Being Tested
${invariantDescriptions}

## Test Code
\`\`\`solidity
${testFile.solidityCode.slice(0, 6000)}
\`\`\`

## Failure Details
${failureDetails}

## Source Contract Code
${relevantSource}

Classify this failure: is the invariant truly violated, or is the test buggy?`;

  // Check cache
  if (cache) {
    const key = cache.computeKey(systemPrompt, userPrompt, model);
    const cached = cache.getJson<{ classification: string; reasoning: string }>(key);
    if (cached) {
      if (verbose) console.error(`  [classifier cache hit]`);
      return {
        classification: normalizeClassification(cached.classification),
        reasoning: cached.reasoning || '',
      };
    }
  }

  try {
    const response = await client.messages.create({
      model,
      max_tokens: 2048,
      system: systemPrompt,
      tools: [CLASSIFY_TOOL],
      tool_choice: { type: 'any' },
      messages: [{ role: 'user', content: userPrompt }],
    });

    for (const block of response.content) {
      if (block.type === 'tool_use' && block.name === 'classify_failure') {
        const input = block.input as { classification: string; reasoning: string };

        // Cache the result
        if (cache) {
          const key = cache.computeKey(systemPrompt, userPrompt, model);
          cache.setJson(key, input, model);
        }

        return {
          classification: normalizeClassification(input.classification),
          reasoning: String(input.reasoning || ''),
        };
      }
    }
  } catch (err) {
    if (verbose) console.error(`  [classifier] LLM error: ${err}`);
  }

  // Fallback: treat as real violation (conservative — better to investigate than ignore)
  return {
    classification: 'real-violation',
    reasoning: 'Could not classify failure — treating as potential real violation for safety',
  };
}

function normalizeClassification(val: unknown): FailureClassification {
  const s = String(val).toLowerCase();
  const valid: FailureClassification[] = [
    'real-violation', 'test-setup-bug', 'import-error',
    'compile-error', 'assertion-bug', 'environment-issue',
  ];
  if (valid.includes(s as FailureClassification)) return s as FailureClassification;
  return 'real-violation'; // Conservative default
}
