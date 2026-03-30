/**
 * Test fixer — LLM-powered fix for broken test files.
 * Given a failure classification and error output, generates corrected test code.
 */

import Anthropic from '@anthropic-ai/sdk';
import { ResponseCache } from '../core/cache.js';
import { FailureClassification, FuzzTestFile, TestRunResult, FoundryConfig, Invariant } from './types.js';

const FIX_TEST_TOOL: Anthropic.Tool = {
  name: 'fix_test',
  description: 'Return the corrected Solidity test file code.',
  input_schema: {
    type: 'object' as const,
    properties: {
      fixedCode: {
        type: 'string',
        description: 'The complete corrected Solidity test file source code',
      },
      changeDescription: {
        type: 'string',
        description: 'Brief description of what was changed and why',
      },
    },
    required: ['fixedCode', 'changeDescription'],
  },
};

export interface FixResult {
  fixedCode: string;
  changeDescription: string;
}

/**
 * Fix a broken test file based on the failure classification and error output.
 */
export async function fixTest(
  client: Anthropic,
  testFile: FuzzTestFile,
  runResult: TestRunResult,
  classification: FailureClassification,
  invariants: Invariant[],
  sourceCode: Map<string, string>,
  foundryConfig: FoundryConfig,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
): Promise<FixResult> {
  const systemPrompt = buildFixSystemPrompt(classification, foundryConfig);
  const userPrompt = buildFixUserPrompt(testFile, runResult, classification, invariants, sourceCode);

  // Check cache
  if (cache) {
    const key = cache.computeKey(systemPrompt, userPrompt, model);
    const cached = cache.getJson<FixResult>(key);
    if (cached) {
      if (verbose) console.error(`  [test-fixer cache hit]`);
      return cached;
    }
  }

  const maxRetries = 2;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await client.messages.create({
        model,
        max_tokens: 16384,
        system: systemPrompt,
        tools: [FIX_TEST_TOOL],
        tool_choice: { type: 'any' },
        messages: [{ role: 'user', content: userPrompt }],
      });

      for (const block of response.content) {
        if (block.type === 'tool_use' && block.name === 'fix_test') {
          const input = block.input as { fixedCode: string; changeDescription: string };
          const result: FixResult = {
            fixedCode: String(input.fixedCode || testFile.solidityCode),
            changeDescription: String(input.changeDescription || 'Applied fix'),
          };

          // Cache result
          if (cache) {
            const key = cache.computeKey(systemPrompt, userPrompt, model);
            cache.setJson(key, result, model);
          }

          return result;
        }
      }

      // Fallback if no tool_use block returned
      return {
        fixedCode: testFile.solidityCode,
        changeDescription: 'LLM did not return a fix — keeping original code',
      };
    } catch (err: unknown) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (lastError.message.includes('rate') || lastError.message.includes('429')) {
        const waitMs = Math.min(1000 * Math.pow(2, attempt), 30000);
        await new Promise(r => setTimeout(r, waitMs));
        continue;
      }
      throw lastError;
    }
  }

  throw lastError || new Error('Test fixer: max retries exceeded');
}

function buildFixSystemPrompt(classification: FailureClassification, foundryConfig: FoundryConfig): string {
  const remappings = foundryConfig.remappings;
  const srcPath = foundryConfig.srcPath;

  const fixGuidance: Record<FailureClassification, string> = {
    'compile-error': `The test has Solidity compilation errors. Fix the syntax, type mismatches, or missing declarations. Common issues:
- Wrong function signatures (check the source contract)
- Type mismatches (uint256 vs address, etc.)
- Missing state variables or function declarations
- Wrong Solidity version pragma`,

    'import-error': `The test has import path errors. Fix the import statements to match the project structure.
Available remappings:
${remappings.map(r => `  ${r}`).join('\n') || '  (none — use relative paths)'}
Source contracts are in: ${srcPath}/
forge-std is typically at: lib/forge-std/src/`,

    'test-setup-bug': `The test's setUp() function is incorrect. The contracts are not being deployed or initialized properly. Fix the deployment sequence:
- Check constructor arguments match the source contract
- Ensure all required initialization functions are called
- Verify addresses and permissions are set correctly
- Make sure token approvals and initial balances are set up`,

    'assertion-bug': `The test's invariant assertion does not correctly express the intended invariant. Fix the assertion logic:
- Check that the assertion matches the invariant description
- Verify the math/logic of the assertion
- Ensure the assertion uses the correct state variables and function calls
- Make sure the assertion is checking the right condition`,

    'real-violation': 'This should not need fixing — the invariant is truly violated.',
    'environment-issue': 'This may not be fixable — check if external dependencies are available.',
  };

  return `You are a Foundry TEST FIXER. A generated invariant test has a bug and you need to fix it. The test was auto-generated and the issue is in the TEST, not the source contract.

## Problem Type: ${classification}

${fixGuidance[classification]}

## Rules
1. Return the COMPLETE fixed Solidity file — not just the changed parts.
2. Preserve all invariant_xxx() functions. Do not remove tests.
3. Keep the SPDX license identifier and pragma.
4. Do not change the source contracts — only fix the test.
5. Use \`bound()\` instead of \`vm.assume()\` for input constraints.
6. Make sure setUp() deploys all necessary contracts in the right order.`;
}

function buildFixUserPrompt(
  testFile: FuzzTestFile,
  runResult: TestRunResult,
  classification: FailureClassification,
  invariants: Invariant[],
  sourceCode: Map<string, string>,
): string {
  const errors = !runResult.compileSuccess
    ? `## Compilation Errors\n${(runResult.compileErrors || []).join('\n\n')}`
    : `## Test Failures\n${runResult.results
        .filter(r => !r.passed)
        .map(r => `${r.testName}: ${r.revertReason || 'failed'}\n${r.rawOutput.slice(0, 1500)}`)
        .join('\n---\n')}`;

  const invariantDescriptions = invariants
    .map(inv => `- ${inv.id}: ${inv.description}${inv.formalExpression ? ` (${inv.formalExpression})` : ''}`)
    .join('\n');

  // Include relevant source contracts
  const relevantSource = invariants
    .map(inv => inv.file)
    .filter((f, i, arr) => arr.indexOf(f) === i && sourceCode.has(f))
    .map(f => `### ${f}\n\`\`\`solidity\n${sourceCode.get(f)!}\n\`\`\``)
    .join('\n\n');

  return `## Current Test Code (has bugs)
\`\`\`solidity
${testFile.solidityCode}
\`\`\`

${errors}

## Invariants Being Tested
${invariantDescriptions}

## Source Contract Code (correct — do not modify)
${relevantSource}

Fix the test so it compiles and correctly tests the listed invariants. Return the complete fixed file.`;
}
