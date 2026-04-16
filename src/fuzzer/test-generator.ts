/**
 * Test generator — takes extracted invariants and generates Foundry
 * invariant test contracts (.t.sol files).
 *
 * Uses Claude tool_use to produce Solidity test code, grouped by contract.
 */

import Anthropic from '@anthropic-ai/sdk';
import { FileInfo, ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { Invariant, FuzzTestFile, FoundryConfig, TestFileCounter } from './types.js';

const TEST_GEN_TOOL: Anthropic.Tool = {
  name: 'report_test_files',
  description: 'Return generated Foundry invariant test file(s) with Solidity code.',
  input_schema: {
    type: 'object' as const,
    properties: {
      testFiles: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            fileName: {
              type: 'string',
              description: 'File name, e.g. InvariantTest_Vault.t.sol',
            },
            solidityCode: {
              type: 'string',
              description: 'Full Solidity source code of the test contract',
            },
            testFunctions: {
              type: 'array',
              items: { type: 'string' },
              description: 'Names of invariant_xxx() functions in this file',
            },
            setupDescription: {
              type: 'string',
              description: 'What setUp() does: deploys, initializes, etc.',
            },
          },
          required: ['fileName', 'solidityCode', 'testFunctions', 'setupDescription'],
        },
      },
    },
    required: ['testFiles'],
  },
};

export interface TestGeneratorOptions {
  architectureContext?: ArchitectureAnalysis | null;
  foundryConfig: FoundryConfig;
  testOutputDir: string;
  verbose?: boolean;
}

/**
 * Generate Foundry invariant test files for a batch of invariants
 * (typically all invariants for one contract).
 */
export async function generateTests(
  client: Anthropic,
  invariants: Invariant[],
  fileContentsMap: Map<string, string>,
  model: string,
  counter: TestFileCounter,
  cache?: ResponseCache | null,
  options?: TestGeneratorOptions,
): Promise<FuzzTestFile[]> {
  if (invariants.length === 0) return [];

  const systemPrompt = buildGeneratorSystemPrompt(options);
  const userPrompt = buildGeneratorUserPrompt(invariants, fileContentsMap, options);

  const raw = await callGenerator(client, systemPrompt, userPrompt, model, cache, options?.verbose);

  return raw.map(r => {
    const id = counter.next();
    const fileName = String(r.fileName || `InvariantTest_${id}.t.sol`);
    return {
      id,
      invariantIds: invariants.map(inv => inv.id),
      fileName,
      filePath: `${options?.testOutputDir || '.audit/invariant-tests'}/${fileName}`,
      solidityCode: String(r.solidityCode || ''),
      testFunctions: Array.isArray(r.testFunctions) ? r.testFunctions.map(String) : [],
      setupDescription: String(r.setupDescription || ''),
    };
  });
}

function buildGeneratorSystemPrompt(options?: TestGeneratorOptions): string {
  const remappings = options?.foundryConfig?.remappings || [];
  const srcPath = options?.foundryConfig?.srcPath || 'src';
  const solcVersion = options?.foundryConfig?.solcVersion;

  const archContext = options?.architectureContext
    ? `\n## Protocol Architecture\n${JSON.stringify(options.architectureContext, null, 2)}\n`
    : '';

  return `You are a Foundry TEST GENERATOR. Given a set of invariants extracted from smart contracts, you generate Solidity test contracts that verify these invariants using Foundry's invariant testing framework.

## Foundry Invariant Testing Pattern

Foundry's invariant testing works by:
1. Calling random sequences of "target functions" on "target contracts"
2. After each call sequence, checking all \`invariant_xxx()\` functions
3. If any invariant function reverts, the invariant is considered violated

\`\`\`solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {TargetContract} from "../src/TargetContract.sol";

contract InvariantTest_Example is Test {
    TargetContract target;

    function setUp() public {
        target = new TargetContract();
        // Configure target contracts and selectors
        targetContract(address(target));
    }

    // Foundry calls this after random sequences of target functions
    function invariant_propertyName() public view {
        // Assert the invariant — if this reverts, the invariant is broken
        assertTrue(target.totalSupply() == target.sumOfBalances());
    }
}
\`\`\`

## Rules for Generated Tests

1. **Pragma**: Use \`pragma solidity ${solcVersion || '^0.8.0'};\`
2. **Imports**: Use the project's import paths. Available remappings:
${remappings.length > 0 ? remappings.map(r => `   - \`${r}\``).join('\n') : '   - forge-std/=lib/forge-std/src/ (default)'}
   Source contracts are in \`${srcPath}/\`.
3. **setUp()**: Deploy ALL contracts needed. Set up realistic initial state.
   - Deploy dependencies first (tokens, oracles, etc.)
   - Use mock contracts for external dependencies when needed.
   - Call initialization functions.
   - Use \`targetContract()\` to tell Foundry which contracts to call randomly.
   - Use \`targetSelector()\` to restrict which functions Foundry calls (exclude admin-only if testing user invariants).
   - Use \`deal()\` from forge-std to set up initial token balances.
4. **invariant_xxx() functions**: One per invariant. Must be \`public view\` or \`public\`.
   - Use \`assertEq\`, \`assertTrue\`, \`assertGe\`, \`assertLe\` for checks.
   - Include the invariant ID in the assertion message: \`"INV-001: totalSupply == sum(balances)"\`
5. **Handler pattern**: For complex protocols, use a Handler contract that wraps target functions with bounded inputs:
   \`\`\`solidity
   contract Handler is Test {
       TargetContract target;
       constructor(TargetContract _target) { target = _target; }
       function deposit(uint256 amount) public {
           amount = bound(amount, 1, 1e24);
           deal(address(token), msg.sender, amount);
           target.deposit(amount);
       }
   }
   \`\`\`
   Then use \`targetContract(address(handler))\` instead of the target directly.
6. **Do NOT use** \`vm.assume()\` in invariant tests — use \`bound()\` instead.
7. **Mock contracts**: If the protocol depends on external contracts (oracles, tokens), create minimal mocks inline or import from forge-std.
8. Each test file should be self-contained and compilable independently.

${archContext}`;
}

function buildGeneratorUserPrompt(
  invariants: Invariant[],
  fileContentsMap: Map<string, string>,
  options?: TestGeneratorOptions,
): string {
  // Group invariants by contract
  const byContract = new Map<string, Invariant[]>();
  for (const inv of invariants) {
    const key = inv.contractName;
    if (!byContract.has(key)) byContract.set(key, []);
    byContract.get(key)!.push(inv);
  }

  // Build invariant listing
  const invListing = invariants.map(inv => {
    const formal = inv.formalExpression ? `\n   Formal: \`${inv.formalExpression}\`` : '';
    return `- **${inv.id}** [${inv.category}, ${inv.priority}]: ${inv.description}${formal}
   Contract: ${inv.contractName} | State: ${inv.stateVariables.join(', ')} | Functions: ${inv.relatedFunctions.join(', ')}`;
  }).join('\n');

  // Include source code for referenced contracts
  const referencedFiles = new Set<string>();
  for (const inv of invariants) {
    referencedFiles.add(inv.file);
  }

  const sourceCode = Array.from(referencedFiles)
    .filter(f => fileContentsMap.has(f))
    .map(f => {
      const content = fileContentsMap.get(f)!;
      return `### ${f}\n\`\`\`solidity\n${content}\n\`\`\``;
    })
    .join('\n\n');

  return `Generate Foundry invariant test files for the following invariants.

## Invariants to Test
${invListing}

## Source Contracts
${sourceCode}

Generate one test file per contract (group invariants by their contract). Each invariant_xxx() function should test exactly one invariant. Include proper setUp() with deployment and initialization.`;
}

async function callGenerator(
  client: Anthropic,
  systemPrompt: string,
  userPrompt: string,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
): Promise<Array<Record<string, unknown>>> {
  // Check cache
  if (cache) {
    const key = cache.computeKey(systemPrompt, userPrompt, model);
    const cached = cache.getJson<Array<Record<string, unknown>>>(key);
    if (cached) {
      if (verbose) console.error(`  [test-gen cache hit]`);
      return cached;
    }
  }

  const maxRetries = 3;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      // Test generation needs more tokens — Solidity code is verbose
      const response = await client.messages.create({
        model,
        max_tokens: 16384,
        system: systemPrompt,
        tools: [TEST_GEN_TOOL],
        tool_choice: { type: 'any' },
        messages: [{ role: 'user', content: userPrompt }],
      });

      const results: Array<Record<string, unknown>> = [];
      for (const block of response.content) {
        if (block.type === 'tool_use' && block.name === 'report_test_files') {
          const input = block.input as { testFiles: Array<Record<string, unknown>> };
          if (Array.isArray(input.testFiles)) {
            results.push(...input.testFiles);
          }
        }
      }

      // Cache results
      if (cache) {
        const key = cache.computeKey(systemPrompt, userPrompt, model);
        cache.setJson(key, results, model);
      }

      return results;
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

  throw lastError || new Error('Test generator: max retries exceeded');
}
