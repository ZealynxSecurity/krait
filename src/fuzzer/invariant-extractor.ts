/**
 * Invariant extractor — understands the code and extracts all properties
 * that must always hold. Does NOT look for vulnerabilities.
 *
 * Mirrors the detector.ts pattern: Claude tool_use with structured output,
 * caching, retry logic, and parallel per-file processing.
 */

import Anthropic from '@anthropic-ai/sdk';
import { FileInfo, ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { ProjectContext, formatContextForPrompt } from '../analysis/context-gatherer.js';
import { formatArchitectureForSystemPrompt, formatArchitectureForFilePrompt } from '../analysis/architecture-pass.js';
import { Invariant, InvariantCategory, InvariantCounter } from './types.js';

const INVARIANT_TOOL: Anthropic.Tool = {
  name: 'report_invariants',
  description: 'Report ALL invariants (properties that must always hold) found in this contract.',
  input_schema: {
    type: 'object' as const,
    properties: {
      invariants: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            description: {
              type: 'string',
              description: 'Human-readable description of the invariant, e.g. "totalSupply must equal the sum of all user balances"',
            },
            category: {
              type: 'string',
              enum: ['accounting', 'access-control', 'state-transition', 'economic', 'token-conservation', 'ordering', 'bounds', 'relationship', 'custom'],
              description: 'Category of the invariant',
            },
            contractName: {
              type: 'string',
              description: 'Name of the contract this invariant applies to',
            },
            stateVariables: {
              type: 'array',
              items: { type: 'string' },
              description: 'State variables involved in this invariant',
            },
            formalExpression: {
              type: 'string',
              description: 'Solidity boolean expression for the invariant, e.g. "totalSupply == sum(balances)"',
            },
            priority: {
              type: 'string',
              enum: ['high', 'medium', 'low'],
              description: 'Priority: high = core protocol invariant, medium = important property, low = nice-to-have check',
            },
            relatedFunctions: {
              type: 'array',
              items: { type: 'string' },
              description: 'Functions that modify the involved state variables',
            },
          },
          required: ['description', 'category', 'contractName', 'stateVariables', 'priority', 'relatedFunctions'],
        },
      },
    },
    required: ['invariants'],
  },
};

export interface InvariantExtractorOptions {
  architectureContext?: ArchitectureAnalysis | null;
  projectContext?: ProjectContext | null;
  verbose?: boolean;
}

/**
 * Extract invariants from a single contract file.
 */
export async function extractInvariants(
  client: Anthropic,
  file: FileInfo,
  fileContent: string,
  model: string,
  counter: InvariantCounter,
  cache?: ResponseCache | null,
  options?: InvariantExtractorOptions,
): Promise<Invariant[]> {
  const systemPrompt = buildExtractorSystemPrompt(options);
  const userPrompt = buildExtractorFilePrompt(file, fileContent, options);

  const raw = await callExtractor(client, systemPrompt, userPrompt, model, cache, options?.verbose);

  return raw.map(r => ({
    id: counter.next(),
    description: String(r.description || ''),
    category: normalizeCategory(r.category),
    contractName: String(r.contractName || file.relativePath),
    file: file.relativePath,
    stateVariables: Array.isArray(r.stateVariables) ? r.stateVariables.map(String) : [],
    formalExpression: r.formalExpression ? String(r.formalExpression) : undefined,
    priority: normalizePriority(r.priority),
    relatedFunctions: Array.isArray(r.relatedFunctions) ? r.relatedFunctions.map(String) : [],
  }));
}

/**
 * Extract cross-contract invariants given the full codebase context.
 * Runs once after per-file extraction.
 */
export async function extractCrossContractInvariants(
  client: Anthropic,
  files: FileInfo[],
  fileContentsMap: Map<string, string>,
  perFileInvariants: Invariant[],
  model: string,
  counter: InvariantCounter,
  cache?: ResponseCache | null,
  options?: InvariantExtractorOptions,
): Promise<Invariant[]> {
  // Build a combined prompt with contract summaries + already-extracted invariants
  const archContext = options?.architectureContext
    ? formatArchitectureForSystemPrompt(options.architectureContext)
    : '';

  const existingInvs = perFileInvariants
    .map(inv => `- [${inv.id}] ${inv.contractName}: ${inv.description}`)
    .join('\n');

  // Include contract summaries (first 100 lines of each, or key functions)
  const contractSummaries = files
    .filter(f => fileContentsMap.has(f.relativePath))
    .map(f => {
      const content = fileContentsMap.get(f.relativePath)!;
      const lines = content.split('\n');
      const preview = lines.slice(0, 80).join('\n');
      return `### ${f.relativePath} (${f.lines} lines)\n\`\`\`solidity\n${preview}\n\`\`\``;
    })
    .join('\n\n');

  const systemPrompt = `You are an invariant engineer analyzing a multi-contract protocol. Your job is to identify CROSS-CONTRACT invariants — properties that span multiple contracts and must hold across the entire system.

You have already extracted per-contract invariants. Now focus on:
1. **Cross-contract accounting**: Do token balances across contracts sum correctly? Are fees/rewards distributed consistently?
2. **Cross-contract state consistency**: If Contract A updates state, does Contract B's dependent state remain valid?
3. **Protocol-level invariants**: Total value locked, exchange rate relationships, global supply constraints.
4. **Fund flow invariants**: Along each fund flow path, what must hold end-to-end?
5. **Trust boundary invariants**: Properties that must hold across trust boundaries.

Do NOT repeat invariants already extracted. Focus only on properties that SPAN multiple contracts.

${archContext}`;

  const userPrompt = `## Already Extracted (per-contract) Invariants
${existingInvs}

## Contract Summaries
${contractSummaries}

Extract CROSS-CONTRACT invariants that span multiple contracts. These are properties that cannot be checked by looking at a single contract in isolation.`;

  const raw = await callExtractor(client, systemPrompt, userPrompt, model, cache, options?.verbose);

  return raw.map(r => ({
    id: counter.next(),
    description: String(r.description || ''),
    category: normalizeCategory(r.category),
    contractName: String(r.contractName || 'cross-contract'),
    file: 'cross-contract',
    stateVariables: Array.isArray(r.stateVariables) ? r.stateVariables.map(String) : [],
    formalExpression: r.formalExpression ? String(r.formalExpression) : undefined,
    priority: normalizePriority(r.priority),
    relatedFunctions: Array.isArray(r.relatedFunctions) ? r.relatedFunctions.map(String) : [],
  }));
}

function buildExtractorSystemPrompt(options?: InvariantExtractorOptions): string {
  const archContext = options?.architectureContext
    ? formatArchitectureForSystemPrompt(options.architectureContext)
    : '';

  const projectBrief = options?.projectContext
    ? formatContextForPrompt(options.projectContext)
    : '';

  return `You are an INVARIANT ENGINEER. Your job is to deeply understand a smart contract and extract every property (invariant) that must always hold. You are NOT looking for bugs — you are documenting the contract's correctness conditions.

## What is an Invariant?

An invariant is a property that must be true at the end of every transaction. Examples:
- "totalSupply == sum of all balances" (accounting)
- "Only the owner can call pause()" (access-control)
- "exchangeRate can only increase over time" (economic)
- "After deposit, user balance increases by exactly the deposited amount minus fee" (token-conservation)

## How to Extract Invariants

1. **Read the state variables**: What data does this contract store? What relationships exist between them?
2. **Read require/assert statements**: These are explicit invariant checks the developer wrote.
3. **Trace state-changing functions**: For each function that modifies state, what must be true before and after?
4. **Look for accounting identities**: Sum relationships, conservation laws, balance equations.
5. **Check access control patterns**: Which functions are restricted? What roles exist?
6. **Identify state machine constraints**: Are there states/phases? What transitions are valid?
7. **Find economic invariants**: Exchange rates, price bounds, fee calculations.

## Priority Guidelines

- **high**: Core protocol invariant — if violated, funds are at risk or protocol is broken. Examples: supply == sum(balances), only owner can withdraw.
- **medium**: Important correctness property. Examples: fees are always <= 10%, nonce always increases.
- **low**: Defensive check, edge case property. Examples: empty string handled correctly, zero-amount doesn't revert.

## Rules

- Include a Solidity boolean expression (formalExpression) when possible — this will be used to generate test assertions.
- List ALL state variables involved so the test generator knows what to track.
- List ALL functions that can modify the involved state (relatedFunctions) — these become fuzzing targets.
- Be thorough: extract 5-20 invariants per non-trivial contract. Better too many than too few.
- Do NOT report code quality issues. Focus only on properties that can be tested.

${archContext}

${projectBrief}`;
}

function buildExtractorFilePrompt(
  file: FileInfo,
  content: string,
  options?: InvariantExtractorOptions,
): string {
  const lines = content.split('\n');
  const numbered = lines.map((line, i) => `${i + 1}: ${line}`).join('\n');

  const archFileContext = options?.architectureContext
    ? formatArchitectureForFilePrompt(options.architectureContext, file, content)
    : '';

  return `Analyze this ${file.language} contract and extract ALL invariants (properties that must always hold).

File: ${file.relativePath}
Lines: ${file.lines}${archFileContext}

\`\`\`${file.language}
${numbered}
\`\`\`

INSTRUCTIONS:
1. Read every state variable declaration. Document relationships between them.
2. Read every require/assert — these encode developer intent about what must hold.
3. For each state-changing function: what must be true before and after execution?
4. Identify accounting identities, conservation laws, access boundaries, state machine constraints.
5. Write formal expressions (Solidity boolean expressions) wherever possible.
6. List the functions that could potentially violate each invariant (these become fuzz targets).`;
}

async function callExtractor(
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
      if (verbose) console.error(`  [extractor cache hit]`);
      return cached;
    }
  }

  const maxRetries = 3;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const estimatedLines = userPrompt.split('\n').length;
      const maxTokens = estimatedLines > 400 ? 8192 : 4096;

      const response = await client.messages.create({
        model,
        max_tokens: maxTokens,
        system: systemPrompt,
        tools: [INVARIANT_TOOL],
        tool_choice: { type: 'any' },
        messages: [{ role: 'user', content: userPrompt }],
      });

      const results: Array<Record<string, unknown>> = [];
      for (const block of response.content) {
        if (block.type === 'tool_use' && block.name === 'report_invariants') {
          const input = block.input as { invariants: Array<Record<string, unknown>> };
          if (Array.isArray(input.invariants)) {
            results.push(...input.invariants);
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

  throw lastError || new Error('Invariant extractor: max retries exceeded');
}

export function normalizeCategory(val: unknown): InvariantCategory {
  const s = String(val).toLowerCase();
  const valid: InvariantCategory[] = [
    'accounting', 'access-control', 'state-transition', 'economic',
    'token-conservation', 'ordering', 'bounds', 'relationship', 'custom',
  ];
  if (valid.includes(s as InvariantCategory)) return s as InvariantCategory;
  return 'custom';
}

export function normalizePriority(val: unknown): 'high' | 'medium' | 'low' {
  const s = String(val).toLowerCase();
  if (['high', 'medium', 'low'].includes(s)) return s as 'high' | 'medium' | 'low';
  return 'medium';
}
