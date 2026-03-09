/**
 * Reasoner agent — builds concrete exploitation proofs for each candidate finding.
 * If it can't construct a working exploit, it marks the candidate as non-exploitable.
 */

import Anthropic from '@anthropic-ai/sdk';
import { ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { CandidateFinding, ExploitProof } from './types.js';
import { formatArchitectureForSystemPrompt } from '../analysis/architecture-pass.js';

const PROOF_TOOL: Anthropic.Tool = {
  name: 'report_proofs',
  description: 'Report exploitation proofs for each candidate vulnerability.',
  input_schema: {
    type: 'object' as const,
    properties: {
      proofs: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            candidateId: { type: 'string', description: 'ID of the candidate finding' },
            isExploitable: { type: 'boolean', description: 'Whether a concrete exploit can be constructed' },
            attackScenario: { type: 'string', description: 'Step-by-step exploit scenario' },
            prerequisites: {
              type: 'array',
              items: { type: 'string' },
              description: 'What the attacker needs (e.g., tokens, role, timing)',
            },
            impactDescription: { type: 'string', description: 'Concrete impact ($ amount, state corruption)' },
            proofSteps: {
              type: 'array',
              items: { type: 'string' },
              description: 'Numbered exploitation steps with specific function calls',
            },
            codeTrace: { type: 'string', description: 'Function call trace showing the exploit path' },
            confidence: { type: 'number', description: 'Confidence in exploit viability 0-100' },
          },
          required: ['candidateId', 'isExploitable', 'attackScenario', 'confidence'],
        },
      },
    },
    required: ['proofs'],
  },
};

const MAX_CANDIDATES_PER_BATCH = 3;

/**
 * Build exploitation proofs for candidates. Batches by file to reduce API calls.
 */
export async function reason(
  client: Anthropic,
  candidates: CandidateFinding[],
  fileContentsMap: Map<string, string>,
  architectureContext: ArchitectureAnalysis | null,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
): Promise<ExploitProof[]> {
  if (candidates.length === 0) return [];

  // Group candidates by file
  const byFile = new Map<string, CandidateFinding[]>();
  for (const c of candidates) {
    const group = byFile.get(c.file) || [];
    group.push(c);
    byFile.set(c.file, group);
  }

  const allProofs: ExploitProof[] = [];

  for (const [file, fileCandidates] of byFile) {
    // Batch within each file group
    for (let i = 0; i < fileCandidates.length; i += MAX_CANDIDATES_PER_BATCH) {
      const batch = fileCandidates.slice(i, i + MAX_CANDIDATES_PER_BATCH);

      try {
        const proofs = await reasonBatch(
          client, batch, file, fileContentsMap, architectureContext, model, cache, verbose,
        );
        allProofs.push(...proofs);
      } catch (err) {
        if (verbose) {
          console.error(`  [reasoner] Error on ${file}: ${err instanceof Error ? err.message : err}`);
        }
        // Mark all in batch as non-exploitable on error
        for (const c of batch) {
          allProofs.push({
            candidateId: c.id,
            isExploitable: false,
            attackScenario: 'Reasoner failed to analyze.',
            prerequisites: [],
            impactDescription: '',
            proofSteps: [],
            codeTrace: '',
            reasonerConfidence: 0,
          });
        }
      }
    }
  }

  return allProofs;
}

async function reasonBatch(
  client: Anthropic,
  candidates: CandidateFinding[],
  file: string,
  fileContentsMap: Map<string, string>,
  architectureContext: ArchitectureAnalysis | null,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
): Promise<ExploitProof[]> {
  const fileContent = fileContentsMap.get(file) || '';

  // Include related contract contents via multiple signals
  const relatedFiles = new Set<string>();

  // Signal 1: candidate relatedContracts field
  for (const c of candidates) {
    for (const rc of c.relatedContracts) {
      for (const [path] of fileContentsMap) {
        if (path !== file && path.toLowerCase().includes(rc.toLowerCase())) {
          relatedFiles.add(path);
        }
      }
    }
  }

  // Signal 2: architecture fund flows that involve this file
  if (architectureContext) {
    for (const flow of architectureContext.fundFlows) {
      if (flow.contracts.some(c => file.toLowerCase().includes(c.toLowerCase()))) {
        for (const contractName of flow.contracts) {
          for (const [path] of fileContentsMap) {
            if (path !== file && path.toLowerCase().includes(contractName.toLowerCase())) {
              relatedFiles.add(path);
            }
          }
        }
      }
    }
  }

  // Signal 3: imports in the file content
  const importMatches = fileContent.matchAll(/import\s+.*?["']\.\/(\w+)/g);
  for (const m of importMatches) {
    const importName = m[1].toLowerCase();
    for (const [path] of fileContentsMap) {
      if (path !== file && path.toLowerCase().includes(importName)) {
        relatedFiles.add(path);
      }
    }
  }

  let relatedContext = '';
  const relatedList = [...relatedFiles].slice(0, 3); // Limit to 3 to avoid token explosion
  for (const rf of relatedList) {
    const content = fileContentsMap.get(rf);
    if (content) {
      relatedContext += `\n### Related: ${rf}\n\`\`\`solidity\n${content}\n\`\`\`\n`;
    }
  }

  const archContext = architectureContext
    ? `\n${formatArchitectureForSystemPrompt(architectureContext)}\n\n**Fund Flows:**\n${architectureContext.fundFlows.map(f => `- ${f.name}: ${f.description} (contracts: ${f.contracts.join(', ')})`).join('\n')}`
    : '';

  const candidateDescriptions = candidates.map(c =>
    `### Candidate ${c.id}: ${c.title}
- Severity: ${c.severity}
- Line: ${c.line}
- Category: ${c.category}
- Description: ${c.description}
- Code: \`${c.codeSnippet}\`
- Detector confidence: ${c.detectorConfidence}`
  ).join('\n\n');

  const numbered = fileContent.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');

  const systemPrompt = `You are a VULNERABILITY ANALYST. For each candidate, determine whether it represents a REAL issue — either an exploitable attack or a correctness/logic bug.

## Two categories of real issues:

### A) Exploitable vulnerabilities
An attacker can profit or cause damage via a specific sequence of actions.
Provide: exact transaction sequence, parameters, state changes, profit/damage.

### B) Logic/correctness bugs
The code produces WRONG RESULTS under normal usage — no attacker needed.
Examples: fee calculated on wrong base, wrong recipient receives tokens, rounding favors user over protocol, invariant violated after normal operations, first depositor gets inflated shares.
Provide: the specific input/state that triggers incorrect behavior, what the code computes vs what it SHOULD compute.

## For each candidate:
1. Read the vulnerable code carefully, tracing the exact execution path
2. Check: does this produce incorrect results OR can it be exploited?
3. If YES (either category): describe the concrete scenario with specific values
4. If NO: explain what prevents it (existing guards, correct math, unreachable conditions)

## Mark isExploitable=true when:
- An attacker can extract value, corrupt state, or cause loss (Category A)
- The code computes wrong results that harm users or the protocol (Category B)
- Edge cases (zero amount, first user, max values) produce unexpected behavior
- **Explicit type casts** (uint128(), uint96(), uint64()) can truncate values that grow over time — reserves, accumulated fees, total supplies. These DO NOT revert in Solidity 0.8+, they silently truncate. This is a REAL bug whenever the value being cast can plausibly reach the type's max. Do NOT dismiss by saying "would need to exceed uint128.max" — the POINT is that the cast SILENTLY wraps, corrupting state.
- Rounding consistently favors users over the protocol (or vice versa) in conversion functions

## Mark isExploitable=false when:
- Existing require/assert/modifier prevents the scenario
- The math is actually correct when you trace it through
- The condition cannot occur given the protocol's constraints (explain WHY with specific bounds)
- It's a cosmetic issue (events, naming, gas)

## IMPORTANT — do NOT dismiss these patterns:
- "Values would need to be astronomically large" — if there's no explicit bounds check, large values CAN accumulate over time. Mark exploitable.
- "Overflow is prevented by Solidity 0.8+" — this only applies to arithmetic (+, -, *), NOT to explicit type casts like uint128(x). Casts silently truncate. Mark exploitable if no bounds check exists.
- "Fee is small so impact is minimal" — even small incorrect fees compound over many transactions. Mark exploitable if the math is wrong.
${archContext}`;

  const userPrompt = `## File: ${file}
\`\`\`solidity
${numbered}
\`\`\`
${relatedContext}

## Candidates to evaluate:

${candidateDescriptions}

For EACH candidate above, provide an exploitation proof. If you cannot construct a concrete exploit, set isExploitable=false and explain why.`;

  // Check cache
  if (cache) {
    const key = cache.computeKey(systemPrompt, userPrompt, model);
    const cached = cache.getJson<ExploitProof[]>(key);
    if (cached) {
      if (verbose) console.error(`  [reasoner cache hit] ${file}`);
      // Remap candidate IDs from cached proofs to current candidates
      return cached.map((proof, i) => ({
        ...proof,
        candidateId: i < candidates.length ? candidates[i].id : proof.candidateId,
      }));
    }
  }

  const maxRetries = 3;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      const response = await client.messages.create({
        model,
        max_tokens: candidates.length > 2 ? 8192 : 4096,
        system: systemPrompt,
        tools: [PROOF_TOOL],
        tool_choice: { type: 'any' },
        messages: [{ role: 'user', content: userPrompt }],
      });

      const proofs: ExploitProof[] = [];
      const seenIds = new Set<string>();

      for (const block of response.content) {
        if (block.type === 'tool_use' && block.name === 'report_proofs') {
          const input = block.input as { proofs: Array<Record<string, unknown>> };
          if (Array.isArray(input.proofs)) {
            for (const raw of input.proofs) {
              const proof: ExploitProof = {
                candidateId: String(raw.candidateId || ''),
                isExploitable: Boolean(raw.isExploitable),
                attackScenario: String(raw.attackScenario || ''),
                prerequisites: Array.isArray(raw.prerequisites) ? raw.prerequisites.map(String) : [],
                impactDescription: String(raw.impactDescription || ''),
                proofSteps: Array.isArray(raw.proofSteps) ? raw.proofSteps.map(String) : [],
                codeTrace: String(raw.codeTrace || ''),
                reasonerConfidence: Number(raw.confidence) || 0,
              };
              seenIds.add(proof.candidateId);
              proofs.push(proof);
            }
          }
        }
      }

      // Fill in any candidates the LLM missed
      for (const c of candidates) {
        if (!seenIds.has(c.id)) {
          proofs.push({
            candidateId: c.id,
            isExploitable: false,
            attackScenario: 'Reasoner did not evaluate this candidate.',
            prerequisites: [],
            impactDescription: '',
            proofSteps: [],
            codeTrace: '',
            reasonerConfidence: 0,
          });
        }
      }

      // Cache actual proofs
      if (cache) {
        const key = cache.computeKey(systemPrompt, userPrompt, model);
        cache.setJson(key, proofs, model);
      }

      return proofs;
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

  throw lastError || new Error('Reasoner: max retries exceeded');
}
