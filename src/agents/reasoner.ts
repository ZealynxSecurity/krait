/**
 * Reasoner agent — builds concrete exploitation proofs for each candidate finding.
 * If it can't construct a working exploit, it marks the candidate as non-exploitable.
 */

import Anthropic from '@anthropic-ai/sdk';
import { ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { CandidateFinding, ExploitProof } from './types.js';
import { formatArchitectureForSystemPrompt } from '../analysis/architecture-pass.js';
import {
  parseStepExecution,
  parseRulesApplied,
  parseDepthEvidence,
  parseImpactPremise,
  parseMissingPrecondition,
  parsePostconditions,
  parseAssumptionDep,
} from './detector.js';

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
            stepExecution: {
              type: 'string',
              description: 'Step execution markers e.g., "✓1,2,3,5 | ✗4(N/A) | ?6,7(uncertain)" — deepens the detector\'s step markers.',
            },
            rulesApplied: {
              type: 'object',
              description: 'Map of rule code (R8/R10/R11/R12/R15/R16) to ✓ / ✗(reason) / ?(reason). Never blank.',
              additionalProperties: { type: 'string' },
            },
            depthEvidence: {
              type: 'array',
              items: { type: 'string' },
              description: 'Depth evidence tags such as [BOUNDARY:X=val], [VARIATION:A→B], [TRACE:path→outcome] — concrete value substitutions, parameter variations, or terminal-state traces.',
            },
            impactPremise: {
              type: 'string',
              description: 'One-sentence concrete user/system HARM — not a mechanism, not a reachable state.',
            },
            missingPrecondition: {
              type: 'object',
              description: 'For PARTIAL/REFUTED-with-caveat findings: what blocks exploitation today.',
              properties: {
                statement: { type: 'string' },
                type: { type: 'string', enum: ['STATE', 'ACCESS', 'TIMING', 'EXTERNAL', 'BALANCE'] },
                reason: { type: 'string' },
              },
            },
            postconditionsCreated: {
              type: 'object',
              description: 'For CONFIRMED/PARTIAL findings: the conditions the bug creates that downstream attacks can chain.',
              properties: {
                conditions: { type: 'array', items: { type: 'string' } },
                types: {
                  type: 'array',
                  items: { type: 'string', enum: ['STATE', 'ACCESS', 'TIMING', 'EXTERNAL', 'BALANCE'] },
                },
                whoBenefits: { type: 'string' },
              },
            },
            assumptionDep: {
              type: 'object',
              description: 'Trust-assumption tag. TRUSTED-ACTOR (fully-trusted actor must act maliciously) or WITHIN-BOUNDS (impact within stated bounds for a semi-trusted actor).',
              properties: {
                kind: { type: 'string', enum: ['TRUSTED-ACTOR', 'WITHIN-BOUNDS'] },
                actor: { type: 'string' },
                assumption: { type: 'string' },
              },
            },
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

## Structured Proof Fields (REQUIRED — your job is to DEEPEN what the detector started)

### \`stepExecution\` — which validation steps you actually ran
Markers like \`"✓1,2,3,5 | ✗4(N/A) | ?6,7(uncertain)"\` referencing the validation steps above. \`✓\` = completed, \`✗(reason)\` = skipped with reason, \`?\` = uncertain.

### \`rulesApplied\` — supplementary rules audit (deepen the detector's pass)
For EACH rule below, set its status. NEVER leave a rule blank.
- **R8** Cached parameters / stored external state staleness — does multi-step or cached state interact here?
- **R10** Worst-state severity — calibrate severity against worst realistic operational state.
- **R11** Unsolicited token transfer — external tokens transferred directly (not via approve/transferFrom)?
- **R12** Exhaustive enabler enumeration — has every actor category that can reach the dangerous state been considered?
- **R15** Flash-loan precondition manipulation — is any balance/oracle/threshold precondition flash-loan-accessible?
- **R16** Oracle integrity — staleness, decimals, zero/negative price, feed-failure handling?

Use \`"✓"\` (rule applied / honored) or \`"✗(reason)"\` (rule does NOT apply, e.g., \`"✗(no oracle dependency)"\`). \`"?"\` only when genuinely undeterminable — the critic will flag it for depth review.

### \`depthEvidence\` — concrete-value evidence tags (DEEPEN the detector's tags)
You must add at least one tag whenever your validation substituted, varied, or traced something:
- \`[BOUNDARY:X=val]\` — substituted a concrete boundary (e.g., \`[BOUNDARY:windowSize=0 → weight=MAX_INT]\`)
- \`[VARIATION:A→B]\` — tested a parameter change (e.g., \`[VARIATION:decimals 18→6 → price inflated 1e12x]\`)
- \`[TRACE:path→outcome]\` — traced execution to a terminal state (e.g., \`[TRACE:withdraw(MAX)→revert L120 "insufficient"]\`)

If the detector emitted tags, build on them — don't just repeat them. Add NEW tags showing the validation you performed.

### \`impactPremise\` — one-sentence concrete harm
A user/system HARM in one sentence (NOT a mechanism, NOT a reachable state). Example: "claimant receives 15% less than their pro-rata share after attack sequence." Mechanism-only ("function can be called") will be rejected by the critic.

### \`missingPrecondition\` (PARTIAL / REFUTED-with-caveat findings only)
If you couldn't construct a working exploit because something blocks it, name the blocker. \`type\` is one of STATE / ACCESS / TIMING / EXTERNAL / BALANCE. Optional.

### \`postconditionsCreated\` (CONFIRMED / PARTIAL findings only)
Optional. If the bug, when triggered, creates a condition that downstream attacks could chain off of, name it. \`whoBenefits\` identifies who can use those conditions.

### \`assumptionDep\` — trust-assumption tag (optional)
- \`{kind: "TRUSTED-ACTOR", actor, assumption}\` — exploit only fires if a fully-trusted actor (governance multisig, DAO, timelock) acts maliciously.
- \`{kind: "WITHIN-BOUNDS", actor, assumption}\` — impact falls within stated operational bounds for a semi-trusted actor (admin, operator, keeper, oracle).
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
                stepExecution: parseStepExecution(raw.stepExecution),
                rulesApplied: parseRulesApplied(raw.rulesApplied),
                depthEvidence: parseDepthEvidence(raw.depthEvidence),
                impactPremise: parseImpactPremise(raw.impactPremise),
                missingPrecondition: parseMissingPrecondition(raw.missingPrecondition),
                postconditionsCreated: parsePostconditions(raw.postconditionsCreated),
                assumptionDep: parseAssumptionDep(raw.assumptionDep),
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
