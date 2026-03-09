/**
 * Critic agent — Devil's Advocate falsification.
 * Actively tries to DISPROVE each finding. Only marks as 'valid' if it cannot find
 * a convincing counterargument.
 */

import Anthropic from '@anthropic-ai/sdk';
import { ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { CandidateFinding, ExploitProof, CriticVerdict } from './types.js';
import { formatArchitectureForSystemPrompt } from '../analysis/architecture-pass.js';

const VERDICT_TOOL: Anthropic.Tool = {
  name: 'report_verdicts',
  description: 'Report verdict for each finding after attempting to disprove it.',
  input_schema: {
    type: 'object' as const,
    properties: {
      verdicts: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            candidateId: { type: 'string', description: 'ID of the candidate finding' },
            verdict: { type: 'string', enum: ['valid', 'invalid', 'uncertain'], description: 'Final verdict' },
            counterarguments: {
              type: 'array',
              items: { type: 'string' },
              description: 'Reasons this might NOT be a real bug',
            },
            rebuttals: {
              type: 'array',
              items: { type: 'string' },
              description: 'Why counterarguments fail (if verdict is valid)',
            },
            mitigatingFactors: {
              type: 'array',
              items: { type: 'string' },
              description: 'Existing protections found in the code',
            },
            finalReasoning: { type: 'string', description: 'Summary judgment explaining the verdict' },
            confidence: { type: 'number', description: 'Confidence in verdict 0-100' },
          },
          required: ['candidateId', 'verdict', 'finalReasoning', 'confidence'],
        },
      },
    },
    required: ['verdicts'],
  },
};

const MAX_PER_BATCH = 3;

/**
 * Run critic on candidates that passed the reasoner.
 * Batches findings to reduce API calls.
 */
export async function criticize(
  client: Anthropic,
  candidates: CandidateFinding[],
  proofs: ExploitProof[],
  fileContentsMap: Map<string, string>,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
  architectureContext?: ArchitectureAnalysis | null,
): Promise<CriticVerdict[]> {
  if (candidates.length === 0) return [];

  // Build proof lookup
  const proofMap = new Map<string, ExploitProof>();
  for (const p of proofs) {
    proofMap.set(p.candidateId, p);
  }

  // Group by file for context efficiency
  const byFile = new Map<string, CandidateFinding[]>();
  for (const c of candidates) {
    const group = byFile.get(c.file) || [];
    group.push(c);
    byFile.set(c.file, group);
  }

  const allVerdicts: CriticVerdict[] = [];

  for (const [file, fileCandidates] of byFile) {
    for (let i = 0; i < fileCandidates.length; i += MAX_PER_BATCH) {
      const batch = fileCandidates.slice(i, i + MAX_PER_BATCH);

      try {
        const verdicts = await criticBatch(
          client, batch, proofMap, file, fileContentsMap, model, cache, verbose, architectureContext,
        );
        allVerdicts.push(...verdicts);
      } catch (err) {
        if (verbose) {
          console.error(`  [critic] Error on ${file}: ${err instanceof Error ? err.message : err}`);
        }
        // Default to uncertain on error
        for (const c of batch) {
          allVerdicts.push({
            candidateId: c.id,
            verdict: 'uncertain',
            counterarguments: ['Critic failed to analyze.'],
            rebuttals: [],
            mitigatingFactors: [],
            finalReasoning: 'Critic encountered an error during analysis.',
            criticConfidence: 30,
          });
        }
      }
    }
  }

  return allVerdicts;
}

async function criticBatch(
  client: Anthropic,
  candidates: CandidateFinding[],
  proofMap: Map<string, ExploitProof>,
  file: string,
  fileContentsMap: Map<string, string>,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
  architectureContext?: ArchitectureAnalysis | null,
): Promise<CriticVerdict[]> {
  const fileContent = fileContentsMap.get(file) || '';
  const numbered = fileContent.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');

  // Gather related contract code for cross-contract context
  const relatedFiles = new Set<string>();
  for (const c of candidates) {
    for (const rc of c.relatedContracts) {
      for (const [path] of fileContentsMap) {
        if (path !== file && path.toLowerCase().includes(rc.toLowerCase())) {
          relatedFiles.add(path);
        }
      }
    }
  }
  // Also use architecture roles to find interacting contracts
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
  let relatedContext = '';
  const relatedList = [...relatedFiles].slice(0, 3); // Limit to 3 related files
  for (const rf of relatedList) {
    const content = fileContentsMap.get(rf);
    if (content) {
      relatedContext += `\n### Related: ${rf}\n\`\`\`solidity\n${content}\n\`\`\`\n`;
    }
  }

  const findingDescriptions = candidates.map(c => {
    const proof = proofMap.get(c.id);
    const proofText = proof
      ? `\n  Exploit scenario: ${proof.attackScenario}\n  Steps: ${proof.proofSteps.join(' → ')}\n  Impact: ${proof.impactDescription}`
      : '\n  No exploit proof available.';

    return `### ${c.id}: ${c.title}
- Severity: ${c.severity} | Line: ${c.line} | Category: ${c.category}
- Description: ${c.description}
- Code: \`${c.codeSnippet}\`${proofText}`;
  }).join('\n\n');

  const archContext = architectureContext
    ? `\n${formatArchitectureForSystemPrompt(architectureContext)}\n\n**Fund Flows:**\n${architectureContext.fundFlows.map(f => `- ${f.name}: ${f.description} (contracts: ${f.contracts.join(', ')})`).join('\n')}\n`
    : '';

  const systemPrompt = `You are a SKEPTICAL CODE REVIEWER performing adversarial validation. Your job is to determine whether each finding is REAL or FALSE. You must commit to a verdict.
${archContext}
## Validation Process (for EACH finding):

1. **Read the cited code** at the exact line numbers. Does the code actually do what the finding claims?
2. **Search for mitigations**: Scan the ENTIRE file for require/assert/revert checks, modifiers (onlyOwner, nonReentrant, whenNotPaused), and guard patterns that prevent the issue.
3. **Verify the math**: If the finding claims arithmetic is wrong, trace the computation with concrete values. Is it actually wrong?
4. **Check compiler protections**: Solidity ≥0.8.0 has overflow protection (except unchecked{} and explicit casts like uint128()).
5. **Consider protocol design**: Does the architecture above make this scenario impossible? Check invariants and trust assumptions.
6. **Evaluate prerequisites**: Are the attack conditions realistic? Can the attacker actually reach this state?

## Verdict Rules (you MUST pick one):

**'valid'** — The finding is REAL. Use when:
- You cannot find any mitigation that prevents it
- The math is demonstrably wrong when you trace it
- The exploit scenario works even after considering all guards
- The code produces incorrect results under normal/edge-case usage

**'invalid'** — The finding is FALSE. Use when:
- A specific require/assert/modifier on a specific line prevents the exploit (cite the line)
- The math is actually correct when traced with concrete values
- Compiler/EVM protections prevent the issue (e.g., 0.8+ overflow)
- The "bug" is intentional design (e.g., admin privileges are designed-in)
- The finding misreads the code or cites wrong line numbers

**'uncertain'** — Use ONLY when ALL of these are true:
- You found a specific partial mitigation (cite it) BUT it doesn't fully prevent the issue
- The exploit works under a narrow set of conditions that you can enumerate
- You genuinely cannot determine if the mitigation is sufficient

Do NOT use 'uncertain' as a default. If you don't find a specific mitigation, it's 'valid'. If you find a clear mitigation, it's 'invalid'. 'Uncertain' requires you to name the specific partial mitigation AND explain why it might not be enough.

## Be specific:
- Cite exact line numbers for every mitigation you find
- For mitigating factors, quote the actual code (e.g., "require(amount > 0) on line 45")
- If you claim the math is correct, show the calculation with values`;

  const userPrompt = `## Contract: ${file}
\`\`\`solidity
${numbered}
\`\`\`
${relatedContext}
## Findings to validate:

${findingDescriptions}

For EACH finding: search for mitigations, verify the math, check for guards. Commit to 'valid' or 'invalid'. Only use 'uncertain' if you find a specific partial mitigation that doesn't fully prevent the issue.`;

  // Check cache
  if (cache) {
    const key = cache.computeKey(systemPrompt, userPrompt, model);
    const cached = cache.getJson<CriticVerdict[]>(key);
    if (cached) {
      if (verbose) console.error(`  [critic cache hit] ${file}`);
      // Remap candidate IDs from cached verdicts to current candidates
      return cached.map((verdict, i) => ({
        ...verdict,
        candidateId: i < candidates.length ? candidates[i].id : verdict.candidateId,
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
        tools: [VERDICT_TOOL],
        tool_choice: { type: 'any' },
        messages: [{ role: 'user', content: userPrompt }],
      });

      const verdicts: CriticVerdict[] = [];
      const seenIds = new Set<string>();

      for (const block of response.content) {
        if (block.type === 'tool_use' && block.name === 'report_verdicts') {
          const input = block.input as { verdicts: Array<Record<string, unknown>> };
          if (Array.isArray(input.verdicts)) {
            for (const raw of input.verdicts) {
              const verdict: CriticVerdict = {
                candidateId: String(raw.candidateId || ''),
                verdict: normalizeVerdict(raw.verdict),
                counterarguments: Array.isArray(raw.counterarguments) ? raw.counterarguments.map(String) : [],
                rebuttals: Array.isArray(raw.rebuttals) ? raw.rebuttals.map(String) : [],
                mitigatingFactors: Array.isArray(raw.mitigatingFactors) ? raw.mitigatingFactors.map(String) : [],
                finalReasoning: String(raw.finalReasoning || ''),
                criticConfidence: Number(raw.confidence) || 50,
              };
              seenIds.add(verdict.candidateId);
              verdicts.push(verdict);
            }
          }
        }
      }

      // Fill in missing candidates
      for (const c of candidates) {
        if (!seenIds.has(c.id)) {
          verdicts.push({
            candidateId: c.id,
            verdict: 'uncertain',
            counterarguments: ['Critic did not evaluate this finding.'],
            rebuttals: [],
            mitigatingFactors: [],
            finalReasoning: 'Not evaluated by critic.',
            criticConfidence: 30,
          });
        }
      }

      // Cache actual verdicts
      if (cache) {
        const key = cache.computeKey(systemPrompt, userPrompt, model);
        cache.setJson(key, verdicts, model);
      }

      return verdicts;
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

  throw lastError || new Error('Critic: max retries exceeded');
}

function normalizeVerdict(val: unknown): CriticVerdict['verdict'] {
  const v = String(val).toLowerCase();
  if (v === 'valid' || v === 'invalid' || v === 'uncertain') return v;
  return 'uncertain';
}
