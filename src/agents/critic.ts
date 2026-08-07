/**
 * Critic agent — Devil's Advocate falsification.
 * Actively tries to DISPROVE each finding. Only marks as 'valid' if it cannot find
 * a convincing counterargument.
 */

import Anthropic from '@anthropic-ai/sdk';
import { ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { CandidateFinding, ConditionType, CriticVerdict, ExploitProof, FpPattern, KillGate, RuleApplication, RuleCode } from './types.js';
import { formatArchitectureForSystemPrompt } from '../analysis/architecture-pass.js';

const CRITIC_CONDITION_ENUM = ['STATE', 'ACCESS', 'TIMING', 'EXTERNAL', 'BALANCE'];
const CRITIC_RULE_ENUM = ['R8', 'R10', 'R11', 'R12', 'R15', 'R16'];
const CRITIC_GATE_ENUM = ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'];
const CRITIC_FP_ENUM = ['FP-1', 'FP-2', 'FP-3', 'FP-4', 'FP-5', 'FP-6', 'FP-7', 'FP-8', 'FP-9', 'FP-10'];

/**
 * Step 0 kill gates — verbatim parity with
 * `.claude/skills/krait/critic/instructions.md` § Step 0.
 * These 8 categories account for 95%+ of false positives across 50 shadow audits.
 * Exported so the parity test can assert both surfaces stay in sync.
 */
export const KILL_GATES = `## Step 0 — AUTOMATIC KILL GATES (run FIRST, before any other analysis)

Run these on EVERY candidate before you attempt any exploit trace. A candidate matching
ANY gate is immediately 'invalid'. No exploit trace is attempted. No exceptions.
Set \`killedByGate\` to the matching letter and state the match in \`finalReasoning\`.

**GATE A — Generic best practice.** "Use SafeERC20/safeTransfer" without naming a
specific failing token, "safeApprove" generically, single-step ownership, missing
event emission, ".transfer() gas limit" without a specific failing recipient, weak
on-chain randomness with no stated payoff, "centralization risk". Zero TPs in 50 contests.

**GATE B — Theoretical but not exploitable.** Requires exotic token behaviour not in
the protocol's actual token list; oracle returning out-of-range values; overflow in
practically bounded values; a condition prevented by deployment/init. TOKEN CONTEXT
CHECK: any finding relying on token behaviour MUST name the SPECIFIC token the protocol
actually uses. "If a fee-on-transfer token is used" without naming which one = kill.

**GATE C — Design is intentional.** Comments or docs indicate deliberate behaviour;
the same pattern exists in the reference implementation (Uniswap V3, Curve, OZ); the
function behaves as its NatSpec describes. FORK CHECK: if this is a fork and the origin
has the same behaviour, it is inherited design. Only report what DIFFERS from the fork origin.

**GATE D — Speculative / no concrete exploit.** "Could be an issue if…", cannot specify
WHO / WHAT / HOW MUCH, vague "manipulation" with no exact path, "stale data" with no
exploitable window. Test: can you write "1. Attacker calls X 2. State becomes Y 3. Profit Z"?
If no → kill.

**GATE E — Admin trust boundary.** Requires a FULLY trusted admin / owner / governance
(multisig, DAO, timelock) to act maliciously. EXCEPTION 1: a missing timelock on an
irreversible destructive action may stand as Medium. EXCEPTION 2: a SEMI-trusted role
(keeper, operator, relayer, oracle updater, sequencer) is NOT fully trusted — do not kill
those here. When a finding survives this gate but still depends on a role acting against a
stated assumption, set \`trustAssumption\` ({actor, assumption}); the report keeps it at one
tier lower with an explicit note rather than discarding it.

**GATE F — Dust / economically insignificant.** Rounding < $1/tx, bounded truncation dust,
precision loss below gas cost. If max_loss × max_iterations < $100, it is dust.

**GATE G — Out of context.** Token behaviours for tokens not in the whitelist,
chain-specific issues on unsupported chains, standards the protocol does not implement,
external protocols it does not integrate with.

**GATE H — Publicly known / acknowledged.** Already in README "Known Issues", a previous
audit, or a bot report. PRECISION REQUIREMENT: match on MECHANISM, not TOPIC. Two bugs in
the same area with different exploit paths are different bugs. Only kill on SAME entry
point + SAME root cause + SAME impact.

**DoS EXCEPTION (overrides gates A, B, D, F):** if the issue permanently or repeatedly
bricks a CORE lifecycle function (settlement, liquidation, withdrawal, unstaking,
repayment, auction) AND an unprivileged attacker can trigger it at low cost AND the effect
is persistent → it survives A/B/D/F at Medium minimum. Set \`dosExceptionApplied: true\`.
25% of historically missed findings were DoS bugs killed incorrectly.`;

/**
 * The 10 empirically-derived FP patterns applied after the kill gates.
 * Parity with the skill critic's § Common False Positive Patterns.
 */
export const FP_PATTERNS = `## Step 2 — False-positive patterns (apply after the gates)

If the candidate survived Step 0, check it against these 10 patterns. A match makes the
verdict 'invalid'; set \`fpPattern\` to the matching ID.

**FP-1 Authorization handled elsewhere** — auth is enforced by the calling function, a
parent-contract modifier, a router/proxy that gates before delegation, or a factory.
Trace ALL callers; if every path goes through auth, the finding is false.

**FP-2 Validation in called functions** — \`_transfer\` checks balance, \`_mint\` checks
address(0), SafeERC20/SafeMath handle the edge case. Read every callee before concluding.

**FP-3 OpenZeppelin / Solmate standard protection** — ERC20 0.8+ overflow checks,
ERC4626 virtual offset against inflation, ReentrancyGuard, Ownable2Step. Verify the
library version and whether the contract overrides a protective virtual function.

**FP-4 Rounding drift cleaned downstream** — a dust threshold catches the remainder, a
reconciliation function rebalances, or the rounding favours the protocol.

**FP-5 Bounded loops / economic constraints** — the loop is bounded by design, growing it
costs more than the griefing benefit, or an admin can prune the array.

**FP-6 Severity inflation** — real issue, wrong severity. A safety check catches the
condition before value loss; impact is leakage not theft; only a trusted role can trigger.
Do NOT mark invalid — return 'valid' and say the correct severity in \`finalReasoning\`.

**FP-7 Solidity 0.8+ arithmetic safety** — checked math reverts rather than wrapping.
IMPORTANT EXCEPTION: explicit casts like \`uint128(x)\` do NOT revert in 0.8+; they
silently truncate. Never dismiss a type-cast truncation finding with this pattern.

**FP-8 Read-only / view confusion** — view/pure functions cannot modify state; staticcall
blocks state changes; the issue only affects off-chain reads.

**FP-9 Test / script / interface-only** — the code is in test/, script/, a mock, or an
interface with no implementation. Not production code.

**FP-10 Documented design decision** — comments or docs explicitly explain the behaviour
as an accepted trade-off.`;

/**
 * A3 — Impact Premise. Hardens Gate D by demanding the HARM, not the mechanism.
 * Parity with the skill critic + reviewer.
 */
export const IMPACT_PREMISE = `## Step 1 — Impact Premise (harm, not mechanism)

Before tracing anything, state the finding's claimed HARM in ONE sentence in
\`harmStatement\`: WHO loses WHAT. Not the mechanism — the consequence.

Mechanism statements (NOT sufficient — these describe machinery, not damage):
- "startLiquidation succeeds while the market is active" — proves a call, not a loss
- "the parameter can be set to zero" — proves a setter works, not that zero causes harm
- "the reentrancy callback is triggered" — proves a callback fires, not that state corrupts

Harm statements (REQUIRED):
- "claimants receive 15% less than their pro-rata share after the attack sequence"
- "a user's withdrawal reverts permanently once the parameter is set to zero"
- "the attacker extracts 1.5x their fair share before the guard triggers"

If you cannot write a harm statement naming a specific user class and a specific
fund / liveness / privilege / accounting consequence, set \`harmIsMechanismOnly: true\`
and the verdict CANNOT be 'valid' — it is 'invalid' via GATE D. "Could be exploited"
and "may be unsafe" are not harm statements.`;

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
            // P0 — kill gate attribution (Step 0)
            killedByGate: {
              type: 'string',
              enum: CRITIC_GATE_ENUM,
              description: 'If this candidate died at Step 0, which kill gate matched. A=generic best practice, B=theoretical, C=intentional design, D=speculative, E=admin trust, F=dust, G=out of context, H=publicly known. Omit if it survived Step 0.',
            },
            dosExceptionApplied: {
              type: 'boolean',
              description: 'True when the DoS carve-out rescued this candidate from gate A/B/D/F (bricks a core lifecycle function, low cost, persistent).',
            },
            // P0 — FP pattern attribution (Step 2)
            fpPattern: {
              type: 'string',
              enum: CRITIC_FP_ENUM,
              description: 'If this candidate died at the false-positive-pattern step, which pattern matched (FP-1..FP-10). Omit if none matched.',
            },
            // A3 — Impact Premise
            harmStatement: {
              type: 'string',
              description: 'The claimed HARM in one sentence: WHO loses WHAT. Not the mechanism. Required to return verdict "valid".',
            },
            harmIsMechanismOnly: {
              type: 'boolean',
              description: 'True when no concrete consequence could be stated (only machinery). Forces verdict to "invalid" via gate D.',
            },
            // A5 — trust-assumption dependency (softer than killing under gate E)
            trustAssumption: {
              type: 'object',
              description: 'Set ONLY when the finding survives gate E but its attack path still requires a trusted or semi-trusted actor to act against a stated assumption. The report drops it one severity tier and prints the note. Do NOT set this for permissionless attacks.',
              properties: {
                actor: { type: 'string', description: 'The role that must misbehave, e.g. "owner", "keeper", "governance".' },
                assumption: { type: 'string', description: 'The stated trust assumption being violated.' },
              },
              required: ['actor', 'assumption'],
            },
            // A1 — record which cross-cutting rules the critic exercised on this finding
            rulesApplied: {
              type: 'array',
              description: 'Which Plamen-derived rules you exercised. Always include R10. Mark others ✗ with reason if N/A. Codes: R8=cached/stored external state, R10=worst-state severity, R11=unsolicited token transfer, R12=enabler enumeration, R15=flash-loan precondition, R16=oracle integrity.',
              items: {
                type: 'object',
                properties: {
                  code: { type: 'string', enum: CRITIC_RULE_ENUM },
                  applied: { type: 'boolean' },
                  reason: { type: 'string' },
                },
                required: ['code', 'applied'],
              },
            },
            // A4 — if the critic finds the candidate is BLOCKED, name the blocker so chain analysis can search for an enabler
            missingPrecondition: {
              type: 'string',
              description: 'If verdict is "invalid" or "uncertain" because a check/state blocks the attack, describe that blocker here. Enables future chain analysis. Optional.',
            },
            preconditionType: {
              type: 'string',
              enum: CRITIC_CONDITION_ENUM,
              description: 'Category of the blocking precondition. Optional.',
            },
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

  const systemPrompt = `You are the KRAIT CRITIC performing adversarial validation. Your job is to DISPROVE each finding. Only findings that survive attempted falsification are real.

**Core rule: INNOCENT UNTIL PROVEN GUILTY. The burden of proof is on the FINDING, not on the code.** When in doubt, kill it. A missed bug is unfortunate; a false positive destroys credibility. Zero false positives is the #1 goal.

Run the steps in order. Step 0 comes FIRST and short-circuits everything else.
${archContext}
${KILL_GATES}

${IMPACT_PREMISE}

## Step 3 — Verification (only for candidates that survived Steps 0-1)

1. **Read the cited code** at the exact line numbers. Does the code actually do what the finding claims?
2. **Search for mitigations**: Scan the ENTIRE file for require/assert/revert checks, modifiers (onlyOwner, nonReentrant, whenNotPaused), and guard patterns that prevent the issue.
3. **Trace the full call chain**: does an internal callee, a modifier, or a PARENT CONTRACT apply the "missing" check? Most FPs come from ignoring inheritance.
4. **Verify the math**: If the finding claims arithmetic is wrong, trace the computation with concrete values. Is it actually wrong?
5. **Check compiler protections**: Solidity ≥0.8.0 has overflow protection (except unchecked{} and explicit casts like uint128(), which truncate silently).
6. **Consider protocol design**: Does the architecture above make this scenario impossible? Check invariants and trust assumptions.
7. **Evaluate prerequisites**: Are the attack conditions realistic? Can the attacker reach this state from a permissionless entry point?

${FP_PATTERNS}

## Verdict Rules (you MUST pick one):

**'valid'** — The finding is REAL. ALL of these must hold:
- It survived every kill gate in Step 0 (\`killedByGate\` is unset)
- \`harmStatement\` names a specific user class and a specific consequence (\`harmIsMechanismOnly\` is false)
- No FP pattern from Step 2 matches (\`fpPattern\` is unset)
- You cannot find any mitigation that prevents it, and the exploit works after considering all guards

**'invalid'** — The finding is FALSE. Use when:
- ANY Step 0 kill gate matched → set \`killedByGate\` (this alone is sufficient; no trace needed)
- No harm statement could be written → \`harmIsMechanismOnly: true\`, gate D
- A Step 2 FP pattern matched → set \`fpPattern\`
- A specific require/assert/modifier on a specific line prevents the exploit (cite the line)
- The math is actually correct when traced with concrete values
- The finding misreads the code or cites wrong line numbers

**'uncertain'** — Use ONLY when ALL of these are true:
- You found a specific partial mitigation (cite it) BUT it doesn't fully prevent the issue
- The exploit works under a narrow set of conditions that you can enumerate
- You genuinely cannot determine if the mitigation is sufficient

Do NOT use 'uncertain' as a default. 'Uncertain' requires you to name the specific partial mitigation AND explain why it might not be enough. A candidate killed by a gate is 'invalid', never 'uncertain'.

Note on FP-6 (severity inflation): that is NOT a kill. Return 'valid' and state the corrected severity in \`finalReasoning\`. A real bug at the wrong severity is still a real bug.

## Be specific:
- Cite exact line numbers for every mitigation you find
- For mitigating factors, quote the actual code (e.g., "require(amount > 0) on line 45")
- If you claim the math is correct, show the calculation with values

## Methodology Audit Trail (optional but recommended)

For each verdict, ALSO emit:

- **rulesApplied**: array exercising the cross-cutting rules. Always include R10 (worst-state severity — did the detector assess the worst plausible state, not just the current snapshot?). Mark others ✗ with a one-line reason if N/A.
  - **R8** — cached parameter / stored external state (multi-step ops only)
  - **R10** — worst-state severity (always — did the severity assessment use the worst realistic state?)
  - **R11** — unsolicited token transfer (when external tokens are involved)
  - **R12** — exhaustive enabler enumeration (when the finding identifies a dangerous precondition state)
  - **R15** — flash-loan precondition manipulation (when balance/oracle/threshold preconditions are flash-loan-accessible)
  - **R16** — oracle integrity (when oracle-dependent logic is involved)
- **missingPrecondition** / **preconditionType**: if your verdict is 'invalid' or 'uncertain' BECAUSE some specific check or state currently blocks the attack, name that blocker and classify it (STATE / ACCESS / TIMING / EXTERNAL / BALANCE). This lets downstream chain analysis look for an enabler that would create the missing precondition. Optional.

These fields do NOT replace finalReasoning — they augment it.`;

  const userPrompt = `## Contract: ${file}
\`\`\`solidity
${numbered}
\`\`\`
${relatedContext}
## Findings to validate:

${findingDescriptions}

For EACH finding, in order:
1. Run the 8 kill gates. If one matches → verdict 'invalid', set killedByGate, move on (do NOT trace).
2. Write the harm statement (WHO loses WHAT). If you can only describe machinery → harmIsMechanismOnly: true, verdict 'invalid'.
3. Verify: read the code, trace the call chain and inheritance, search for mitigations, check the math.
4. Check the 10 FP patterns. If one matches (except FP-6) → verdict 'invalid', set fpPattern.
5. Commit to 'valid' or 'invalid'. Only use 'uncertain' if you found a specific partial mitigation that doesn't fully prevent the issue.`;

  // Check cache
  if (cache) {
    const key = cache.computeKey(systemPrompt, userPrompt, model);
    const cached = cache.getJson<CriticVerdict[]>(key);
    if (cached) {
      if (verbose) console.error(`  [critic cache hit] ${file}`);
      // Remap candidate IDs from cached verdicts to current candidates
      return cached.map((verdict, i) => enforceGateContract({
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
              const verdict: CriticVerdict = enforceGateContract({
                candidateId: String(raw.candidateId || ''),
                verdict: normalizeVerdict(raw.verdict),
                counterarguments: Array.isArray(raw.counterarguments) ? raw.counterarguments.map(String) : [],
                rebuttals: Array.isArray(raw.rebuttals) ? raw.rebuttals.map(String) : [],
                mitigatingFactors: Array.isArray(raw.mitigatingFactors) ? raw.mitigatingFactors.map(String) : [],
                finalReasoning: String(raw.finalReasoning || ''),
                criticConfidence: Number(raw.confidence) || 50,
                ...extractVerdictMethodologyFields(raw),
              });
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

/**
 * Mechanical enforcement of the gate contract. The prompt asks for it; this makes it
 * true regardless of what the model returns.
 *
 * - a candidate attributed to a kill gate is 'invalid', never 'valid'/'uncertain'
 * - a candidate with no harm statement (mechanism only) is 'invalid' via gate D
 * - FP-6 is severity inflation, not a falsification: it must NOT flip the verdict
 *
 * Exported for the unit tests.
 */
export function enforceGateContract(verdict: CriticVerdict): CriticVerdict {
  // FP-6 is a severity correction, not a kill. Drop the attribution so it can't
  // be read downstream as a falsification.
  if (verdict.fpPattern === 'FP-6') {
    const { fpPattern: _dropped, ...rest } = verdict;
    verdict = rest as CriticVerdict;
  }

  if (verdict.killedByGate && verdict.verdict !== 'invalid') {
    return {
      ...verdict,
      verdict: 'invalid',
      finalReasoning: `Killed by gate ${verdict.killedByGate}. ${verdict.finalReasoning}`.trim(),
    };
  }

  if (verdict.harmIsMechanismOnly && verdict.verdict === 'valid') {
    return {
      ...verdict,
      verdict: 'invalid',
      killedByGate: verdict.killedByGate ?? 'D',
      finalReasoning: `Killed by gate D: no concrete harm stated, only a mechanism. ${verdict.finalReasoning}`.trim(),
    };
  }

  if (verdict.fpPattern && verdict.verdict === 'valid') {
    return {
      ...verdict,
      verdict: 'invalid',
      finalReasoning: `Matched false-positive pattern ${verdict.fpPattern}. ${verdict.finalReasoning}`.trim(),
    };
  }

  return verdict;
}

/**
 * Pull A1 (rules applied), A3 (impact premise), A4 (blocking precondition) and
 * P0 (gate / FP attribution) fields from a raw verdict.
 * All optional; older verdicts without them stay valid.
 */
function extractVerdictMethodologyFields(raw: Record<string, unknown>): Partial<CriticVerdict> {
  const out: Partial<CriticVerdict> = {};
  if (typeof raw.killedByGate === 'string' && CRITIC_GATE_ENUM.includes(raw.killedByGate)) {
    out.killedByGate = raw.killedByGate as KillGate;
  }
  if (typeof raw.fpPattern === 'string' && CRITIC_FP_ENUM.includes(raw.fpPattern)) {
    out.fpPattern = raw.fpPattern as FpPattern;
  }
  if (typeof raw.dosExceptionApplied === 'boolean' && raw.dosExceptionApplied) {
    out.dosExceptionApplied = true;
  }
  if (typeof raw.harmStatement === 'string' && raw.harmStatement.trim()) {
    out.harmStatement = raw.harmStatement.trim();
  }
  if (typeof raw.harmIsMechanismOnly === 'boolean' && raw.harmIsMechanismOnly) {
    out.harmIsMechanismOnly = true;
  }
  if (typeof raw.trustAssumption === 'object' && raw.trustAssumption !== null) {
    const ta = raw.trustAssumption as Record<string, unknown>;
    const actor = typeof ta.actor === 'string' ? ta.actor.trim() : '';
    const assumption = typeof ta.assumption === 'string' ? ta.assumption.trim() : '';
    if (actor && assumption) out.trustAssumption = { actor, assumption };
  }
  if (Array.isArray(raw.rulesApplied)) {
    const rules: RuleApplication[] = [];
    for (const x of raw.rulesApplied) {
      if (typeof x !== 'object' || x === null) continue;
      const obj = x as Record<string, unknown>;
      const code = String(obj.code || '');
      if (!CRITIC_RULE_ENUM.includes(code)) continue;
      rules.push({
        code: code as RuleCode,
        applied: Boolean(obj.applied),
        reason: typeof obj.reason === 'string' && obj.reason.trim() ? obj.reason.trim() : undefined,
      });
    }
    if (rules.length > 0) out.rulesApplied = rules;
  }
  if (typeof raw.missingPrecondition === 'string' && raw.missingPrecondition.trim()) {
    out.missingPrecondition = raw.missingPrecondition.trim();
  }
  if (typeof raw.preconditionType === 'string' && CRITIC_CONDITION_ENUM.includes(raw.preconditionType)) {
    out.preconditionType = raw.preconditionType as ConditionType;
  }
  return out;
}
