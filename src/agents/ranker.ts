/**
 * Ranker agent — local scoring, deduplication, and threshold filtering.
 * No API calls needed — pure computation.
 */

import { Finding, Severity, AssumptionDep } from '../core/types.js';
import { CandidateFinding, ExploitProof, CriticVerdict, RankedFinding } from './types.js';

const DEFAULT_THRESHOLD = 40;

const SEVERITY_ORDER: Severity[] = ['info', 'low', 'medium', 'high', 'critical'];

function downgradeOneTier(s: Severity): Severity {
  const idx = SEVERITY_ORDER.indexOf(s);
  if (idx <= 0) return 'info';
  return SEVERITY_ORDER[idx - 1];
}

/**
 * Score, deduplicate, and filter findings. Produces final RankedFinding[].
 */
export function rank(
  candidates: CandidateFinding[],
  proofs: ExploitProof[],
  verdicts: CriticVerdict[],
  threshold: number = DEFAULT_THRESHOLD,
): RankedFinding[] {
  // Build lookup maps
  const proofMap = new Map<string, ExploitProof>();
  for (const p of proofs) proofMap.set(p.candidateId, p);

  const verdictMap = new Map<string, CriticVerdict>();
  for (const v of verdicts) verdictMap.set(v.candidateId, v);

  // Score each candidate
  const scored: RankedFinding[] = [];

  for (const candidate of candidates) {
    const proof = proofMap.get(candidate.id);
    const verdict = verdictMap.get(candidate.id);

    if (!proof || !verdict) continue;

    // Critic verdict weight: valid=1.0, uncertain=0.5, invalid=0.0
    const verdictWeight = verdict.verdict === 'valid' ? 1.0
      : verdict.verdict === 'uncertain' ? 0.5
      : 0.0;

    // Composite score
    const compositeScore = (
      0.3 * candidate.detectorConfidence +
      0.3 * proof.reasonerConfidence +
      0.4 * (verdict.criticConfidence * verdictWeight)
    );

    // Severity adjustment: if critic found mitigations, consider downgrade
    let adjustedSeverity: Severity = candidate.severity;
    if (verdict.mitigatingFactors.length >= 2 && verdict.verdict === 'uncertain') {
      // Downgrade one level if multiple mitigations found
      if (adjustedSeverity === 'critical') adjustedSeverity = 'high';
      else if (adjustedSeverity === 'high') adjustedSeverity = 'medium';
    }

    // A5: trust-assumption downgrade. Prefer reasoner-stage assumptionDep (it has
    // seen the exploit trace); fall back to detector-stage assumptionDep otherwise.
    const assumptionDep: AssumptionDep | undefined = proof.assumptionDep ?? candidate.assumptionDep;
    const preTrustSeverity: Severity = adjustedSeverity;
    let originalSeverity: Severity | undefined;
    let trustAdjustmentNote = '';
    if (assumptionDep?.kind === 'TRUSTED-ACTOR') {
      const downgraded = downgradeOneTier(adjustedSeverity);
      if (downgraded !== adjustedSeverity) {
        originalSeverity = preTrustSeverity;
        adjustedSeverity = downgraded;
        const actor = assumptionDep.actor || 'a fully-trusted actor';
        const assumption = assumptionDep.assumption || 'the stated trust assumption';
        trustAdjustmentNote = `Severity adjusted from ${preTrustSeverity} — attack requires ${actor} to violate stated trust assumption: ${assumption}.`;
      }
    } else if (assumptionDep?.kind === 'WITHIN-BOUNDS') {
      const actor = assumptionDep.actor || 'a semi-trusted actor';
      const assumption = assumptionDep.assumption || 'protocol\'s stated operational bounds';
      trustAdjustmentNote = `Note: impact falls within the protocol's stated operational bounds for ${actor} (${assumption}).`;
    }

    // Confidence mapping
    const confidence = compositeScore >= 70 ? 'high' as const
      : compositeScore >= 45 ? 'medium' as const
      : 'low' as const;

    const description = buildEnrichedDescription(candidate, proof, verdict, trustAdjustmentNote);

    // A4 carry-through: prefer reasoner-stage (deepens detector) where present.
    const missingPrecondition = proof.missingPrecondition ?? candidate.missingPrecondition;
    const postconditionsCreated = proof.postconditionsCreated ?? candidate.postconditionsCreated;

    // A1/A2 carry-through. Reasoner deepens detector — merge tags additively.
    const stepExecution = proof.stepExecution ?? candidate.stepExecution;
    const rulesApplied = mergeRulesApplied(
      candidate.rulesApplied,
      proof.rulesApplied,
      verdict.rulesApplied,
    );
    const depthEvidence = mergeDepthEvidence(candidate.depthEvidence, proof.depthEvidence);

    // A3: critic's validated impact premise wins. Empty string means rejected,
    // but those are already filtered as verdict='invalid' below.
    const impactPremise = verdict.impactPremise && verdict.impactPremise.length > 0
      ? verdict.impactPremise
      : (proof.impactPremise ?? candidate.impactPremise);

    const finding: Finding = {
      id: '', // Will be reassigned by orchestrator
      title: candidate.title,
      severity: adjustedSeverity,
      confidence,
      file: candidate.file,
      line: candidate.line,
      endLine: candidate.endLine,
      description,
      impact: proof.impactDescription || candidate.description,
      remediation: candidate.remediation || '',
      category: candidate.category,
      codeSnippet: candidate.codeSnippet,
      stepExecution,
      rulesApplied,
      depthEvidence,
      impactPremise,
      missingPrecondition,
      postconditionsCreated,
      assumptionDep,
      originalSeverity,
    };

    scored.push({
      finding,
      exploitProof: proof,
      criticVerdict: verdict,
      compositeScore,
    });
  }

  // Filter by threshold
  let filtered = scored.filter(s => s.compositeScore >= threshold);

  // Drop invalid verdicts entirely
  filtered = filtered.filter(s => s.criticVerdict.verdict !== 'invalid');

  // Deduplicate by title similarity + same file + same category
  filtered = deduplicateRanked(filtered);

  // Sort by composite score descending
  filtered.sort((a, b) => b.compositeScore - a.compositeScore);

  return filtered;
}

/**
 * Build enriched description incorporating exploit proof and critic reasoning.
 */
function buildEnrichedDescription(
  candidate: CandidateFinding,
  proof: ExploitProof,
  verdict: CriticVerdict,
  trustAdjustmentNote = '',
): string {
  let desc = candidate.description;

  if (proof.attackScenario && proof.isExploitable) {
    desc += `\n\n**Exploit Scenario:**\n${proof.attackScenario}`;
    if (proof.proofSteps.length > 0) {
      desc += '\n\n**Proof Steps:**\n' + proof.proofSteps.map((s, i) => `${i + 1}. ${s}`).join('\n');
    }
    if (proof.prerequisites.length > 0) {
      desc += '\n\n**Prerequisites:** ' + proof.prerequisites.join(', ');
    }
  }

  if (verdict.verdict === 'valid' && verdict.rebuttals.length > 0) {
    desc += '\n\n**Validation:** Finding confirmed after adversarial review.';
  } else if (verdict.verdict === 'uncertain') {
    desc += '\n\n**Note:** ' + verdict.finalReasoning;
  }

  if (trustAdjustmentNote) {
    desc += '\n\n**Trust Assumption:** ' + trustAdjustmentNote;
  }

  return desc;
}

function mergeRulesApplied(
  ...sources: Array<Record<string, string> | undefined>
): Record<string, string> | undefined {
  const out: Record<string, string> = {};
  let any = false;
  for (const src of sources) {
    if (!src) continue;
    for (const [k, v] of Object.entries(src)) {
      if (!v) continue;
      out[k] = v; // later source wins — critic > reasoner > detector
      any = true;
    }
  }
  return any ? out : undefined;
}

function mergeDepthEvidence(
  ...sources: Array<string[] | undefined>
): string[] | undefined {
  const seen = new Set<string>();
  const out: string[] = [];
  for (const src of sources) {
    if (!src) continue;
    for (const tag of src) {
      if (!tag || seen.has(tag)) continue;
      seen.add(tag);
      out.push(tag);
    }
  }
  return out.length > 0 ? out : undefined;
}

/**
 * Deduplicate ranked findings using Jaccard similarity on title words + same-file + same-category.
 */
function deduplicateRanked(findings: RankedFinding[]): RankedFinding[] {
  if (findings.length <= 1) return findings;

  const result: RankedFinding[] = [];
  const dropped = new Set<number>();

  for (let i = 0; i < findings.length; i++) {
    if (dropped.has(i)) continue;

    for (let j = i + 1; j < findings.length; j++) {
      if (dropped.has(j)) continue;

      const a = findings[i];
      const b = findings[j];

      // Same file + same category + similar title → duplicate
      if (a.finding.file === b.finding.file && a.finding.category === b.finding.category) {
        const sim = jaccardSimilarity(a.finding.title, b.finding.title);
        if (sim >= 0.35) {
          // Keep the higher-scored one
          if (a.compositeScore >= b.compositeScore) {
            dropped.add(j);
          } else {
            dropped.add(i);
            break;
          }
        }
      }

      // Same line + same file → likely duplicate even with different categories
      if (a.finding.file === b.finding.file && Math.abs(a.finding.line - b.finding.line) <= 3) {
        const sim = jaccardSimilarity(a.finding.title, b.finding.title);
        if (sim >= 0.25) {
          if (a.compositeScore >= b.compositeScore) {
            dropped.add(j);
          } else {
            dropped.add(i);
            break;
          }
        }
      }
    }

    if (!dropped.has(i)) {
      result.push(findings[i]);
    }
  }

  return result;
}

function jaccardSimilarity(a: string, b: string): number {
  const wordsA = new Set(a.toLowerCase().split(/\s+/).filter(w => w.length > 2));
  const wordsB = new Set(b.toLowerCase().split(/\s+/).filter(w => w.length > 2));

  if (wordsA.size === 0 && wordsB.size === 0) return 1;

  let intersection = 0;
  for (const w of wordsA) {
    if (wordsB.has(w)) intersection++;
  }

  const union = wordsA.size + wordsB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}
