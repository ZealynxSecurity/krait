/**
 * Ranker agent — local scoring, deduplication, and threshold filtering.
 * No API calls needed — pure computation.
 */

import { Finding } from '../core/types.js';
import { CandidateFinding, ExploitProof, CriticVerdict, RankedFinding } from './types.js';

const DEFAULT_THRESHOLD = 40;

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
    let adjustedSeverity = candidate.severity;
    if (verdict.mitigatingFactors.length >= 2 && verdict.verdict === 'uncertain') {
      // Downgrade one level if multiple mitigations found
      if (adjustedSeverity === 'critical') adjustedSeverity = 'high';
      else if (adjustedSeverity === 'high') adjustedSeverity = 'medium';
    }

    // Confidence mapping
    const confidence = compositeScore >= 70 ? 'high' as const
      : compositeScore >= 45 ? 'medium' as const
      : 'low' as const;

    const finding: Finding = {
      id: '', // Will be reassigned by orchestrator
      title: candidate.title,
      severity: adjustedSeverity,
      confidence,
      file: candidate.file,
      line: candidate.line,
      endLine: candidate.endLine,
      description: buildEnrichedDescription(candidate, proof, verdict),
      impact: proof.impactDescription || candidate.description,
      remediation: candidate.remediation || '',
      category: candidate.category,
      codeSnippet: candidate.codeSnippet,
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

  return desc;
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
