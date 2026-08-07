/**
 * Ranker agent — local scoring, deduplication, and threshold filtering.
 * No API calls needed — pure computation.
 */

import { Finding, Severity } from '../core/types.js';
import { CandidateFinding, ExploitProof, CriticVerdict, RankedFinding } from './types.js';

const DEFAULT_THRESHOLD = 40;

/** Severity ladder, strongest first. Used by the A5 trust downgrade. */
const SEVERITY_LADDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];

/**
 * A5 — drop a finding one severity tier. Floor is 'info'; 'info' never moves.
 */
export function demoteOneTier(severity: Severity): Severity {
  const idx = SEVERITY_LADDER.indexOf(severity);
  if (idx < 0 || idx === SEVERITY_LADDER.length - 1) return severity;
  return SEVERITY_LADDER[idx + 1];
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

    // A5 — trust-assumption downgrade. The attack path needs a trusted actor to
    // violate a stated assumption: report it, but one tier lower, with a note.
    // This is the middle option between gate E (kill outright) and full severity.
    let trustAdjustment: Finding['trustAdjustment'];
    if (verdict.trustAssumption) {
      const originalSeverity = adjustedSeverity;
      const demoted = demoteOneTier(adjustedSeverity);
      if (demoted !== originalSeverity) {
        adjustedSeverity = demoted;
        trustAdjustment = {
          actor: verdict.trustAssumption.actor,
          assumption: verdict.trustAssumption.assumption,
          originalSeverity,
        };
      }
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
      ...mergeMethodologyFields(candidate, proof, verdict),
      ...(trustAdjustment ? { trustAdjustment } : {}),
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

  // A7 — consolidate remaining findings that share a root cause and fix across files
  filtered = consolidateByRootCause(filtered);

  // Sort by composite score descending
  filtered.sort((a, b) => b.compositeScore - a.compositeScore);

  return filtered;
}

/**
 * A7 — root-cause consolidation.
 *
 * Deduplication (above) removes findings that are the SAME bug seen twice. This step
 * handles the different problem: N findings that are genuinely distinct locations of
 * ONE root cause with ONE fix — the "10 separate missing-event findings" shape. They
 * become a single finding carrying a locations table, so the report reflects the work
 * a developer actually has to do.
 *
 * Merge requires ALL of:
 *   1. same severity tier      (a tier gap means different impact — keep separate)
 *   2. same category           (proxy for vulnerability class)
 *   3. same normalized fix     (proxy for "one fix closes all of them")
 *   4. at least 2 members, capped at 6 locations for readability
 *
 * Conservative by design: when the fix text differs, nothing merges. A duplicate
 * finding in a report is cosmetic; a dropped true positive is a missed vulnerability.
 */
export function consolidateByRootCause(findings: RankedFinding[]): RankedFinding[] {
  if (findings.length <= 1) return findings;

  const MAX_LOCATIONS = 6;
  const groups = new Map<string, RankedFinding[]>();

  for (const f of findings) {
    const key = [
      f.finding.severity,
      f.finding.category.toLowerCase().trim(),
      normalizeFix(f.finding.remediation),
    ].join('|');
    const bucket = groups.get(key);
    if (bucket) bucket.push(f);
    else groups.set(key, [f]);
  }

  const result: RankedFinding[] = [];

  for (const bucket of groups.values()) {
    // A single-member group, an empty fix, or an over-large group stays untouched.
    if (bucket.length < 2 || bucket.length > MAX_LOCATIONS || !normalizeFix(bucket[0].finding.remediation)) {
      result.push(...bucket);
      continue;
    }

    // Keep the highest-scoring member as the surviving finding.
    const sorted = [...bucket].sort((a, b) => b.compositeScore - a.compositeScore);
    const primary = sorted[0];
    const absorbed = sorted.slice(1);

    const locations = sorted.map(f => ({
      file: f.finding.file,
      line: f.finding.line,
      note: f.finding.title,
    }));

    result.push({
      ...primary,
      finding: {
        ...primary.finding,
        title: classLevelTitle(primary.finding.title, sorted.length),
        description:
          `${primary.finding.description}\n\n**Affected locations (${sorted.length}):**\n` +
          locations.map(l => `- \`${l.file}:${l.line}\` — ${l.note}`).join('\n'),
        consolidatedFrom: absorbed.map(f => f.finding.title),
        locations,
      },
    });
  }

  return result;
}

/**
 * Normalize a remediation string so two fixes that say the same thing in different
 * words collapse to the same key. Deliberately strict: identifiers and file paths are
 * dropped (they differ per location), but the verbs and nouns of the fix are kept.
 */
function normalizeFix(remediation: string): string {
  return remediation
    .toLowerCase()
    .replace(/`[^`]*`/g, ' ')          // drop inline code (identifiers, paths)
    .replace(/\b\d+\b/g, ' ')          // drop line numbers and literals
    .replace(/[^a-z\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 3)
    .slice(0, 12)                       // first dozen significant words carry the intent
    .join(' ')
    .trim();
}

/**
 * Turn a single-location title into a class-level one when several locations merge.
 * Keeps the original wording (it already describes the bug) and appends the count.
 */
function classLevelTitle(title: string, count: number): string {
  return `${title} (${count} locations)`;
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

/**
 * Merge A1/A2/A4 metadata from candidate (detector), proof (reasoner), and verdict (critic)
 * into the final Finding. Critic is authoritative for rules/preconditions; reasoner is
 * authoritative for postconditions (the proof actually demonstrates them).
 * All fields stay optional — findings with no metadata still validate.
 */
export function mergeMethodologyFields(
  candidate: CandidateFinding,
  proof: ExploitProof,
  verdict: CriticVerdict,
): Partial<Finding> {
  const out: Partial<Finding> = {};

  // Step Execution: concatenate detector + critic views (different phases, both useful)
  const stepParts: string[] = [];
  if (candidate.stepExecution) stepParts.push(`Detector: ${candidate.stepExecution}`);
  if (verdict.verdict === 'valid' || verdict.verdict === 'uncertain') {
    // Critic's stepExecution lives elsewhere (per the skill, in the verified-findings template);
    // the TS pipeline doesn't have a slot for it on CriticVerdict today. Plumbed only if available.
    const criticStep = (verdict as unknown as { stepExecution?: string }).stepExecution;
    if (typeof criticStep === 'string' && criticStep.trim()) stepParts.push(`Critic: ${criticStep.trim()}`);
  }
  if (stepParts.length > 0) out.stepExecution = stepParts.join(' | ');

  // A3 — the critic's harm statement is authoritative (it gates the verdict)
  if (verdict.harmStatement) out.harmStatement = verdict.harmStatement;

  // Rules Applied: prefer critic's (later, authoritative), fall back to detector
  if (verdict.rulesApplied && verdict.rulesApplied.length > 0) {
    out.rulesApplied = verdict.rulesApplied.map(r => ({ ...r }));
  } else if (candidate.rulesApplied && candidate.rulesApplied.length > 0) {
    out.rulesApplied = candidate.rulesApplied.map(r => ({ ...r }));
  }

  // Depth Evidence: union of all sources (deduplicated)
  const evidence = new Set<string>();
  for (const e of candidate.depthEvidence || []) evidence.add(e);
  for (const e of proof.depthEvidence || []) evidence.add(e);
  if (evidence.size > 0) out.depthEvidence = [...evidence];

  // Precondition: critic's blocker when verdict isn't 'valid'; else detector's
  if (verdict.verdict !== 'valid' && verdict.missingPrecondition) {
    out.missingPrecondition = verdict.missingPrecondition;
    if (verdict.preconditionType) out.preconditionType = verdict.preconditionType;
  } else if (candidate.missingPrecondition) {
    out.missingPrecondition = candidate.missingPrecondition;
    if (candidate.preconditionType) out.preconditionType = candidate.preconditionType;
  }

  // Postconditions: reasoner is authoritative (proof actually creates them); fall back to detector
  if (proof.postconditionsCreated) {
    out.postconditionsCreated = proof.postconditionsCreated;
    if (proof.postconditionTypes && proof.postconditionTypes.length > 0) {
      out.postconditionTypes = [...proof.postconditionTypes];
    }
    if (proof.whoBenefits) out.whoBenefits = proof.whoBenefits;
  } else if (candidate.postconditionsCreated) {
    out.postconditionsCreated = candidate.postconditionsCreated;
    if (candidate.postconditionTypes && candidate.postconditionTypes.length > 0) {
      out.postconditionTypes = [...candidate.postconditionTypes];
    }
    if (candidate.whoBenefits) out.whoBenefits = candidate.whoBenefits;
  }

  return out;
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
