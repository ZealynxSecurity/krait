/**
 * Multi-agent pipeline types.
 * Detector → Reasoner → Critic → Ranker
 */

import { Finding } from '../core/types.js';

/**
 * Precondition/postcondition type classification used by A4 and (future) chain analysis.
 * - STATE: contract storage value (balance, mapping entry, flag)
 * - ACCESS: caller identity, role, or signature
 * - TIMING: block.timestamp / block.number / deadline window
 * - EXTERNAL: state of an external contract (oracle, AMM, callback target)
 * - BALANCE: native or token balance of a specific address
 */
export type ConditionType = 'STATE' | 'ACCESS' | 'TIMING' | 'EXTERNAL' | 'BALANCE';

/**
 * Plamen-derived cross-cutting rules picked because they don't duplicate Krait's 8 kill gates.
 * Detector/reasoner/critic should record which rules they applied and which they skipped (with reason).
 */
export type RuleCode = 'R8' | 'R10' | 'R11' | 'R12' | 'R15' | 'R16';

export interface RuleApplication {
  code: RuleCode;
  applied: boolean;               // true = rule was checked and contributed evidence; false = N/A or skipped
  reason?: string;                // short note: why N/A (e.g. "no oracle dependency") or what the rule surfaced
}

export interface CandidateFinding {
  id: string;                     // Temporary ID for pipeline tracking (candidate-001, etc.)
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  file: string;
  line: number;
  endLine?: number;
  category: string;
  description: string;
  codeSnippet: string;
  affectedFunctions: string[];
  relatedContracts: string[];
  detectorConfidence: number;     // 0-100
  remediation: string;
  // A1 — methodology audit trail (optional)
  stepExecution?: string;         // e.g. "Lens: A=✓ B=✓ C=✗(N/A) D=?"
  rulesApplied?: RuleApplication[];
  // A2 — depth evidence tags (optional)
  depthEvidence?: string[];       // ["[BOUNDARY:amount=0]", "[VARIATION:decimals 18→6]"]
  // A4 — precondition/postcondition (optional, preparation for chain analysis)
  missingPrecondition?: string;
  preconditionType?: ConditionType;
  postconditionsCreated?: string;
  postconditionTypes?: ConditionType[];
  whoBenefits?: string;
}

export interface ExploitProof {
  candidateId: string;
  isExploitable: boolean;
  attackScenario: string;
  prerequisites: string[];
  impactDescription: string;
  proofSteps: string[];
  codeTrace: string;
  reasonerConfidence: number;     // 0-100
  // A2 — depth evidence tags surfaced while building the proof
  depthEvidence?: string[];
  // A4 — postconditions created by a successful exploit
  postconditionsCreated?: string;
  postconditionTypes?: ConditionType[];
  whoBenefits?: string;
}

/**
 * The 8 automatic kill gates. Parity with
 * `.claude/skills/krait/critic/instructions.md` § Step 0 — any change here must be
 * mirrored there (enforced by src/agents/__tests__/parity.test.ts).
 */
export type KillGate = 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H';

/**
 * The 10 empirically-derived false-positive patterns applied after the kill gates.
 * Parity with the skill critic's § Common False Positive Patterns.
 */
export type FpPattern =
  | 'FP-1' | 'FP-2' | 'FP-3' | 'FP-4' | 'FP-5'
  | 'FP-6' | 'FP-7' | 'FP-8' | 'FP-9' | 'FP-10';

export interface CriticVerdict {
  candidateId: string;
  verdict: 'valid' | 'invalid' | 'uncertain';
  counterarguments: string[];
  rebuttals: string[];
  mitigatingFactors: string[];
  finalReasoning: string;
  criticConfidence: number;       // 0-100
  // P0 — kill gate / FP pattern attribution (parity with the skill critic)
  killedByGate?: KillGate;        // set when the candidate died at Step 0
  fpPattern?: FpPattern;          // set when the candidate died at the FP-pattern step
  dosExceptionApplied?: boolean;  // true when the DoS carve-out rescued it from A/B/D/F
  // A1 — which rules the critic actually exercised (vs N/A)
  rulesApplied?: RuleApplication[];
  // A3 — Impact Premise: the concrete HARM, not the mechanism
  harmStatement?: string;
  harmIsMechanismOnly?: boolean;  // true = no concrete consequence stated -> cannot be 'valid'
  // A5 — trust-assumption dependency. Set when the attack path requires a trusted or
  // semi-trusted actor to act against a stated assumption, but the finding still stands
  // (i.e. gate E did not kill it). The ranker turns this into a -1 tier adjustment.
  trustAssumption?: {
    actor: string;
    assumption: string;
  };
  // A4 — if 'uncertain' or 'invalid' because a precondition was missing
  missingPrecondition?: string;
  preconditionType?: ConditionType;
}

export interface RankedFinding {
  finding: Finding;
  exploitProof: ExploitProof;
  criticVerdict: CriticVerdict;
  compositeScore: number;         // 0-100
}

export interface MultiAgentStats {
  detectCandidates: number;
  afterConfidenceFilter: number;
  reasonerExploitable: number;
  criticValid: number;
  criticUncertain: number;
  criticInvalid: number;
  finalFindings: number;
}
