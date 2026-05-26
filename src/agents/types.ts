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

export interface CriticVerdict {
  candidateId: string;
  verdict: 'valid' | 'invalid' | 'uncertain';
  counterarguments: string[];
  rebuttals: string[];
  mitigatingFactors: string[];
  finalReasoning: string;
  criticConfidence: number;       // 0-100
  // A1 — which rules the critic actually exercised (vs N/A)
  rulesApplied?: RuleApplication[];
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
