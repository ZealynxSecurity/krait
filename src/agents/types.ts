/**
 * Multi-agent pipeline types.
 * Detector → Reasoner → Critic → Ranker
 */

import {
  Finding,
  MissingPrecondition,
  PostconditionsCreated,
  AssumptionDep,
} from '../core/types.js';

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
  // A1
  stepExecution?: string;
  rulesApplied?: Record<string, string>;
  // A2
  depthEvidence?: string[];
  // A3 (raw harm assertion seeded by detector/reasoner; critic validates)
  impactPremise?: string;
  // A4
  missingPrecondition?: MissingPrecondition;
  postconditionsCreated?: PostconditionsCreated;
  // A5
  assumptionDep?: AssumptionDep;
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
  // A1
  stepExecution?: string;
  rulesApplied?: Record<string, string>;
  // A2 (reasoner deepens what detector started)
  depthEvidence?: string[];
  // A3
  impactPremise?: string;
  // A4
  missingPrecondition?: MissingPrecondition;
  postconditionsCreated?: PostconditionsCreated;
  // A5
  assumptionDep?: AssumptionDep;
}

export interface CriticVerdict {
  candidateId: string;
  verdict: 'valid' | 'invalid' | 'uncertain';
  counterarguments: string[];
  rebuttals: string[];
  mitigatingFactors: string[];
  finalReasoning: string;
  criticConfidence: number;       // 0-100
  // A1: critic audits the rules-applied claims
  rulesApplied?: Record<string, string>;
  // A3: critic-validated harm statement (empty string when rejected)
  impactPremise?: string;
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
