/**
 * Multi-agent pipeline types.
 * Detector → Reasoner → Critic → Ranker
 */

import { Finding } from '../core/types.js';

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
}

export interface CriticVerdict {
  candidateId: string;
  verdict: 'valid' | 'invalid' | 'uncertain';
  counterarguments: string[];
  rebuttals: string[];
  mitigatingFactors: string[];
  finalReasoning: string;
  criticConfidence: number;       // 0-100
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
