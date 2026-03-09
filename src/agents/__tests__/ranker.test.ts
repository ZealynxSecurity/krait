import { describe, it, expect } from 'vitest';
import { rank } from '../ranker.js';
import { CandidateFinding, ExploitProof, CriticVerdict } from '../types.js';

function makeCandidate(overrides: Partial<CandidateFinding> = {}): CandidateFinding {
  return {
    id: 'candidate-001',
    title: 'Test Finding',
    severity: 'high',
    file: 'Test.sol',
    line: 42,
    category: 'reentrancy',
    description: 'A test finding',
    codeSnippet: 'code()',
    affectedFunctions: ['foo'],
    relatedContracts: [],
    detectorConfidence: 80,
    remediation: 'Fix the code.',
    ...overrides,
  };
}

function makeProof(overrides: Partial<ExploitProof> = {}): ExploitProof {
  return {
    candidateId: 'candidate-001',
    isExploitable: true,
    attackScenario: 'Attacker calls X to drain Y',
    prerequisites: ['Attacker has tokens'],
    impactDescription: 'Loss of funds',
    proofSteps: ['Step 1', 'Step 2'],
    codeTrace: 'foo() → bar()',
    reasonerConfidence: 70,
    ...overrides,
  };
}

function makeVerdict(overrides: Partial<CriticVerdict> = {}): CriticVerdict {
  return {
    candidateId: 'candidate-001',
    verdict: 'valid',
    counterarguments: [],
    rebuttals: ['No guard found'],
    mitigatingFactors: [],
    finalReasoning: 'Finding confirmed.',
    criticConfidence: 80,
    ...overrides,
  };
}

describe('Ranker', () => {
  it('should score and return valid findings above threshold', () => {
    const candidates = [makeCandidate()];
    const proofs = [makeProof()];
    const verdicts = [makeVerdict()];

    const result = rank(candidates, proofs, verdicts);
    expect(result.length).toBe(1);
    expect(result[0].finding.title).toBe('Test Finding');
    expect(result[0].compositeScore).toBeGreaterThan(40);
  });

  it('should filter findings below threshold', () => {
    const candidates = [makeCandidate({ detectorConfidence: 10 })];
    const proofs = [makeProof({ reasonerConfidence: 10 })];
    const verdicts = [makeVerdict({ criticConfidence: 10 })];

    const result = rank(candidates, proofs, verdicts, 50);
    expect(result.length).toBe(0);
  });

  it('should drop invalid verdicts', () => {
    const candidates = [makeCandidate()];
    const proofs = [makeProof()];
    const verdicts = [makeVerdict({ verdict: 'invalid', criticConfidence: 90 })];

    const result = rank(candidates, proofs, verdicts, 0);
    expect(result.length).toBe(0);
  });

  it('should weight uncertain verdicts at 50%', () => {
    const candidateValid = makeCandidate({ id: 'c-1', title: 'Reentrancy exploit', detectorConfidence: 80, category: 'reentrancy' });
    const candidateUncertain = makeCandidate({ id: 'c-2', title: 'Overflow in deposit', detectorConfidence: 80, category: 'overflow', line: 100 });

    const proofValid = makeProof({ candidateId: 'c-1', reasonerConfidence: 80 });
    const proofUncertain = makeProof({ candidateId: 'c-2', reasonerConfidence: 80 });

    const verdictValid = makeVerdict({ candidateId: 'c-1', verdict: 'valid', criticConfidence: 80 });
    const verdictUncertain = makeVerdict({ candidateId: 'c-2', verdict: 'uncertain', criticConfidence: 80 });

    const result = rank(
      [candidateValid, candidateUncertain],
      [proofValid, proofUncertain],
      [verdictValid, verdictUncertain],
      0,
    );

    expect(result.length).toBe(2);
    const validScore = result.find(r => r.finding.title === 'Reentrancy exploit')!.compositeScore;
    const uncertainScore = result.find(r => r.finding.title === 'Overflow in deposit')!.compositeScore;
    expect(validScore).toBeGreaterThan(uncertainScore);
  });

  it('should deduplicate similar findings in same file/category', () => {
    const c1 = makeCandidate({ id: 'c-1', title: 'Reentrancy in withdraw function', line: 42 });
    const c2 = makeCandidate({ id: 'c-2', title: 'Reentrancy in withdraw logic', line: 44 });

    const p1 = makeProof({ candidateId: 'c-1', reasonerConfidence: 80 });
    const p2 = makeProof({ candidateId: 'c-2', reasonerConfidence: 70 });

    const v1 = makeVerdict({ candidateId: 'c-1', criticConfidence: 80 });
    const v2 = makeVerdict({ candidateId: 'c-2', criticConfidence: 70 });

    const result = rank([c1, c2], [p1, p2], [v1, v2], 0);
    expect(result.length).toBe(1); // Deduplicated
  });

  it('should downgrade severity when critic finds multiple mitigations', () => {
    const candidates = [makeCandidate({ severity: 'high' })];
    const proofs = [makeProof()];
    const verdicts = [makeVerdict({
      verdict: 'uncertain',
      mitigatingFactors: ['Access control on line 10', 'Reentrancy guard on line 20'],
    })];

    const result = rank(candidates, proofs, verdicts, 0);
    expect(result.length).toBe(1);
    expect(result[0].finding.severity).toBe('medium'); // Downgraded
  });

  it('should sort by composite score descending', () => {
    const c1 = makeCandidate({ id: 'c-1', title: 'Low scorer fee bug', detectorConfidence: 30, category: 'fee-math', line: 10 });
    const c2 = makeCandidate({ id: 'c-2', title: 'High scorer overflow', detectorConfidence: 90, category: 'overflow', line: 200 });

    const p1 = makeProof({ candidateId: 'c-1', reasonerConfidence: 30 });
    const p2 = makeProof({ candidateId: 'c-2', reasonerConfidence: 90 });

    const v1 = makeVerdict({ candidateId: 'c-1', criticConfidence: 30 });
    const v2 = makeVerdict({ candidateId: 'c-2', criticConfidence: 90 });

    const result = rank([c1, c2], [p1, p2], [v1, v2], 0);
    expect(result.length).toBe(2);
    expect(result[0].finding.title).toBe('High scorer overflow');
    expect(result[1].finding.title).toBe('Low scorer fee bug');
  });

  it('should handle empty inputs', () => {
    expect(rank([], [], []).length).toBe(0);
  });

  it('should skip candidates without matching proof/verdict', () => {
    const candidates = [makeCandidate()];
    // No matching proof
    const result = rank(candidates, [], []);
    expect(result.length).toBe(0);
  });

  it('should assign correct confidence levels based on composite score', () => {
    // High confidence (score >= 70)
    const c1 = makeCandidate({ id: 'c-1', detectorConfidence: 90 });
    const p1 = makeProof({ candidateId: 'c-1', reasonerConfidence: 90 });
    const v1 = makeVerdict({ candidateId: 'c-1', verdict: 'valid', criticConfidence: 90 });

    const result = rank([c1], [p1], [v1], 0);
    expect(result[0].finding.confidence).toBe('high');

    // Low confidence (score < 45)
    const c2 = makeCandidate({ id: 'c-2', detectorConfidence: 30 });
    const p2 = makeProof({ candidateId: 'c-2', reasonerConfidence: 30 });
    const v2 = makeVerdict({ candidateId: 'c-2', verdict: 'uncertain', criticConfidence: 30 });

    const result2 = rank([c2], [p2], [v2], 0);
    expect(result2[0].finding.confidence).toBe('low');
  });

  it('should enrich description with exploit proof', () => {
    const candidates = [makeCandidate()];
    const proofs = [makeProof({ attackScenario: 'Call withdraw() before deposit settles' })];
    const verdicts = [makeVerdict()];

    const result = rank(candidates, proofs, verdicts, 0);
    expect(result[0].finding.description).toContain('Call withdraw() before deposit settles');
  });
});
