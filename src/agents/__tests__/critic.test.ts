import { describe, it, expect, vi } from 'vitest';
import { criticize } from '../critic.js';
import { CandidateFinding, ExploitProof } from '../types.js';

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
    remediation: 'Fix it.',
    ...overrides,
  };
}

function makeProof(overrides: Partial<ExploitProof> = {}): ExploitProof {
  return {
    candidateId: 'candidate-001',
    isExploitable: true,
    attackScenario: 'Attacker calls X',
    prerequisites: ['Tokens'],
    impactDescription: 'Loss of funds',
    proofSteps: ['Step 1'],
    codeTrace: 'foo()',
    reasonerConfidence: 70,
    ...overrides,
  };
}

function makeMockClient(verdictResults: Array<Record<string, unknown>>) {
  return {
    messages: {
      create: vi.fn().mockResolvedValue({
        content: [
          {
            type: 'tool_use',
            name: 'report_verdicts',
            input: { verdicts: verdictResults },
          },
        ],
      }),
    },
  } as any;
}

describe('Critic', () => {
  it('should return empty array for empty candidates', async () => {
    const client = makeMockClient([]);
    const result = await criticize(client, [], [], new Map(), 'test-model');
    expect(result).toEqual([]);
    expect(client.messages.create).not.toHaveBeenCalled();
  });

  it('should parse verdicts from API response', async () => {
    const client = makeMockClient([
      {
        candidateId: 'candidate-001',
        verdict: 'valid',
        counterarguments: ['None found'],
        rebuttals: ['No guard exists'],
        mitigatingFactors: [],
        finalReasoning: 'Finding confirmed.',
        confidence: 85,
      },
    ]);

    const fileMap = new Map([['Test.sol', 'contract Test { function foo() {} }']]);
    const candidates = [makeCandidate()];
    const proofs = [makeProof()];

    const result = await criticize(client, candidates, proofs, fileMap, 'test-model');
    expect(result).toHaveLength(1);
    expect(result[0].candidateId).toBe('candidate-001');
    expect(result[0].verdict).toBe('valid');
    expect(result[0].criticConfidence).toBe(85);
  });

  it('should normalize invalid verdict strings', async () => {
    const client = makeMockClient([
      {
        candidateId: 'candidate-001',
        verdict: 'VALID',  // Uppercase
        finalReasoning: 'Confirmed.',
        confidence: 80,
      },
    ]);

    const fileMap = new Map([['Test.sol', 'contract Test {}']]);
    const result = await criticize(client, [makeCandidate()], [makeProof()], fileMap, 'test-model');
    expect(result[0].verdict).toBe('valid');
  });

  it('should default unknown verdicts to uncertain', async () => {
    const client = makeMockClient([
      {
        candidateId: 'candidate-001',
        verdict: 'maybe',  // Invalid value
        finalReasoning: 'Not sure.',
        confidence: 50,
      },
    ]);

    const fileMap = new Map([['Test.sol', 'contract Test {}']]);
    const result = await criticize(client, [makeCandidate()], [makeProof()], fileMap, 'test-model');
    expect(result[0].verdict).toBe('uncertain');
  });

  it('should fill in missing candidates with uncertain', async () => {
    const client = makeMockClient([
      {
        candidateId: 'candidate-001',
        verdict: 'valid',
        finalReasoning: 'Confirmed.',
        confidence: 80,
      },
      // candidate-002 missing from response
    ]);

    const fileMap = new Map([['Test.sol', 'contract Test {}']]);
    const candidates = [
      makeCandidate({ id: 'candidate-001' }),
      makeCandidate({ id: 'candidate-002', title: 'Second', line: 100 }),
    ];
    const proofs = [
      makeProof({ candidateId: 'candidate-001' }),
      makeProof({ candidateId: 'candidate-002' }),
    ];

    const result = await criticize(client, candidates, proofs, fileMap, 'test-model');
    expect(result).toHaveLength(2);

    const second = result.find(v => v.candidateId === 'candidate-002');
    expect(second?.verdict).toBe('uncertain');
    expect(second?.criticConfidence).toBe(30);
  });

  it('should handle API errors with uncertain defaults', async () => {
    const client = {
      messages: {
        create: vi.fn().mockRejectedValue(new Error('API error')),
      },
    } as any;

    const fileMap = new Map([['Test.sol', 'contract Test {}']]);
    const candidates = [makeCandidate()];
    const proofs = [makeProof()];

    const result = await criticize(client, candidates, proofs, fileMap, 'test-model');
    expect(result).toHaveLength(1);
    expect(result[0].verdict).toBe('uncertain');
    expect(result[0].criticConfidence).toBe(30);
  });

  it('should batch candidates by file', async () => {
    const client = makeMockClient([
      { candidateId: 'c-1', verdict: 'valid', finalReasoning: 'OK', confidence: 80 },
    ]);

    const fileMap = new Map([
      ['A.sol', 'contract A {}'],
      ['B.sol', 'contract B {}'],
    ]);

    const candidates = [
      makeCandidate({ id: 'c-1', file: 'A.sol' }),
      makeCandidate({ id: 'c-2', file: 'B.sol', line: 10 }),
    ];
    const proofs = [
      makeProof({ candidateId: 'c-1' }),
      makeProof({ candidateId: 'c-2' }),
    ];

    await criticize(client, candidates, proofs, fileMap, 'test-model');
    // 2 files = 2 API calls
    expect(client.messages.create).toHaveBeenCalledTimes(2);
  });

  it('should handle empty arrays in response fields', async () => {
    const client = makeMockClient([
      {
        candidateId: 'candidate-001',
        verdict: 'invalid',
        // Missing counterarguments, rebuttals, mitigatingFactors
        finalReasoning: 'Protected by modifier.',
        confidence: 90,
      },
    ]);

    const fileMap = new Map([['Test.sol', 'contract Test {}']]);
    const result = await criticize(client, [makeCandidate()], [makeProof()], fileMap, 'test-model');
    expect(result[0].counterarguments).toEqual([]);
    expect(result[0].rebuttals).toEqual([]);
    expect(result[0].mitigatingFactors).toEqual([]);
  });
});
