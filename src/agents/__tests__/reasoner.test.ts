import { describe, it, expect, vi } from 'vitest';
import { reason } from '../reasoner.js';
import { CandidateFinding } from '../types.js';

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

function makeMockClient(proofResults: Array<Record<string, unknown>>) {
  return {
    messages: {
      create: vi.fn().mockResolvedValue({
        content: [
          {
            type: 'tool_use',
            name: 'report_proofs',
            input: { proofs: proofResults },
          },
        ],
      }),
    },
  } as any;
}

describe('Reasoner', () => {
  it('should return empty array for empty candidates', async () => {
    const client = makeMockClient([]);
    const result = await reason(client, [], new Map(), null, 'test-model');
    expect(result).toEqual([]);
    expect(client.messages.create).not.toHaveBeenCalled();
  });

  it('should parse exploit proofs from API response', async () => {
    const client = makeMockClient([
      {
        candidateId: 'candidate-001',
        isExploitable: true,
        attackScenario: 'Call withdraw after deposit',
        prerequisites: ['Tokens'],
        impactDescription: 'Loss of funds',
        proofSteps: ['Step 1', 'Step 2'],
        codeTrace: 'foo() → bar()',
        confidence: 85,
      },
    ]);

    const fileMap = new Map([['Test.sol', 'contract Test { function foo() {} }']]);
    const candidates = [makeCandidate()];

    const result = await reason(client, candidates, fileMap, null, 'test-model');
    expect(result).toHaveLength(1);
    expect(result[0].candidateId).toBe('candidate-001');
    expect(result[0].isExploitable).toBe(true);
    expect(result[0].reasonerConfidence).toBe(85);
    expect(result[0].attackScenario).toBe('Call withdraw after deposit');
  });

  it('should fill in missing candidates with non-exploitable', async () => {
    // LLM only evaluates one of two candidates
    const client = makeMockClient([
      {
        candidateId: 'candidate-001',
        isExploitable: true,
        attackScenario: 'Exploit A',
        confidence: 70,
      },
    ]);

    const fileMap = new Map([['Test.sol', 'contract Test {}']]);
    const candidates = [
      makeCandidate({ id: 'candidate-001' }),
      makeCandidate({ id: 'candidate-002', title: 'Second finding', line: 100 }),
    ];

    const result = await reason(client, candidates, fileMap, null, 'test-model');
    expect(result).toHaveLength(2);

    const first = result.find(p => p.candidateId === 'candidate-001');
    const second = result.find(p => p.candidateId === 'candidate-002');
    expect(first?.isExploitable).toBe(true);
    expect(second?.isExploitable).toBe(false);
    expect(second?.reasonerConfidence).toBe(0);
  });

  it('should batch candidates by file', async () => {
    const client = makeMockClient([
      { candidateId: 'c-1', isExploitable: true, attackScenario: 'A', confidence: 70 },
    ]);

    const fileMap = new Map([
      ['A.sol', 'contract A {}'],
      ['B.sol', 'contract B {}'],
    ]);

    const candidates = [
      makeCandidate({ id: 'c-1', file: 'A.sol' }),
      makeCandidate({ id: 'c-2', file: 'B.sol', line: 10 }),
    ];

    await reason(client, candidates, fileMap, null, 'test-model');
    // Should make 2 API calls (one per file)
    expect(client.messages.create).toHaveBeenCalledTimes(2);
  });

  it('should handle API errors gracefully', async () => {
    const client = {
      messages: {
        create: vi.fn().mockRejectedValue(new Error('API error')),
      },
    } as any;

    const fileMap = new Map([['Test.sol', 'contract Test {}']]);
    const candidates = [makeCandidate()];

    const result = await reason(client, candidates, fileMap, null, 'test-model');
    expect(result).toHaveLength(1);
    expect(result[0].isExploitable).toBe(false);
    expect(result[0].reasonerConfidence).toBe(0);
  });

  it('should handle malformed API response', async () => {
    const client = makeMockClient([
      {
        candidateId: 'candidate-001',
        // Missing isExploitable — should default to false via Boolean()
        attackScenario: 'Something',
        confidence: 50,
      },
    ]);

    const fileMap = new Map([['Test.sol', 'contract Test {}']]);
    const candidates = [makeCandidate()];

    const result = await reason(client, candidates, fileMap, null, 'test-model');
    expect(result).toHaveLength(1);
    expect(result[0].isExploitable).toBe(false); // Boolean(undefined) = false
  });
});
