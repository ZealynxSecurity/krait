import { describe, it, expect } from 'vitest';
import { consolidateByRootCause, demoteOneTier, rank } from '../ranker.js';
import { CandidateFinding, CriticVerdict, ExploitProof, RankedFinding } from '../types.js';
import { Finding, Severity } from '../../core/types.js';

function makeRanked(overrides: Partial<Finding> & { score?: number } = {}): RankedFinding {
  const { score = 80, ...findingOverrides } = overrides;
  const finding: Finding = {
    id: 'KRAIT-001',
    title: 'Missing reward checkpoint',
    severity: 'medium',
    confidence: 'high',
    file: 'Staking.sol',
    line: 100,
    description: 'desc',
    impact: 'impact',
    remediation: 'Call `_updateReward(msg.sender)` before mutating the staked balance.',
    category: 'state-desync',
    ...findingOverrides,
  };
  return {
    finding,
    exploitProof: {} as ExploitProof,
    criticVerdict: {} as CriticVerdict,
    compositeScore: score,
  };
}

describe('demoteOneTier', () => {
  it('walks the severity ladder down one step', () => {
    expect(demoteOneTier('critical')).toBe('high');
    expect(demoteOneTier('high')).toBe('medium');
    expect(demoteOneTier('medium')).toBe('low');
    expect(demoteOneTier('low')).toBe('info');
  });

  it('floors at info', () => {
    expect(demoteOneTier('info')).toBe('info');
  });

  it('leaves an unknown severity untouched', () => {
    expect(demoteOneTier('bogus' as Severity)).toBe('bogus');
  });
});

describe('consolidateByRootCause (A7)', () => {
  it('merges findings sharing severity, category and fix', () => {
    const out = consolidateByRootCause([
      makeRanked({ file: 'Staking.sol', line: 142, title: 'withdraw skips checkpoint', score: 90 }),
      makeRanked({ file: 'Staking.sol', line: 201, title: 'emergencyWithdraw skips checkpoint', score: 70 }),
      makeRanked({ file: 'Migrator.sol', line: 88, title: 'migrate skips checkpoint', score: 60 }),
    ]);

    expect(out).toHaveLength(1);
    expect(out[0].finding.locations).toHaveLength(3);
    expect(out[0].finding.consolidatedFrom).toHaveLength(2);
    // Highest-scoring member survives as the primary.
    expect(out[0].finding.title).toContain('withdraw skips checkpoint');
    expect(out[0].finding.title).toContain('(3 locations)');
    expect(out[0].finding.description).toContain('Migrator.sol:88');
  });

  it('does NOT merge across severity tiers', () => {
    const out = consolidateByRootCause([
      makeRanked({ severity: 'high', line: 1 }),
      makeRanked({ severity: 'medium', line: 2 }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('does NOT merge across categories', () => {
    const out = consolidateByRootCause([
      makeRanked({ category: 'state-desync', line: 1 }),
      makeRanked({ category: 'access-control', line: 2 }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('does NOT merge when the fixes differ', () => {
    const out = consolidateByRootCause([
      makeRanked({ line: 1, remediation: 'Call `_updateReward` before mutating the staked balance.' }),
      makeRanked({ line: 2, remediation: 'Add the `nonReentrant` modifier to the withdrawal entry point.' }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('ignores identifiers and line numbers when comparing fixes', () => {
    const out = consolidateByRootCause([
      makeRanked({ line: 10, remediation: 'Call `_updateReward(a)` before mutating the staked balance at 142.' }),
      makeRanked({ line: 20, remediation: 'Call `_updateRewardFor(b)` before mutating the staked balance at 201.' }),
    ]);
    expect(out).toHaveLength(1);
  });

  it('leaves a group larger than 6 locations unmerged for readability', () => {
    const many = Array.from({ length: 7 }, (_, i) => makeRanked({ line: i + 1 }));
    expect(consolidateByRootCause(many)).toHaveLength(7);
  });

  it('never merges on an empty remediation', () => {
    const out = consolidateByRootCause([
      makeRanked({ line: 1, remediation: '' }),
      makeRanked({ line: 2, remediation: '' }),
    ]);
    expect(out).toHaveLength(2);
  });

  it('passes single findings straight through', () => {
    const one = [makeRanked()];
    expect(consolidateByRootCause(one)).toEqual(one);
    expect(consolidateByRootCause([])).toEqual([]);
  });
});

describe('trust-assumption downgrade (A5) through rank()', () => {
  function fixture(verdictOverrides: Partial<CriticVerdict>) {
    const candidate: CandidateFinding = {
      id: 'c1',
      title: 'Keeper can submit a stale price',
      severity: 'high',
      file: 'Oracle.sol',
      line: 55,
      category: 'oracle',
      description: 'desc',
      codeSnippet: 'code()',
      affectedFunctions: ['push'],
      relatedContracts: [],
      detectorConfidence: 90,
      remediation: 'Bound the accepted deviation.',
    };
    const proof: ExploitProof = {
      candidateId: 'c1',
      isExploitable: true,
      attackScenario: 'scenario',
      prerequisites: [],
      impactDescription: 'Borrowers are liquidated at a wrong price.',
      proofSteps: ['step'],
      codeTrace: 'trace',
      reasonerConfidence: 90,
    };
    const verdict: CriticVerdict = {
      candidateId: 'c1',
      verdict: 'valid',
      counterarguments: [],
      rebuttals: [],
      mitigatingFactors: [],
      finalReasoning: 'stands',
      criticConfidence: 90,
      ...verdictOverrides,
    };
    return rank([candidate], [proof], [verdict], 0);
  }

  it('drops one tier and records the original severity', () => {
    const out = fixture({
      trustAssumption: { actor: 'keeper', assumption: 'keepers submit prices within 1% of market' },
    });
    expect(out).toHaveLength(1);
    expect(out[0].finding.severity).toBe('medium');
    expect(out[0].finding.trustAdjustment).toEqual({
      actor: 'keeper',
      assumption: 'keepers submit prices within 1% of market',
      originalSeverity: 'high',
    });
  });

  it('leaves severity alone when there is no trust dependency', () => {
    const out = fixture({});
    expect(out[0].finding.severity).toBe('high');
    expect(out[0].finding.trustAdjustment).toBeUndefined();
  });

  it('propagates the harm statement onto the finding', () => {
    const out = fixture({ harmStatement: 'Borrowers lose 12% of collateral to wrongful liquidation.' });
    expect(out[0].finding.harmStatement).toBe('Borrowers lose 12% of collateral to wrongful liquidation.');
  });
});
