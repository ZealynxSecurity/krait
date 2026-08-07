import { describe, it, expect } from 'vitest';
import { enforceGateContract, KILL_GATES, FP_PATTERNS, IMPACT_PREMISE } from '../critic.js';
import { CriticVerdict } from '../types.js';

function makeVerdict(overrides: Partial<CriticVerdict> = {}): CriticVerdict {
  return {
    candidateId: 'candidate-001',
    verdict: 'valid',
    counterarguments: [],
    rebuttals: [],
    mitigatingFactors: [],
    finalReasoning: 'Looks exploitable.',
    criticConfidence: 80,
    ...overrides,
  };
}

describe('enforceGateContract', () => {
  it('forces a gated candidate to invalid even when the model said valid', () => {
    const out = enforceGateContract(makeVerdict({ verdict: 'valid', killedByGate: 'A' }));
    expect(out.verdict).toBe('invalid');
    expect(out.killedByGate).toBe('A');
    expect(out.finalReasoning).toContain('gate A');
  });

  it('forces a gated candidate to invalid even when the model said uncertain', () => {
    const out = enforceGateContract(makeVerdict({ verdict: 'uncertain', killedByGate: 'E' }));
    expect(out.verdict).toBe('invalid');
  });

  it('kills a mechanism-only finding via gate D', () => {
    const out = enforceGateContract(makeVerdict({ verdict: 'valid', harmIsMechanismOnly: true }));
    expect(out.verdict).toBe('invalid');
    expect(out.killedByGate).toBe('D');
    expect(out.finalReasoning).toContain('no concrete harm');
  });

  it('does not overwrite an existing gate attribution when harm is missing', () => {
    const out = enforceGateContract(
      makeVerdict({ verdict: 'valid', harmIsMechanismOnly: true, killedByGate: 'B' }),
    );
    expect(out.killedByGate).toBe('B');
  });

  it('kills a candidate matching an FP pattern', () => {
    const out = enforceGateContract(makeVerdict({ verdict: 'valid', fpPattern: 'FP-3' }));
    expect(out.verdict).toBe('invalid');
    expect(out.finalReasoning).toContain('FP-3');
  });

  it('treats FP-6 as severity inflation, not a kill', () => {
    const out = enforceGateContract(makeVerdict({ verdict: 'valid', fpPattern: 'FP-6' }));
    expect(out.verdict).toBe('valid');
    expect(out.fpPattern).toBeUndefined();
  });

  it('leaves a clean valid verdict untouched', () => {
    const input = makeVerdict({ harmStatement: 'Depositors lose 30% of their share.' });
    const out = enforceGateContract(input);
    expect(out).toEqual(input);
  });

  it('leaves an ungated invalid verdict untouched', () => {
    const input = makeVerdict({ verdict: 'invalid', finalReasoning: 'require on line 12 blocks it.' });
    expect(enforceGateContract(input)).toEqual(input);
  });

  it('preserves the DoS exception flag through enforcement', () => {
    const out = enforceGateContract(makeVerdict({ verdict: 'valid', dosExceptionApplied: true }));
    expect(out.verdict).toBe('valid');
    expect(out.dosExceptionApplied).toBe(true);
  });
});

describe('critic prompt blocks', () => {
  it('declares all 8 kill gates', () => {
    for (const gate of ['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H']) {
      expect(KILL_GATES).toContain(`GATE ${gate} —`);
    }
  });

  it('declares the DoS exception', () => {
    expect(KILL_GATES).toContain('DoS EXCEPTION');
    expect(KILL_GATES).toContain('dosExceptionApplied');
  });

  it('declares all 10 FP patterns', () => {
    for (let i = 1; i <= 10; i++) {
      expect(FP_PATTERNS).toContain(`FP-${i} `);
    }
  });

  it('keeps the type-cast carve-out on FP-7', () => {
    expect(FP_PATTERNS).toContain('uint128(x)');
    expect(FP_PATTERNS).toContain('silently truncate');
  });

  it('requires a harm statement rather than a mechanism', () => {
    expect(IMPACT_PREMISE).toContain('WHO loses WHAT');
    expect(IMPACT_PREMISE).toContain('harmIsMechanismOnly');
  });
});
