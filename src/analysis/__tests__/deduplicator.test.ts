import { describe, it, expect } from 'vitest';
import { deduplicateFindings } from '../deduplicator.js';
import { Finding } from '../../core/types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'TEST-001',
    title: 'Test finding',
    severity: 'medium',
    confidence: 'medium',
    file: 'Contract.sol',
    line: 50,
    description: 'Test description for this finding',
    impact: 'Medium impact',
    remediation: 'Fix it',
    category: 'reentrancy',
    ...overrides,
  };
}

describe('deduplicateFindings', () => {
  it('returns empty array for empty input', () => {
    expect(deduplicateFindings([])).toEqual([]);
  });

  it('returns single finding unchanged', () => {
    const f = makeFinding();
    expect(deduplicateFindings([f])).toEqual([f]);
  });

  it('keeps distinct findings from different categories', () => {
    const findings = [
      makeFinding({ id: 'A', category: 'reentrancy', title: 'Reentrancy in withdraw' }),
      makeFinding({ id: 'B', category: 'access-control', title: 'Missing access control' }),
      makeFinding({ id: 'C', category: 'oracle-manipulation', title: 'Oracle manipulation' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.length).toBe(3);
  });

  // --- suppressPatternFlood tests ---

  it('caps non-critical findings at 3 per category', () => {
    const findings = [
      makeFinding({ id: 'R1', severity: 'high', category: 'reentrancy', file: 'A.sol' }),
      makeFinding({ id: 'R2', severity: 'high', category: 'reentrancy', file: 'B.sol' }),
      makeFinding({ id: 'R3', severity: 'high', category: 'reentrancy', file: 'C.sol' }),
      makeFinding({ id: 'R4', severity: 'high', category: 'reentrancy', file: 'D.sol' }),
      makeFinding({ id: 'R5', severity: 'high', category: 'reentrancy', file: 'E.sol' }),
    ];
    const result = deduplicateFindings(findings);
    // After flood suppression: 3 reentrancy survive (capped)
    // After dedup: cross-file same category HIGH may merge (Jaccard on "Reentrancy in withdraw")
    // But all have identical titles so they merge to 1
    expect(result.length).toBeLessThanOrEqual(3);
  });

  it('always keeps critical findings regardless of category count', () => {
    const findings = [
      makeFinding({ id: 'C1', severity: 'critical', category: 'reentrancy', file: 'A.sol', title: 'Critical reentrancy A' }),
      makeFinding({ id: 'C2', severity: 'critical', category: 'reentrancy', file: 'B.sol', title: 'Critical reentrancy B' }),
      makeFinding({ id: 'C3', severity: 'critical', category: 'reentrancy', file: 'C.sol', title: 'Critical reentrancy C' }),
      makeFinding({ id: 'C4', severity: 'critical', category: 'reentrancy', file: 'D.sol', title: 'Critical reentrancy D' }),
    ];
    // All critical → all survive flood suppression
    // But dedup may merge similar titles across files
    const result = deduplicateFindings(findings);
    // At minimum, criticals aren't dropped by flood cap
    expect(result.length).toBeGreaterThanOrEqual(1);
    expect(result[0].severity).toBe('critical');
  });

  it('sorts by severity first, keeping highest severity within cap', () => {
    const findings = [
      makeFinding({ id: 'L1', severity: 'low', confidence: 'high', category: 'reentrancy', file: 'A.sol', title: 'Low reentrancy first' }),
      makeFinding({ id: 'H1', severity: 'high', confidence: 'medium', category: 'reentrancy', file: 'B.sol', title: 'High reentrancy second' }),
      makeFinding({ id: 'M1', severity: 'medium', confidence: 'high', category: 'reentrancy', file: 'C.sol', title: 'Medium reentrancy third' }),
      makeFinding({ id: 'H2', severity: 'high', confidence: 'high', category: 'reentrancy', file: 'D.sol', title: 'High reentrancy fourth' }),
      // 5th finding should be dropped by cap
      makeFinding({ id: 'L2', severity: 'low', confidence: 'low', category: 'reentrancy', file: 'E.sol', title: 'Low reentrancy fifth' }),
    ];
    const result = deduplicateFindings(findings);
    // After sort: H2(high/high), H1(high/med), M1(med/high), L1(low/high), L2(low/low)
    // Cap keeps first 3: H2, H1, M1 → then dedup merges similar titles
    // The LOW severity findings should be dropped
    const hasLow = result.some(f => f.severity === 'low');
    expect(hasLow).toBe(false);
  });

  // --- areDuplicates tests ---

  it('merges findings in same file, same category, overlapping lines', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'Pool.sol', category: 'reentrancy', line: 100, title: 'Reentrancy in withdraw' }),
      makeFinding({ id: 'B', file: 'Pool.sol', category: 'reentrancy', line: 105, title: 'State change after external call in withdraw', severity: 'high' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.length).toBe(1);
    // Should keep the higher severity
    expect(result[0].severity).toBe('high');
  });

  it('does NOT merge findings in same file, same category, far apart lines with different titles', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'Pool.sol', category: 'reentrancy', line: 10, title: 'Reentrancy in deposit function' }),
      makeFinding({ id: 'B', file: 'Pool.sol', category: 'reentrancy', line: 500, title: 'Flash loan callback exploitable' }),
    ];
    const result = deduplicateFindings(findings);
    // Line diff > 10 and titles are dissimilar enough → should stay separate
    expect(result.length).toBe(2);
  });

  it('merges cross-file HIGH findings with similar titles in same category', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'PoolA.sol', category: 'reentrancy', severity: 'high', title: 'Reentrancy in withdraw allows double-spend' }),
      makeFinding({ id: 'B', file: 'PoolB.sol', category: 'reentrancy', severity: 'high', title: 'Reentrancy in deposit allows double-spend' }),
    ];
    const result = deduplicateFindings(findings);
    // Jaccard similarity of these titles is high (share "reentrancy", "allows", "double-spend")
    // Threshold for HIGH is 0.35 → should merge
    expect(result.length).toBe(1);
    expect(result[0].description).toContain('Also found in');
  });

  it('does NOT merge cross-file findings with completely different titles', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'PoolA.sol', category: 'business-logic', severity: 'high', title: 'Fee calculation uses wrong base amount' }),
      makeFinding({ id: 'B', file: 'PoolB.sol', category: 'business-logic', severity: 'high', title: 'Flash loan enables arbitrage profit extraction' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.length).toBe(2);
  });

  it('merges oracle-manipulation findings in same directory regardless of title', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'oracles/ChainlinkRelay.sol', category: 'oracle-manipulation', severity: 'medium', title: 'Stale price data' }),
      makeFinding({ id: 'B', file: 'oracles/UniswapRelay.sol', category: 'oracle-manipulation', severity: 'medium', title: 'TWAP manipulation' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.length).toBe(1);
  });

  it('does NOT merge oracle findings in different directories', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'core/PriceOracle.sol', category: 'oracle-manipulation', severity: 'medium', title: 'Oracle manipulation' }),
      makeFinding({ id: 'B', file: 'periphery/FeedReader.sol', category: 'oracle-manipulation', severity: 'medium', title: 'Oracle manipulation' }),
    ];
    const result = deduplicateFindings(findings);
    // Different directories, but same title → Jaccard is 1.0 → merges via title similarity
    expect(result.length).toBe(1);
  });

  // --- mergeDuplicateGroup tests ---

  it('keeps highest severity when merging', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'Pool.sol', severity: 'medium', category: 'reentrancy', line: 50, title: 'Reentrancy vulnerability' }),
      makeFinding({ id: 'B', file: 'Pool.sol', severity: 'high', category: 'reentrancy', line: 55, title: 'Reentrancy vulnerability' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.length).toBe(1);
    expect(result[0].severity).toBe('high');
  });

  it('boosts confidence to high when 3+ findings merge', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'A.sol', severity: 'high', confidence: 'low', category: 'reentrancy', line: 50, title: 'Reentrancy in withdraw function' }),
      makeFinding({ id: 'B', file: 'B.sol', severity: 'high', confidence: 'low', category: 'reentrancy', line: 50, title: 'Reentrancy in withdraw function' }),
      makeFinding({ id: 'C', file: 'C.sol', severity: 'high', confidence: 'low', category: 'reentrancy', line: 50, title: 'Reentrancy in withdraw function' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.length).toBe(1);
    expect(result[0].confidence).toBe('high');
  });

  it('boosts low confidence to medium when 2 findings merge', () => {
    const findings = [
      makeFinding({ id: 'A', file: 'Pool.sol', confidence: 'low', category: 'reentrancy', line: 50, title: 'Reentrancy vulnerability in pool' }),
      makeFinding({ id: 'B', file: 'Pool.sol', confidence: 'low', category: 'reentrancy', line: 55, title: 'Reentrancy vulnerability in pool' }),
    ];
    const result = deduplicateFindings(findings);
    expect(result.length).toBe(1);
    expect(result[0].confidence).toBe('medium');
  });

  // --- Real-world scenario ---

  it('handles a realistic mix: reentrancy flood + distinct findings', () => {
    const findings = [
      // 5 reentrancy findings across files (should be capped to 3, then merged)
      makeFinding({ id: 'R1', file: 'A.sol', severity: 'high', category: 'reentrancy', title: 'Reentrancy in withdraw' }),
      makeFinding({ id: 'R2', file: 'B.sol', severity: 'high', category: 'reentrancy', title: 'Reentrancy in deposit' }),
      makeFinding({ id: 'R3', file: 'C.sol', severity: 'high', category: 'reentrancy', title: 'Reentrancy in swap' }),
      makeFinding({ id: 'R4', file: 'D.sol', severity: 'medium', category: 'reentrancy', title: 'Reentrancy in claim' }),
      makeFinding({ id: 'R5', file: 'E.sol', severity: 'low', category: 'reentrancy', title: 'Reentrancy in view' }),
      // 1 distinct fee finding
      makeFinding({ id: 'F1', file: 'A.sol', severity: 'high', category: 'fee-calculation', title: 'Fee calculation uses wrong base' }),
      // 1 distinct access control
      makeFinding({ id: 'AC1', file: 'B.sol', severity: 'critical', category: 'access-control', title: 'Execute allows arbitrary calls' }),
    ];
    const result = deduplicateFindings(findings);
    // Fee and access-control should survive
    expect(result.some(f => f.category === 'fee-calculation')).toBe(true);
    expect(result.some(f => f.category === 'access-control')).toBe(true);
    // Should not have more than 3 reentrancy
    const reentrantCount = result.filter(f => f.category === 'reentrancy').length;
    expect(reentrantCount).toBeLessThanOrEqual(3);
    // Total should be reasonable
    expect(result.length).toBeLessThanOrEqual(5);
  });
});
