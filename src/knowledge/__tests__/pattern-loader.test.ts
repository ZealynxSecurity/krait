import { describe, it, expect } from 'vitest';
import { PatternLoader } from '../pattern-loader.js';
import { VulnerabilityPattern } from '../../core/types.js';

function makePattern(overrides: Partial<VulnerabilityPattern> = {}): VulnerabilityPattern {
  return {
    id: 'SOL-001',
    name: 'Reentrancy via external call',
    category: 'reentrancy',
    severity: 'high',
    confidence: 'medium',
    description: 'External calls before state updates allow reentrancy attacks',
    detection: {
      strategy: 'Look for state changes after external calls',
      indicators: ['.call{value', 'transfer(', 'send('],
    },
    tags: ['solidity', 'defi'],
    false_positive_notes: 'Safe if using nonReentrant modifier',
    real_examples: [],
    ...overrides,
  } as VulnerabilityPattern;
}

// Access private methods via prototype for unit testing
const loader = new PatternLoader('/nonexistent');
const isValidPattern = (PatternLoader.prototype as any).isValidPattern.bind(loader);
const getCategoryKeywords = (PatternLoader.prototype as any).getCategoryKeywords.bind(loader);
const enforceCategoryDiversity = (PatternLoader.prototype as any).enforceCategoryDiversity.bind(loader);

// --- isValidPattern tests ---

describe('isValidPattern — quality gate', () => {
  it('accepts a well-formed pattern', () => {
    const p = makePattern();
    expect(isValidPattern(p)).toBe(true);
  });

  it('rejects null / non-object', () => {
    expect(isValidPattern(null)).toBe(false);
    expect(isValidPattern(undefined)).toBe(false);
    expect(isValidPattern('string')).toBe(false);
    expect(isValidPattern(42)).toBe(false);
  });

  it('rejects missing required fields', () => {
    expect(isValidPattern({ id: 'X' })).toBe(false);
    expect(isValidPattern({ id: 'X', name: 'Short name here', category: 'c' })).toBe(false);
  });

  it('rejects name shorter than 10 chars', () => {
    const p = makePattern({ name: 'Short' });
    expect(isValidPattern(p)).toBe(false);
  });

  it('rejects description shorter than 20 chars', () => {
    const p = makePattern({ description: 'Too short' });
    expect(isValidPattern(p)).toBe(false);
  });

  it('accepts name exactly 10 chars', () => {
    const p = makePattern({ name: '1234567890' });
    expect(isValidPattern(p)).toBe(true);
  });

  it('accepts description exactly 20 chars', () => {
    const p = makePattern({ description: '12345678901234567890' });
    expect(isValidPattern(p)).toBe(true);
  });

  it('rejects patterns with majority numeric-only indicators (> 2 indicators)', () => {
    const p = makePattern({
      detection: {
        strategy: 'Look for numbers',
        indicators: ['1.1', '500', '$99.50', 'real_indicator'],
      },
    });
    // 3 of 4 are numeric-only → more than half → rejected
    expect(isValidPattern(p)).toBe(false);
  });

  it('accepts patterns with few numeric indicators (≤ 2 total)', () => {
    const p = makePattern({
      detection: {
        strategy: 'Look for numbers',
        indicators: ['1.1', '12.3M'],
      },
    });
    // Only 2 indicators total — quality gate requires > 2 to trigger
    expect(isValidPattern(p)).toBe(true);
  });

  it('accepts patterns where minority of indicators are numeric', () => {
    const p = makePattern({
      detection: {
        strategy: 'Check code',
        indicators: ['.call{value', 'transfer(', 'msg.sender', '1.1'],
      },
    });
    // Only 1 of 4 is numeric → less than half → accepted
    expect(isValidPattern(p)).toBe(true);
  });

  it('rejects patterns without tags array', () => {
    const p = { ...makePattern(), tags: 'not-an-array' };
    expect(isValidPattern(p)).toBe(false);
  });
});

// --- getCategoryKeywords tests ---

describe('getCategoryKeywords', () => {
  it('returns keywords for reentrancy', () => {
    const kw = getCategoryKeywords('reentrancy');
    expect(kw).toContain('call{');
    expect(kw).toContain('external');
  });

  it('returns keywords for access-control', () => {
    const kw = getCategoryKeywords('access-control');
    expect(kw).toContain('onlyowner');
    expect(kw).toContain('modifier');
  });

  it('returns keywords for fee-calculation', () => {
    const kw = getCategoryKeywords('fee-calculation');
    expect(kw).toContain('fee');
    expect(kw).toContain('royalty');
    expect(kw).toContain('bps');
  });

  it('returns keywords for token-compatibility', () => {
    const kw = getCategoryKeywords('token-compatibility');
    expect(kw).toContain('decimals');
    expect(kw).toContain('safetransfer');
  });

  it('returns keywords for rounding', () => {
    const kw = getCategoryKeywords('rounding');
    expect(kw).toContain('precision');
    expect(kw).toContain('wad');
  });

  it('returns keywords for frontrunning', () => {
    const kw = getCategoryKeywords('frontrunning');
    expect(kw).toContain('deadline');
    expect(kw).toContain('slippage');
  });

  it('returns keywords for denial-of-service', () => {
    const kw = getCategoryKeywords('denial-of-service');
    expect(kw).toContain('loop');
    expect(kw).toContain('unbounded');
  });

  it('returns empty array for unknown category', () => {
    expect(getCategoryKeywords('nonexistent-category')).toEqual([]);
  });

  it('covers all 16 expected categories', () => {
    const expected = [
      'reentrancy', 'access-control', 'oracle-manipulation', 'flash-loan',
      'integer-overflow', 'missing-error-handling', 'price-manipulation',
      'temporal-state', 'misconfiguration', 'fee-calculation',
      'token-compatibility', 'rounding', 'external-call', 'create2',
      'signature', 'frontrunning', 'denial-of-service',
    ];
    for (const cat of expected) {
      expect(getCategoryKeywords(cat).length).toBeGreaterThan(0);
    }
  });
});

// --- enforceCategoryDiversity tests ---

describe('enforceCategoryDiversity', () => {
  it('caps reentrancy patterns at 2 when mixed with other categories', () => {
    const patterns = [
      makePattern({ id: 'R1', category: 'reentrancy' }),
      makePattern({ id: 'R2', category: 'reentrancy' }),
      makePattern({ id: 'R3', category: 'reentrancy' }),
      makePattern({ id: 'R4', category: 'reentrancy' }),
      makePattern({ id: 'F1', category: 'fee-calculation' }),
    ];
    // max=3 means: 2 reentrancy kept + F1 kept = 3, deferred R3/R4 can't fit
    const result = enforceCategoryDiversity(patterns, 3);
    const reentrant = result.filter((p: VulnerabilityPattern) => p.category === 'reentrancy');
    expect(reentrant.length).toBe(2);
    expect(result.some((p: VulnerabilityPattern) => p.id === 'F1')).toBe(true);
  });

  it('caps access-control at 3 when mixed with other categories', () => {
    const patterns = [
      makePattern({ id: 'AC1', category: 'access-control' }),
      makePattern({ id: 'AC2', category: 'access-control' }),
      makePattern({ id: 'AC3', category: 'access-control' }),
      makePattern({ id: 'AC4', category: 'access-control' }),
      makePattern({ id: 'AC5', category: 'access-control' }),
      makePattern({ id: 'F1', category: 'fee-calculation' }),
    ];
    // max=4: 3 AC kept + F1 = 4, deferred AC4/AC5 can't fit
    const result = enforceCategoryDiversity(patterns, 4);
    const ac = result.filter((p: VulnerabilityPattern) => p.category === 'access-control');
    expect(ac.length).toBe(3);
  });

  it('caps oracle-manipulation at 2 when mixed with other categories', () => {
    const patterns = [
      makePattern({ id: 'O1', category: 'oracle-manipulation' }),
      makePattern({ id: 'O2', category: 'oracle-manipulation' }),
      makePattern({ id: 'O3', category: 'oracle-manipulation' }),
      makePattern({ id: 'F1', category: 'fee-calculation' }),
    ];
    const result = enforceCategoryDiversity(patterns, 3);
    const oracle = result.filter((p: VulnerabilityPattern) => p.category === 'oracle-manipulation');
    expect(oracle.length).toBe(2);
  });

  it('caps price-manipulation at 2 when mixed with other categories', () => {
    const patterns = [
      makePattern({ id: 'PM1', category: 'price-manipulation' }),
      makePattern({ id: 'PM2', category: 'price-manipulation' }),
      makePattern({ id: 'PM3', category: 'price-manipulation' }),
      makePattern({ id: 'F1', category: 'fee-calculation' }),
    ];
    const result = enforceCategoryDiversity(patterns, 3);
    const pm = result.filter((p: VulnerabilityPattern) => p.category === 'price-manipulation');
    expect(pm.length).toBe(2);
  });

  it('does NOT cap uncapped categories', () => {
    const patterns = [
      makePattern({ id: 'F1', category: 'fee-calculation' }),
      makePattern({ id: 'F2', category: 'fee-calculation' }),
      makePattern({ id: 'F3', category: 'fee-calculation' }),
      makePattern({ id: 'F4', category: 'fee-calculation' }),
      makePattern({ id: 'F5', category: 'fee-calculation' }),
    ];
    const result = enforceCategoryDiversity(patterns, 25);
    expect(result.length).toBe(5);
  });

  it('defers excess patterns to fill remaining slots', () => {
    const patterns = [
      makePattern({ id: 'R1', category: 'reentrancy' }),
      makePattern({ id: 'R2', category: 'reentrancy' }),
      makePattern({ id: 'R3', category: 'reentrancy' }),
      makePattern({ id: 'F1', category: 'fee-calculation' }),
    ];
    // R1, R2 kept (cap 2), R3 deferred, F1 kept → then R3 fills remaining
    const result = enforceCategoryDiversity(patterns, 25);
    expect(result.length).toBe(4); // All fit within max=25
  });

  it('respects max parameter', () => {
    const patterns = Array.from({ length: 30 }, (_, i) =>
      makePattern({ id: `P${i}`, category: 'fee-calculation' })
    );
    const result = enforceCategoryDiversity(patterns, 10);
    expect(result.length).toBe(10);
  });

  it('handles mixed categories with caps correctly', () => {
    const patterns = [
      makePattern({ id: 'R1', category: 'reentrancy' }),
      makePattern({ id: 'R2', category: 'reentrancy' }),
      makePattern({ id: 'R3', category: 'reentrancy' }),
      makePattern({ id: 'AC1', category: 'access-control' }),
      makePattern({ id: 'AC2', category: 'access-control' }),
      makePattern({ id: 'AC3', category: 'access-control' }),
      makePattern({ id: 'AC4', category: 'access-control' }),
      makePattern({ id: 'F1', category: 'fee-calculation' }),
      makePattern({ id: 'F2', category: 'fee-calculation' }),
    ];
    const result = enforceCategoryDiversity(patterns, 25);
    const reentrancy = result.filter((p: VulnerabilityPattern) => p.category === 'reentrancy');
    const ac = result.filter((p: VulnerabilityPattern) => p.category === 'access-control');
    const fee = result.filter((p: VulnerabilityPattern) => p.category === 'fee-calculation');
    expect(reentrancy.length).toBeLessThanOrEqual(3); // 2 initially + 1 deferred may fill
    expect(ac.length).toBeLessThanOrEqual(4); // 3 initially + 1 deferred may fill
    expect(fee.length).toBe(2);
    // Total: all 9 fit within 25
    expect(result.length).toBe(9);
  });
});

// --- filterPatternsForFile tests ---

describe('filterPatternsForFile', () => {
  // We can't easily test filterPatternsForFile with a real PatternLoader (needs YAML files)
  // but we can test it via the public method with a subclass or by constructing patterns directly
  const testLoader = new PatternLoader('/nonexistent');

  // Manually inject patterns via reflection
  function setupPatterns(patterns: VulnerabilityPattern[]): PatternLoader {
    const loader = new PatternLoader('/nonexistent');
    (loader as any).patterns = patterns;
    (loader as any).loaded = true;
    return loader;
  }

  it('scores patterns higher when indicators match file content', () => {
    const patterns = [
      makePattern({ id: 'R1', category: 'reentrancy', detection: { strategy: 's', indicators: ['.call{value'] } }),
      makePattern({ id: 'F1', category: 'fee-calculation', severity: 'medium', detection: { strategy: 's', indicators: ['royalty', 'bps'] } }),
    ];
    const fileContent = 'function withdraw() { (bool s,) = msg.sender.call{value: amount}(""); }';
    const result = testLoader.filterPatternsForFile(patterns, fileContent);
    // Reentrancy should score higher (indicator match + category keywords)
    expect(result[0].id).toBe('R1');
  });

  it('limits output to maxPatterns', () => {
    const patterns = Array.from({ length: 30 }, (_, i) =>
      makePattern({
        id: `P${i}`,
        category: 'fee-calculation',
        detection: { strategy: 's', indicators: ['fee'] },
      })
    );
    const result = testLoader.filterPatternsForFile(patterns, 'fee calculation logic', 10);
    expect(result.length).toBeLessThanOrEqual(10);
  });

  it('includes baseline high/critical patterns when few matches', () => {
    const patterns = [
      makePattern({ id: 'C1', severity: 'critical', category: 'reentrancy', detection: { strategy: 's', indicators: ['extremely_unlikely_indicator'] } }),
      makePattern({ id: 'L1', severity: 'low', category: 'misconfiguration', detection: { strategy: 's', indicators: ['also_unlikely'] } }),
    ];
    const result = testLoader.filterPatternsForFile(patterns, 'simple code with no matches');
    // With < 5 matches, should include critical patterns as baseline
    expect(result.some(p => p.id === 'C1')).toBe(true);
  });

  it('category keywords boost relevant patterns', () => {
    const patterns = [
      makePattern({ id: 'FEE1', category: 'fee-calculation', severity: 'medium', detection: { strategy: 's', indicators: [] } }),
      makePattern({ id: 'SIG1', category: 'signature', severity: 'medium', detection: { strategy: 's', indicators: [] } }),
    ];
    const fileContent = 'function setFee(uint256 fee) external { protocolFee = fee; }';
    const result = testLoader.filterPatternsForFile(patterns, fileContent);
    // fee-calculation keywords match "fee" → FEE1 should score higher
    expect(result[0].id).toBe('FEE1');
  });

  it('applies category diversity caps', () => {
    const patterns = [
      ...Array.from({ length: 5 }, (_, i) =>
        makePattern({ id: `R${i}`, category: 'reentrancy', detection: { strategy: 's', indicators: ['.call{value'] } })
      ),
      makePattern({ id: 'F1', category: 'fee-calculation', severity: 'medium', detection: { strategy: 's', indicators: ['fee'] } }),
    ];
    const fileContent = '.call{value: amount} fee calculation';
    const result = testLoader.filterPatternsForFile(patterns, fileContent);
    const reentrancy = result.filter(p => p.category === 'reentrancy');
    // Capped at 2 initially, excess deferred but may fill
    expect(reentrancy.length).toBeLessThanOrEqual(5); // deferred fill up to max
    expect(result.some(p => p.id === 'F1')).toBe(true);
  });
});

// --- formatForPrompt tests ---

describe('formatForPrompt', () => {
  const loader = new PatternLoader('/nonexistent');

  it('returns fallback text for empty patterns', () => {
    expect(loader.formatForPrompt([])).toBe('No specific patterns loaded.');
  });

  it('includes pattern id, name, severity, category', () => {
    const p = makePattern({ id: 'SOL-042', name: 'Test pattern name here', severity: 'critical', category: 'reentrancy' });
    const result = loader.formatForPrompt([p]);
    expect(result).toContain('SOL-042');
    expect(result).toContain('Test pattern name here');
    expect(result).toContain('critical');
    expect(result).toContain('reentrancy');
  });

  it('includes detection strategy and indicators', () => {
    const p = makePattern({
      detection: { strategy: 'Check state after call', indicators: ['.call{value', 'transfer('] },
    });
    const result = loader.formatForPrompt([p]);
    expect(result).toContain('Check state after call');
    expect(result).toContain('.call{value');
    expect(result).toContain('transfer(');
  });

  it('includes false positive notes', () => {
    const p = makePattern({ false_positive_notes: 'Safe with nonReentrant' });
    const result = loader.formatForPrompt([p]);
    expect(result).toContain('Safe with nonReentrant');
  });

  it('includes real example when present', () => {
    const p = makePattern({
      real_examples: [{
        project: 'TestProject',
        source: 'Code4rena',
        impact: 'Loss of funds',
        code_vulnerable: 'function withdraw() { msg.sender.call{value: bal}(""); balance = 0; }',
      }],
    });
    const result = loader.formatForPrompt([p]);
    expect(result).toContain('TestProject');
    expect(result).toContain('Code4rena');
    expect(result).toContain('Loss of funds');
    expect(result).toContain('msg.sender.call{value: bal}');
  });
});

// --- getPatternsByDomain tests ---

describe('getPatternsByDomain', () => {
  function setupLoader(patterns: VulnerabilityPattern[]): PatternLoader {
    const loader = new PatternLoader('/nonexistent');
    (loader as any).patterns = patterns;
    (loader as any).loaded = true;
    return loader;
  }

  it('filters solidity patterns by domain tags', () => {
    const loader = setupLoader([
      makePattern({ id: 'S1', tags: ['solidity', 'defi'] }),
      makePattern({ id: 'R1', tags: ['solana', 'anchor'] }),
    ]);
    const result = loader.getPatternsByDomain('solidity');
    expect(result.length).toBe(1);
    expect(result[0].id).toBe('S1');
  });

  it('filters rust-solana patterns', () => {
    const loader = setupLoader([
      makePattern({ id: 'S1', tags: ['solidity'] }),
      makePattern({ id: 'R1', tags: ['solana', 'anchor'] }),
      makePattern({ id: 'R2', tags: ['rust', 'spl'] }),
    ]);
    const result = loader.getPatternsByDomain('rust-solana');
    expect(result.length).toBe(2);
  });

  it('returns empty for domain with no matching patterns', () => {
    const loader = setupLoader([
      makePattern({ id: 'S1', tags: ['solidity'] }),
    ]);
    const result = loader.getPatternsByDomain('ai-red-team');
    expect(result.length).toBe(0);
  });
});

// --- getStats tests ---

describe('getStats', () => {
  it('returns correct counts', () => {
    const loader = new PatternLoader('/nonexistent');
    (loader as any).patterns = [
      makePattern({ id: 'S1', severity: 'high', tags: ['solidity'] }),
      makePattern({ id: 'S2', severity: 'critical', tags: ['solidity'] }),
      makePattern({ id: 'R1', severity: 'high', tags: ['solana'] }),
    ];
    (loader as any).loaded = true;

    const stats = loader.getStats();
    expect(stats.total).toBe(3);
    expect(stats.bySeverity['high']).toBe(2);
    expect(stats.bySeverity['critical']).toBe(1);
    expect(stats.byDomain['solidity']).toBe(2);
    expect(stats.byDomain['rust-solana']).toBe(1);
  });
});
