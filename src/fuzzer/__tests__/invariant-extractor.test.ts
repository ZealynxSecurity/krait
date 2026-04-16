import { describe, it, expect } from 'vitest';
import { normalizeCategory, normalizePriority } from '../invariant-extractor.js';

describe('normalizeCategory', () => {
  it('returns valid categories as-is', () => {
    expect(normalizeCategory('accounting')).toBe('accounting');
    expect(normalizeCategory('access-control')).toBe('access-control');
    expect(normalizeCategory('state-transition')).toBe('state-transition');
    expect(normalizeCategory('economic')).toBe('economic');
    expect(normalizeCategory('token-conservation')).toBe('token-conservation');
    expect(normalizeCategory('bounds')).toBe('bounds');
    expect(normalizeCategory('relationship')).toBe('relationship');
    expect(normalizeCategory('custom')).toBe('custom');
  });

  it('normalizes case', () => {
    expect(normalizeCategory('ACCOUNTING')).toBe('accounting');
    expect(normalizeCategory('Access-Control')).toBe('access-control');
  });

  it('returns custom for unknown values', () => {
    expect(normalizeCategory('unknown')).toBe('custom');
    expect(normalizeCategory('')).toBe('custom');
    expect(normalizeCategory(42)).toBe('custom');
    expect(normalizeCategory(undefined)).toBe('custom');
  });
});

describe('normalizePriority', () => {
  it('returns valid priorities as-is', () => {
    expect(normalizePriority('high')).toBe('high');
    expect(normalizePriority('medium')).toBe('medium');
    expect(normalizePriority('low')).toBe('low');
  });

  it('normalizes case', () => {
    expect(normalizePriority('HIGH')).toBe('high');
    expect(normalizePriority('Medium')).toBe('medium');
  });

  it('returns medium for unknown values', () => {
    expect(normalizePriority('critical')).toBe('medium');
    expect(normalizePriority('')).toBe('medium');
    expect(normalizePriority(null)).toBe('medium');
  });
});
