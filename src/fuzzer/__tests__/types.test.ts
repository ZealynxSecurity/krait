import { describe, it, expect } from 'vitest';
import { InvariantCounter, TestFileCounter } from '../types.js';

describe('InvariantCounter', () => {
  it('produces sequential zero-padded IDs', () => {
    const counter = new InvariantCounter();
    expect(counter.next()).toBe('INV-001');
    expect(counter.next()).toBe('INV-002');
    expect(counter.next()).toBe('INV-003');
  });

  it('tracks count', () => {
    const counter = new InvariantCounter();
    expect(counter.count).toBe(0);
    counter.next();
    counter.next();
    expect(counter.count).toBe(2);
  });
});

describe('TestFileCounter', () => {
  it('produces sequential zero-padded IDs', () => {
    const counter = new TestFileCounter();
    expect(counter.next()).toBe('TEST-001');
    expect(counter.next()).toBe('TEST-002');
  });

  it('tracks count', () => {
    const counter = new TestFileCounter();
    expect(counter.count).toBe(0);
    counter.next();
    expect(counter.count).toBe(1);
  });
});
