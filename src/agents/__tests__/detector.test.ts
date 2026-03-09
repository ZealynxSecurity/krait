import { describe, it, expect } from 'vitest';
import { CandidateCounter } from '../detector.js';

describe('CandidateCounter', () => {
  it('should generate sequential IDs', () => {
    const counter = new CandidateCounter();
    expect(counter.next()).toBe('candidate-001');
    expect(counter.next()).toBe('candidate-002');
    expect(counter.next()).toBe('candidate-003');
  });

  it('should track count', () => {
    const counter = new CandidateCounter();
    expect(counter.count).toBe(0);
    counter.next();
    counter.next();
    expect(counter.count).toBe(2);
  });

  it('should pad IDs correctly', () => {
    const counter = new CandidateCounter();
    for (let i = 0; i < 99; i++) counter.next();
    expect(counter.next()).toBe('candidate-100');
  });

  it('should be independent per instance', () => {
    const c1 = new CandidateCounter();
    const c2 = new CandidateCounter();
    c1.next();
    c1.next();
    expect(c2.next()).toBe('candidate-001'); // Independent
    expect(c1.count).toBe(2);
    expect(c2.count).toBe(1);
  });
});
