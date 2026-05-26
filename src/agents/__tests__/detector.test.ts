import { describe, it, expect } from 'vitest';
import { CandidateCounter, extractMethodologyFields } from '../detector.js';

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

describe('extractMethodologyFields', () => {
  it('returns empty object when no methodology fields present', () => {
    expect(extractMethodologyFields({})).toEqual({});
  });

  it('extracts stepExecution string and trims whitespace', () => {
    expect(extractMethodologyFields({ stepExecution: '  Lens: A=✓ B=✓  ' })).toEqual({
      stepExecution: 'Lens: A=✓ B=✓',
    });
  });

  it('ignores empty stepExecution', () => {
    expect(extractMethodologyFields({ stepExecution: '   ' })).toEqual({});
  });

  it('extracts valid rulesApplied entries and skips unknown rule codes', () => {
    const result = extractMethodologyFields({
      rulesApplied: [
        { code: 'R10', applied: true, reason: 'worst-state checked' },
        { code: 'R99', applied: true, reason: 'bogus' },     // unknown — dropped
        { code: 'R11', applied: false, reason: 'no external tokens' },
        'not an object',                                       // dropped
        null,                                                  // dropped
      ],
    });
    expect(result.rulesApplied).toEqual([
      { code: 'R10', applied: true, reason: 'worst-state checked' },
      { code: 'R11', applied: false, reason: 'no external tokens' },
    ]);
  });

  it('omits rulesApplied entirely when no valid entries remain', () => {
    expect(extractMethodologyFields({ rulesApplied: [{ code: 'BOGUS', applied: true }] })).toEqual({});
  });

  it('extracts depthEvidence tags and filters empty strings', () => {
    expect(
      extractMethodologyFields({
        depthEvidence: ['[BOUNDARY:amount=0]', '', '   ', '[TRACE:withdraw(MAX)→revert]'],
      }),
    ).toEqual({
      depthEvidence: ['[BOUNDARY:amount=0]', '[TRACE:withdraw(MAX)→revert]'],
    });
  });

  it('validates preconditionType against the ConditionType enum', () => {
    expect(extractMethodologyFields({ preconditionType: 'STATE' }).preconditionType).toBe('STATE');
    expect(extractMethodologyFields({ preconditionType: 'BOGUS' }).preconditionType).toBeUndefined();
  });

  it('filters unknown postconditionTypes', () => {
    expect(
      extractMethodologyFields({ postconditionTypes: ['STATE', 'WAT', 'TIMING'] }).postconditionTypes,
    ).toEqual(['STATE', 'TIMING']);
  });

  it('extracts the full A1/A2/A4 bundle when all fields present', () => {
    const result = extractMethodologyFields({
      stepExecution: 'Lens: A=✓',
      rulesApplied: [{ code: 'R10', applied: true }],
      depthEvidence: ['[BOUNDARY:reserve=0]'],
      missingPrecondition: 'amount must exceed MIN_TRADE',
      preconditionType: 'STATE',
      postconditionsCreated: 'pool reserve below threshold',
      postconditionTypes: ['STATE', 'BALANCE'],
      whoBenefits: 'attacker',
    });
    expect(result).toEqual({
      stepExecution: 'Lens: A=✓',
      rulesApplied: [{ code: 'R10', applied: true, reason: undefined }],
      depthEvidence: ['[BOUNDARY:reserve=0]'],
      missingPrecondition: 'amount must exceed MIN_TRADE',
      preconditionType: 'STATE',
      postconditionsCreated: 'pool reserve below threshold',
      postconditionTypes: ['STATE', 'BALANCE'],
      whoBenefits: 'attacker',
    });
  });
});
