import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, vi } from 'vitest';
import { Command } from 'commander';
import type { ShadowAuditResult } from '../runner.js';
import { runBatchShadowAudit } from '../runner.js';
import { generateFeedback } from '../feedback.js';
import { updateDashboard } from '../dashboard.js';

vi.mock('../runner.js', () => ({ runBatchShadowAudit: vi.fn() }));
vi.mock('../feedback.js', () => ({
  generateFeedback: vi.fn(() => []),
  writeFeedbackReport: vi.fn(),
}));
vi.mock('../dashboard.js', () => ({
  updateDashboard: vi.fn(() => ({ entries: [] })),
  loadDashboard: vi.fn(),
  formatDashboard: vi.fn(() => 'mock dashboard'),
}));

function result(error?: string): ShadowAuditResult {
  return {
    contestId: 'basin-2023-07',
    contestName: 'Basin',
    timestamp: '2026-10-19T08:00:00Z',
    duration: 0,
    comparison: {
      contestName: 'Basin', officialFindings: [], kraitFindings: [], matches: [],
      truePositives: 0, falseNegatives: 1, falsePositives: 0,
      precision: 0, recall: 0, f1: 0,
      byRisk: {
        high: { tp: 0, fn: 1, total: 1, recall: 0 },
        medium: { tp: 0, fn: 0, total: 0, recall: 0 },
      },
    },
    reportPath: '',
    ...(error ? { error } : {}),
  };
}

describe('shadow-audit CLI completion status', () => {
  let program: Command;
  const originalExitCode = process.exitCode;

  beforeAll(async () => {
    // Capture the real command without executing process.argv during import.
    const commands: Command[] = [];
    const parse = vi.spyOn(Command.prototype, 'parse').mockImplementation(function (this: Command) {
      commands.push(this);
      return this;
    });
    try {
      await import('../../cli.js');
    } finally {
      parse.mockRestore();
    }
    program = commands[0];
  });

  beforeEach(() => {
    vi.clearAllMocks();
    process.exitCode = undefined;
    vi.spyOn(console, 'log').mockImplementation(() => undefined);
  });

  afterEach(() => {
    vi.restoreAllMocks();
    process.exitCode = originalExitCode;
  });

  afterAll(() => { process.exitCode = originalExitCode; });

  async function run(results: ShadowAuditResult[], dryRun = false) {
    vi.mocked(runBatchShadowAudit).mockResolvedValue(results);
    await program.parseAsync([
      'shadow-audit', '--contest', 'basin-2023-07',
      ...(dryRun ? ['--dry-run'] : []),
    ], { from: 'user' });
  }

  it('returns failure when every contest fails, retaining the error summary', async () => {
    await run([result('Anthropic API key required')]);
    expect(process.exitCode).toBe(1);
    expect(console.log).toHaveBeenCalledWith(expect.stringContaining('Anthropic API key required'));
    expect(updateDashboard).not.toHaveBeenCalled();
    expect(generateFeedback).not.toHaveBeenCalled();
  });

  it('returns failure for partial completion while retaining successful results', async () => {
    const completed = result();
    await run([completed, result('Clone failed')]);
    expect(process.exitCode).toBe(1);
    expect(updateDashboard).toHaveBeenCalledWith(expect.any(String), [completed], expect.any(String));
    expect(generateFeedback).toHaveBeenCalledTimes(1);
  });

  it('leaves a completed zero-finding run successful regardless of recall', async () => {
    await run([result()]);
    expect(process.exitCode ?? 0).toBe(0);
    expect(updateDashboard).toHaveBeenCalledTimes(1);
  });

  it('keeps a successful dry run successful without updating the dashboard', async () => {
    await run([result()], true);
    expect(process.exitCode ?? 0).toBe(0);
    expect(updateDashboard).not.toHaveBeenCalled();
  });

  it('returns failure if a dry run cannot complete its prerequisites', async () => {
    await run([result('No report.md found')], true);
    expect(process.exitCode).toBe(1);
    expect(updateDashboard).not.toHaveBeenCalled();
  });
});
