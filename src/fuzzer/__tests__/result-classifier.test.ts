import { describe, it, expect } from 'vitest';
import { classifyFailure } from '../result-classifier.js';
import type { TestRunResult, FuzzTestFile, Invariant } from '../types.js';

// Heuristic classification paths don't call the LLM, so we pass a null client.
const nullClient = null as any;
const dummyTestFile: FuzzTestFile = {
  id: 'TEST-001',
  invariantIds: ['INV-001'],
  fileName: 'Test.t.sol',
  filePath: '/tmp/Test.t.sol',
  solidityCode: '',
  testFunctions: ['invariant_test'],
  setupDescription: '',
};
const dummyInvariants: Invariant[] = [];
const emptySource = new Map<string, string>();

function makeRunResult(overrides: Partial<TestRunResult>): TestRunResult {
  return {
    testFileId: 'TEST-001',
    compileSuccess: true,
    results: [],
    rawStdout: '',
    rawStderr: '',
    duration: 100,
    ...overrides,
  };
}

describe('classifyFailure — heuristic paths', () => {
  it('detects forge not installed', async () => {
    const result = await classifyFailure(
      nullClient, dummyTestFile,
      makeRunResult({ rawStdout: 'forge: command not found' }),
      dummyInvariants, emptySource, 'test-model',
    );
    expect(result.classification).toBe('environment-issue');
  });

  it('detects compile errors', async () => {
    const result = await classifyFailure(
      nullClient, dummyTestFile,
      makeRunResult({
        compileSuccess: false,
        compileErrors: ['Error (2314): Expected semicolon'],
        rawStdout: 'Compiler run failed',
      }),
      dummyInvariants, emptySource, 'test-model',
    );
    expect(result.classification).toBe('compile-error');
  });

  it('detects import errors', async () => {
    const result = await classifyFailure(
      nullClient, dummyTestFile,
      makeRunResult({
        compileSuccess: false,
        compileErrors: ['Source "forge-std/Test.sol" not found'],
        rawStdout: '',
      }),
      dummyInvariants, emptySource, 'test-model',
    );
    expect(result.classification).toBe('import-error');
  });

  it('detects setUp failures when all tests fail with setUp in output', async () => {
    const result = await classifyFailure(
      nullClient, dummyTestFile,
      makeRunResult({
        results: [
          { testName: 'invariant_a', passed: false, revertReason: 'setUp revert', rawOutput: 'setUp failed' },
          { testName: 'invariant_b', passed: false, revertReason: 'setUp revert', rawOutput: 'setUp failed' },
        ],
      }),
      dummyInvariants, emptySource, 'test-model',
    );
    expect(result.classification).toBe('test-setup-bug');
  });

  it('detects setUp issues when all failures revert without counterexample or assertion', async () => {
    const result = await classifyFailure(
      nullClient, dummyTestFile,
      makeRunResult({
        results: [
          { testName: 'invariant_a', passed: false, revertReason: 'EvmError: Revert', rawOutput: 'revert' },
          { testName: 'invariant_b', passed: false, revertReason: 'EvmError: Revert', rawOutput: 'revert' },
        ],
      }),
      dummyInvariants, emptySource, 'test-model',
    );
    expect(result.classification).toBe('test-setup-bug');
  });
});
