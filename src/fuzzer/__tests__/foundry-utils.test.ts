import { describe, it, expect } from 'vitest';
import { mkdirSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { parseForgeOutput, detectFoundryConfig } from '../foundry-utils.js';

describe('parseForgeOutput', () => {
  it('parses passing tests', () => {
    const output = `[PASS] invariant_totalSupply() (runs: 1000, calls: 15000, reverts: 20)`;
    const results = parseForgeOutput(output);
    expect(results).toHaveLength(1);
    expect(results[0].testName).toBe('invariant_totalSupply');
    expect(results[0].passed).toBe(true);
  });

  it('parses failing tests with reason', () => {
    const output = `[FAIL. Reason: Assertion failed] invariant_balanceConsistent() (runs: 50, calls: 750)`;
    const results = parseForgeOutput(output);
    expect(results).toHaveLength(1);
    expect(results[0].testName).toBe('invariant_balanceConsistent');
    expect(results[0].passed).toBe(false);
    expect(results[0].revertReason).toBe('Assertion failed');
  });

  it('extracts counterexamples from failed tests', () => {
    const output = [
      '[FAIL. Reason: Assertion failed] invariant_noOverflow() (runs: 100)',
      '  Counterexample: calldata=deposit(uint256) args=[115792089237316195423570985008687907853269984665640564039457584007913129639935]',
    ].join('\n');
    const results = parseForgeOutput(output);
    expect(results).toHaveLength(1);
    expect(results[0].counterexample).toContain('deposit(uint256)');
  });

  it('handles mixed pass and fail results', () => {
    const output = [
      '[PASS] invariant_ownerOnly() (runs: 1000, calls: 15000)',
      '[FAIL. Reason: Assertion failed] invariant_totalSupply() (runs: 50)',
      '[PASS] invariant_nonReentrant() (runs: 1000, calls: 15000)',
    ].join('\n');
    const results = parseForgeOutput(output);
    expect(results).toHaveLength(3);
    expect(results[0].passed).toBe(true);
    expect(results[1].passed).toBe(false);
    expect(results[2].passed).toBe(true);
  });

  it('returns empty array for output with no test results', () => {
    const output = 'Compiling 5 files...\nCompiler run successful!\n';
    const results = parseForgeOutput(output);
    expect(results).toHaveLength(0);
  });
});

describe('detectFoundryConfig', () => {
  const tmpBase = join(tmpdir(), 'krait-test-foundry-' + Date.now());

  function makeTmpProject(files: Record<string, string>): string {
    const dir = join(tmpBase, String(Math.random()).slice(2, 8));
    mkdirSync(dir, { recursive: true });
    for (const [name, content] of Object.entries(files)) {
      writeFileSync(join(dir, name), content);
    }
    return dir;
  }

  afterAll(() => {
    try { rmSync(tmpBase, { recursive: true, force: true }); } catch {}
  });

  it('returns defaults for empty directory', () => {
    const dir = makeTmpProject({});
    const config = detectFoundryConfig(dir);
    expect(config.srcPath).toBe('src');
    expect(config.testPath).toBe('test');
    expect(config.remappings).toEqual([]);
    expect(config.libPaths).toEqual(['lib']);
  });

  it('parses solc version from foundry.toml', () => {
    const dir = makeTmpProject({
      'foundry.toml': `[profile.default]\nsolc_version = "0.8.20"\n`,
    });
    const config = detectFoundryConfig(dir);
    expect(config.solcVersion).toBe('0.8.20');
  });

  it('parses src and test paths from foundry.toml', () => {
    const dir = makeTmpProject({
      'foundry.toml': `[profile.default]\nsrc = "contracts"\ntest = "tests"\n`,
    });
    const config = detectFoundryConfig(dir);
    expect(config.srcPath).toBe('contracts');
    expect(config.testPath).toBe('tests');
  });

  it('parses remappings from foundry.toml', () => {
    const dir = makeTmpProject({
      'foundry.toml': `[profile.default]\nremappings = ["@openzeppelin/=lib/openzeppelin-contracts/", "forge-std/=lib/forge-std/src/"]\n`,
    });
    const config = detectFoundryConfig(dir);
    expect(config.remappings).toContain('@openzeppelin/=lib/openzeppelin-contracts/');
    expect(config.remappings).toContain('forge-std/=lib/forge-std/src/');
  });

  it('parses remappings.txt and merges with foundry.toml', () => {
    const dir = makeTmpProject({
      'foundry.toml': `[profile.default]\nremappings = ["forge-std/=lib/forge-std/src/"]\n`,
      'remappings.txt': `@oz/=lib/oz/\nforge-std/=lib/forge-std/src/\n`,
    });
    const config = detectFoundryConfig(dir);
    // forge-std should not be duplicated
    const forgeStdCount = config.remappings.filter(r => r.startsWith('forge-std/')).length;
    expect(forgeStdCount).toBe(1);
    // @oz should be added
    expect(config.remappings).toContain('@oz/=lib/oz/');
  });

  it('parses evm version', () => {
    const dir = makeTmpProject({
      'foundry.toml': `[profile.default]\nevm_version = "shanghai"\n`,
    });
    const config = detectFoundryConfig(dir);
    expect(config.evmVersion).toBe('shanghai');
  });
});
