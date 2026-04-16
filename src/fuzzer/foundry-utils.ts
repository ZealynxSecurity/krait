/**
 * Foundry interaction utilities — forge detection, config parsing,
 * test file writing, and test execution.
 */

import { execSync, execFile } from 'child_process';
import { promisify } from 'util';
import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { resolve, join, dirname } from 'path';
import { FoundryConfig, ForgeTestResult, TestRunResult } from './types.js';

const execFileAsync = promisify(execFile);

/**
 * Check if forge is available on the system PATH.
 * Returns the version string, or null if not installed.
 */
export function checkFoundryInstalled(): string | null {
  try {
    const version = execSync('forge --version', { encoding: 'utf-8', timeout: 10_000 }).trim();
    return version;
  } catch {
    return null;
  }
}

/**
 * Parse foundry.toml and remappings.txt from a project directory
 * to understand import paths and compiler settings.
 */
export function detectFoundryConfig(projectPath: string): FoundryConfig {
  const config: FoundryConfig = {
    remappings: [],
    srcPath: 'src',
    testPath: 'test',
    libPaths: ['lib'],
  };

  // Parse foundry.toml
  const tomlPath = resolve(projectPath, 'foundry.toml');
  if (existsSync(tomlPath)) {
    const content = readFileSync(tomlPath, 'utf-8');

    // Extract solc version
    const solcMatch = content.match(/solc[_-]version\s*=\s*["']([^"']+)["']/);
    if (solcMatch) config.solcVersion = solcMatch[1];

    // Extract src path
    const srcMatch = content.match(/src\s*=\s*["']([^"']+)["']/);
    if (srcMatch) config.srcPath = srcMatch[1];

    // Extract test path
    const testMatch = content.match(/test\s*=\s*["']([^"']+)["']/);
    if (testMatch) config.testPath = testMatch[1];

    // Extract lib paths
    const libsMatch = content.match(/libs\s*=\s*\[([^\]]*)\]/);
    if (libsMatch) {
      config.libPaths = libsMatch[1]
        .split(',')
        .map(s => s.trim().replace(/["']/g, ''))
        .filter(Boolean);
    }

    // Extract remappings from foundry.toml
    const remapMatch = content.match(/remappings\s*=\s*\[([^\]]*)\]/s);
    if (remapMatch) {
      const remaps = remapMatch[1]
        .split(',')
        .map(s => s.trim().replace(/["'\n]/g, ''))
        .filter(Boolean);
      config.remappings.push(...remaps);
    }

    // Extract evm version
    const evmMatch = content.match(/evm[_-]version\s*=\s*["']([^"']+)["']/);
    if (evmMatch) config.evmVersion = evmMatch[1];
  }

  // Parse remappings.txt (may complement or override foundry.toml)
  const remappingsPath = resolve(projectPath, 'remappings.txt');
  if (existsSync(remappingsPath)) {
    const content = readFileSync(remappingsPath, 'utf-8');
    const fileRemaps = content
      .split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#') && l.includes('='));
    // Merge, preferring remappings.txt entries
    const existing = new Set(config.remappings.map(r => r.split('=')[0]));
    for (const remap of fileRemaps) {
      const key = remap.split('=')[0];
      if (!existing.has(key)) {
        config.remappings.push(remap);
      }
    }
  }

  return config;
}

/**
 * Verify the Foundry project compiles before running fuzz tests.
 * Fails fast with clear error if the base project has compile errors.
 */
export async function checkProjectCompiles(
  projectPath: string,
  verbose?: boolean,
): Promise<{ success: boolean; errors?: string }> {
  try {
    if (verbose) console.error('  [forge] Running forge build...');
    await execFileAsync('forge', ['build'], {
      cwd: projectPath,
      timeout: 120_000, // 2 minute timeout
      maxBuffer: 10 * 1024 * 1024,
    });
    return { success: true };
  } catch (err: unknown) {
    const execErr = err as { stdout?: string; stderr?: string };
    const output = (execErr.stderr || execErr.stdout || 'Unknown compile error').slice(0, 3000);
    return { success: false, errors: output };
  }
}

/**
 * Write a test file to disk, creating directories as needed.
 */
export function writeTestFile(filePath: string, code: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
  writeFileSync(filePath, code, 'utf-8');
}

/**
 * Run `forge test` on a specific test file and return structured results.
 * Uses execFile with args array to prevent command injection from LLM-generated paths.
 */
export async function runForgeTest(
  projectPath: string,
  testFilePath: string,
  fuzzRuns: number,
  verbose?: boolean,
): Promise<TestRunResult> {
  const start = Date.now();
  const testFileId = testFilePath; // caller maps this to the FuzzTestFile.id
  const args = ['test', '--match-path', testFilePath, '--fuzz-runs', String(fuzzRuns), '-vvv'];

  if (verbose) console.error(`    [forge] forge ${args.join(' ')}`);

  try {
    const { stdout, stderr } = await execFileAsync('forge', args, {
      cwd: projectPath,
      timeout: 300_000, // 5 minute timeout
      maxBuffer: 10 * 1024 * 1024, // 10MB
    });

    const output = stdout + '\n' + stderr;
    const results = parseForgeOutput(output);
    const hasCompileError = output.includes('Compiler run failed') || output.includes('Error (');

    return {
      testFileId,
      compileSuccess: !hasCompileError,
      compileErrors: hasCompileError ? extractCompileErrors(output) : undefined,
      results,
      rawStdout: stdout,
      rawStderr: stderr,
      duration: Date.now() - start,
    };
  } catch (err: unknown) {
    const execErr = err as { stdout?: string; stderr?: string; status?: number };
    const stdout = execErr.stdout || '';
    const stderr = execErr.stderr || '';
    const combined = stdout + '\n' + stderr;

    const hasCompileError =
      combined.includes('Compiler run failed') ||
      combined.includes('Error (') ||
      combined.includes('ParserError') ||
      combined.includes('DeclarationError');

    const results = hasCompileError ? [] : parseForgeOutput(combined);

    return {
      testFileId,
      compileSuccess: !hasCompileError,
      compileErrors: hasCompileError ? extractCompileErrors(combined) : undefined,
      results,
      rawStdout: stdout,
      rawStderr: stderr,
      duration: Date.now() - start,
    };
  }
}

/**
 * Parse forge test output into structured results.
 * Handles both passing and failing tests.
 */
export function parseForgeOutput(output: string): ForgeTestResult[] {
  const results: ForgeTestResult[] = [];
  const lines = output.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];

    // Match [PASS] or [FAIL] lines
    // [PASS] invariant_totalSupplyConsistent() (runs: 1000, ...)
    // [FAIL. Reason: Assertion failed] invariant_xxx() (runs: 50, ...)
    // [FAIL: Reason: ...] invariant_xxx()
    const passMatch = line.match(/\[PASS\]\s+(\w+)\(\)\s*\(.*?(?:gas:\s*(\d+))?/);
    const failMatch = line.match(/\[FAIL[.:]\s*(?:Reason:\s*)?([^\]]*)\]\s+(\w+)\(\)/);

    if (passMatch) {
      results.push({
        testName: passMatch[1],
        passed: true,
        gasUsed: passMatch[2] ? parseInt(passMatch[2], 10) : undefined,
        rawOutput: line,
      });
    } else if (failMatch) {
      const reason = failMatch[1].trim() || undefined;
      const testName = failMatch[2];

      // Look ahead for counterexample
      let counterexample: string | undefined;
      for (let j = i + 1; j < Math.min(i + 20, lines.length); j++) {
        const ceMatch = lines[j].match(/Counterexample:\s*(.+)/);
        if (ceMatch) {
          counterexample = ceMatch[1].trim();
          break;
        }
        // Also check for "Sequence" in invariant tests
        const seqMatch = lines[j].match(/Sequence.*?:\s*(.+)/i);
        if (seqMatch) {
          counterexample = (counterexample || '') + seqMatch[1].trim() + '\n';
        }
      }

      results.push({
        testName,
        passed: false,
        revertReason: reason,
        counterexample,
        rawOutput: collectTestTrace(lines, i),
      });
    }
  }

  return results;
}

/**
 * Extract compilation error messages from forge output.
 */
function extractCompileErrors(output: string): string[] {
  const errors: string[] = [];
  const lines = output.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    // Match Solidity error lines
    if (
      line.includes('Error (') ||
      line.includes('ParserError') ||
      line.includes('DeclarationError') ||
      line.includes('TypeError')
    ) {
      // Collect the error and a few context lines
      const errLines = [line];
      for (let j = i + 1; j < Math.min(i + 5, lines.length); j++) {
        if (lines[j].trim()) errLines.push(lines[j]);
        else break;
      }
      errors.push(errLines.join('\n'));
    }
  }

  return errors.length > 0 ? errors : [output.slice(0, 2000)];
}

/**
 * Collect the full trace output for a failed test (up to the next test or EOF).
 */
function collectTestTrace(lines: string[], failLineIndex: number): string {
  const traceLines = [lines[failLineIndex]];
  for (let j = failLineIndex + 1; j < lines.length; j++) {
    // Stop at next test result or suite boundary
    if (lines[j].match(/^\[(?:PASS|FAIL)/)) break;
    if (lines[j].match(/^Suite result:/)) break;
    traceLines.push(lines[j]);
  }
  return traceLines.join('\n');
}
