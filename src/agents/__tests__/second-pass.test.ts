import { describe, it, expect } from 'vitest';
import { buildExclusionList, findUncoveredFiles, buildClusters, parseInheritance, rescan } from '../second-pass.js';
import { CandidateCounter } from '../detector.js';
import { CandidateFinding } from '../types.js';
import { FileInfo } from '../../core/types.js';

function makeFile(relativePath: string, lines = 100): FileInfo {
  return { path: `/abs/${relativePath}`, relativePath, language: 'solidity', lines, size: lines * 40 };
}

function makeCandidate(overrides: Partial<CandidateFinding> = {}): CandidateFinding {
  return {
    id: 'c1',
    title: 'Missing check',
    severity: 'high',
    file: 'Vault.sol',
    line: 10,
    category: 'access-control',
    description: 'desc',
    codeSnippet: '',
    affectedFunctions: [],
    relatedContracts: [],
    detectorConfidence: 70,
    remediation: 'fix',
    ...overrides,
  };
}

describe('buildExclusionList', () => {
  it('renders one compact line per candidate', () => {
    const out = buildExclusionList([
      makeCandidate({ file: 'Vault.sol', line: 10, title: 'A', severity: 'high' }),
      makeCandidate({ file: 'Pool.sol', line: 22, title: 'B', severity: 'medium' }),
    ]);
    expect(out).toBe('- [HIGH] Vault.sol:10 — A\n- [MEDIUM] Pool.sol:22 — B');
  });

  it('says so explicitly when nothing was found', () => {
    expect(buildExclusionList([])).toContain('first pass');
  });
});

describe('findUncoveredFiles', () => {
  it('returns files with no candidate — the blind spots', () => {
    const files = [makeFile('Vault.sol'), makeFile('Pool.sol'), makeFile('Math.sol')];
    const out = findUncoveredFiles(files, [makeCandidate({ file: 'Vault.sol' })]);
    expect(out).toEqual(['Pool.sol', 'Math.sol']);
  });
});

describe('parseInheritance', () => {
  it('maps declarations to files and captures parents', () => {
    const contents = new Map([
      ['Base.sol', 'abstract contract Base { }'],
      ['Vault.sol', 'contract Vault is Base, Ownable { }'],
    ]);
    const { declaredIn, parentsOf } = parseInheritance(contents);
    expect(declaredIn.get('Base')).toBe('Base.sol');
    expect(declaredIn.get('Vault')).toBe('Vault.sol');
    expect(parentsOf.get('Vault')).toEqual(['Base', 'Ownable']);
  });

  it('strips constructor arguments from the inherit list', () => {
    const { parentsOf } = parseInheritance(new Map([['A.sol', 'contract A is ERC20("n","s"), Base { }']]));
    expect(parentsOf.get('A')).toEqual(['ERC20', 'Base']);
  });

  it('handles libraries and interfaces', () => {
    const { declaredIn } = parseInheritance(new Map([
      ['L.sol', 'library SafeMathLike { }'],
      ['I.sol', 'interface IVault is IERC20 { }'],
    ]));
    expect(declaredIn.get('SafeMathLike')).toBe('L.sol');
    expect(declaredIn.get('IVault')).toBe('I.sol');
  });
});

describe('buildClusters', () => {
  it('groups a child with the file declaring its parent', () => {
    const files = [makeFile('Base.sol'), makeFile('Vault.sol'), makeFile('Unrelated.sol')];
    const contents = new Map([
      ['Base.sol', 'abstract contract Base { }'],
      ['Vault.sol', 'contract Vault is Base { }'],
      ['Unrelated.sol', 'contract Unrelated { }'],
    ]);
    const clusters = buildClusters(files, contents);
    const withBoth = clusters.find(c => c.includes('Vault.sol') && c.includes('Base.sol'));
    expect(withBoth).toBeDefined();
    expect(clusters.find(c => c.includes('Unrelated.sol'))).toEqual(['Unrelated.sol']);
  });

  it('does not merge on a parent that is out of scope', () => {
    const files = [makeFile('Vault.sol')];
    const contents = new Map([['Vault.sol', 'contract Vault is Ownable { }']]);
    expect(buildClusters(files, contents)).toEqual([['Vault.sol']]);
  });

  it('caps the number of clusters', () => {
    const files = Array.from({ length: 20 }, (_, i) => makeFile(`C${i}.sol`));
    const contents = new Map(files.map(f => [f.relativePath, `contract C${f.relativePath} { }`]));
    expect(buildClusters(files, contents).length).toBeLessThanOrEqual(8);
  });

  it('skips files with no loaded content', () => {
    const files = [makeFile('A.sol'), makeFile('Missing.sol')];
    const contents = new Map([['A.sol', 'contract A { }']]);
    expect(buildClusters(files, contents)).toEqual([['A.sol']]);
  });
});

describe('rescan hard-exit rule', () => {
  it('makes no API call when pass 1 found nothing above Info', async () => {
    let called = 0;
    const client = { messages: { create: async () => { called++; return { content: [] }; } } };
    const out = await rescan(
      client as never,
      [makeFile('A.sol')],
      new Map([['A.sol', 'contract A { }']]),
      [makeCandidate({ severity: 'low' })],
      'model',
      new CandidateCounter(),
      null,
    );
    expect(out).toEqual([]);
    expect(called).toBe(0);
  });

  it('runs when pass 1 found something above Info', async () => {
    let called = 0;
    const client = {
      messages: {
        create: async () => {
          called++;
          return { content: [{ type: 'tool_use', name: 'report_candidates', input: { candidates: [] } }] };
        },
      },
    };
    await rescan(
      client as never,
      [makeFile('A.sol')],
      new Map([['A.sol', 'contract A { }']]),
      [makeCandidate({ severity: 'high' })],
      'model',
      new CandidateCounter(),
      null,
      { rescanAgents: 2 },
    );
    expect(called).toBeGreaterThan(0);
  });

  it('drops candidates that came back without a file path', async () => {
    const client = {
      messages: {
        create: async () => ({
          content: [{
            type: 'tool_use',
            name: 'report_candidates',
            input: {
              candidates: [
                { title: 'ok', severity: 'high', file: 'A.sol', line: 5, category: 'x', description: 'd', confidence: 60 },
                { title: 'no file', severity: 'high', line: 6, category: 'x', description: 'd', confidence: 60 },
              ],
            },
          }],
        }),
      },
    };
    const out = await rescan(
      client as never,
      [makeFile('A.sol')],
      new Map([['A.sol', 'contract A { }']]),
      [makeCandidate({ severity: 'high' })],
      'model',
      new CandidateCounter(),
      null,
      { rescanAgents: 1 },
    );
    expect(out).toHaveLength(1);
    expect(out[0].file).toBe('A.sol');
  });

  it('survives an agent error without failing the audit', async () => {
    const client = { messages: { create: async () => { throw new Error('boom'); } } };
    const out = await rescan(
      client as never,
      [makeFile('A.sol')],
      new Map([['A.sol', 'contract A { }']]),
      [makeCandidate({ severity: 'high' })],
      'model',
      new CandidateCounter(),
      null,
      { rescanAgents: 1 },
    );
    expect(out).toEqual([]);
  });
});
