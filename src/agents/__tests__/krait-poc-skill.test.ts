/**
 * krait-poc skill integrity.
 *
 * The skill uses progressive disclosure: a tight SKILL.md that points at reference files
 * loaded on demand. That only works if every referenced file exists, and the whole value
 * proposition rests on the "assert harm, not mechanism" rule staying central and in sync
 * with the critic's Impact Premise. These tests guard both without needing an LLM.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync, readdirSync } from 'fs';
import { join } from 'path';

const REPO_ROOT = join(import.meta.dirname, '../../..');
const SKILL_DIR = join(REPO_ROOT, '.claude/skills/krait-poc');

function read(rel: string): string {
  const full = join(SKILL_DIR, rel);
  expect(existsSync(full), `${rel} should exist`).toBe(true);
  return readFileSync(full, 'utf-8');
}

describe('krait-poc skill structure', () => {
  const skill = read('SKILL.md');

  it('has valid frontmatter with the right name', () => {
    expect(skill.startsWith('---')).toBe(true);
    expect(skill).toMatch(/^name:\s*krait-poc\s*$/m);
    expect(skill).toMatch(/^description:/m);
  });

  it('keeps the entry point tight (progressive disclosure)', () => {
    // The whole point is a small always-on entry that pulls references on demand.
    // If SKILL.md itself balloons, that discipline is broken.
    expect(skill.split('\n').length).toBeLessThan(200);
  });

  it('every reference the workflow names exists on disk', () => {
    const referenced = new Set(skill.match(/references\/[a-z-]+\.md/g) ?? []);
    expect(referenced.size).toBeGreaterThan(5);
    for (const ref of referenced) {
      expect(existsSync(join(SKILL_DIR, ref)), `missing ${ref}`).toBe(true);
    }
  });

  it('every reference file is actually pointed at by SKILL.md', () => {
    // A reference nobody links is dead weight (ATTRIBUTION is linked from prose, so it
    // is allowed to sit outside the workflow table).
    const files = readdirSync(join(SKILL_DIR, 'references')).map(f => `references/${f}`);
    const unreferenced = files.filter(
      f => !skill.includes(f) && !f.endsWith('ATTRIBUTION.md'),
    );
    expect(unreferenced, `unreferenced reference files: ${unreferenced.join(', ')}`).toEqual([]);
  });
});

describe('krait-poc central rule: assert harm, not mechanism', () => {
  const skill = read('SKILL.md');
  const critic = readFileSync(
    join(REPO_ROOT, '.claude/skills/krait/critic/instructions.md'),
    'utf-8',
  );

  it('SKILL.md leads with the harm-not-mechanism rule', () => {
    expect(skill).toMatch(/assert HARM, not mechanism/i);
  });

  it('stays in sync with the critic Impact Premise (both demand harm over mechanism)', () => {
    // These are the same idea on two surfaces; if one loses it they have drifted.
    expect(skill).toMatch(/mechanism/i);
    expect(critic).toContain('IMPACT PREMISE');
    expect(critic).toMatch(/harm/i);
  });

  it('defines the three evidence tags the critic consumes', () => {
    for (const tag of ['[POC-PASS]', '[POC-FAIL]', '[CODE-TRACE]']) {
      expect(skill).toContain(tag);
    }
  });

  it('critic Verification Method D routes to the krait-poc skill', () => {
    expect(critic).toContain('krait-poc');
    expect(critic).toMatch(/\[POC-PASS\]/);
  });
});

describe('krait-poc harness compiles conceptually', () => {
  const harness = read('references/harness.md');

  it('ships a self-contained base contract, not a copy of a third-party file', () => {
    // MIT SPDX (ours), not the corpus's UNLICENSED headers.
    expect(harness).toContain('SPDX-License-Identifier: MIT');
    expect(harness).toContain('BaseTestWithBalanceLog');
  });

  it('pins the fork block in its example (non-reproducible otherwise)', () => {
    expect(harness).toMatch(/createSelectFork\([^)]*,\s*\d[\d_]*\)/);
  });

  it('attribution documents the license reasoning for every corpus', () => {
    const attr = read('references/ATTRIBUTION.md');
    expect(attr).toContain('Apache-2.0');
    expect(attr).toContain('DeFiHackLabs');
    expect(attr).toMatch(/no third-party solidity/i);
  });
});
