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
    // Cap raised 200 -> 215 when the falsification gate added a 9th workflow step (the
    // anti-confirmation-bias defect-mutation/fix-efficacy control). Essential growth, not
    // bloat — the gate's detail lives in references/falsification-gate.md, not here.
    expect(skill.split('\n').length).toBeLessThan(215);
  });

  it('every reference the workflow names exists on disk', () => {
    const referenced = new Set(skill.match(/references\/[a-z-]+\.md/g) ?? []);
    expect(referenced.size).toBeGreaterThan(5);
    for (const ref of referenced) {
      expect(existsSync(join(SKILL_DIR, ref)), `missing ${ref}`).toBe(true);
    }
  });

  it('makes environment recon a mandatory gating first step', () => {
    // Building tests without profiling the target is the failure this guards against.
    expect(skill).toContain('references/environment-recon.md');
    expect(skill).toMatch(/Recon the target's PoC environment.*MANDATORY/i);
    expect(skill).toMatch(/[Dd]o not write a line of test code until/);
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

  it('defines the evidence tags the critic consumes', () => {
    for (const tag of ['[POC-PASS]', '[POC-FAIL]', '[CODE-TRACE]', '[POC-UNPINNED]']) {
      expect(skill).toContain(tag);
    }
  });

  it('states that inability to PoC is not a refutation', () => {
    // The load-bearing epistemic rule: only [POC-FAIL] argues invalidity.
    expect(skill).toMatch(/inability to PoC does neither|un-PoC-able/i);
  });

  it('critic Verification Method D routes to the krait-poc skill', () => {
    expect(critic).toContain('krait-poc');
    expect(critic).toMatch(/\[POC-PASS\]/);
  });
});

describe('krait-poc falsification gate (anti-confirmation-bias)', () => {
  const skill = read('SKILL.md');
  const gate = read('references/falsification-gate.md');

  it('SKILL.md makes the gate mandatory before a POC-PASS stands', () => {
    expect(skill).toMatch(/falsification gate/i);
    expect(skill).toMatch(/green test is a hypothesis, not a proof/i);
    expect(skill).toMatch(/Step 7/);
  });

  it('separates the defect-mutation (pin) from the fix-efficacy (remediation) control', () => {
    // Conflating these was the flaw: a failed fix could be theater OR a real bug with a bad fix.
    expect(gate).toMatch(/Defect-mutation/);
    expect(gate).toMatch(/Fix-efficacy/);
    expect(gate).toMatch(/two DIFFERENT questions/i);
  });

  it('uses the corrected defective line as the pin, not the proposed fix', () => {
    // The pin must be independent of whether we got the fix right.
    expect(gate).toMatch(/defective line/i);
    expect(gate).toMatch(/independent of any fix/i);
  });

  it('treats a surviving defect-mutation as UNPINNED (theater), downgraded to CODE-TRACE', () => {
    expect(gate).toContain('[POC-UNPINNED]');
    expect(gate).toMatch(/\[POC-UNPINNED\][^\n]*CODE-TRACE|not pinned/i);
  });

  it('treats a surviving fix on a pinned bug as FIX-INSUFFICIENT, never a demotion', () => {
    expect(gate).toContain('FIX-INSUFFICIENT');
    expect(gate).toMatch(/finding, not a failure|higher.*value|never a demotion/i);
  });

  it('forbids iterating a candidate fix against a single exploit test (the recursion trap)', () => {
    expect(gate).toMatch(/never iterate a candidate fix|do not iterate a candidate fix/i);
    expect(gate).toMatch(/fuzz\/variant sweep|fuzz.variant/i);
  });

  it('requires a negative/baseline control as a cross-check', () => {
    expect(gate).toMatch(/negative.*control|baseline control/i);
  });

  it('keeps the human in the loop for remediation', () => {
    expect(gate).toMatch(/human review/i);
  });
});

describe('krait-poc environment recon', () => {
  const recon = read('references/environment-recon.md');
  const deploy = read('references/deploy-shapes.md');

  it('reviews the target build/test/deploy environment before construction', () => {
    for (const field of ['BUILD SYSTEM', 'FORGE CONFIG', 'FORK FEASIBLE', 'TEST CONVENTION', 'TARGET SHAPE']) {
      expect(recon).toContain(field);
    }
  });

  it('answers the fork-vs-local decision as a framework, not a crude mode pick', () => {
    expect(recon).toMatch(/local.*fork.*hybrid|Harness decision/i);
    // The key correction: fork is often necessary for in-scope findings, not just incidents.
    expect(recon).toMatch(/fork testing is frequently necessary for in-scope/i);
  });

  it('treats a missing fork RPC as BLOCKED, not FAIL', () => {
    expect(recon).toContain('NO_FORK_RPC');
    expect(recon).toMatch(/BLOCKED, not FAIL/);
  });

  it('covers non-trivial deployment shapes', () => {
    for (const shape of ['Proxy', 'Factory', 'Diamond', 'Multi-contract', 'init sequence']) {
      expect(deploy).toMatch(new RegExp(shape, 'i'));
    }
  });

  it('tells the model to reuse the project’s own deploy scripts and fixtures', () => {
    expect(recon).toMatch(/REUSE, do not reinvent/i);
    expect(deploy).toMatch(/project's own deploy script/i);
  });
});

describe('krait-poc batch triage', () => {
  const skill = read('SKILL.md');
  const triage = read('references/batch-triage.md');

  it('is offered as a distinct mode from SKILL.md', () => {
    expect(skill).toContain('references/batch-triage.md');
    expect(skill).toMatch(/batch triage/i);
  });

  it('separates the four PoC-ability lanes', () => {
    for (const lane of ['TESTABLE', 'STRUCTURAL', 'BLOCKED', 'NO-HARM']) {
      expect(triage).toContain(lane);
    }
  });

  it('keeps un-PoC-able findings at their severity, never marking them invalid', () => {
    expect(triage).toMatch(/valid.*un-PoC-able|un-PoC-able.*valid/i);
    // The single most important guarantee: only POC-FAIL counts against a finding.
    // (POC-FAIL is wrapped in backticks/bold in the prose, so match loosely.)
    expect(triage).toMatch(/POC-FAIL.{0,4}bucket is the ONLY one that counts against/i);
  });

  it('names the structural reasons a finding can be un-PoC-able', () => {
    for (const reason of ['TRUSTED_ACTOR', 'OFF_CHAIN_HARM', 'CROSS_CHAIN_DESTINATION']) {
      expect(triage).toContain(reason);
    }
  });

  it('caps re-attempts and forbids re-attempting structural findings', () => {
    expect(triage).toMatch(/3 attempts/);
    expect(triage).toMatch(/[Nn]ever re-attempt a STRUCTURAL/);
  });

  it('is explicitly not a filter that drops un-PoC-able findings', () => {
    expect(triage).toMatch(/not a filter/i);
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
