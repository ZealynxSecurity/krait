/**
 * Skill ↔ CLI parity.
 *
 * Krait ships two surfaces that must encode the SAME methodology: the Claude Code skill
 * under `.claude/skills/krait/` and the TypeScript pipeline under `src/`. They diverged
 * once already — the CLI critic ran a generic "skeptical reviewer" prompt with none of
 * the 8 kill gates, while the published precision numbers were attributed to those gates.
 *
 * These tests fail when the two surfaces drift apart on the parts that decide whether a
 * finding ships. They deliberately assert on STRUCTURE (which gates and patterns exist),
 * not on wording — prose can improve on either side without breaking the build.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { KILL_GATES, FP_PATTERNS, IMPACT_PREMISE } from '../critic.js';

const REPO_ROOT = join(import.meta.dirname, '../../..');
const SKILL_DIR = join(REPO_ROOT, '.claude/skills/krait');

function readSkill(relativePath: string): string {
  const full = join(SKILL_DIR, relativePath);
  if (!existsSync(full)) throw new Error(`Skill file missing: ${relativePath}`);
  return readFileSync(full, 'utf-8');
}

describe('skill ↔ CLI parity: kill gates', () => {
  const skillCritic = readSkill('critic/instructions.md');

  it.each(['A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'])('gate %s exists on both surfaces', gate => {
    expect(skillCritic).toContain(`GATE ${gate} —`);
    expect(KILL_GATES).toContain(`GATE ${gate} —`);
  });

  it('the DoS exception exists on both surfaces', () => {
    expect(skillCritic).toContain('DoS SEVERITY EXCEPTION');
    expect(KILL_GATES).toContain('DoS EXCEPTION');
  });

  it('both surfaces name the same gates in the DoS carve-out', () => {
    // The carve-out must rescue from A/B/D/F on both sides — not a different subset.
    expect(skillCritic).toMatch(/Gates? A, B, D, F|A\/B\/D\/F/);
    expect(KILL_GATES).toMatch(/gates A, B, D, F|A\/B\/D\/F/);
  });

  it('gate H requires a mechanism match, not a topic match, on both surfaces', () => {
    expect(skillCritic).toContain('MECHANISM, not TOPIC');
    expect(KILL_GATES).toContain('MECHANISM, not TOPIC');
  });
});

describe('skill ↔ CLI parity: false-positive patterns', () => {
  const skillCritic = readSkill('critic/instructions.md');

  it.each(Array.from({ length: 10 }, (_, i) => i + 1))('FP-%i exists on both surfaces', n => {
    expect(skillCritic).toContain(`### FP-${n}:`);
    expect(FP_PATTERNS).toContain(`FP-${n} `);
  });

  it('both surfaces keep the explicit-type-cast carve-out on FP-7', () => {
    // Solidity 0.8 checked math does NOT cover explicit casts; forgetting this on either
    // surface silently kills a whole class of real truncation bugs.
    expect(skillCritic).toContain('silently truncate');
    expect(FP_PATTERNS).toContain('silently truncate');
  });
});

describe('skill ↔ CLI parity: Impact Premise (A3)', () => {
  const skillCritic = readSkill('critic/instructions.md');
  const skillReviewer = readSkill('reviewer/instructions.md');

  it('the harm-not-mechanism gate exists on both surfaces', () => {
    expect(skillCritic).toContain('IMPACT PREMISE');
    expect(IMPACT_PREMISE).toContain('Impact Premise');
  });

  it('both surfaces demand WHO loses WHAT', () => {
    expect(skillCritic).toContain('WHO loses WHAT');
    expect(IMPACT_PREMISE).toContain('WHO loses WHAT');
  });

  it('the reviewer knows how to re-examine a MECHANISM-ONLY kill', () => {
    expect(skillReviewer).toContain('MECHANISM-ONLY');
  });
});

describe('skill ↔ CLI parity: second-pass phases (B3/B4)', () => {
  it('both recall phases have a skill file', () => {
    expect(() => readSkill('detector/rescan.md')).not.toThrow();
    expect(() => readSkill('detector/per-contract.md')).not.toThrow();
  });

  it('rescan documents the hard-exit rule that the CLI implements', () => {
    const rescan = readSkill('detector/rescan.md');
    expect(rescan).toContain('Hard exit rule');
    expect(rescan).toMatch(/above Info/i);
  });

  it('per-contract documents the cluster cap the CLI enforces', () => {
    const perContract = readSkill('detector/per-contract.md');
    expect(perContract).toContain('Maximum 8 clusters');
  });

  it('the critic skill reads every candidate file the pipeline produces', () => {
    const skillCritic = readSkill('critic/instructions.md');
    for (const artifact of [
      'detector-candidates.md',
      'rescan-candidates.md',
      'percontract-candidates.md',
      'state-candidates.md',
    ]) {
      expect(skillCritic).toContain(artifact);
    }
  });
});

describe('skill ↔ CLI parity: reporter rules (A5/A7)', () => {
  const skillReporter = readSkill('reporter/instructions.md');

  it('root-cause consolidation exists on both surfaces', () => {
    expect(skillReporter).toContain('Root-Cause Consolidation');
    // The CLI caps a consolidated finding at 6 locations; the skill must say the same.
    expect(skillReporter).toContain('6 locations');
  });

  it('trust-assumption downgrade exists and is one tier on both surfaces', () => {
    expect(skillReporter).toContain('Trust-Assumption Downgrade');
    expect(skillReporter).toContain('−1 severity tier');
  });
});

describe('prompt size budget', () => {
  // v7 measured that shrinking this file improved instruction adherence; it then grew
  // back. 700 is the cap Plamen uses for comparable scanner templates.
  it('detector instructions stay under 700 lines', () => {
    const detector = readSkill('detector/instructions.md');
    expect(detector.split('\n').length).toBeLessThan(700);
  });

  it('every heuristic ID referenced by the detector resolves to a heuristics file', () => {
    const detector = readSkill('detector/instructions.md');
    const catalogue = readSkill('detector/heuristics-core.md') + readSkill('detector/heuristics-extended.md');
    const referenced = new Set(detector.match(/\b[A-Z][A-Z0-9-]{2,}-\d{2}\b/g) ?? []);
    const unresolved = [...referenced].filter(id => !catalogue.includes(id));
    expect(unresolved).toEqual([]);
  });
});

describe('krait ↔ krait-poc integration (opt-in handoff)', () => {
  const REPO = join(import.meta.dirname, '../../..');
  const readF = (p: string) => readFileSync(join(REPO, p), 'utf-8');

  const command = readF('.claude/commands/krait.md');
  const critic = readF('.claude/skills/krait/critic/instructions.md');
  const reporter = readF('.claude/skills/krait/reporter/instructions.md');

  it('the /krait command offers the PoC pass as opt-in, not automatic', () => {
    expect(command).toContain('/krait-poc triage');
    expect(command).toMatch(/opt-in|do not run\s+automatically|offer — do not run/i);
  });

  it('critic Method D is a targeted escalation, not a routine per-High step', () => {
    expect(critic).toContain('Method D');
    expect(critic).toMatch(/targeted, rare|Do NOT PoC every High/i);
  });

  it('reporter surfaces an evidence tier distinguishing PROVEN from REASONED', () => {
    expect(reporter).toContain('Evidence Tier');
    expect(reporter).toContain('PROVEN');
    expect(reporter).toContain('REASONED');
  });

  it('reporter evidence tier recognizes the falsification-gate outcomes', () => {
    // A PoC-verified finding must distinguish "fix works" from "fix insufficient", and an
    // unpinned PoC must fall back to REASONED, never inflate to PROVEN.
    expect(reporter).toContain('FIX-INSUFFICIENT');
    expect(reporter).toContain('POC-UNPINNED');
  });

  it('reporter states REASONED is not a weaker/unverified finding', () => {
    // The load-bearing guarantee: lacking a PoC never reads as doubt. Punctuation-robust.
    expect(reporter).toMatch(/is not a weaker finding/i);
    expect(reporter).toMatch(/\*\*NOT\*\*\s*"?unverified/i);
    expect(reporter).toMatch(/un-PoC-able/i);
  });
});
