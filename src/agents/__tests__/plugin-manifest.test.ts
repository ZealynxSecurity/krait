/**
 * Plugin + marketplace manifest invariants.
 *
 * The checklist plugin shipped for months with `"repository": { "type": "git", "url": ... }`
 * in its plugin.json. The Claude Code schema requires a STRING there, so
 * `claude plugin validate` failed and the plugin could never be installed — even though its
 * README documented the install command. Nothing caught it because nothing checked.
 *
 * These tests assert the manifest invariants that `claude plugin validate` enforces, so a
 * regression fails in CI without needing the Claude CLI on the runner. When in doubt, the
 * CLI is authoritative: `claude plugin validate .` and `claude plugin validate ./checklist`.
 */

import { describe, it, expect } from 'vitest';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';

const REPO_ROOT = join(import.meta.dirname, '../../..');

function readJson(relativePath: string): Record<string, unknown> {
  const full = join(REPO_ROOT, relativePath);
  expect(existsSync(full), `${relativePath} should exist`).toBe(true);
  return JSON.parse(readFileSync(full, 'utf-8'));
}

describe('marketplace manifest', () => {
  const marketplace = readJson('.claude-plugin/marketplace.json');

  it('has the fields the schema requires', () => {
    expect(typeof marketplace.name).toBe('string');
    expect(marketplace.owner).toBeTypeOf('object');
    expect(Array.isArray(marketplace.plugins)).toBe(true);
    expect((marketplace.plugins as unknown[]).length).toBeGreaterThan(0);
  });

  it('every listed plugin resolves to a real plugin.json', () => {
    for (const entry of marketplace.plugins as Array<Record<string, string>>) {
      const source = entry.source.replace(/^\.\//, '');
      expect(
        existsSync(join(REPO_ROOT, source, '.claude-plugin/plugin.json')),
        `${entry.name}: no plugin.json at ${source}`,
      ).toBe(true);
    }
  });

  it('marketplace entry name matches the plugin.json name', () => {
    // The command namespace is derived from this name: plugin `krait` + skill `scan`
    // gives `/krait:scan`. A mismatch silently changes every documented command.
    for (const entry of marketplace.plugins as Array<Record<string, string>>) {
      const source = entry.source.replace(/^\.\//, '');
      const plugin = readJson(join(source, '.claude-plugin/plugin.json'));
      expect(plugin.name, `${entry.name}: name mismatch with ${source}`).toBe(entry.name);
    }
  });
});

describe('checklist plugin manifest', () => {
  const plugin = readJson('checklist/.claude-plugin/plugin.json');

  it('declares repository as a STRING, not an object', () => {
    // This is the exact defect that made the plugin uninstallable.
    if ('repository' in plugin) {
      expect(typeof plugin.repository).toBe('string');
    }
  });

  it('declares name, description and version', () => {
    expect(typeof plugin.name).toBe('string');
    expect(typeof plugin.description).toBe('string');
    expect(typeof plugin.version).toBe('string');
  });

  it('ships the three documented skills', () => {
    for (const skill of ['scan', 'assess', 'check']) {
      const path = join(REPO_ROOT, 'checklist/skills', skill, 'SKILL.md');
      expect(existsSync(path), `missing skill: ${skill}`).toBe(true);
      // The skill's own frontmatter name is what follows the colon in `/krait:scan`.
      const frontmatter = readFileSync(path, 'utf-8').split('---')[1] ?? '';
      expect(frontmatter).toMatch(new RegExp(`^name:\\s*${skill}\\s*$`, 'm'));
    }
  });

  it('ships the framework tiers the skills actually read', () => {
    // Skills read frameworks/index.json, frameworks/scan/ and frameworks/condensed/.
    // The full frameworks/*.json tier is gitignored and must NOT be a runtime dependency.
    expect(existsSync(join(REPO_ROOT, 'checklist/frameworks/index.json'))).toBe(true);
    for (const vertical of ['lending', 'vaults', 'dasf', 'common']) {
      expect(
        existsSync(join(REPO_ROOT, `checklist/frameworks/scan/${vertical}.json`)),
        `missing scan framework: ${vertical}`,
      ).toBe(true);
      expect(
        existsSync(join(REPO_ROOT, `checklist/frameworks/condensed/${vertical}.json`)),
        `missing condensed framework: ${vertical}`,
      ).toBe(true);
    }
  });

  it('keeps the checklist separate from the audit pipeline', () => {
    // Different products with different bars. If someone starts wiring kill gates into
    // the checklist skills, that is a design error, not an improvement.
    const scan = readFileSync(join(REPO_ROOT, 'checklist/skills/scan/SKILL.md'), 'utf-8');
    expect(scan).not.toContain('.claude/skills/krait/');
  });
});
