#!/usr/bin/env tsx
/**
 * Shadow-audit regression gate.
 *
 * Krait's published bar is "100% precision across blind shadow audits". That bar only
 * means anything if it is checked mechanically, on a change, before merge — so this
 * script runs a slice of the contest registry and FAILS (exit 1) on any new false
 * positive versus a stored baseline.
 *
 *   npm run shadow:regress -- --contests neobase,opendollar     # check against baseline
 *   npm run shadow:regress -- --contests neobase --update       # (re)write the baseline
 *   npm run shadow:regress -- --difficulty small --quick
 *
 * Policy, in order of severity:
 *   BLOCK  any new false positive on any contest        (precision is the product)
 *   BLOCK  a recall drop worse than --max-recall-drop   (default 2 percentage points)
 *   WARN   a recall improvement                          (good, but re-baseline deliberately)
 *
 * Requires ANTHROPIC_API_KEY. Baseline lives in shadow-audits/regression-baseline.json.
 */

import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { runBatchShadowAudit, ShadowAuditResult } from '../src/shadow/runner.js';
import { CONTEST_REGISTRY, ContestEntry } from '../src/shadow/registry.js';

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const BASELINE_PATH = join(REPO_ROOT, 'shadow-audits/regression-baseline.json');
const DEFAULT_WORK_DIR = join(REPO_ROOT, 'shadow-results');
const DEFAULT_MAX_RECALL_DROP = 2; // percentage points

interface BaselineEntry {
  contestId: string;
  contestName: string;
  falsePositives: number;
  truePositives: number;
  precision: number;   // 0-1
  recall: number;      // 0-1
  recordedAt: string;
}

interface Baseline {
  version: string;
  entries: Record<string, BaselineEntry>;
}

interface Args {
  contests: string[];
  difficulty?: ContestEntry['difficulty'];
  update: boolean;
  quick: boolean;
  verbose: boolean;
  workDir: string;
  maxRecallDrop: number;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    contests: [],
    update: false,
    quick: false,
    verbose: false,
    workDir: DEFAULT_WORK_DIR,
    maxRecallDrop: DEFAULT_MAX_RECALL_DROP,
  };

  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const next = () => argv[++i];
    switch (arg) {
      case '--contests':     args.contests = (next() ?? '').split(',').map(s => s.trim()).filter(Boolean); break;
      case '--difficulty':   args.difficulty = next() as ContestEntry['difficulty']; break;
      case '--update':       args.update = true; break;
      case '--quick':        args.quick = true; break;
      case '--verbose':      args.verbose = true; break;
      case '--work-dir':     args.workDir = next() ?? DEFAULT_WORK_DIR; break;
      case '--max-recall-drop': args.maxRecallDrop = Number(next()); break;
      case '-h':
      case '--help':
        console.log(readFileSync(fileURLToPath(import.meta.url), 'utf-8').split('*/')[0].replace(/^#!.*\n/, ''));
        process.exit(0);
        break;
      default:
        console.error(`Unknown argument: ${arg}`);
        process.exit(2);
    }
  }
  return args;
}

function loadBaseline(): Baseline {
  if (!existsSync(BASELINE_PATH)) return { version: '1', entries: {} };
  try {
    return JSON.parse(readFileSync(BASELINE_PATH, 'utf-8')) as Baseline;
  } catch (err) {
    console.error(`Baseline at ${BASELINE_PATH} is unreadable: ${err instanceof Error ? err.message : err}`);
    process.exit(2);
  }
}

function saveBaseline(baseline: Baseline): void {
  mkdirSync(dirname(BASELINE_PATH), { recursive: true });
  writeFileSync(BASELINE_PATH, JSON.stringify(baseline, null, 2) + '\n');
}

function selectContests(args: Args): ContestEntry[] {
  if (args.contests.length > 0) {
    const selected: ContestEntry[] = [];
    for (const id of args.contests) {
      const entry = CONTEST_REGISTRY.find(c => c.id === id);
      if (!entry) {
        console.error(`Unknown contest id: ${id}`);
        console.error(`Known ids: ${CONTEST_REGISTRY.map(c => c.id).join(', ')}`);
        process.exit(2);
      }
      selected.push(entry);
    }
    return selected;
  }
  if (args.difficulty) {
    return CONTEST_REGISTRY.filter(c => c.difficulty === args.difficulty);
  }
  console.error('Specify --contests <id,id> or --difficulty <small|medium|large>.');
  process.exit(2);
}

function pct(v: number): string {
  return `${(v * 100).toFixed(1)}%`;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));

  if (!process.env.ANTHROPIC_API_KEY) {
    console.error('ANTHROPIC_API_KEY is not set — the regression gate runs real audits.');
    process.exit(2);
  }

  const contests = selectContests(args);
  const baseline = loadBaseline();

  console.log(`Shadow regression: ${contests.length} contest(s)`);
  console.log(`Baseline: ${existsSync(BASELINE_PATH) ? BASELINE_PATH : '(none yet)'}`);
  console.log(`Mode: ${args.update ? 'UPDATE BASELINE' : 'CHECK'}\n`);

  const results: ShadowAuditResult[] = await runBatchShadowAudit(contests, {
    workDir: args.workDir,
    patternsDir: join(REPO_ROOT, 'patterns'),
    quick: args.quick,
    verbose: args.verbose,
  });

  const blocking: string[] = [];
  const warnings: string[] = [];
  const rows: string[] = [];

  for (const result of results) {
    if (result.error) {
      blocking.push(`${result.contestId}: audit failed — ${result.error}`);
      continue;
    }

    const c = result.comparison;
    const prior = baseline.entries[result.contestId];

    if (args.update) {
      baseline.entries[result.contestId] = {
        contestId: result.contestId,
        contestName: result.contestName,
        falsePositives: c.falsePositives,
        truePositives: c.truePositives,
        precision: c.precision,
        recall: c.recall,
        recordedAt: new Date().toISOString(),
      };
      rows.push(`  ${result.contestId}: recorded FP=${c.falsePositives} P=${pct(c.precision)} R=${pct(c.recall)}`);
      continue;
    }

    if (!prior) {
      warnings.push(`${result.contestId}: no baseline entry — run with --update to record one. FP=${c.falsePositives} P=${pct(c.precision)} R=${pct(c.recall)}`);
      continue;
    }

    const fpDelta = c.falsePositives - prior.falsePositives;
    const recallDeltaPp = (c.recall - prior.recall) * 100;

    // Precision is the product. Any new FP blocks, full stop.
    if (fpDelta > 0) {
      blocking.push(
        `${result.contestId}: ${fpDelta} NEW false positive(s) — ${prior.falsePositives} → ${c.falsePositives}`,
      );
    }

    if (recallDeltaPp < -args.maxRecallDrop) {
      blocking.push(
        `${result.contestId}: recall dropped ${Math.abs(recallDeltaPp).toFixed(1)}pp ` +
        `(${pct(prior.recall)} → ${pct(c.recall)}), limit is ${args.maxRecallDrop}pp`,
      );
    }

    if (recallDeltaPp > 0.05) {
      warnings.push(
        `${result.contestId}: recall improved ${recallDeltaPp.toFixed(1)}pp ` +
        `(${pct(prior.recall)} → ${pct(c.recall)}) — re-baseline with --update once you trust it`,
      );
    }

    if (fpDelta < 0) {
      warnings.push(`${result.contestId}: ${Math.abs(fpDelta)} fewer false positive(s) — good`);
    }

    rows.push(
      `  ${result.contestId}: FP ${prior.falsePositives}→${c.falsePositives} | ` +
      `P ${pct(prior.precision)}→${pct(c.precision)} | R ${pct(prior.recall)}→${pct(c.recall)}`,
    );
  }

  console.log('\n─── Results ───');
  for (const row of rows) console.log(row);

  if (args.update) {
    saveBaseline(baseline);
    console.log(`\nBaseline written to ${BASELINE_PATH}`);
    return;
  }

  if (warnings.length > 0) {
    console.log('\n─── Warnings ───');
    for (const w of warnings) console.log(`  ⚠ ${w}`);
  }

  if (blocking.length > 0) {
    console.log('\n─── BLOCKING ───');
    for (const b of blocking) console.log(`  ✗ ${b}`);
    console.log(`\nRegression gate FAILED (${blocking.length} blocking issue(s)).`);
    process.exit(1);
  }

  console.log('\nRegression gate PASSED — no new false positives, no recall regression.');
}

main().catch(err => {
  console.error(err instanceof Error ? err.stack : err);
  process.exit(2);
});
