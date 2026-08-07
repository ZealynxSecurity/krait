/**
 * Second-pass detection agents.
 *
 * B4 — RESCAN: broad agents re-read the codebase told explicitly what pass 1 already
 * found, so their attention goes to the gaps. Counters the attention-saturation effect
 * where a prominent bug masks quieter ones nearby.
 *
 * B3 — PER-CONTRACT: one agent per inheritance cluster with a narrow scope. Counters
 * attention dilution on multi-contract codebases, where a whole-codebase agent spends
 * its budget on the two most interesting files.
 *
 * Both are recall plays and both are exclusion-list driven: a candidate already found is
 * not worth spending a second agent's budget on. Neither invents new severity rules —
 * everything they surface still goes through the reasoner and the critic's kill gates.
 */

import Anthropic from '@anthropic-ai/sdk';
import { FileInfo, ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { CandidateFinding } from './types.js';
import { CandidateCounter, extractMethodologyFields } from './detector.js';
import { formatArchitectureForSystemPrompt } from '../analysis/architecture-pass.js';
import { runParallel } from '../core/parallel.js';

/** Max source characters handed to a single second-pass agent. */
const AGENT_CHAR_BUDGET = 60_000;
/** B3 — at most this many clusters get an agent (cost control). */
const MAX_CLUSTERS = 8;
/** B3 — a cluster stops accepting files past this size. */
const CLUSTER_CHAR_CAP = 45_000;

export interface SecondPassOptions {
  architectureContext?: ArchitectureAnalysis | null;
  verbose?: boolean;
  /** B4 — how many broad rescan agents to run. Default 2. */
  rescanAgents?: number;
  concurrency?: number;
}

const CANDIDATE_TOOL: Anthropic.Tool = {
  name: 'report_candidates',
  description: 'Report security issues that the first pass MISSED. Do not repeat anything on the exclusion list.',
  input_schema: {
    type: 'object' as const,
    properties: {
      candidates: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            title: { type: 'string' },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
            file: { type: 'string', description: 'Relative path of the file this is in — required, you are looking at several files.' },
            line: { type: 'number' },
            endLine: { type: 'number' },
            category: { type: 'string' },
            description: { type: 'string', description: 'What is wrong and why' },
            codeSnippet: { type: 'string' },
            affectedFunctions: { type: 'array', items: { type: 'string' } },
            relatedContracts: { type: 'array', items: { type: 'string' } },
            confidence: { type: 'number', description: 'Confidence 0-100' },
            remediation: { type: 'string' },
            depthEvidence: {
              type: 'array',
              items: { type: 'string' },
              description: 'Concrete-value tags: ["[BOUNDARY:amount=0]", "[TRACE:withdraw(MAX)→revert L120]"]',
            },
            missingPrecondition: { type: 'string' },
            postconditionsCreated: { type: 'string' },
            whoBenefits: { type: 'string' },
          },
          required: ['title', 'severity', 'file', 'line', 'category', 'description', 'confidence'],
        },
      },
    },
    required: ['candidates'],
  },
};

/**
 * Compact one-line-per-candidate exclusion list. Kept terse on purpose: the agent needs
 * to recognise a duplicate, not re-litigate the original analysis. Passing full
 * descriptions would both blow the budget and anchor the agent on prior conclusions.
 */
export function buildExclusionList(candidates: CandidateFinding[]): string {
  if (candidates.length === 0) return '(nothing found yet — you are the first pass over this code)';
  return candidates
    .map(c => `- [${c.severity.toUpperCase()}] ${c.file}:${c.line} — ${c.title}`)
    .join('\n');
}

/**
 * Files that produced no candidate in pass 1. These are the blind spots — an agent's
 * attention is worth more here than on the file that already yielded five findings.
 */
export function findUncoveredFiles(files: FileInfo[], candidates: CandidateFinding[]): string[] {
  const covered = new Set(candidates.map(c => c.file));
  return files.map(f => f.relativePath).filter(p => !covered.has(p));
}

/**
 * Declarations of the form `contract A is B, C` / `abstract contract A is B` /
 * `library A` / `interface A is B`. Captures the declared name and the inherit list.
 */
const DECL_RE = /(?:^|\n)\s*(?:abstract\s+)?(?:contract|library|interface)\s+(\w+)(?:\s+is\s+([^{]+))?/g;

/**
 * Map every contract/library/interface name to the file that declares it, and collect
 * each declaration's parents. Regex-level, deliberately: this only decides how to GROUP
 * files for analysis, so a missed edge costs a slightly worse cluster, never a wrong result.
 */
export function parseInheritance(contents: Map<string, string>): {
  declaredIn: Map<string, string>;
  parentsOf: Map<string, string[]>;
} {
  const declaredIn = new Map<string, string>();
  const parentsOf = new Map<string, string[]>();

  for (const [path, source] of contents) {
    DECL_RE.lastIndex = 0;
    let m: RegExpExecArray | null;
    while ((m = DECL_RE.exec(source)) !== null) {
      const name = m[1];
      declaredIn.set(name, path);
      if (m[2]) {
        // Strip constructor-argument groups BEFORE splitting: `ERC20("n","s"), Base`
        // contains a comma inside the parens, so splitting first would shred it.
        const parents = stripParenGroups(m[2])
          .split(',')
          .map(s => s.trim())
          .filter(s => /^\w+$/.test(s));
        if (parents.length > 0) parentsOf.set(name, parents);
      }
    }
  }

  return { declaredIn, parentsOf };
}

/** Remove balanced `(...)` groups, including nested ones, leaving the surrounding text. */
function stripParenGroups(s: string): string {
  let out = '';
  let depth = 0;
  for (const ch of s) {
    if (ch === '(') depth++;
    else if (ch === ')') depth = Math.max(0, depth - 1);
    else if (depth === 0) out += ch;
  }
  return out;
}

/**
 * B3 — group files into analysis clusters.
 *
 * Merges a contract with the files declaring its parents, so a base and its derived
 * contracts land in one cluster — a "missing" check often lives in the parent, and an
 * agent that only sees the child reports a false positive. Clusters are capped by
 * character budget and count.
 */
export function buildClusters(
  files: FileInfo[],
  contents: Map<string, string>,
  _architecture?: ArchitectureAnalysis | null,
): string[][] {
  const size = (p: string) => contents.get(p)?.length ?? 0;
  const inScope = files.map(f => f.relativePath).filter(p => contents.has(p));
  const inScopeSet = new Set(inScope);

  // Seed each file as its own cluster, then merge along inheritance edges.
  const clusterOf = new Map<string, number>();
  inScope.forEach((p, i) => clusterOf.set(p, i));

  const merge = (a: string, b: string) => {
    const ca = clusterOf.get(a);
    const cb = clusterOf.get(b);
    if (ca === undefined || cb === undefined || ca === cb) return;
    for (const [p, c] of clusterOf) if (c === cb) clusterOf.set(p, ca);
  };

  const { declaredIn, parentsOf } = parseInheritance(contents);
  for (const [child, parents] of parentsOf) {
    const childPath = declaredIn.get(child);
    if (!childPath || !inScopeSet.has(childPath)) continue;
    for (const parent of parents) {
      const parentPath = declaredIn.get(parent);
      if (parentPath && parentPath !== childPath && inScopeSet.has(parentPath)) {
        merge(childPath, parentPath);
      }
    }
  }

  const grouped = new Map<number, string[]>();
  for (const p of inScope) {
    const c = clusterOf.get(p)!;
    const bucket = grouped.get(c);
    if (bucket) bucket.push(p);
    else grouped.set(c, [p]);
  }

  // Split any cluster that blew the character cap; keep the largest clusters first,
  // since inheritance groups carry more cross-file signal than lone files.
  const clusters: string[][] = [];
  for (const members of grouped.values()) {
    let current: string[] = [];
    let used = 0;
    for (const p of members) {
      const s = size(p);
      if (current.length > 0 && used + s > CLUSTER_CHAR_CAP) {
        clusters.push(current);
        current = [];
        used = 0;
      }
      current.push(p);
      used += s;
    }
    if (current.length > 0) clusters.push(current);
  }

  clusters.sort((a, b) => {
    const byMembers = b.length - a.length;
    if (byMembers !== 0) return byMembers;
    return b.reduce((n, p) => n + size(p), 0) - a.reduce((n, p) => n + size(p), 0);
  });

  return clusters.slice(0, MAX_CLUSTERS);
}

/**
 * B4 — broad rescan with an exclusion list.
 *
 * Returns [] without any API call when pass 1 found nothing above Info: with no
 * exclusion list there is nothing for a rescan to diverge from, and running the same
 * broad analysis twice just pays twice for the same answer.
 */
export async function rescan(
  client: Anthropic,
  files: FileInfo[],
  contents: Map<string, string>,
  priorCandidates: CandidateFinding[],
  model: string,
  counter: CandidateCounter,
  cache?: ResponseCache | null,
  options?: SecondPassOptions,
): Promise<CandidateFinding[]> {
  const aboveInfo = priorCandidates.filter(c => c.severity !== 'low');
  if (aboveInfo.length === 0) {
    if (options?.verbose) {
      console.error('    [rescan] pass 1 found nothing above Info — skipping (hard exit rule)');
    }
    return [];
  }

  const agentCount = Math.max(1, Math.min(3, options?.rescanAgents ?? 2));
  const exclusion = buildExclusionList(priorCandidates);
  const uncovered = findUncoveredFiles(files, priorCandidates);

  // Interleave so each agent sees a spread of the codebase rather than one contiguous
  // slice; overlap between agents is intentional.
  const shards: FileInfo[][] = Array.from({ length: agentCount }, () => []);
  files.filter(f => contents.has(f.relativePath)).forEach((f, i) => {
    shards[i % agentCount].push(f);
  });

  const tasks = shards.map((shard, idx) => async () => {
    if (shard.length === 0) return [];
    const systemPrompt = buildRescanSystemPrompt(idx + 1, agentCount, exclusion, uncovered, options);
    const userPrompt = buildSourcePrompt(shard, contents);
    return callSecondPass(client, systemPrompt, userPrompt, model, counter, cache, `rescan-${idx + 1}`, options?.verbose);
  });

  const results = await runParallel(tasks, options?.concurrency ?? 3);
  return results.flat();
}

/**
 * B3 — per-contract focused analysis, one agent per inheritance cluster.
 */
export async function perContract(
  client: Anthropic,
  files: FileInfo[],
  contents: Map<string, string>,
  priorCandidates: CandidateFinding[],
  model: string,
  counter: CandidateCounter,
  cache?: ResponseCache | null,
  options?: SecondPassOptions,
): Promise<CandidateFinding[]> {
  const clusters = buildClusters(files, contents, options?.architectureContext);
  if (clusters.length === 0) return [];

  const exclusion = buildExclusionList(priorCandidates);
  const byPath = new Map(files.map(f => [f.relativePath, f]));

  const tasks = clusters.map((cluster, idx) => async () => {
    const shard = cluster.map(p => byPath.get(p)).filter((f): f is FileInfo => Boolean(f));
    if (shard.length === 0) return [];
    const systemPrompt = buildPerContractSystemPrompt(cluster, exclusion, options);
    const userPrompt = buildSourcePrompt(shard, contents);
    return callSecondPass(client, systemPrompt, userPrompt, model, counter, cache, `per-contract-${idx + 1}`, options?.verbose);
  });

  const results = await runParallel(tasks, options?.concurrency ?? 3);
  return results.flat();
}

// ─── prompts ─────────────────────────────────────────────────────────────────

function buildRescanSystemPrompt(
  index: number,
  total: number,
  exclusion: string,
  uncovered: string[],
  options?: SecondPassOptions,
): string {
  const arch = options?.architectureContext
    ? `\n${formatArchitectureForSystemPrompt(options.architectureContext)}\n`
    : '';

  const blindSpots = uncovered.length > 0
    ? `\n## Blind spots — files the first pass found NOTHING in\n\n${uncovered.map(f => `- ${f}`).join('\n')}\n\nA file with no findings is UNDER-ANALYZED, not clean. Spend your time here first.\n`
    : '';

  return `You are Rescan Agent ${index} of ${total} — the SECOND pass over this codebase.

A first pass already analyzed this code and found the issues listed below. Your job is to find what it MISSED. You are not re-checking its work.
${arch}
## Already-known findings — DO NOT REPORT THESE

${exclusion}

If something you spot matches one of these in location AND root cause, skip it silently.
Reporting a duplicate wastes the slot; the pipeline will drop it anyway.
${blindSpots}
## What attention saturation hides

A first pass fixates on the most prominent bug in each file and under-reads everything near it. Look specifically for:

1. **Cross-function state inconsistencies** — function A assumes an invariant that function B breaks
2. **Asymmetric operations** — the deposit path handles X but the withdraw path does not
3. **Parameter encoding mismatches between paired functions** — create/consume, lock/unlock, deposit/refund, encode/decode. Do both sides use the same inputs in the same order?
4. **Economic assumptions violated at the edges** — first user, last user, zero state, max state
5. **Time-dependent state going stale** under a specific operation sequence
6. **The quiet file next to the interesting one** — the helper, the library, the base contract

## Rules

- Every finding needs a **specific file:line**. No location, no finding.
- Report the file path exactly as given in the source headers below.
- Do not report generic best practice ("use SafeERC20", "add events", "missing zero-address check"). A later gate kills those automatically, so they only cost you budget.
- Prefer one well-traced finding over five speculative ones, but do not self-censor a concrete mechanism just because you are unsure of the impact — a Critic validates later.
- Where you reason with concrete values, record them in \`depthEvidence\` (e.g. \`[BOUNDARY:reserve=0]\`, \`[TRACE:redeem(MAX)→revert L88]\`).`;
}

function buildPerContractSystemPrompt(
  cluster: string[],
  exclusion: string,
  options?: SecondPassOptions,
): string {
  const arch = options?.architectureContext
    ? `\n${formatArchitectureForSystemPrompt(options.architectureContext)}\n`
    : '';

  return `You are a Per-Contract Analysis Agent. Your scope is deliberately NARROW:

${cluster.map(f => `- ${f}`).join('\n')}

Analyze ONLY these files, at MAXIMUM depth. Broad-scope agents have already swept the whole codebase; your value is the depth they could not afford. Do not wander into other contracts.
${arch}
## Already-known findings — DO NOT REPORT THESE

${exclusion}

## Method — apply to EVERY function in scope

1. **State completeness** — does every state-modifying path update ALL related state? (timestamps, accumulators, snapshots, mirrored balances)
2. **Conditional branch audit** — for each if/else, what state is written in each branch? Is anything stale on the skip path?
3. **Boundary values** — what happens at 0, 1, MAX, and the type boundary for every parameter?
4. **Pairing audit** — for each encode/normalize/hash/lock, trace its inverse (decode/denormalize/verify/unlock). Same inputs, same order?
5. **Fee and reward trace** — follow accrual → accumulation → claim → transfer. Do assets and shares stay consistent at every step?
6. **Inheritance** — if a base contract is in your cluster, check the parent's unconditional paths on their own terms, not only through the child's override.

When an issue sits on a boundary with a contract outside your scope, describe it from YOUR file's perspective and name the external contract. Do not trace into it — that is another agent's job.

## Rules

- Every finding needs a **specific file:line**, using the path exactly as given below.
- Maximum 5 findings. Prioritise by severity — this is a depth pass, not a volume pass.
- Do not report generic best practice; a later gate kills those automatically.
- Record concrete values you tested in \`depthEvidence\`.`;
}

function buildSourcePrompt(files: FileInfo[], contents: Map<string, string>): string {
  const parts: string[] = [];
  let used = 0;
  let truncated = 0;

  for (const f of files) {
    const content = contents.get(f.relativePath);
    if (!content) continue;
    if (used + content.length > AGENT_CHAR_BUDGET) {
      truncated++;
      continue;
    }
    used += content.length;
    const numbered = content
      .split('\n')
      .map((l, i) => `${String(i + 1).padStart(4)}  ${l}`)
      .join('\n');
    parts.push(`### FILE: ${f.relativePath}\n\`\`\`solidity\n${numbered}\n\`\`\``);
  }

  const note = truncated > 0
    ? `\n\n(${truncated} further file(s) omitted for budget — report only on what is shown above.)`
    : '';

  return `## Source\n\n${parts.join('\n\n')}${note}\n\nReport only issues NOT on the exclusion list. Use the exact file paths shown in the FILE headers.`;
}

// ─── transport ───────────────────────────────────────────────────────────────

async function callSecondPass(
  client: Anthropic,
  systemPrompt: string,
  userPrompt: string,
  model: string,
  counter: CandidateCounter,
  cache: ResponseCache | null | undefined,
  label: string,
  verbose?: boolean,
): Promise<CandidateFinding[]> {
  let raw: Array<Record<string, unknown>> | null = null;

  if (cache) {
    const key = cache.computeKey(systemPrompt, userPrompt, model);
    const hit = cache.getJson<Array<Record<string, unknown>>>(key);
    if (hit) {
      if (verbose) console.error(`    [${label} cache hit]`);
      raw = hit;
    }
  }

  if (!raw) {
    try {
      const response = await client.messages.create({
        model,
        max_tokens: 8192,
        system: systemPrompt,
        tools: [CANDIDATE_TOOL],
        tool_choice: { type: 'any' },
        messages: [{ role: 'user', content: userPrompt }],
      });

      raw = [];
      for (const block of response.content) {
        if (block.type === 'tool_use' && block.name === 'report_candidates') {
          const input = block.input as { candidates?: Array<Record<string, unknown>> };
          if (Array.isArray(input.candidates)) raw.push(...input.candidates);
        }
      }

      if (cache) {
        cache.setJson(cache.computeKey(systemPrompt, userPrompt, model), raw, model);
      }
    } catch (err) {
      // A second-pass agent is a recall bonus, never a hard dependency. Losing one
      // must not fail the audit.
      if (verbose) {
        console.error(`    [${label}] error — ${err instanceof Error ? err.message : err}`);
      }
      return [];
    }
  }

  const out = raw.map(r => ({
    id: counter.next(),
    title: String(r.title || 'Untitled'),
    severity: normalizeSeverity(r.severity),
    file: String(r.file || ''),
    line: Number(r.line) || 0,
    endLine: r.endLine ? Number(r.endLine) : undefined,
    category: String(r.category || 'unknown'),
    description: String(r.description || ''),
    codeSnippet: String(r.codeSnippet || ''),
    affectedFunctions: Array.isArray(r.affectedFunctions) ? r.affectedFunctions.map(String) : [],
    relatedContracts: Array.isArray(r.relatedContracts) ? r.relatedContracts.map(String) : [],
    detectorConfidence: Number(r.confidence) || 50,
    remediation: String(r.remediation || ''),
    ...extractMethodologyFields(r),
  })).filter(c => c.file.length > 0);

  if (verbose) console.error(`    [${label}] ${out.length} new candidates`);
  return out;
}

function normalizeSeverity(val: unknown): CandidateFinding['severity'] {
  const s = String(val).toLowerCase();
  if (s === 'critical' || s === 'high' || s === 'medium' || s === 'low') return s;
  return 'medium';
}
