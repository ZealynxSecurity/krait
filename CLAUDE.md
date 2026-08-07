# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project shape

Krait is a Solidity security auditor with **three delivery surfaces**. The first two share patterns and methodology but have separate runtimes; the third is a separate product that happens to live in the same repo.

1. **Claude Code skill** under `.claude/` — invoked via `/krait`, `/krait-quick`, `/krait-fuzz`, `/krait-review`, plus the read-only preflight `/krait-init`. Pure prompt + methodology files; runs inside the user's Claude session, no API key. Source of truth for the audit *methodology*.
2. **Standalone CLI** under `src/` (TypeScript, Node ≥20) — calls the Anthropic SDK directly. Used for batch/shadow audits and CI; needs `ANTHROPIC_API_KEY`.
3. **Checklist plugin** under `checklist/` — a self-contained Claude Code plugin providing `/krait:scan`, `/krait:assess`, `/krait:check`. Evaluates code against 845 fixed checks across 39 DeFi verticals and emits an importable assessment. **Do not apply the audit methodology here**: surfaces 1–2 reason adversarially toward exploit traces with a zero-FP bar; the checklist answers "am I audit-ready?" with per-check coverage. Changes to kill gates, heuristics or lenses do NOT propagate to it, and vice versa.

`checklist/` was migrated in from the Zealynx-WebSite repo, where it had been developed despite its own `plugin.json` naming this repo as its home. Its framework JSONs are a synced copy — the website's `public/frameworks/` is the source of truth, refreshed weekly from Solodit by a workflow in *that* repo. Pull updates with `checklist/scripts/sync-frameworks.sh <path-to-website>/public/frameworks`. The checklist↔website mapping bridge (`src/data/krait-checklist-mapping.ts`) and its maintainer skill intentionally stayed in the website repo, since they validate against that repo's published data.

Repo root carries `.claude-plugin/marketplace.json` so `/plugin marketplace add ZealynxSecurity/krait` resolves — the install path `checklist/README.md` had always documented but which had no manifest to back it. Install id is `krait@krait` (plugin `krait` from marketplace `krait`); skills are namespaced `<plugin>:<skill>`, giving `/krait:scan`, `/krait:assess`, `/krait:check`.

**Validate manifests after touching either one:**

```bash
claude plugin validate .            # marketplace
claude plugin validate ./checklist  # plugin
```

The migrated `plugin.json` had `"repository": { "type": "git", "url": ... }` — the schema requires a **string**, so validation failed and the plugin was uninstallable despite its README documenting the install. `src/agents/__tests__/plugin-manifest.test.ts` now asserts that invariant plus name/skill/framework wiring, so CI catches it without needing the Claude CLI. The CLI remains authoritative; the test is the cheap gate.

Renaming the plugin silently renames every command (`krait` → `/krait:scan`), so the test also pins the marketplace entry name to `plugin.json`'s name.

When fixing bugs or adding heuristics, the methodology lives in BOTH places: the Claude Code instructions under `.claude/skills/krait/**/instructions.md` and the equivalent prompt builders/heuristics in `src/`. Check both before declaring a change complete. `METHODOLOGY.md` documents the canonical pipeline.

**Surface parity is enforced, not aspirational (v8.2).** The two surfaces drifted badly once: the CLI critic ran a generic "skeptical reviewer" prompt with none of the 8 kill gates, while the published 100%-precision numbers were attributed to those gates — and `src/shadow/runner.ts` benchmarks the CLI, not the skill. That is fixed, and `src/agents/__tests__/parity.test.ts` now fails the build when a gate, the DoS carve-out, an FP pattern, or a reporter rule exists on one surface but not the other. If you add or rename one, update both surfaces **and** the parity test. Decision-critical prompt text lives in exported constants (`KILL_GATES`, `FP_PATTERNS`, `IMPACT_PREMISE` in `src/agents/critic.ts`) so the test can assert on it.

Prompts request behaviour; code enforces it. `enforceGateContract()` in `src/agents/critic.ts` forces a gate-attributed verdict to `invalid` no matter what the model returned, and treats FP-6 (severity inflation) as a correction rather than a kill. When you add a rule that decides whether a finding ships, add the mechanical enforcement too — a prompt instruction alone is not a gate.

**v8.1 — Tier A methodology audit trail.** Every detector / state-auditor / critic finding emits six structured fields alongside the standard schema: `stepExecution` (which lenses/phases/gates ran), `rulesApplied` (R8 cached params, R10 worst-state severity, R11 unsolicited token transfer, R12 enabler enumeration, R15 flash-loan precondition, R16 oracle integrity), `depthEvidence` (`[BOUNDARY:…]` / `[VARIATION:…]` / `[TRACE:…]` tags), `missingPrecondition` + `preconditionType`, `postconditionsCreated` + `postconditionTypes` + `whoBenefits`. The rule and tag definitions are ported (under MIT) from PlamenTSV/plamen. All six are **optional** — pre-existing caches and findings still validate. CLI types live in `src/agents/types.ts` and `src/core/types.ts`; merge logic between the three pipeline stages is in `src/agents/ranker.ts` (`mergeMethodologyFields`). Schema is also embedded in the four skill files (`detector/state-auditor/critic/reviewer/instructions.md`). When adding new findings or modifying agent prompts, keep the audit-trail emission patterns consistent — they're the foundation for future chain analysis (D2 in `improvements-backlog.md`).

## Common commands

```
npm run build        # tsc → dist/
npm run dev          # tsx src/cli.ts (run CLI without building)
npm test             # vitest run (config: vitest.config.ts, only src/**/*.test.ts)
npm run test:watch
npm run lint         # eslint src/
npm run format       # prettier --write src/

npm run install:skills   # copy skills to ~/.claude + build + register MCP servers
npm run mcp:build        # build both MCP servers (also runs on postinstall)
npm run mcp:rebuild      # force reinstall + rebuild
npm run shadow:regress   # regression gate — see below

# Run a single test file or test by name:
npx vitest run src/core/__tests__/cache.test.ts
npx vitest run -t "kill gate"

# MCP servers (each is a separate Node project under mcp-servers/):
cd mcp-servers/solodit && npm install && npm run build   # local pattern search
cd mcp-servers/forge   && npm install && npm run build   # forge build/test gateway
```

The compiled CLI exposes (`src/cli.ts`): `audit`, `fuzz`, `patterns`, `compare`, `shadow-audit`, `dashboard`, `contests`, `ingest-solodit`, `version`. `--help` on each reveals options. `--dry-run` is supported on `audit` and `fuzz` and avoids API calls.

## CLI architecture (`src/`)

The audit uses a **multi-agent pipeline** orchestrated by `src/agents/multi-agent.ts`:

```
Detector (wide net, per-file, parallel)
  → Reasoner (deepens candidates with cross-file context)
  → Critic (8 kill gates A–H + 10 FP patterns; aggressive — zero-FP is the goal)
  → Ranker (composite score; default threshold 40)
```

- `src/analysis/` — pre-pipeline passes: `architecture-pass.ts` (whole-codebase arch summary), `contract-summarizer.ts`, `context-gatherer.ts`, plus the `ai-analyzer.ts` (legacy single-pass mode used when `--no-multi-agent`), `deduplicator.ts`, `post-processor.ts` (Solodit enrichment).
- `src/core/` — infra: `config.ts` (env + flag resolution), `file-discovery.ts`/`file-scorer.ts` (deterministic risk scoring → tiers, see `RISK_SCORE` formula in METHODOLOGY.md), `cache.ts` (response cache, `.krait-cache/`), `parallel.ts`, `reporter.ts` (md + JSON), `comparator.ts` (used by `compare` and `shadow-audit`).
- `src/knowledge/` — pattern + Solodit data: `pattern-loader.ts` reads YAML from `patterns/` per the schema in `patterns/schema.yaml`; `solodit-client.ts` + `solodit-parser.ts` handle live and pre-ingested data.
- `src/fuzzer/` — `fuzz` command pipeline: invariant extraction → Foundry test generation → run/fix loop → report. Requires `forge` on PATH and a Foundry project as input.
- `src/shadow/` — benchmarking: `runner.ts` clones contests from `shadow-audits/registry.yaml`, runs Krait, diffs against official findings via `comparator.ts`, updates `dashboard.ts`. Results go to `shadow-results/` (gitignored).

`src/agents/__tests__/` has unit tests for each pipeline stage; `src/core/__tests__/` covers cache + scorer. Vitest globals are enabled (`describe`/`it` available without import).

## Skill architecture (`.claude/`)

`.claude/commands/*.md` are the slash-command entry points. Each one is a thin wrapper that tells Claude to **read and follow** the corresponding `instructions.md` under `.claude/skills/krait/<phase>/`. The phases mirror the CLI agents:

```
preflight/     (shared readiness check; gate mode for /krait, report mode for /krait-init)
recon/         (Phase 0: AST + Slither + risk scoring + primer selection)
detector/      (Phase 1: 3-pass detection, 4 lenses × 4 mindsets)
  modules/           (15 deep-dive modules, loaded selectively by protocol type)
  primers/           (7 protocol primers: DEX, lending, staking, GameFi, bridges, proxies, wallets)
  heuristics-core.md (43 core trigger heuristics — extracted from instructions.md in v8.2)
  heuristics-extended.md (58 further vectors from open-source sources)
  rescan.md          (Phase 1b: broad second pass with exclusion list)
  per-contract.md    (Phase 1c: one agent per inheritance cluster)
state-auditor/ (Phase 2: coupled-state pair analysis)
critic/        (Phase 3: 8 kill gates A–H, Impact Premise, FP patterns)
reviewer/      (Phase 3b: second-opinion on killed findings)
reporter/      (Phase 4: consolidation + trust downgrade + format to .audit/)
fuzzer/        (used by /krait-fuzz)
```

`detector/instructions.md` has a **700-line cap**, asserted by the parity test. v7 measured
that shrinking it improved instruction adherence, and it had grown back past the threshold
by v8.1. When it approaches the cap, extract a catalogue into its own file and leave a
pointer — do not delete methodology to fit.

Output for both surfaces lands in `.audit/` inside the target project (not this repo). The skill's reporter also emits a `https://krait.zealynx.io/...` web-links banner — keep that block intact when editing reporter prompts.

**Preflight is shared** between `/krait` and `/krait-init`. `/krait` runs the preflight in *gate mode* automatically (hard checks only; aborts on miss), so users never need to invoke `/krait-init` to get a clean run. `/krait-init` runs the same skill in *report mode* (full table, never aborts) for CI setup and debugging. If you change recon's tool requirements (forge / slither / jq) or the project shape it expects, mirror those changes in `.claude/skills/krait/preflight/instructions.md` — both commands pick them up automatically.

## MCP servers (`mcp-servers/`)

Each subdirectory is its own Node project with its own `package.json`, `tsconfig.json`, and build output under `build/`.

- `mcp-servers/solodit/` — local YAML pattern search (`search_similar_findings`, `get_enrichment`, `validate_hypothesis`). Reads from `patterns/`.
- `mcp-servers/forge/` — Foundry gateway (`forge_version`, `forge_build`, `forge_test`, `forge_fmt_check`). Sandboxes `cwd` under the MCP root and caps output at 200 KB. Use this from `/krait-fuzz` and PoC-verification flows instead of pasting shell output back.

**Two registration scopes, and the difference matters.** The root `.mcp.json` uses paths relative to the project root, so it only works when Claude Code is open *in this clone* — useless for a user auditing their own project, which is the actual use case. `scripts/install.sh` therefore registers both servers at **user scope** with absolute paths (`claude mcp add <name> --scope user -- node <abs>/build/index.js`), so they resolve everywhere. Keep `.mcp.json` for working inside this repo; don't treat it as the user-facing wiring.

Builds are automatic: `scripts/build-mcp.sh` runs on `postinstall` and from `scripts/install.sh`. It is deliberately **non-fatal** — a missing toolchain or a broken optional server prints a diagnostic and exits 0, because neither should ever block `npm install` or an audit. Skip it with `KRAIT_SKIP_MCP_BUILD=1`; force a clean rebuild with `npm run mcp:rebuild`. Build output and `node_modules/` are gitignored per-server.

## Patterns directory

`patterns/` is consumed by both the CLI (`PatternLoader`) and the optional MCP server. New patterns must conform to `patterns/schema.yaml`. Subdirs are by domain (`solidity/`, `rust-solana/`, `web2-typescript/`, `ai-red-team/`) plus `learned/` for promoted patterns. The CLI auto-detects domain from file extensions in the target project.

## Editing the audit methodology

The repo iterates via blind shadow audits — see `shadow-audits/progress.md` and `shadow-audits/registry.yaml`. The measured bar is **100% precision across 50 contests (v8)**. False positives are treated as more severe than missed findings; the kill gates in `critic/instructions.md` are deliberately aggressive.

Validate a change with the regression gate rather than by eyeballing a report:

```bash
npm run shadow:regress -- --contests <ids> --update   # record the current baseline
npm run shadow:regress -- --contests <ids>            # gate a change against it
```

It blocks on **any** new false positive and on a recall drop worse than 2 pp (tunable with `--max-recall-drop`). Baseline lives in `shadow-audits/regression-baseline.json`. Needs `ANTHROPIC_API_KEY`, since it runs real audits.

**Version claims must track measurement.** v8.1 and v8.2 changed methodology after the 50-contest run and have NOT been re-measured. `METHODOLOGY.md` quarantines their numbers under "Unvalidated since the v8 baseline", and the README publishes only v8. Do not promote an unmeasured version into a headline table — a 3-contest pilot against stale baselines is a hint, not a benchmark. When the full regression runs, move the numbers up and delete the quarantine section.
