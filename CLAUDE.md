# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project shape

Krait is a Solidity security auditor with **two delivery surfaces that share patterns and methodology but otherwise have separate runtimes**:

1. **Claude Code skill** under `.claude/` — invoked via `/krait`, `/krait-quick`, `/krait-proven`, `/krait-fuzz`, `/krait-review`, plus the read-only preflight `/krait-init`. Pure prompt + methodology files; runs inside the user's Claude session, no API key. Source of truth for the audit *methodology*.
2. **Standalone CLI** under `src/` (TypeScript, Node ≥20) — calls the Anthropic SDK directly. Used for batch/shadow audits and CI; needs `ANTHROPIC_API_KEY`.

When fixing bugs or adding heuristics, the methodology usually lives in BOTH places: the Claude Code instructions under `.claude/skills/krait/**/instructions.md` and the equivalent prompt builders/heuristics in `src/`. Check both before declaring a change complete. `METHODOLOGY.md` documents the canonical pipeline.

## Common commands

```
npm run build        # tsc → dist/
npm run dev          # tsx src/cli.ts (run CLI without building)
npm test             # vitest run (config: vitest.config.ts, only src/**/*.test.ts)
npm run test:watch
npm run lint         # eslint src/
npm run format       # prettier --write src/

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
  modules/     (15 deep-dive modules, loaded selectively by protocol type)
  primers/     (7 protocol primers: DEX, lending, staking, GameFi, bridges, proxies, wallets)
state-auditor/ (Phase 2: coupled-state pair analysis)
critic/        (Phase 3: 8 kill gates A–H, FP patterns)
reviewer/      (Phase 3b: second-opinion on killed findings)
reporter/      (Phase 4: format to .audit/krait-report.md + krait-findings.json)
fuzzer/        (used by /krait-fuzz)
```

Output for both surfaces lands in `.audit/` inside the target project (not this repo). The skill's reporter also emits a `https://krait.zealynx.io/...` web-links banner — keep that block intact when editing reporter prompts.

**Preflight is shared** between `/krait` and `/krait-init`. `/krait` runs the preflight in *gate mode* automatically (hard checks only; aborts on miss), so users never need to invoke `/krait-init` to get a clean run. `/krait-init` runs the same skill in *report mode* (full table, never aborts) for CI setup and debugging. If you change recon's tool requirements (forge / slither / jq) or the project shape it expects, mirror those changes in `.claude/skills/krait/preflight/instructions.md` — both commands pick them up automatically.

## MCP servers (`mcp-servers/`)

Each subdirectory is its own Node project with its own `package.json`, `tsconfig.json`, and build output under `build/`. Wired into Claude Code via the root `.mcp.json`.

- `mcp-servers/solodit/` — local YAML pattern search (`search_similar_findings`, `get_enrichment`, `validate_hypothesis`). Reads from `patterns/`.
- `mcp-servers/forge/` — Foundry gateway (`forge_version`, `forge_build`, `forge_test`, `forge_fmt_check`). Sandboxes `cwd` under the MCP root and caps output at 200 KB. Use this from `/krait-fuzz` and PoC-verification flows instead of pasting shell output back.

Both servers must be built (`npm install && npm run build` inside each) before Claude Code can launch them. Build output and `node_modules/` are gitignored per-server.

## Patterns directory

`patterns/` is consumed by both the CLI (`PatternLoader`) and the optional MCP server. New patterns must conform to `patterns/schema.yaml`. Subdirs are by domain (`solidity/`, `rust-solana/`, `web2-typescript/`, `ai-red-team/`) plus `learned/` for promoted patterns. The CLI auto-detects domain from file extensions in the target project.

## Editing the audit methodology

The repo iterates via blind shadow audits — see `shadow-audits/progress.md` and `shadow-audits/registry.yaml`. The current bar is **100% precision across 50 contests**, so any change that could raise FPs needs to be validated by re-running affected contests via `npm run dev shadow-audit` (or `node dist/cli.js shadow-audit`) before merging. False positives are treated as more severe than missed findings; the kill gates in `critic/instructions.md` are deliberately aggressive.
