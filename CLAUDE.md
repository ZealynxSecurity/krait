# CLAUDE.md — Krait AI Security Auditor

## What Is Krait

Krait is an AI-first multi-domain security auditor built by Zealynx Security. It uses Claude as the core analysis engine, with structured vulnerability patterns as context — not regex-based detection. Named after one of the deadliest snakes: silent, precise, lethal.

## Owner

Carlos Vendrell Felici (@TheBlockChainer / @Bloqarl), founder of Zealynx Security.

## Two Modes of Operation

### 1. Claude Code Skills (Zero Cost)
Run `/krait` inside Claude Code on any project. Uses your Claude subscription — no API costs.
- `/krait` — Full 4-phase audit (recon → detect → state analysis → verify → report)
- `/krait-quick` — Fast mode (skips state analysis)
- `/krait-recon`, `/krait-detect`, `/krait-state`, `/krait-critic`, `/krait-report` — Individual phases

### 2. CLI Tool (API-Powered)
Run `npx krait audit <path>` for automated batch processing. Uses Anthropic API — costs money per run.
See "Build Instructions" below for CLI development phases.

## Build Instructions

This project is being built from scratch. Follow the phases below **in order**. Complete each phase fully before moving to the next. Do not skip steps. Do not over-engineer — keep it lean and working.

### Pre-Build Setup

1. Create GitHub repo: `gh repo create ZealynxSecurity/krait --private --clone`
2. Initialize: TypeScript, Node.js, strict tsconfig
3. Copy YAML patterns from old repo: `gh api 'repos/ZealynxSecurity/agent-training/git/trees/main?recursive=1'` — download all `patterns/**/*.yaml` files. These are 161 real vulnerability patterns extracted from actual audits. They are the seed knowledge base.

### Phase 1: Foundation

**Goal**: CLI that can ingest a project directory and output structured findings using Claude.

1. **Project scaffold**:
   - `src/cli.ts` — CLI entry point (Commander.js)
   - `src/core/types.ts` — Core type definitions (Finding, Report, Severity, etc.)
   - `src/core/config.ts` — Configuration management
   - `package.json` with scripts: `build`, `dev`, `test`, `lint`
   - `tsconfig.json` — strict mode

2. **Pattern loader** (`src/knowledge/pattern-loader.ts`):
   - Load all YAML patterns from `patterns/` directory
   - Parse into structured `VulnerabilityPattern[]`
   - Validate against schema
   - Expose as formatted context string for LLM prompts

3. **File discovery** (`src/core/file-discovery.ts`):
   - Discover source files in target project
   - Smart filtering: exclude tests, node_modules, libraries, mocks
   - Support multiple languages: `.sol`, `.rs`, `.ts`, `.js`
   - Return structured file list with metadata (path, language, LOC)

4. **AI Analyzer** (`src/analysis/ai-analyzer.ts`):
   - **This is the core engine**. Claude analyzes code, not regex.
   - Takes: source file content + relevant patterns + project context
   - Returns: structured findings with file, line, severity, description, remediation
   - Uses Anthropic SDK directly (`@anthropic-ai/sdk`)
   - Model selection: Sonnet for initial pass, Opus for deep analysis (configurable)
   - Structured output via tool_use to enforce finding schema
   - Rate limiting and retry logic

5. **Report generator** (`src/core/reporter.ts`):
   - Generate JSON report (machine-readable)
   - Generate Markdown report (human-readable)
   - Include: findings with file:line, severity breakdown, confidence scores

6. **CLI commands**:
   - `krait audit <path>` — run full audit on a project directory
   - `krait audit <path> --quick` — fast pass (Sonnet only, no cross-contract)
   - `krait patterns` — list loaded patterns and stats
   - `krait version`

7. **Validation — REAL, NOT MOCKED**:
   - Clone a known past contest (e.g., `2023-07-amphora` from Code4rena — small, well-documented)
   - Run Krait against it using REAL Anthropic API calls (Sonnet)
   - Compare Krait's findings against the official accepted findings
   - Verify every finding has: real file path, real line number, valid severity, actionable description
   - Measure precision and recall against known results
   - If precision < 50% or findings lack file:line — fix before moving on
   - **Do not proceed to Phase 2 until this validation passes**
   - Budget: ~$1-3 per shadow audit run using Sonnet. This is the cost of building something real.

### Phase 2: Detection Quality

**Goal**: Multi-pass analysis that catches real vulnerabilities with high precision.

1. **Per-file analysis**: Each source file analyzed individually against relevant patterns
2. **Cross-contract analysis**: After per-file pass, analyze interactions between contracts (call graphs, state dependencies, trust boundaries)
3. **Slither integration** (optional pre-filter): Run Slither, parse output, feed as additional context to Claude
4. **Deduplication**: Merge findings that describe the same issue from different analysis passes
5. **Confidence scoring**: Based on pattern match strength, cross-references, and LLM confidence
6. **False positive reduction**: Domain-specific heuristics (test file exclusion, standard library awareness, modifier detection)
7. **Validation**: Re-run against amphora + at least 2 more contests (e.g., asymmetry, salty). Track precision/recall improvements. Target: 60%+ precision, 30%+ recall before moving on.

### Phase 3: Shadow Audit Pipeline

**Goal**: Automated benchmarking against known public contest results.

1. **Contest registry**: Curated list of past C4/Sherlock/CodeHawks contests with known findings
2. **Shadow audit runner**: Clone repo → Run Krait blind → Fetch official findings → Compare
3. **Scoring**: Precision, Recall, F1, broken down by severity
4. **Feedback reports**: For each miss, generate a pattern suggestion
5. **GitHub Actions workflow**: Schedule weekly shadow audits, publish results
6. **Performance dashboard**: Track improvement over time

### Phase 4: Solodit Ingestion

**Goal**: Absorb 49K+ real audit findings into the pattern database.

1. Clone `solodit/solodit_content` repo (public)
2. Parse all finding markdown files into structured data
3. Use Claude to classify each into vulnerability taxonomy
4. Generate new YAML patterns from clusters of similar findings
5. Deduplicate against existing patterns
6. Quality gate: only add patterns with 3+ real examples

### Phase 5: Multi-Domain

**Goal**: Extend beyond Solidity to cover all four domains.

1. **Rust/Solana**: Anchor-specific patterns, account validation, CPI security
2. **TypeScript/Web2**: OWASP Top 10, API security, auth bypass, SSRF, injection
3. **AI/MCP Security**: Prompt injection, function-calling abuse, model evasion, data poisoning
4. Domain-specific file discovery and analysis prompts
5. Language-aware pattern loading (only load relevant patterns per domain)

### Phase 6: Productization

1. **npm package**: `npx @zealynx/krait audit ./my-protocol`
2. **GitHub Action**: Run on PRs, comment findings
3. **API endpoint**: POST code → GET report
4. **PDF reports**: Professional format for client deliverables

---

## Architecture

```
Target Project Directory
        │
        ▼
  ┌─────────────┐
  │ File Discovery │  ← Smart filtering (exclude tests, libs, mocks)
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ Pattern Loader │  ← 161+ YAML patterns as structured LLM context
  └──────┬──────┘
         │
         ▼
  ┌─────────────────┐
  │ AI Analyzer       │  ← Claude (Sonnet speed pass → Opus deep analysis)
  │                   │     Per-file + cross-contract + economic logic
  │  [Anthropic API]  │     Structured output via tool_use
  └──────┬──────────┘
         │
         ▼
  ┌─────────────┐
  │ Post-Processing │  ← Dedup, confidence scoring, FP reduction
  └──────┬──────┘
         │
         ▼
  ┌─────────────┐
  │ Reporter      │  ← JSON + Markdown + PDF output
  └─────────────┘
```

## Tech Stack

- **Language**: TypeScript (Node.js 20+)
- **AI**: Anthropic SDK (`@anthropic-ai/sdk`) — Sonnet 4.6 for speed, Opus 4.6 for depth
- **CLI**: Commander.js
- **YAML parsing**: js-yaml
- **Testing**: Vitest
- **Linting**: ESLint + Prettier
- **Static analysis**: Slither (optional, for Solidity pre-filtering)
- **CI/CD**: GitHub Actions

## API Key & Cost Model

**Two separate systems, two separate billing:**

1. **Claude Code (this CLI building the project)** — Max plan, free. No API cost for development work.
2. **Krait's runtime API calls** — When Krait audits code, it calls the Anthropic API via `@anthropic-ai/sdk`. This costs real money per token. Set `ANTHROPIC_API_KEY` env var or pass `--api-key` flag.

**Cost estimates per audit run (Sonnet):**
- Small project (~500 LOC): ~$0.30-0.50
- Medium project (~2K LOC): ~$1-3
- Large project (~10K LOC): ~$5-15

**IMPORTANT**: Always test with real API calls, never mocks. The whole point is validating real output quality. Use Sonnet during development. Opus for production audits.

**Never skip real validation to save money.** Building a tool that doesn't work costs infinitely more than $3 of API calls.

## Patterns

Patterns live in `patterns/` as YAML files following the schema in `patterns/schema.yaml`. Each pattern has:
- `id`, `name`, `category`, `severity`
- `detection.strategy` — human-readable description of what to look for
- `detection.indicators` — code smells and signals
- `real_examples` — actual audit findings with vulnerable + fixed code
- `false_positive_notes` — when the pattern is actually safe

Patterns are NOT used for regex matching. They are formatted and included in the LLM system prompt so Claude knows what vulnerability classes to look for and has real examples to reference.

## Key Principles

1. **AI is the engine, not a supplement.** Claude analyzes code. Patterns provide knowledge context. Regex is dead.
2. **Every finding must have file:line.** No generic warnings. Actionable or nothing.
3. **Precision over recall.** Better to miss subtle issues than flood with false positives.
4. **Multi-domain from day one.** Architecture supports Solidity, Rust, TypeScript, AI — even if only Solidity is implemented first.
5. **Shadow audits are the training loop.** Regular automated benchmarking against known contests drives improvement.
6. **Keep it lean.** No fake agents, no unnecessary abstractions, no over-engineering.

## Communication Style

Be direct. Skip theory. Show working code and results. When something doesn't work, say so and fix it.

**Always give brutally honest, back-to-reality feedback.** When asked to evaluate progress, features, or results — don't sugarcoat. Compare claims against actual data. Call out when we're building features before fixing the core, when metrics are misleading, when we're optimizing for the wrong thing. The owner needs tough truth, not comfortable narratives. This applies to everything we build, not just Krait.

## Related Resources

- Old patterns to copy: `ZealynxSecurity/agent-training` repo, `patterns/` directory
- Solodit content: `solodit/solodit_content` repo (public, 49K+ findings)
- Contest repos: `code-423n4` org (C4), `sherlock-audit` org (Sherlock)
- Anthropic SDK docs: https://docs.anthropic.com/en/docs
