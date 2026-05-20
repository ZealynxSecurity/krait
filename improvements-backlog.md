# Krait improvement backlog (inspired by Plamen)

## Context

Krait today is a high-precision single-pass auditor: Recon → Detector (3 passes / 4 lenses / 4 mindsets) → State Auditor → Critic (8 kill gates) → Reviewer → Reporter, with a parallel TypeScript CLI mirroring the same stages. Shadow-audit results show 100% precision and ~15% recall over 50 contests.

Plamen (PlamenTSV/plamen, v2.0.0, cloned to /tmp/plamen-research) is a multi-language auditor with a much larger surface area: explicit recon-instantiation-breadth-rescan-percontract-inventory-semantic-depth-RAG-chain-dedup-verify-skepticjudge-report pipeline, 8 niche agents, 9 injectable skills, 4-axis confidence scoring, Devil's-Advocate iteration, and a post-audit improvement protocol. Recall is higher (15%+ across blind tests in its own published numbers) at the cost of much higher complexity and token usage.

The asymmetry between the two projects is the source of the improvement list. Krait's strength is the zero-FP filter; Plamen's strength is the recall-oriented machinery on top of breadth/depth. The items below port the highest-leverage pieces of Plamen into Krait without compromising the zero-FP bar, ordered from lowest to highest effort. Every item names the target surface(s) (skill / CLI / MCP / patterns) and the exact files involved.

Out of scope unless explicitly called out: multi-language support (Solana/Aptos/Sui/Soroban), L1 chain coverage, full report-tier-writer split, multi-tier mode system. Those are bigger architectural projects than what this backlog targets.

## Improvement backlog (lowest → highest effort)

### Tier A — single-file prompt tweaks (hours each)

> **Status — v8.1 landed in PR #3 (commit history under `security-fixes-and-forge-mcp`).** A1 + A2 + A4 shipped as a single bundle. 3-contest pilot (PoolTogether / Arcade / Frankencoin) showed 100% precision held, average recall +38.7 pp, zero new FPs. Schema-only change, no architectural impact. A3 / A5 / A6 / A7 remain open.

**A1. Add `Step Execution` + `Rules Applied` fields to the finding schema.** ✅ DONE in v8.1.
- Surfaces: skill (`.claude/skills/krait/detector/instructions.md`, `state-auditor/instructions.md`, `critic/instructions.md`, `reviewer/instructions.md`) + CLI (`src/agents/types.ts` if findings have a typed schema, plus `detector.ts`/`reasoner.ts`/`critic.ts` prompts).
- Reuse: Plamen's `~/.plamen/rules/finding-output-format.md` (already in context) — the R4–R16 table maps cleanly onto Krait's existing 8 kill gates. Pick ~6 rules that don't duplicate the kill gates (R8 cached params, R10 worst-state severity, R11 unsolicited transfer, R12 enabler enumeration, R15 flash-loan precondition, R16 oracle integrity).
- Why first: pure prompt change; no orchestration change; immediately makes reviewer's "worth manual review" routing data-driven instead of vibes.

**A2. Add Depth Evidence tags (`[BOUNDARY:X=val]`, `[VARIATION:A→B]`, `[TRACE:path→outcome]`) to detector/state-auditor output.** ✅ DONE in v8.1.
- Surfaces: skill (same four files as A1) + CLI (`src/agents/detector.ts`, `reasoner.ts`).
- Reuse: tag definitions in `finding-output-format.md`. They incentivize agents to substitute concrete values rather than reason in the abstract.
- Why second: zero schema risk (additive), but materially changes what the LLM does. Pairs with A1.

**A3. Impact Premise gate (harm-not-mechanism) before any finding is reported.**
- Surfaces: skill (`.claude/skills/krait/critic/instructions.md`, `reviewer/instructions.md`) + CLI (`src/agents/critic.ts`).
- Reuse: `~/.plamen/rules/phase5-poc-execution.md` § "Impact Premise Verification" — copy the three example mechanism-tests and three example harm-tests verbatim.
- Why: kill-gate D ("speculative, no concrete exploit") is the right idea but loose; the harm-statement requirement makes it mechanical.

**A4. `Missing Precondition` / `Postconditions Created` fields on every finding (preparation only).** ✅ DONE in v8.1.
- Surfaces: same as A1.
- This is the schema-level prerequisite for D2 (chain analysis). Adding it now, even without consumers, is cheap and makes the eventual chain feature drop-in.

**A5. Trust-assumption downgrade in the reporter.**
- Surfaces: skill (`.claude/skills/krait/reporter/instructions.md`) + CLI (`src/core/reporter.ts`, `src/agents/ranker.ts`).
- Reuse: `~/.plamen/rules/report-template.md` § "Downgrade modifiers". A finding tagged `[ASSUMPTION-DEP: TRUSTED-ACTOR]` gets −1 tier (floor: Informational). Krait's kill gate E already kills admin-trust findings outright — this is the softer middle option (report at lower severity with a note).
- Why: better client deliverable; fewer borderline-killed findings lost entirely.

**A6. Proven-only mode flag.**
- Surfaces: skill (new `.claude/commands/krait-proven.md` or flag in `/krait`) + CLI (`src/cli.ts audit --proven-only`).
- Reuse: report-template.md § "Proven-only demotion". Caps any finding whose best evidence is reasoning-only (no executed PoC, no fork test) at Low. Useful for shadow-audit benchmarking and for clients who only want mechanically-proven findings driving severity.

**A7. Root-cause consolidation in the reporter.**
- Surfaces: skill (`.claude/skills/krait/reporter/instructions.md`) + CLI (`src/core/reporter.ts`).
- Reuse: `~/.plamen/rules/phase6-report-prompts.md` § STEP 1.5. Merge same-fix-pattern + same-tier + same-vuln-class findings into one finding with a locations table. Fixes the "10 separate missing-event findings" problem cleanly.

### Tier B — new mechanical sweep agents (1–2 days each)

**B1. Three blind-spot scanners as a new skill phase.**
- Surfaces: skill (new `.claude/skills/krait/blind-spot-scanners/instructions.md` invoked between state-auditor and critic) + CLI (new `src/agents/blind-spot-scanner.ts` slotted into `multi-agent.ts` after reasoner).
- Reuse: Plamen's scanner archetype (the methodology is in its `prompts/{evm}/phase4b-scanner-templates.md` — sweep over `/tmp/plamen-research/prompts/evm/` to copy the three checklists). Three mechanical lists: (A) missing events / incomplete state init, (B) reentrancy / delegatecall / assembly hygiene, (C) guard-parameter injection / proxy-storage collision.
- Why: low FP (mechanical), low budget cost, catches a class Krait has historically missed (guard-parameter injection).

**B2. Operational Implications quality gate in recon.**
- Surfaces: skill (`.claude/skills/krait/recon/instructions.md`) + CLI (`src/analysis/architecture-pass.ts`).
- Reuse: Plamen's Rule 14 (Operational Implications Quality Gate, in `~/.claude/CLAUDE.md`). After recon emits invariants, require one operational-implication sentence per invariant; if missing, re-prompt before proceeding.
- Why: cheapest way to keep downstream agents from analyzing a protocol they don't understand. Shadow audits where Krait got the protocol model wrong are the obvious target.

**B3. Per-contract focused-analysis pass.**
- Surfaces: skill (new `.claude/skills/krait/detector/per-contract.md` invoked after the main detector pass) + CLI (`src/agents/multi-agent.ts` adds a per-contract stage).
- Reuse: `~/.plamen/rules/phase3b-rescan-prompt.md` § "Phase 3c". One agent per inheritance cluster, max 1500 LOC per cluster, max 8 agents total. Receives the existing findings inventory as exclusion list.
- Why: counters attention dilution on multi-contract codebases. Plamen's measured contribution is most of its iteration-2 yield.

**B4. Re-scan pass with exclusion list.**
- Surfaces: skill (new `.claude/skills/krait/detector/rescan.md`) + CLI (`src/agents/multi-agent.ts`).
- Reuse: `~/.plamen/rules/phase3b-rescan-prompt.md` § iterations 1–2. 2–3 sonnet agents told "find what pass 1 missed", with the iteration-1 finding list as exclusion. Hard exit if iteration 1 above-Info count is zero.
- Why: complements B3 (re-scan covers cross-contract bugs, per-contract covers depth).

**B5. Design Stress Testing as a single reserved agent slot.**
- Surfaces: skill (new `.claude/skills/krait/design-stress/instructions.md` invoked once per audit) + CLI (`src/agents/design-stress.ts`).
- Reuse: the unconditional 1-slot pattern from Plamen's Thorough mode. Stress scenarios: bulk withdraw, full unbond, all-rewards-claimed, zero-reserve pool, oracle extremes.

### Tier C — confidence + verification machinery (3–5 days each)

**C1. 4-axis confidence scoring (Evidence / Consensus / Analysis Quality / RAG).**
- Surfaces: CLI (`src/agents/ranker.ts` extends current composite formula; new `src/agents/confidence-scorer.ts`) + skill (`.claude/skills/krait/reporter/instructions.md` consumes the scores).
- Reuse: `~/.plamen/rules/phase4-confidence-scoring.md` — copy the formula `Evidence × 0.25 + Consensus × 0.25 + Quality × 0.3 + RAG × 0.2` and the routing thresholds (≥0.7 CONFIDENT, 0.4–0.7 UNCERTAIN, <0.4 LOW). Reuse Krait's existing detectorConfidence/reasonerConfidence/criticConfidence as inputs to the Evidence/Consensus axes.
- Why: prerequisite for D1 (adaptive depth) and a useful improvement on its own (better ranker output, severity-weighted routing).

**C2. Mandatory PoC execution via the existing forge MCP.**
- Surfaces: skill (new `.claude/skills/krait/verifier/instructions.md` invoked between critic and reporter) + CLI (new `src/agents/verifier.ts` calling `mcp-servers/forge` via a TypeScript client).
- Reuse: forge MCP already in repo (`mcp-servers/forge/src/index.ts`), `~/.plamen/rules/phase5-poc-execution.md` § Execution Protocol. Evidence tags `[POC-PASS]`/`[POC-FAIL]`/`[CODE-TRACE]` feed the Evidence axis in C1.
- Why: turns "this might be exploitable" into "this is, here's the failing test". Pairs naturally with the existing fuzzer skill.

**C3. RAG validation sweep + extend solodit MCP.**
- Surfaces: MCP (`mcp-servers/solodit/src/index.ts` — add `validate_hypothesis` and `search_solodit_live` tools matching Plamen's signatures) + skill (new `.claude/skills/krait/rag-sweep/instructions.md`) + CLI (new `src/agents/rag-sweep.ts`).
- Reuse: Krait's solodit MCP already exposes `search_similar_findings`, `get_enrichment`, `validate_hypothesis` — the gap is `search_solodit_live` and a structured score (0–10) instead of free-text. Methodology in `~/.plamen/rules/phase4-confidence-scoring.md` § Phase 4b.5.
- Why: 4th confidence axis; differentiates novel-vector findings from "this exact bug has 47 historical examples".

**C4. Verifier-generated fix diffs.**
- Surfaces: skill (`.claude/skills/krait/verifier/instructions.md` — extends C2) + CLI (`src/agents/verifier.ts`).
- Reuse: `~/.plamen/rules/phase5-poc-execution.md` § "Generate fix". After a `[POC-PASS]`, emit a minimal diff and (optionally) re-run the PoC with the diff applied. Only for proven findings.
- Why: huge UX win in the client report at near-zero marginal model cost (verifier already has the context).

### Tier D — architectural changes (1–2 weeks each)

**D1. Adaptive depth loop (iterations 2–3 with Devil's Advocate).**
- Surfaces: skill (new orchestration block in `.claude/commands/krait.md` driving multiple reasoner passes) + CLI (`src/agents/multi-agent.ts` re-spawns reasoner with filtered inputs).
- Reuse: `~/.plamen/rules/phase4-confidence-scoring.md` § AD-1 through AD-6 and § Convergence Criteria — copy the iteration-cap (3), the dynamic spawn cap formula, and the AD-2 hard Devil's Advocate prompt verbatim. Requires C1 (confidence scoring) as input.
- Why: highest single-feature recall lift in Plamen's own ablations.

**D2. Chain analysis (enabler enumeration + postcondition/precondition matching).**
- Surfaces: skill (new `.claude/skills/krait/chain-analyzer/instructions.md`) + CLI (`src/agents/chain-analyzer.ts`) + reporter changes downstream.
- Reuse: `~/.plamen/rules/phase4c-chain-prompt.md` — split into Agent 1 (Rule-12 5-actor enumeration + grouping) and Agent 2 (postcondition→precondition matching + composition coverage map). Requires A4 (precondition/postcondition fields) as input.
- Why: this is the feature that turns isolated LOW + isolated MEDIUM into reported HIGH/CRITICAL. The biggest qualitative gap between Krait and Plamen.

**D3. Niche agents (event-completeness + signature-verification first).**
- Surfaces: skill (new `.claude/skills/krait/niche/event-completeness/`, `signature-verification/`) + CLI (`src/agents/niche-*.ts`) + recon updates to set the trigger flags.
- Reuse: agent definitions in `/tmp/plamen-research/agents/` and `/tmp/plamen-research/skills/`. Start with two with the highest EVM ROI: `event-completeness` (always-relevant) and `signature-verification` (high-value when EIP-712/permit appears).
- Why: focused depth on specific concern areas. Each is one standalone agent and one recon flag; the rest of Plamen's eight can follow incrementally.

**D4. Injectable protocol-type skills (vault / lending / governance / DEX-integration).**
- Surfaces: skill (new `.claude/skills/krait/injectable/vault.md`, `lending.md`, `governance.md`, `dex-integration.md`) + recon flag detection + detector prompt appendage.
- Reuse: `~/.plamen/skills/injectable/` content; Krait's existing `detector/primers/` directory is the closest analogue (7 protocol primers already exist) — these would be loaded into detector/reasoner conditionally instead of via the existing primer mechanism, with stronger methodology.
- Why: better depth on specific protocol types. Krait already has primers; this evolves them.

**D5. Inventory pass between phases (structured deduplication + tagging).**
- Surfaces: skill (new `.claude/skills/krait/inventory/instructions.md` after state-auditor and again after verifier) + CLI (new `src/agents/inventory.ts`).
- Reuse: `~/.plamen/prompts/evm/phase4a-inventory-prompt.md`. Three-step: shard plan (haiku) → parallel chunks (sonnet) → merge (opus). Produces `findings_inventory.md` with assumption tags.
- Why: structured intermediary that makes A1/A4/A5 actually usable downstream. Without an inventory pass, the schema fields exist but no one aggregates them.

**D6. Skeptic-Judge filter for HIGH/CRITICAL findings.**
- Surfaces: skill (new `.claude/skills/krait/skeptic/`) + CLI.
- Reuse: Plamen's Phase 5.1 mechanic — skeptic gets finding + code but not verifier's reasoning; judge resolves disagreement. Demotes unresolved findings by one tier, flags for human review.
- Why: extra FP protection at the tier where FPs hurt clients most.

### Items intentionally deferred

- Post-audit improvement protocol with RC-AGENT exclusion test. Requires the discipline of ephemeral-session improvement reviews; useful only after the above are in place.
- Multi-language support. The skill structure is EVM-only and CLAUDE.md says so. Worth its own initiative, not a backlog item here.
- Full report tier-writer split (Index → 3 writers → Assembler). Krait's reporter is already clean at current finding volumes; revisit only if reports start truncating.
- Mode tier system (light/core/thorough). Krait has `/krait-quick`; a full three-tier system is more useful once D1+D2 exist to differentiate.

## Critical files

| File | Touched by |
|---|---|
| `.claude/skills/krait/detector/instructions.md` | A1, A2, A4, B3, B4 |
| `.claude/skills/krait/state-auditor/instructions.md` | A1, A2 |
| `.claude/skills/krait/critic/instructions.md` | A1, A3 |
| `.claude/skills/krait/reviewer/instructions.md` | A1, A3 |
| `.claude/skills/krait/reporter/instructions.md` | A5, A7, C1 (consumer) |
| `.claude/skills/krait/recon/instructions.md` | B2, D3 (flag emission), D4 (flag emission) |
| `src/agents/{detector,reasoner,critic,ranker}.ts` | A1–A7 mirrors |
| `src/agents/multi-agent.ts` | every B/C/D orchestration item |
| `src/core/reporter.ts` | A5, A7 |
| `mcp-servers/solodit/src/index.ts` | C3 |
| `mcp-servers/forge/src/index.ts` (consumer only) | C2, C4 |
| `METHODOLOGY.md` | every item (keep the canonical doc updated) |

## Verification

Krait's published bar is "100% precision across 50 blind shadow audits" — that bar applies to every change. The validation harness already exists:

1. After any change in tiers A or B, run `npm run dev shadow-audit` against a small slice of `shadow-audits/registry.yaml` (3–5 contests) and confirm no new false positives appear. Diff the report against the prior baseline with `src/core/comparator.ts` semantics — only severity demotions and new findings are acceptable; any new FP blocks the change.
2. After tier C changes, re-run the full 50-contest shadow audit (`npm run dev shadow-audit`) and check both precision (must stay 100%) and recall (target: monotonic improvement). Recall regression of >2% on any single contest is a block.
3. Tier D changes (D1/D2 especially) need staged rollout: ship behind a flag (`--enable-chain-analysis`), run on the full registry with and without the flag, compare deltas before making the flag default-on.
4. The forge MCP itself is exercised by `mcp-servers/forge/` integration tests; the verifier (C2) should add tests there that exercise `forge_build` and `forge_test` from a deliberately broken contract to confirm error capture.
5. Patterns directory changes (none in this backlog directly, but D4 injectables touch the same instinct) validate via `src/knowledge/__tests__/pattern-loader.test.ts` (extend if injectable skills bypass the loader).
