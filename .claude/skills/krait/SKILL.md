---
name: krait
description: AI-first security auditor for Solidity smart contracts. 4-phase pipeline (recon → detection → state analysis → verification) with 101 heuristics, 15 detection modules, 8 kill gates, and a 6-field methodology audit trail per finding (v8.1). Tested at 100% precision across 50 blind shadow audits.
---

# Krait — AI Security Auditor

Krait is a structured audit methodology for Solidity smart contracts, encoded as Claude Code skills. It runs a 4-phase pipeline with multi-mindset analysis and strict verification gates.

## How It Works

When invoked via `/krait`, a preflight readiness check runs first, then the 4-phase pipeline runs sequentially:

- **Preflight** (`preflight/instructions.md`): Hard checks (forge / bash / jq / `.sol` files) before any work. Same skill is invoked in *report* mode by `/krait-init` and in *gate* mode by `/krait`.
1. **Phase 0 — Recon** (`recon/instructions.md`): Architecture mapping, deterministic file risk scoring, module selection
2. **Phase 1 — Detection** (`detector/instructions.md`): 3-pass analysis with 4 parallel lenses × 4 mindsets, 101 heuristics, activated detection modules
3. **Phase 1b — Rescan** (`detector/rescan.md`): Second broad pass with pass-1 findings as an exclusion list; counters attention saturation. Self-skips when pass 1 found nothing above Info
4. **Phase 1c — Per-Contract** (`detector/per-contract.md`): One agent per inheritance cluster at maximum depth; counters attention dilution
5. **Phase 2 — State Analysis** (`state-auditor/instructions.md`): Coupled state pair analysis, mutation matrix, masking code detection
6. **Phase 3 — Verification** (`critic/instructions.md`): 8 automatic kill gates + Impact Premise (harm, not mechanism); concrete exploit trace required for every H/M finding
7. **Phase 3b — Review** (`reviewer/instructions.md`): Second opinion on killed findings, catches over-filtering
8. **Phase 4 — Report** (`reporter/instructions.md`): Root-cause consolidation, trust-assumption downgrade, dedup, rank, format to markdown + JSON

## Reference Files

### Phase Instructions
- `preflight/instructions.md` — Shared readiness check (gate vs report mode)
- `recon/instructions.md` — Full recon methodology
- `detector/instructions.md` — Detection methodology with all question categories and heuristics
- `detector/rescan.md` — Phase 1b second pass with exclusion list
- `detector/per-contract.md` — Phase 1c per-cluster deep analysis
- `state-auditor/instructions.md` — State inconsistency analysis
- `critic/instructions.md` — Kill gates and verification
- `reviewer/instructions.md` — Second opinion methodology
- `reporter/instructions.md` — Report generation
- `fuzzer/SKILL.md` — Invariant fuzz pipeline (used by `/krait-fuzz`)

### Detection Modules (loaded selectively based on protocol type)
- `detector/modules/*.md` — 15 deep-dive detection modules (ERC-4626 vaults, lending/liquidation, AMM/MEV, governance, oracles, etc.)
- `detector/primers/*.md` — 7 protocol-type primers (DEX, lending, staking, bridges, proxies, wallets, gamefi)
- `detector/heuristics-core.md` — 43 core trigger-based heuristics
- `detector/heuristics-extended.md` — 58 advanced detection vectors

### Supporting Files
- `recon/ast-extract.sh` — AST fact extraction script
- `recon/slither-summary.sh` — Slither output parser
- `ATTRIBUTION.md` — Detection source attribution

## Commands

| Command | Description |
|---------|-------------|
| `/krait` | Full 4-phase audit (auto-runs preflight first) |
| `/krait-quick` | Skip state analysis for speed |
| `/krait-review` | Second opinion on killed findings |
| `/krait-fuzz` | Generate and run Foundry invariant fuzz tests |
| `/krait-init` | Standalone readiness report (preflight in report mode) |

## Benchmarks

100% precision across 50 blind shadow audits against Code4rena contests. 0 false positives per contest (v7+v8). See `shadow-audits/progress.md` for full results.

v8.1 Tier A methodology audit trail (3-contest pilot): 100% precision / 54.1% avg recall / 0 FPs across PoolTogether, Arcade, Frankencoin. Schema-driven; awaits full 50-contest regression.

Built by [Zealynx Security](https://zealynx.io).
