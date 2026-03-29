---
name: krait
description: AI-first security auditor for Solidity smart contracts. 4-phase pipeline (recon → detection → state analysis → verification) with 101 heuristics, 15 detection modules, and 8 kill gates. Tested at 100% precision across 50 blind shadow audits.
---

# Krait — AI Security Auditor

Krait is a structured audit methodology for Solidity smart contracts, encoded as Claude Code skills. It runs a 4-phase pipeline with multi-mindset analysis and strict verification gates.

## How It Works

When invoked via `/krait`, the pipeline runs 4 phases sequentially:

1. **Phase 0 — Recon** (`recon/instructions.md`): Architecture mapping, deterministic file risk scoring, module selection
2. **Phase 1 — Detection** (`detector/instructions.md`): 3-pass analysis with 4 parallel lenses × 4 mindsets, 101 heuristics, activated detection modules
3. **Phase 2 — State Analysis** (`state-auditor/instructions.md`): Coupled state pair analysis, mutation matrix, masking code detection
4. **Phase 3 — Verification** (`critic/instructions.md`): 8 automatic kill gates, concrete exploit trace required for every H/M finding
5. **Phase 3b — Review** (`reviewer/instructions.md`): Second opinion on killed findings, catches over-filtering
6. **Phase 4 — Report** (`reporter/instructions.md`): Dedup, rank, format to markdown + JSON

## Reference Files

### Phase Instructions
- `recon/instructions.md` — Full recon methodology
- `detector/instructions.md` — Detection methodology with all question categories and heuristics
- `state-auditor/instructions.md` — State inconsistency analysis
- `critic/instructions.md` — Kill gates and verification
- `reviewer/instructions.md` — Second opinion methodology
- `reporter/instructions.md` — Report generation

### Detection Modules (loaded selectively based on protocol type)
- `detector/modules/*.md` — 15 deep-dive detection modules (ERC-4626 vaults, lending/liquidation, AMM/MEV, governance, oracles, etc.)
- `detector/primers/*.md` — 7 protocol-type primers (DEX, lending, staking, bridges, proxies, wallets, gamefi)
- `detector/heuristics-extended.md` — 58 advanced detection vectors

### Supporting Files
- `recon/ast-extract.sh` — AST fact extraction script
- `recon/slither-summary.sh` — Slither output parser
- `ATTRIBUTION.md` — Detection source attribution

## Commands

| Command | Description |
|---------|-------------|
| `/krait` | Full 4-phase audit |
| `/krait-quick` | Skip state analysis for speed |
| `/krait-review` | Second opinion on killed findings |

## Benchmarks

100% precision across 50 blind shadow audits against Code4rena contests. 0 false positives per contest (v7+v8). See `shadow-audits/progress.md` for full results.

Built by [Zealynx Security](https://zealynx.io).
