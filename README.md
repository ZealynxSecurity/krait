# Krait — AI-First Smart Contract Security Auditor

**Silent. Precise. Lethal.** Named after one of the deadliest snakes.

Krait is an AI-powered security auditor built by [Zealynx Security](https://zealynx.io). It uses Claude as the core analysis engine with structured vulnerability knowledge — not regex-based detection. It runs as Claude Code slash commands (zero API cost) or as a standalone CLI.

> Built entirely with Claude Code. Every methodology iteration, every detection heuristic, every kill gate — developed and refined through iterative blind testing against real audit contest results.

---

## What Makes Krait Different

Most AI audit tools follow the same pattern: **scan code → report findings**. One pass, no verification, no published benchmarks. Krait does four things we haven't seen anywhere else:

### 1. Benchmarked Against 40 Real Contests

No other AI audit tool publishes precision and recall numbers against real audit competitions. Krait has been **blind-tested against 40 Code4rena contests** — every result tracked and verifiable in [`shadow-audits/`](shadow-audits/).

```
Latest (v6.4):  90% precision  ·  0.2 FPs/contest  ·  4 of 5 contests at 100% precision
```

| Version | Contests | Precision | FPs/Contest | What Changed |
|---------|----------|-----------|-------------|--------------|
| v1 | 1–3 | 12% | 1.3 | Baseline |
| v2 | 5–10 | 66% | 2.3 | Structured phases |
| v5 | 31–35 | 70% | 0.6 | Kill gates |
| **v6.4** | **36–40** | **90%** | **0.2** | **Full pipeline maturity** |

### 2. Verification Phase That Kills False Positives

Other tools generate findings and dump them. Krait has a **dedicated adversarial phase** that tries to disprove every finding before reporting it. Eight kill gates automatically eliminate noise — and have **never killed a true positive** across 40 contests:

| Gate | What It Kills |
|------|---------------|
| A: Best Practice | "Use SafeERC20", "add events", "centralization risk" |
| B: Theoretical | Exotic token behavior not in the protocol |
| C: Intentional Design | Matches docs or reference implementation |
| D: Speculative | Can't name WHO steals WHAT for HOW MUCH |
| E: Admin Trust | Requires trusted admin to be malicious |
| F: Dust | Impact < $100 |
| G: Out of Context | Tokens/chains/standards not used |
| H: Known Issue | Already acknowledged in README |

This dropped false positives from 4.2/contest to 0.2/contest — a **95% reduction**.

### 3. Self-Improving Through Shadow Audits

After each blind test, every miss is root-caused and fed back into the methodology:

```
Blind audit → Score vs official findings → Root-cause every miss → Update methodology → Re-test
```

This loop produced 50+ detection heuristics, 30 analysis modules, and 7 protocol-specific primers — all from analyzing **real missed findings**, not theoretical checklists.

### 4. Four-Phase Pipeline

| Phase | What It Does |
|-------|-------------|
| **Recon** | Architecture map, deterministic file risk scoring, protocol primer selection |
| **Detection** | Three passes with 4 parallel analysis lenses on highest-risk files |
| **State Analysis** | Coupled state pairs, mutation matrix — catches sync bugs that scanning misses |
| **Verification** | Kill gates + concrete exploit trace required for every H/M finding |

---

## Real Bugs Found (Blind Audits)

These are bugs Krait found without ever seeing the official results:

- **AuraVault claim double-spend** (LoopFi H-401) — reward calculation doesn't deduct fees, draining vault
- **UniV3 fee drain via shared position** (Vultisig H-43) — first claimer steals all investors' fees
- **ILO launch DoS** (Vultisig H-41) — attacker blocks all token launches via slot0 manipulation
- **Public internal functions → permanent fund lock** (Phi H-51) — anyone can corrupt state, locking ETH
- **Both HIGHs found** (Munchables H-01, H-02) — lockOnBehalf griefing + early unlock, 100% precision
- **Assembly encoding bug** (DittoETH M-221) — `add` vs `and` in inline assembly corrupts data
- **ERC4626 first depositor inflation** (Basin), **Reentrancy in rental system** (reNFT), **EIP-712 typehash mismatch** (reNFT), **Oracle precision loss** (Dopex), **TVL calculation error** (Renzo)

---

## Quick Start

### Claude Code Skills (Recommended — Zero Cost)

```bash
# Clone krait so Claude Code can access the methodology
git clone https://github.com/ZealynxSecurity/krait.git

# Open Claude Code in your target project, then:
/krait                  # Full 4-phase audit
/krait-quick            # Fast mode (skips state analysis)
```

Individual phases: `/krait-recon`, `/krait-detect`, `/krait-state`, `/krait-critic`, `/krait-report`

### CLI (API-Powered)

```bash
cd krait && npm install && npm run build
export ANTHROPIC_API_KEY=your-key-here

npx krait audit /path/to/project
npx krait audit /path/to/project --quick   # Sonnet only, faster + cheaper
npx krait patterns                          # List loaded patterns
```

| Project Size | Estimated Cost |
|-------------|---------------|
| ~500 LOC | ~$0.30–0.50 |
| ~2K LOC | ~$1–3 |
| ~10K LOC | ~$5–15 |

---

## How It's Built

The methodology lives in `.claude/skills/` (single source of truth) and is invoked via `.claude/commands/` (slash commands). The CLI in `src/` mirrors the same pipeline using the Anthropic SDK directly.

Key components:
- **Skills**: Detector (50+ heuristics, 30 modules, 4 parallel lenses), Critic (8 kill gates), Recon (risk scoring + AST extraction), State Auditor, Reporter
- **7 protocol primers**: DEX/AMM, Lending, Staking/Governance, GameFi/NFT, Bridge, Proxy/Upgrades, Wallet/AA — distilled from 333 checks across [Zealynx's audit-readiness platform](https://zealynx.io)
- **59 YAML patterns**: Vulnerability knowledge base from real audit findings
- **Shadow audit pipeline**: Automated blind benchmarking + miss analysis + methodology updates

### Known Strengths
Reentrancy/CEI, access control gaps, oracle issues, EIP compliance, first-depositor inflation, accounting errors, assembly bugs, pause bypasses

### Known Weaknesses (Improving)
Complex math (CDP liquidation, options pricing), deep cross-chain edge cases, game mechanic exploits, protocol-specific integration bugs, economic design flaws

---

## Dual-Engine Architecture

Krait operates as two complementary systems sharing the same knowledge base:

### Engine 1: CLI Agent (this repo)

The AI auditor — 4-phase adversarial pipeline that runs directly on codebases. Designed for security researchers and audit teams who want deep, automated vulnerability analysis with concrete exploit traces.

### Engine 2: Web Assessment Platform ([krait.zealynx.io](https://krait.zealynx.io))

Protocol-specific security assessment for teams who want structured guidance before or alongside an AI/human audit.

- **39 DeFi verticals** — DEX/AMM, lending, staking, bridges, vaults, stablecoins, perpetuals, and 32 more
- **845+ security checks** backed by real Solodit audit references
- **Smart filtering** — checks adapt based on project config (oracle type, admin model, flash loans, etc.)
- **Auto-generated insights** — Architectural Security Observations + Security Strengths sections, same format as professional Zealynx audit reports
- **Branded exportable reports** — Markdown + interactive web view with score ring, risk breakdown, evidence appendix
- Auth via Supabase (email + GitHub OAuth)

Both engines draw from the same vulnerability patterns, protocol primers, and Solodit references. CLI scan results can be uploaded to the web platform for a combined security score.

**Status:** Live at [krait.zealynx.io](https://krait.zealynx.io). Assessment flow functional, AI scan integration in progress.

---

## Project Status

| Component | Status |
|-----------|--------|
| Claude Code audit pipeline (4 phases) | ✅ Production |
| Kill gate FP elimination | ✅ Production |
| Shadow audit benchmarking (40 contests) | ✅ Production |
| Self-improvement loop | ✅ Production |
| Protocol detection primers (7 domains) | ✅ Production |
| Web assessment platform (39 verticals) | ✅ Live |
| Architectural observations engine | ✅ Live |
| CLI tool | Beta |
| CLI ↔ Web score integration | In progress |
| Multi-domain (Rust, TypeScript, AI) | Planned |
| GitHub Action for PRs | Planned |

---

## Author

**Carlos Vendrell Felici** — Founder, [Zealynx Security](https://zealynx.io)
[Twitter/X](https://x.com/TheBlockChainer) · [GitHub](https://github.com/vendrell46)

## License

[MIT](LICENSE) © Zealynx Security
