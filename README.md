# Krait — AI-First Security Auditor

**Silent. Precise. Lethal.** Named after one of the deadliest snakes.

Krait is an AI-powered smart contract security auditor built by [Zealynx Security](https://zealynx.io). It uses Claude as the core analysis engine with structured vulnerability knowledge — not regex-based detection.

> Built entirely with Claude Code. Every methodology iteration, every detection heuristic, every kill gate — developed and refined through iterative blind testing against real audit contest results.

---

## What Makes Krait Different

Most AI audit tools — including every Claude Code skill we've seen — follow the same pattern: **scan code → report findings**. One pass, no verification, no benchmarks. Krait does four things nobody else does:

### 1. Benchmarked Against Real Contests (40 and counting)

Every other AI audit tool says "we find bugs." None publish precision and recall numbers against real audit contests. Krait has been **blind-tested against 40 Code4rena contests** with every result tracked:

```
v6.4 (latest):  90% precision  ·  0.2 FPs/contest  ·  4 of 5 contests at 100% precision
```

| Version | Contests | Avg Precision | FPs/Contest | Key Change |
|---------|----------|---------------|-------------|------------|
| v1 | 1-3 | 12% | 1.3 | Baseline |
| v2 | 5-10 | 66% | 2.3 | Structured phases |
| v3 | 11-20 | 34% | 3.3 | Multi-pass (precision regressed) |
| v4 | 21-30 | 37% | 4.2 | Heuristics (FPs still rising) |
| v5 | 31-35 | 70% | 0.6 | **Kill gates (FP breakthrough)** |
| **v6.4** | **36-40** | **90%** | **0.2** | **Primers + architecture cleanup** |

Every number is verifiable — the [shadow-audits/](shadow-audits/) directory has the full registry and scoring for all 40 contests.

### 2. Dedicated Verification Phase (Kill Gates)

Other tools generate findings and dump them. Krait has a **dedicated adversarial critic phase** that tries to disprove every finding before it reaches you. Eight automatic kill gates eliminate 95%+ of false positives:

| Gate | Kills | Example |
|------|-------|---------|
| A: Generic Best Practice | "Use SafeERC20", "add events" | 0 TPs ever across 40 contests |
| B: Theoretical | Exotic token behavior not in protocol | 0 TPs ever |
| C: Intentional Design | Matches docs/reference implementation | 0 TPs ever |
| D: Speculative | Can't name WHO steals WHAT for HOW MUCH | 0 TPs ever |
| E: Admin Trust | Requires trusted admin to be malicious | 0 TPs ever |
| F: Dust | Impact < $100 | 0 TPs ever |
| G: Out of Context | Tokens/chains not used by protocol | 0 TPs ever |
| H: Known Issue | Already in README known issues | 0 TPs ever |

These gates have **never killed a true positive** across 40 contests. They only kill noise.

### 3. Self-Improving Through Shadow Audits

Krait doesn't just audit — it **learns from every miss**. After each blind test:

```
Blind audit → Score against official findings → Root-cause every miss
→ Add new heuristic/module/primer to methodology → Re-test
```

This loop has produced 50+ detection heuristics, 30 analysis modules, and 7 protocol-specific primers — all derived from analyzing **real missed findings**, not theoretical checklists. The methodology evolves with every contest.

### 4. Four-Phase Pipeline (Not Just "Scan and Report")

| Phase | Purpose | What Others Do |
|-------|---------|---------------|
| **Recon** | Architecture map, risk scoring, file triage | Skip or minimal |
| **Detection** | Three-pass analysis with 4 parallel lenses | Single scan pass |
| **State Analysis** | Coupled state pairs, mutation matrix | Nobody does this |
| **Verification** | Kill gates + exploit trace requirement | No verification |

The state analysis phase catches bugs that require understanding how two pieces of state must stay in sync — a category that pure scanning misses entirely.

---

## Benchmarks at a Glance

### Latest: v6.4 (Contests 36-40)

| Contest | Type | Official H+M | TPs | FPs | Precision |
|---------|------|-------------|-----|-----|-----------|
| LoopFi | Lending/Looping | 45 | 2 | 0 | **100%** |
| DittoETH | Stablecoin/OrderBook | 16 | 1 | 1 | 50% |
| Phi | Social/NFT | 15 | 1 | 0 | **100%** |
| Vultisig | ILO/Token | 6 | 2 | 0 | **100%** |
| Predy | DeFi Derivatives | 12 | 1 | 0 | **100%** |

### Real Bugs Found in Blind Audits

- **AuraVault claim double-spend** (LoopFi) — reward calculation doesn't deduct fees, draining vault
- **UniV3 fee drain via shared position** (Vultisig) — first claimer steals all investors' fees
- **ILO launch DoS** (Vultisig) — attacker blocks all token launches by manipulating slot0 price
- **Public internal functions → permanent fund lock** (Phi) — anyone can corrupt state, locking ETH forever
- **Both HIGHs found** (Munchables) — lockOnBehalf griefing + early unlock, 100% precision
- **Assembly encoding bug** (DittoETH) — `add` vs `and` in inline assembly corrupts redemption data
- **ERC4626 first depositor inflation** (Basin), **Reentrancy in rental system** (reNFT), **EIP-712 typehash mismatch** (reNFT), **Oracle precision loss** (Dopex), **TVL calculation error** (Renzo)

---

## How It Works

Krait operates in two modes:

### 1. Claude Code Skills (Zero API Cost)

Run `/krait` inside [Claude Code](https://docs.anthropic.com/en/docs/claude-code) on any project. Uses your Claude subscription directly.

```
/krait                     # Full 4-phase audit
/krait src/contracts/      # Audit specific directory
/krait-quick               # Fast mode (skip state analysis)
```

Individual phases:
```
/krait-recon               # Phase 0: Architecture mapping + file risk scoring
/krait-detect              # Phase 1: Three-pass vulnerability detection
/krait-state               # Phase 2: State inconsistency analysis
/krait-critic              # Phase 3: Verification + false positive elimination
/krait-report              # Phase 4: Generate final report
```

### 2. CLI Tool (API-Powered)

```bash
npx krait audit <path>           # Full audit
npx krait audit <path> --quick   # Fast pass (Sonnet only)
npx krait patterns               # List loaded patterns
```

Requires `ANTHROPIC_API_KEY` environment variable.

---

## The 4-Phase Audit Pipeline

```
┌──────────────────────────────────────────────────────────────────┐
│  Phase 0: RECON                                                  │
│  Architecture map → Fund flows → Trust boundaries → File risk    │
│  scoring (deterministic formula) → Tier assignment (DEEP /       │
│  STANDARD / SCAN) → Protocol primer selection                    │
└──────────────┬───────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Phase 1: DETECTION (Three-Pass Analysis)                        │
│                                                                  │
│  Pass 1 — Tiered Scan                                            │
│    Tier 1: Full Feynman interrogation + heuristic triggers       │
│    Tier 2: Standard analysis                                     │
│    Tier 3: Signatures + obvious patterns only                    │
│                                                                  │
│  Pass 2 — Parallel Lens Deep Dive (Tier 1 only, max 5 files)    │
│    Lens A: Access Control, State & Governance                    │
│    Lens B: Value Flow & Economic Logic                           │
│    Lens C: External Interactions & Cross-Contract                │
│    Lens D: Edge Cases, Math & Standards                          │
│                                                                  │
│  Pass 3 — Mechanical "What's Missing" Sweep                      │
│    Missing inverses, missing access control, missing reward      │
│    checkpoints, parameter transition safety, DoS on core funcs   │
└──────────────┬───────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Phase 2: STATE INCONSISTENCY ANALYSIS                           │
│  Coupled state dependency map → Mutation matrix → Cross-check    │
│  every writer → Parallel path comparison → Masking code detect   │
└──────────────┬───────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Phase 3: VERIFICATION (Critic)                                  │
│                                                                  │
│  Step 0: Kill Gates A-H (automatic FP elimination)               │
│    A: Generic best practice  B: Theoretical/unrealistic          │
│    C: Intentional design     D: Speculative (no concrete trace)  │
│    E: Admin trust boundary   F: Dust/insignificant               │
│    G: Out of context         H: Known/acknowledged issue         │
│                                                                  │
│  Steps 1-5: Code re-read → Call chain trace → Exploit trace      │
│  with concrete values → Deep FP elimination → Verdict            │
│                                                                  │
│  DoS Exception: Core lifecycle DoS + low cost + persistent       │
│  = Medium minimum (survives Gates A/B/D/F)                       │
└──────────────┬───────────────────────────────────────────────────┘
               ▼
┌──────────────────────────────────────────────────────────────────┐
│  Phase 4: REPORT                                                 │
│  Only VERIFIED findings → Dedup → Rank → Format                  │
│  Every H/M has: file:line, exploit trace, root cause, fix        │
└──────────────────────────────────────────────────────────────────┘
```

### Deterministic File Risk Scoring

Files are triaged by a deterministic formula, not subjective judgment:

```
RISK_SCORE = (external_calls × 5) + (state_writing_functions × 4)
           + (payable_functions × 4) + (assembly_blocks × 6)
           + (unchecked_blocks × 3) + (LOC × 0.05)
           + novel_code_bonus(15) + value_handling_bonus(10)
           + immaturity_bonus(10)
```

**Tier 1** (top 5 by score): Full 3-pass treatment with deep dives.
**Tier 2** (next 10): Standard analysis.
**Tier 3** (rest): Signature scan only. Every file read at least once.

### Protocol-Specific Detection Primers

Seven attack-pattern primers distilled from 333 checks across Zealynx's audit-readiness platform:

| Primer | Patterns | Source Checks |
|--------|----------|---------------|
| DEX / AMM / Liquidity Pool | 25 | 150 |
| Lending / Borrowing | 22 | Miss analysis |
| Staking / Governance | 22 | 55 + miss analysis |
| GameFi / NFT | 17 | 55 |
| Bridge / Cross-chain | 12 | 17 |
| Proxy / Upgrades | 15 | 33 |
| Wallet / Safe / AA | 12 | Miss analysis |

---

## Benchmark Results: 40 Shadow Audits

Krait has been blind-tested against **40 real Code4rena contest codebases**. For each: run a fully blind audit → fetch official findings → score precision/recall/F1. Every miss is analyzed and fed back into the methodology.

### Latest Results (v6.4 — Contests 36-40)

| # | Contest | Type | Official H+M | TPs | FPs | Precision | Recall | F1 |
|---|---------|------|-------------|-----|-----|-----------|--------|-----|
| 36 | LoopFi | Lending/Looping | 45 | 2 | 0 | **100%** | 4.4% | 8.4% |
| 37 | DittoETH | Stablecoin/OrderBook | 16 | 1 | 1 | 50% | 6.3% | 11.2% |
| 38 | Phi | Social/NFT | 15 | 1 | 0 | **100%** | 6.7% | 12.6% |
| 39 | Vultisig | ILO/Token | 6 | 2 | 0 | **100%** | 33.3% | **50.0%** |
| 40 | Predy | DeFi Derivatives | 12 | 1 | 0 | **100%** | 8.3% | 15.3% |

**v6.4 Totals: 90% avg precision, 0.2 FPs/contest, 4 of 5 contests at 100% precision**

### Progression Across 40 Contests

| Metric | v1 (1-3) | v2 (5-10) | v3 (11-20) | v4 (21-30) | v5 (31-35) | v6.4 (36-40) |
|--------|----------|-----------|------------|------------|------------|-------------|
| Avg Precision | 12% | 66% | 34% | 37% | 70% | **90%** |
| Avg Recall | 6% | 30% | 14% | 14% | 10% | **12%** |
| FPs/contest | 1.3 | 2.3 | 3.3 | 4.2 | 0.6 | **0.2** |
| 100% precision | 0/3 | 1/6 | 1/10 | 1/10 | 3/5 | **4/5** |

### What These Numbers Mean

**Precision = trust.** When Krait reports a finding, there's a 90% chance it's real. In v6.4, 4 out of 5 contests had zero false positives.

**Recall = coverage.** Krait currently finds ~10-15% of all contest-level bugs. This is the frontier — recall is bounded by the depth of single-pass AI analysis vs. weeks of human expert review.

**The tradeoff is intentional.** Zero false positives is the #1 design goal. A false positive wastes reviewer time and destroys trust. Better to miss a bug than report a fake one.

### Notable Findings Across 40 Contests

Real bugs found by Krait in blind audits:

- **AuraVault claim double-spend** (LoopFi H-401) — reward calculation doesn't deduct fees
- **UniV3 fee drain via shared position** (Vultisig H-43) — first claimer steals all fees
- **ILO launch DoS via slot0 manipulation** (Vultisig H-41) — attacker blocks all launches
- **Public internal functions → permanent DoS** (Phi H-51) — funds permanently locked
- **Pause bypass via direct function call** (LoopFi M-204) — emergency pause circumvented
- **ERC4626 first depositor inflation** (Basin H-01)
- **Reentrancy in rental system** (reNFT H-02)
- **EIP-712 typehash mismatch** (reNFT)
- **LockOnBehalf griefing** (Munchables H-01, H-02) — both HIGHs found, 100% precision
- **Oracle precision loss** (Dopex)
- **TVL calculation error** (Renzo)
- **Assembly encoding bug** (DittoETH M-221) — `add` vs `and` in inline assembly
- **Chainlink staleness** (Predy M-69)

---

## Architecture

```
krait/
├── .claude/
│   ├── commands/              # Slash commands for Claude Code
│   │   ├── krait.md           # Main 4-phase orchestrator (215 lines)
│   │   ├── krait-shadow.md    # Shadow audit pipeline (blind benchmark + learn)
│   │   ├── krait-learn.md     # Post-audit lesson integration
│   │   ├── krait-outreach.md  # Audit + outreach verification pass
│   │   └── krait-{phase}.md   # Individual phase commands
│   └── skills/                # Detailed methodology (single source of truth)
│       ├── krait-detector/
│       │   ├── SKILL.md       # Detection: 9 question categories, 50+ heuristics,
│       │   │                  #   30 modules, 4 parallel lenses, 3-pass strategy
│       │   └── primers/       # 7 protocol-specific attack pattern files
│       │       ├── defi-dex-amm.md
│       │       ├── defi-lending.md
│       │       ├── defi-staking-governance.md
│       │       ├── gamefi-nft.md
│       │       ├── bridge-crosschain.md
│       │       ├── proxy-upgrades.md
│       │       └── wallet-safe-aa.md
│       ├── krait-critic/
│       │   └── SKILL.md       # Verification: 8 kill gates, 10 FP patterns,
│       │                      #   exploit trace requirements, verdict format
│       ├── krait-recon/
│       │   ├── SKILL.md       # Recon: risk scoring, scope rules, architecture mapping
│       │   ├── ast-extract.sh # Solidity AST fact extraction
│       │   └── slither-summary.sh
│       ├── krait-state-auditor/
│       │   └── SKILL.md       # State analysis: coupled pairs, mutation matrix
│       └── krait-reporter/
│           └── SKILL.md       # Report formatting and dedup
│
├── src/                       # CLI tool (TypeScript, API-powered)
│   ├── cli.ts                 # CLI entry point (Commander.js)
│   ├── core/
│   │   ├── types.ts           # Core types (Finding, Report, Severity, Domain)
│   │   ├── config.ts          # Configuration management
│   │   ├── file-discovery.ts  # Smart file filtering (multi-language)
│   │   ├── file-scorer.ts     # Deterministic risk scoring
│   │   ├── reporter.ts        # JSON + Markdown report generation
│   │   ├── cache.ts           # Response caching for API calls
│   │   └── comparator.ts      # Finding comparison for shadow audits
│   ├── analysis/
│   │   ├── ai-analyzer.ts     # Core AI engine (Anthropic SDK)
│   │   ├── architecture-pass.ts # Cross-contract architecture analysis
│   │   ├── context-gatherer.ts  # Project context extraction
│   │   ├── contract-summarizer.ts
│   │   ├── deduplicator.ts    # Finding deduplication
│   │   ├── domain-checklists.ts # Domain-specific check generation
│   │   └── post-processor.ts  # Confidence scoring, FP reduction
│   ├── agents/                # Multi-agent analysis pipeline
│   │   ├── multi-agent.ts     # Agent orchestration
│   │   ├── detector.ts        # Detection agent
│   │   ├── critic.ts          # Verification agent
│   │   ├── ranker.ts          # Severity ranking agent
│   │   └── reasoner.ts        # Cross-contract reasoning agent
│   ├── knowledge/
│   │   ├── pattern-loader.ts  # YAML pattern ingestion
│   │   ├── audit-heuristics.ts # Domain heuristic library
│   │   ├── solodit-client.ts  # Solodit API integration
│   │   └── solodit-parser.ts  # Solodit content parsing
│   └── shadow/
│       ├── runner.ts          # Shadow audit automation
│       ├── registry.ts        # Contest registry management
│       ├── dashboard.ts       # Performance dashboard
│       └── feedback.ts        # Miss analysis feedback loop
│
├── patterns/                  # Vulnerability knowledge base (59 YAML files)
│   ├── solidity/              # Solidity-specific patterns (13 files)
│   ├── ai-red-team/           # AI/MCP security patterns (8 files)
│   └── learned/               # Archived lessons from shadow audits (25+ files)
│
├── shadow-audits/             # Benchmark tracking
│   ├── registry.yaml          # All 40 contest results
│   └── progress.md            # Cumulative metrics + trend charts
│
├── CLAUDE.md                  # Project instructions for Claude Code
├── package.json
└── tsconfig.json
```

### How Knowledge Flows

```
                    ┌─────────────────┐
                    │ Shadow Audit #N  │
                    │ (blind test)     │
                    └────────┬────────┘
                             │ score against
                             │ official findings
                             ▼
                    ┌─────────────────┐
                    │ Miss Analysis    │
                    │ WHY was it missed│
                    └────────┬────────┘
                             │
              ┌──────────────┼──────────────┐
              ▼              ▼              ▼
     ┌──────────────┐ ┌───────────┐ ┌───────────────┐
     │ New heuristic │ │ New module│ │ New FP pattern│
     │ in detector   │ │ in detect │ │ in critic     │
     │ SKILL.md      │ │ SKILL.md  │ │ SKILL.md      │
     └──────┬───────┘ └─────┬─────┘ └──────┬────────┘
            │               │              │
            └───────────────┼──────────────┘
                            ▼
                   ┌─────────────────┐
                   │ Shadow Audit #N+1│
                   │ (tests the fix)  │
                   └─────────────────┘
```

Every lesson goes into the SKILL.md files — they are the single source of truth. The slash commands (`krait.md`) reference SKILL.md files; they don't duplicate methodology.

---

## Kill Gate System

The biggest innovation in Krait's methodology. Eight automatic filters that run *before* any exploit trace is attempted. These account for 95%+ of all false positives across 40 contests.

| Gate | Name | What It Kills | TPs Ever |
|------|------|--------------|----------|
| A | Generic Best Practice | "Use SafeERC20", "add events", "centralization risk" | 0 |
| B | Theoretical | Exotic token behavior, oracle out-of-range, bounded overflow | 0 |
| C | Intentional Design | Matches docs/comments/reference implementation | 0 |
| D | Speculative | Can't state WHO/WHAT/HOW MUCH concretely | 0 |
| E | Admin Trust | Requires trusted admin to act maliciously | 0 |
| F | Dust | Rounding < $1/tx, precision loss < gas cost | 0 |
| G | Out of Context | Tokens/chains/standards not in protocol scope | 0 |
| H | Known/Acknowledged | Already in README known issues (mechanism match, not topic) | 0 |

**Result**: FPs dropped from 4.2/contest (v4) to 0.2/contest (v6.4) — a **95% reduction**.

---

## The Self-Improvement Loop

Krait doesn't just audit — it learns from every miss.

### Shadow Audit Pipeline (`/krait-shadow`)

```
Phase A: Setup      → Clone contest repo, create .audit/
Phase B: Blind Audit → Run full /krait — NO peeking at findings
Phase C: Score      → Fetch official H/M findings, map against blind report
Phase D: Learn      → Root-cause every miss, upgrade SKILL.md files
Phase E: Verify     → Re-run to confirm lessons work
Phase F: Registry   → Update metrics, track improvement
```

### Methodology Evolution

| Version | Key Changes | Impact |
|---------|-------------|--------|
| v1 | Basic prompting, no structure | 6% recall |
| v2 | Structured phases, heuristics | 30% recall |
| v3 | Multi-pass detection, modules | Precision issues (3.3 FP/contest) |
| v4 | 13 new heuristics, FP kill rules | Marginal gains |
| v5 | **Kill Gate system** | FPs: 4.2 → 0.6/contest |
| v5.1 | Two-pass detection, Gate H, Module D30 | +87% TPs, +14% precision |
| v5.2 | Cross-contract read, primers, What's Missing sweep | Non-determinism discovered |
| v6 | Deterministic file scoring, adaptive passes | Consistency fix |
| v6.4 | Architecture cleanup, 7 primers, Sprint 3+4 | **90% precision, 0.2 FP/contest** |

---

## Detection Coverage

### What Krait Catches Well
- Reentrancy / CEI violations
- Access control gaps and missing modifiers
- Oracle manipulation and staleness
- EIP/ERC standard compliance issues
- First depositor / share inflation attacks
- TVL and accounting calculation errors
- Public/exposed internal functions
- Pause mechanism bypasses
- Assembly encoding bugs
- UniV3 position management issues

### Known Weaknesses (Improving)
- Complex mathematical logic (CDP liquidation math, options pricing)
- Deep cross-chain bridge edge cases
- Game mechanic exploits requiring full game-theory reasoning
- Protocol-specific deep integration bugs (Curve adapters, UniV3 tick math)
- Economic design flaws (incentive misalignment vs. code bugs)

---

## Getting Started

### Prerequisites

- Node.js 20+
- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) for slash command mode
- Anthropic API key for CLI mode

### Using with Claude Code (Recommended)

1. Clone this repo into your projects
2. Open Claude Code in the target project directory
3. Run `/krait` to start a full audit

The methodology files in `.claude/skills/` are loaded automatically by Claude Code.

### Using the CLI

```bash
# Install
git clone https://github.com/ZealynxSecurity/krait.git
cd krait
npm install
npm run build

# Set API key
export ANTHROPIC_API_KEY=your-key-here

# Audit a project
npx krait audit /path/to/project

# Quick mode (Sonnet only, faster, cheaper)
npx krait audit /path/to/project --quick

# List loaded patterns
npx krait patterns
```

### Running a Shadow Audit

```bash
# Inside Claude Code:
/krait-shadow 2024-07-loopfi

# This runs the full blind benchmark:
# 1. Clones contest repo
# 2. Runs blind audit
# 3. Fetches official findings
# 4. Scores precision/recall
# 5. Analyzes misses
# 6. Updates methodology
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| AI Engine | Claude (Anthropic SDK) — Sonnet for speed, Opus for depth |
| Language | TypeScript (Node.js 20+) |
| CLI | Commander.js |
| Patterns | YAML knowledge base (59 files) |
| Testing | Vitest |
| Static Analysis | Slither integration (optional, Solidity pre-filter) |

---

## Project Status

| Component | Status |
|-----------|--------|
| Claude Code skills (full audit pipeline) | Production |
| Kill Gate false positive elimination | Production |
| Shadow audit benchmarking (40 contests) | Production |
| Self-improvement learning loop | Production |
| Protocol-specific detection primers (7 domains) | Production |
| CLI tool (API-powered) | Beta |
| Multi-agent pipeline | Beta |
| Solodit integration | Beta |
| Multi-domain (Rust, TypeScript, AI) | Planned |
| GitHub Action | Planned |
| PDF reports | Planned |

---

## Cost Model

| Mode | Cost |
|------|------|
| Claude Code skills | $0 (uses Claude subscription) |
| CLI — Small project (~500 LOC) | ~$0.30-0.50 |
| CLI — Medium project (~2K LOC) | ~$1-3 |
| CLI — Large project (~10K LOC) | ~$5-15 |

---

## Stats

- **40** shadow audits against real Code4rena contests
- **90%** average precision (v6.4)
- **0.2** false positives per contest (v6.4)
- **59** vulnerability patterns in knowledge base
- **50+** detection heuristics across 9 categories
- **30** targeted analysis modules
- **8** automatic kill gates for FP elimination
- **7** protocol-specific detection primers
- **333** source checks distilled from Zealynx audit-readiness platform

---

## Author

**Carlos Vendrell Felici** ([@TheBlockChainer](https://x.com/TheBlockChainer) / [@Bloqarl](https://github.com/Bloqarl))
Founder, [Zealynx Security](https://zealynx.io)

---

## License

[MIT](LICENSE) © [Zealynx Security](https://zealynx.io)

---

*Built with Claude Code. Every methodology iteration, every shadow audit, every lesson learned — developed in partnership with AI.*
