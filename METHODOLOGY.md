# Krait Methodology — Full Detection Pipeline

This document describes exactly how Krait finds vulnerabilities. Every technique here was derived from real missed findings in blind shadow audits against Code4rena contests, then validated by measuring precision/recall improvements.

Current version: **v7.0** (methodology) / **v6.4** (shadow audit scoring)

---

## Pipeline Overview

```
Phase 0: RECON           Phase 1: DETECTION           Phase 2: STATE           Phase 3: VERIFY
───────────────          ─────────────────           ─────────────          ──────────────
AST extraction           Pass 1: Tiered scan          Dependency map          8 kill gates
Risk scoring             ├─ Feynman interrogation     Mutation matrix         10 FP patterns
File tiering             ├─ 40 heuristic triggers     Cross-check verify      Deep code trace
Attack surface           └─ Function-state matrix     Operation ordering      PoC construction
Primer selection                                      Parallel paths          Severity assignment
                         Pass 2: 4 parallel lenses    User journey sim
      │                  ├─ A: Access/State/Gov       Masking detection           │
      │                  ├─ B: Value/Economic                                     │
      │                  ├─ C: External/Cross-contract    ◄── cross-feed ──►      │
      │                  └─ D: Edge/Math/Standards                                │
      │                                                                           ▼
      │                  Pass 3: Mechanical sweep                          Phase 4: REPORT
      │                  26 targeted modules (A-X)                         ──────────────
      ▼                  7 domain primers                                  Dedup + rank
  .audit/recon.md        .audit/findings/                                  JSON + Markdown
                         detector-candidates.md                            .audit/krait-report.md
```

---

## Phase 0: Recon — Deterministic Risk Scoring

Every file gets a risk score. This determines analysis depth — not random, not LLM-decided.

### Risk Score Formula

```
RISK_SCORE = (external_calls × 5)
           + (state_writing_functions × 4)
           + (payable_functions × 4)
           + (assembly_blocks × 6)
           + (unchecked_blocks × 3)
           + (LOC × 0.05)
           + (novel_code_bonus: +15)
           + (value_handling_bonus: +10)
           + (immaturity_bonus: +10)
```

### File Tiers

| Tier | Files | Treatment |
|------|-------|-----------|
| TIER 1 (DEEP) | Top 5 by risk score | Full 3-pass analysis, all lenses, all modules |
| TIER 2 (STANDARD) | Next 10 | Standard analysis, selected modules |
| TIER 3 (SCAN) | Remainder | Quick scan, heuristic triggers only |

### Recon Outputs

- **AST Fact Extraction** — compiler-verified inheritance trees, function registry, call graphs, modifier usage, state variables (via `ast-extract.sh`, fallback to regex)
- **Fund Flows** — where value enters, moves, and exits the protocol
- **Trust Boundaries** — which contracts trust which, external protocol dependencies
- **Contract Maturity** — fork detection, novel code identification
- **Protocol Primer Selection** — automatically selects domain-specific detection primers (DEX, Lending, Staking, etc.)
- **Optional Slither Pre-Scan** — supplementary signal, never auto-reported

---

## Phase 1: Detection — 16-Angle Analysis

### Multi-Mindset × Multi-Lens (v7.0)

Each function in Tier 1 files is examined from **16 angles**:

**4 Independent Mindsets:**

| Mindset | Core Question |
|---------|--------------|
| **Attacker** | "How would I exploit this to drain funds or escalate privilege?" |
| **Accountant** | "Trace every wei — do the numbers add up across all paths?" |
| **Spec Auditor** | "Does the code match what docs, comments, and EIPs say it should do?" |
| **Edge Case Hunter** | "What breaks at zero, max, empty, self-referential, or reentrant?" |

**4 Focused Lenses (Pass 2):**

| Lens | Focus Area |
|------|-----------|
| **A** | Access control, state integrity, governance invariants |
| **B** | Value flow, economic logic, fee consistency, rounding |
| **C** | External interactions, cross-contract, reentrancy, CEI |
| **D** | Edge cases, math safety, type casts, EIP/ERC compliance |

Findings discovered by multiple mindsets or lenses get a **consensus boost**. Single-source findings get extra scrutiny in verification.

### Pass 1: Feynman Interrogation

Every function is questioned through 7 categories (28+ questions):

1. **PURPOSE** — What invariant does this function protect? What breaks if it's removed?
2. **ORDERING** — Can I reorder operations to create an inconsistent state?
3. **CONSISTENCY** — Why does function A have this guard but function B doesn't?
4. **ASSUMPTIONS** — What's implicitly trusted? What if that trust is violated?
5. **BOUNDARIES** — First call, last call, double-call, empty state, max values?
6. **RETURN VALUES** — What persists on revert? Can a failed call leave dirty state?
7. **EXTERNAL CALLS** — What can happen between the call and the next line? Cross-tx windows?

### Pass 1: 40 Heuristic Triggers

Each heuristic was extracted from a real missed finding in shadow audits:

**Business Logic**: flash loan interactions, first-depositor inflation, round-trip exploits, fee-free arbitrage, circular collateral, liquidation profitability edge

**Reentrancy & State**: CEI violations, cross-function reentrancy, read-only reentrancy, state update ordering, storage collision

**Access Control**: missing modifiers on state writers, privilege escalation, proxy admin confusion, initializer re-call, ownership transfer gaps

**Value Handling**: unchecked transfer returns, ETH stuck in contract, fee-on-transfer tokens, rebasing tokens, ERC-777 hooks, approval race conditions

**Math & Precision**: unsafe type casts (uint256→uint128 silent truncation), rounding direction errors, accumulator overflow, division before multiplication, decimal mismatch

**External Integration**: oracle staleness, Chainlink sequencer downtime, Uniswap V3 tick math, Curve pool read-only reentrancy, Aave/Compound deprecated functions

**Governance & Time**: flash-loan voting, snapshot manipulation, timelock bypass, emergency pause incomplete, proposal front-running

**Cross-Chain**: bridge message replay, relayer trust, finality assumptions, chain-specific block.timestamp behavior

### Pass 3: Mechanical "What's Missing" Sweep

7 systematic checks run after the creative analysis:

1. **Missing inverse operations** — set without unset, lock without unlock, pause without unpause
2. **Missing access control** — state-writing functions without modifiers
3. **Missing reward checkpoint** — reward state not updated before balance change
4. **Missing restriction coverage** — some paths restricted, parallel paths unrestricted
5. **Missing paired operation validation** — deposit validates but withdraw doesn't
6. **Parameter transition safety** — retroactive impact on existing positions
7. **DoS on core functions** — unbounded loops, external call reverts, dust griefing

### 26 Targeted Analysis Modules (A-X)

Protocol-specific deep dives, triggered by recon findings:

Each high-impact module has a dedicated skill file in [`detector/modules/`](.claude/skills/krait/detector/modules/) with structured tables, step-by-step methodology, and trigger patterns. The detector reads the relevant module files based on what recon identifies.

| Module | Focus |
|--------|-------|
| A | Untrusted recipient analysis |
| B | Type cast safety (uint256→uint128, int256→uint256) |
| C | Transfer order / implicit flash loans |
| D | Fee consistency cross-check (deposit vs withdraw vs liquidate) |
| E | EIP/Standard compliance (ERC-712 typehash char-by-char!) |
| F | Token compatibility (fee-on-transfer, rebasing, ERC-777) |
| G | Factory/deployment patterns |
| H | Ownership/permission persistence across upgrades |
| I | Weight/proportionality calculations |
| J | External protocol integration (Convex, Aave, Uniswap — permissionless function check, shutdown/deprecation, silent failure) |
| K | Multi-transaction attack sequences |
| L | Derived class / override completeness |
| M | State variable lifecycle tracing |
| N | DoS-to-exploit escalation paths |
| O | Payment/distribution flow tracing |
| P | Cross-chain bridge security |
| Q | NFT attribute & randomness integrity |
| R | Governance voting integrity |
| S | Cross-contract state on transfer |
| T | Cross-interaction batch analysis |
| U | DeFi integration library (Curve, UniV3, Chainlink, Aave/Compound, Lido/stETH) |
| V | Economic design reasoning (circular collateral, liquidation profitability, first/last mover) |
| W | Missing functionality detection |
| X | Version & standard compliance audit (EIP-712, Safe version, OZ version, Solidity version) |

### 7 Domain-Specific Primers

Automatically selected based on recon:

| Primer | Checks |
|--------|--------|
| DEX/AMM | 20 checks — first depositor, round-trip exploit, flash loan price manipulation, LP pricing, factory rug |
| Lending | 22 checks — oracle manipulation, liquidation profitability, interest precision, health factor staleness |
| Staking/Governance | Reward timing, snapshot manipulation, delegation attacks, vote weight flash loans |
| Proxy/Upgrades | Storage collision, initializer safety, implementation selfdestruct, transparent vs UUPS |
| GameFi/NFT | Randomness manipulation, attribute collision, mint griefing, royalty bypass |
| Bridge/Cross-chain | Message replay, relayer trust, finality assumptions, token mapping |
| Wallet/Safe/AA | Signature validation, nonce management, module injection, guard bypass |

---

## Phase 2: State Analysis — Coupled State Inconsistency

This phase catches bugs that per-function analysis misses — where the vulnerability is in the **relationship** between state variables across different functions.

### 8-Step Methodology

1. **Dependency Mapping** — Every state variable paired with its coupled dependencies (totalSupply ↔ sum of balances, rewardDebt ↔ stakedAmount)
2. **Mutation Matrix** — For each state variable, list EVERY function that modifies it
3. **Cross-Check Verification** — When StateA updates, does ALL dependent StateB update in the same tx?
4. **Operation Ordering** — Trace sequential order of state changes within each function
5. **Parallel Path Comparison** — Compare similar operations (deposit vs mint, withdraw vs liquidate, normal vs emergency)
6. **User Journey Simulation** — Test realistic sequences (deposit → claim → withdraw → re-deposit)
7. **Masking Code Detection** — Flag defensive patterns (ternary clamps, try/catch, min/max caps) that HIDE broken invariants instead of fixing them
8. **Cross-Feed from Detector** — Consume detector candidates, trace structural issues deeper

### Why This Matters

28% of missed findings in shadow audits v1-v4 were state coupling bugs that per-function analysis couldn't see. Adding this phase improved recall by 15% in v5+.

---

## Phase 3: Verification — 8 Kill Gates

Every candidate finding must survive **all 8 gates** before reaching the report. These gates have eliminated 95% of false positives and have **never killed a true positive** across 40 contests.

### Automatic Kill Gates

| Gate | Kills | Example |
|------|-------|---------|
| **A** | Generic best practice | "Use SafeERC20", "Add events", "Use two-step ownership" |
| **B** | Theoretical / not exploitable | Exotic token behavior not in actual token list |
| **C** | Intentional design | Matches documentation, reference implementation, or fork origin |
| **D** | Speculative | "Could be an issue if..." — no concrete WHO/WHAT/HOW MUCH |
| **E** | Admin trust | Requires trusted admin action (exception: missing timelock on irreversible destructive ops) |
| **F** | Dust | Rounding loss < $1/tx, bounded truncation, precision loss < gas cost |
| **G** | Out of context | Token behaviors for unlisted tokens, chain issues on unsupported chains |
| **H** | Publicly known | Already in README "Known Issues" or previous audits |

**DoS Exception**: DoS that bricks a core lifecycle function + low cost to trigger + persistent = Medium minimum, survives gates A/B/D/F.

### 10 False Positive Patterns

After kill gates, remaining candidates are checked against 10 empirically-derived FP patterns:

1. **Authorization handled elsewhere** — auth in calling function, modifier, router, factory
2. **Validation in called functions** — guard in internal/external callee, library protection
3. **OpenZeppelin/Solmate standard protection** — battle-tested library provides the guard
4. **Rounding drift cleaned downstream** — dust threshold, reconciliation, safe rounding direction
5. **Bounded loops / economic constraints** — max iterations bounded, griefing too expensive
6. **Severity inflation** — real issue but actual impact lower than claimed
7. **Solidity 0.8+ arithmetic safety** — checked math built in (exception: explicit casts truncate silently)
8. **Read-only / view function confusion** — view functions can't modify state
9. **Test/script/interface-only** — not production code
10. **Documented design decision** — intentional trade-off acknowledged in code

### Verification Methods

| Method | When Used |
|--------|-----------|
| **Deep Code Trace** | Read cited code, trace full call chain, check for mitigating code in parent contracts, modifiers, guards |
| **PoC Trace** | Construct concrete attack: initial state → function calls → state changes → stolen amount |
| **Hybrid** | Code trace + PoC with actual values |

### Verdict Assignment

- **TRUE POSITIVE (TP)** — Verified exploitable, include proof trace
- **LIKELY TRUE (LT)** — Mechanism confirmed, edge-case dependent
- **DOWNGRADE** — Real issue, wrong severity
- **FALSE POSITIVE (FP)** — Disproven with evidence
- **INSUFFICIENT EVIDENCE (IE)** — Can't prove or disprove

---

## Phase 4: Report

1. Load only **VERIFIED + LIKELY TRUE** findings
2. **Deduplicate** — same file + lines + root cause → merge
3. **Rank** — CRITICAL > HIGH > MEDIUM
4. Generate `.audit/krait-report.md` (markdown) + `.audit/krait-findings.json` (JSON)

### Severity Rubric

| Severity | Criteria |
|----------|----------|
| **CRITICAL** | Direct, unconditional fund loss or permanent DoS. Any user can trigger. |
| **HIGH** | Conditional fund loss, privilege escalation, broken core invariant. Attacker can create conditions. |
| **MEDIUM** | Value leakage, griefing with cost, degraded functionality. Limited impact or unlikely conditions. |
| **LOW** | Informational, gas optimization, cosmetic. |

Every H/M finding includes: file:line location, description, impact assessment, concrete exploit trace (WHO does WHAT to steal HOW MUCH), root cause, recommendation with code before/after.

---

## Second Opinion: `/krait-review`

The kill gates are aggressive by design — zero false positives is the #1 priority. But aggressive gates can over-kill legitimate findings. `/krait-review` re-examines killed findings:

| Gate | Re-examination |
|------|---------------|
| **C** (intentional design) | Does the "intentional" design CREATE an exploitable condition? |
| **E** (admin trust) | Missing timelock on irreversible destructive action? Rug vector? |
| **B** (theoretical) | Can a multi-step exploit be constructed with flash loans or MEV? |
| **F** (dust) | Can dust accumulate over many transactions? Protocol-TVL context? |
| **D** (speculative) | Can a concrete trace be constructed now with more context? |

Revived findings are surfaced as **"Worth Manual Review"** — flags for the auditor, not verified TPs. The main report's zero-FP standard is preserved.

---

## Cross-Feed Iteration Loop

After Detection and State Analysis complete their first pass, findings cross-feed:

```
Detector candidates ──► State Auditor: "Does this happen during state inconsistency?"
State gaps           ──► Detector: "Why doesn't function X update coupled state Y?"
Masking code         ──► Both: "What invariant is broken underneath?"
```

If new findings emerge, the loop runs max 2 additional cycles. This catches bugs that neither phase would find alone.

---

## Shadow Audit Results

Tested blind against 40 Code4rena contests. The full results are in [`shadow-audits/`](shadow-audits/).

### Progression

| Version | Contests | Avg Precision | FPs/Contest | Key Change |
|---------|----------|--------------|-------------|------------|
| v1 | 1-3 | 12% | 1.3 | Baseline |
| v2 | 5-10 | 66% | 2.3 | Multi-pass + lenses |
| v3 | 11-20 | 34% | 3.3 | Over-engineered, regression |
| v4 | 21-30 | 37% | 4.2 | Module expansion |
| v5 | 31-35 | 70% | 0.6 | Kill gates introduced |
| **v6.4** | **36-40** | **90%** | **0.2** | Primers + architecture cleanup |

### Latest 5 Contests (v6.4)

| Contest | Type | LOC | TPs | FPs | Precision |
|---------|------|-----|-----|-----|-----------|
| LoopFi | Lending/Looping | 10,383 | 2 | 0 | **100%** |
| DittoETH | Stablecoin/OrderBook | 16,215 | 1 | 1 | 50% |
| Phi | Social/NFT | 3,964 | 1 | 0 | **100%** |
| Vultisig | ILO/Token | 2,705 | 2 | 0 | **100%** |
| Predy | DeFi Derivatives | 7,631 | 1 | 0 | **100%** |

4 consecutive 100% precision contests. 0.2 FPs/contest. No other AI audit tool publishes these numbers.

### Self-Improving Loop

After each blind test: score → root-cause every miss → update methodology → re-test. This loop produced the 40 heuristics, 26 modules, 7 primers, and 10 FP patterns from real missed findings — not from theory.

---

## By the Numbers

| Metric | Count |
|--------|-------|
| Detection heuristics | 40 |
| Targeted analysis modules | 26 (A-X) |
| Analysis angles per function | 16 (4 lenses × 4 mindsets) |
| Domain-specific primers | 7 |
| Kill gates | 8 |
| False positive patterns | 10 |
| Feynman question categories | 7 (28+ questions) |
| Mechanical sweep checks | 7 |
| Shadow audits completed | 40 |
| Precision (latest) | 90% |
| FPs per contest (latest) | 0.2 |
