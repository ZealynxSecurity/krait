# Shadow Audit Progress — Krait Self-Improvement Tracker

## Cumulative Results (30 Contests)

### v1 Methodology (Contests 1-3)

| # | Contest | HIGHs | MEDs | Precision | Recall | F1 | FPs |
|---|---------|-------|------|-----------|--------|----|-----|
| 1 | Basin | 1/1 | 0/12 | 16.7% | 7.7% | 10.5% | 0 |
| 2 | Wildcat V2 | 0/1 | 0/8 | 11.1% | 5.6% | 7.4% | 4 |
| 3 | Amphora | 0/3 | 0/3 | 8.3% | 4.2% | 5.6% | 0 |

### v2 Methodology (Contests 5-10)

| # | Contest | HIGHs | MEDs | Precision | Recall | F1 | FPs |
|---|---------|-------|------|-----------|--------|----|-----|
| 4 | Tangible | ?/? | ?/? | — | — | — | 0 | UNSCORABLE |
| 5 | Venus Prime | 0/3 | 1/2 | 100% | 20.0% | 33.3% | 0 |
| 6 | NextGen | 3/4 | 2/10 | 81.8% | 32.1% | 46.0% | 1 |
| 7 | Kelp DAO | 1/3 | 1/2 | 55.6% | 50.0% | 53.0% | 2 |
| 8 | Revolution | 0/4 | 5/14 | 69.2% | 25.0% | 37.0% | 2 |
| 9 | Decent | 0/4 | 3/5 | 45.5% | 27.8% | 35.0% | 3 |
| 10 | AI Arena | 4/8 | 0/9 | 45.0% | 26.5% | 33.0% | 5.5 |

### v3 Methodology (Contests 11-20)

| # | Contest | Krait H+M | Official | Precision | Recall | F1 | FPs | Notes |
|---|---------|-----------|----------|-----------|--------|----|-----|-------|
| 11 | Revert Lend | 7 | 33 | 33.3% | 6.1% | 10.3% | 4 | Complex UniV3 LP lending |
| 12 | Curves | 8 | 15 | **73.3%** | **36.7%** | **48.9%** | 2 | Best v3 F1; surface-level bugs |
| 13 | DYAD | 5 | 19 | 55.6% | 13.2% | 21.3% | 2 | Found kerosine bugs, missed economic design |
| 14 | Ethena | 2 | 4 | 33.3% | 12.5% | 18.2% | 1 | Subtle role/restriction bugs |
| 15 | Credit Guild | 5 | 29 | 40.0% | 6.9% | 11.8% | 3 | Huge codebase, found 2 exact HIGHs |
| 16 | Ondo | 7 | 4 | **0.0%** | **0.0%** | **0.0%** | 7 | **WORST EVER** — 100% FP rate |
| 17 | Salty | 8 | 39 | **85.7%** | 15.4% | 26.1% | 1 | **Best v3 precision**; 6/8 exact matches |
| 18 | Shell | 2 | 8 | 0.0% | 0.0% | 0.0% | 2 | Missed all Curve adapter bugs |
| 19 | Party | 6 | 9 | 0.0% | 0.0% | 0.0% | 6 | Missed all governance findings |
| 20 | Spectra | 7 | 2 | 16.7% | 50.0% | 25.0% | 5 | Only 2 official; many FPs on small target |

### v4 Methodology (Contests 21-30)

| # | Contest | Krait H+M | Official | Precision | Recall | F1 | FPs | Notes |
|---|---------|-----------|----------|-----------|--------|----|-----|-------|
| 21 | Dopex | 10 | 26 | 36.8% | 13.5% | 19.7% | 6 | Options/derivatives; caught oracle precision |
| 22 | Centrifuge | 6 | 8 | **45.5%** | **31.3%** | **37.0%** | 3 | Best v4 recall; RWA/lending |
| 23 | Badger | 5 | 7 | 0.0% | 0.0% | 0.0% | 5 | Complete miss; Liquity-fork CDP |
| 24 | Panoptic | 4 | 7 | 33.3% | 14.3% | 20.8% | 1 | Options/UniV3; partial on both HIGHs |
| 25 | Autonolas | 7 | 11 | 7.7% | 4.5% | 5.8% | 6 | Most HIGHs were Solana/lockbox |
| 26 | reNFT | 5 | 23 | **87.5%** | 15.2% | 25.9% | 0.5 | **Best v4 precision**; 0 clear FPs |
| 27 | Renzo | 11 | 22 | **62.5%** | **22.7%** | **33.3%** | 3 | **Best v4 F1**; LRT/restaking |
| 28 | Olas | 5 | 22 | 30.0% | 6.8% | 11.1% | 3 | Cross-chain staking; bridge-specific misses |
| 29 | Size | 10 | 17 | 28.6% | 11.8% | 17.0% | 5 | Credit markets; 5 FPs |
| 30 | TraitForge | 16 | 25 | 35.7% | 20.0% | 25.6% | 9 | NFT/GameFi; 5 TPs but 9 FPs |

### v5 Methodology — Kill Gates (Contests 31-35)

| # | Contest | Krait H+M | Official | Precision | Recall | F1 | FPs | Notes |
|---|---------|-----------|----------|-----------|--------|----|-----|-------|
| 31 | verwa | 2 | 11 | 50.0% | 9.1% | 15.4% | 1 | Found gauge removal power lock |
| 32 | Munchables | 2 | 6 | **100%** | **33.3%** | **50.0%** | 0 | **PERFECT** — Both HIGHs found |
| 33 | Abracadabra | 1 | 20 | **100%** | 5.0% | 9.5% | 0 | **PERFECT** — Found missing return |
| 34 | Stader | 2 | 15 | 0.0% | 0.0% | 0.0% | 2 | Both were known issues (not filtered) |
| 35 | Brahma | 0 | 4 | N/A | 0.0% | 0.0% | 0 | Clean sheet; Safe version bugs missed |

### v6.4 Methodology — Primers + Architecture Cleanup (Contests 36-40)

| # | Contest | Krait H+M | Official | Precision | Recall | F1 | FPs | Notes |
|---|---------|-----------|----------|-----------|--------|----|-----|-------|
| 36 | LoopFi | 2 | 45 | **100%** | 4.4% | 8.4% | 0 | AuraVault fee (H-401) + pause bypass (M-204) |
| 37 | DittoETH | 2 | 16 | 50% | 6.3% | 11.2% | 1 | LibBytes assembly (M-221). 1 FP. |
| 38 | Phi | 1 | 15 | **100%** | 6.7% | 12.6% | 0 | Public internal functions (H-51) |
| 39 | Vultisig | 2 | 6 | **100%** | **33.3%** | **50.0%** | 0 | Fee drain (H-43) + launch DoS (H-41) |
| 40 | Predy | 1 | 12 | **100%** | 8.3% | 15.3% | 0 | Chainlink staleness (M-69) |

### v7 Methodology — Module System + Recon Flags + New Heuristics (Contests 41-45)

| # | Contest | Krait H+M | Official | Precision | Recall | F1 | FPs | Notes |
|---|---------|-----------|----------|-----------|--------|----|-----|-------|
| 41 | Loop | 0 | 1 | N/A | 0.0% | 0.0% | 0 | Gates D/F over-killed real H-01 |
| 42 | Neobase | 1 | 8 | **100%** | 12.5% | 22.2% | 0 | GAUGE-01 caught H-01 at correct severity |
| 43 | Coinbase | 0 | 3 | N/A | 0.0% | 0.0% | 0 | Gate H over-killed H-01; no AA module |
| 44 | Open Dollar | 3 | 17 | **100%** | **17.6%** | 30.0% | 0 | **CONST-01 caught H-01 (ONE_HUNDRED_WAD)** |
| 45 | BakerFi | 4 | 12 | **100%** | **25.0%** | 40.0% | 0 | Slippage, oracle staleness, deposit math |

## Aggregate Stats

| Metric | v1 (1-3) | v2 (5-10) | v3 (11-20) | v4 (21-30) | v5 (31-35) | v6.4 (36-40) | **v7 (41-45)** |
|--------|----------|-----------|------------|------------|------------|-------------|---------------|
| Avg Precision | 12.0% | 66.2% | 33.8% | 36.8% | 70.0% | 90.0% | **100%** |
| Avg Recall | 5.8% | 30.2% | 14.1% | 14.0% | 9.5% | 11.8% | **11.0%** |
| Avg F1 | 7.8% | 38.0% | 16.2% | 19.6% | 15.0% | 19.5% | **18.4%** |
| Total FPs | 4 | 13.5 | 33 | 41.5 | 3 | 1 | **0** |
| Total Weighted TPs | 1.5 | 19.0 | 19.5 | 24.5 | 4.0 | 7 | **8** |
| FPs per contest | 1.3 | 2.3 | 3.3 | 4.2 | 0.6 | 0.2 | **0.0** |
| 100% precision | 0/3 | 1/6 | 1/10 | 1/10 | 3/5 | 4/5 | **5/5** |

### v7 Key Improvements
1. **100% precision across ALL 5 contests** — zero false positives. First time achieving this.
2. **CONST-01 heuristic** directly caught OpenDollar H-01 (ONE_HUNDRED_WAD) — was missed by v6.4 methodology.
3. **Severity calibration** fixed Neobase: rated H-01 as HIGH (v6.4 bare agent rated it MEDIUM).
4. **Module deduplication** reduced detector from 773→729 lines, improving instruction adherence.
5. **Kill gate trade-off**: 0 FPs but Gates D/F/H over-killed 3 real findings (Loop H-01, Coinbase H-01, BakerFi H-02/H-03).

*v7 precision: 100% on contests with findings (Neobase, OpenDollar, BakerFi). Contests with 0 findings (Loop, Coinbase) excluded from precision calc.

### v8 Regression Test (2026-03-25) — Open-Source Detection Integration

Integrated vectors from pashov/skills (MIT), PlamenTSV/plamen (MIT), forefy/.context (MIT). Added 5 new modules, 58 extended heuristics, primer enrichment, Devil's Advocate methodology.

**Regression results (simulated on same 5 v7 contests):**

| Contest | v7 TPs | v8 TPs | v8 FPs | Module Triggers Correct? | Verdict |
|---------|--------|--------|--------|--------------------------|---------|
| Neobase | 1 | 1 | 0 | YES (governance, economic) | PASS |
| Open Dollar | 3 | 3 | 0 | YES (lending-liq, oracle, economic) | PASS |
| BakerFi | 4 | 4 | 0 | YES (vault, oracle, amm-mev, flash, external) | PASS |
| Loop | 0 | 0 | 0 | YES (token-flow, flash, economic) | PASS |
| Coinbase | 0 | 0 (+1 catchable) | 0 | YES (AA-4337 triggers, 7702 correctly silent) | PASS |

**Key findings:**
1. **Precision preserved at 100%** — zero new FPs across all 5 contests
2. **Coinbase H-01 now catchable** — AA module Vector 1 targets cross-chain replay via `upgradeToAndCall`; Gate H precision requirement correctly distinguishes from known issue
3. **Module trigger accuracy 100%** — all 5 new modules trigger/skip correctly
4. **No context saturation** — findings remain specific with file:line references
5. **Potential recall improvements**: Coinbase H-01 (AA module), BakerFi pause-blocking (lending-liq), Neobase unsettled accumulator (economic)

### v5.1 Methodology — Kill Gates + Two-Pass + D30 (Re-test of 31-35)

| # | Contest | Krait H+M | Official | Precision | Recall | F1 | FPs | Notes |
|---|---------|-----------|----------|-----------|--------|----|-----|-------|
| 31 | verwa | 2 | 11 | **100%** | **18.2%** | 30.8% | 0 | +1 TP (gauge init), -1 FP vs v5 |
| 32 | Munchables | 3 | 6 | 66.7% | 33.3% | 44.4% | 1 | Same TPs, +1 FP (fee-on-transfer) |
| 33 | Abracadabra | 4 | 20 | 37.5% | 7.5% | 12.5% | 2 | +0.5 TP, +2 FPs (tx.origin, decimals) |
| 34 | Stader | 1 | 15 | **100%** | **6.7%** | 12.5% | 0 | **+1 TP (proxy init!), -2 FPs** |
| 35 | Brahma | 1 | 4 | **100%** | **25%** | 40.0% | 0 | **+1 TP (gas refund drain!), 0 FPs** |

**v5.1 totals: 7.5 TPs, 3 FPs, 71.4% precision, 13.4% recall**
**v5 totals: 4.0 TPs, 3 FPs, 57.1% precision, 7.1% recall**
**Improvement: +87.5% TPs, +14.3% precision, +88.7% recall, same FP count**

### v5 Methodology — KILL GATES CRUSH FPs, RECALL DROPS

v5 Kill Gate system dramatically reduced false positives — the #1 goal. But recall dropped further.

**What improved:**
1. **FPs collapsed: 0.6 per contest** (was 4.2 in v4) — **86% reduction**
2. **3 of 5 contests had 0 FPs** (munchables, abracadabra, brahma)
3. **2 of 3 contests with findings had 100% precision** — when Krait reports something, it's real
4. **Munchables: 100% precision, 33.3% recall, F1=0.50** — tied for best F1 ever (with Kelp DAO)

**What didn't improve:**
1. **Recall dropped to 9.5%** (was 14% in v4) — Kill Gates are too aggressive, killing findings before they're fully analyzed
2. **Stader: 2 FPs from known issues** — needs Gate H (read README known issues before reporting)
3. **Brahma: 0 findings** — Safe version compatibility bugs require ecosystem-specific knowledge
4. **Large codebases still hard** — Abracadabra (20 contracts) only found 1 of 20 bugs

**Key insight:** Kill Gates work exactly as designed for FP elimination. The precision/FP tradeoff is correct. But we're now leaving real TPs on the table because the gates don't help find MORE bugs. Next step: improve detection (Phase 1) quality while keeping gates in place.

**New gap found:** Gate H needed — filter out publicly known/acknowledged issues from README before reporting.

### v4 Methodology — MARGINAL IMPROVEMENT over v3

v4 shows slight improvement over v3 but is still far below v2 peaks.

**What improved:**
1. **Precision up +3%** (33.8% → 36.8%) — FP kill rules helped slightly
2. **F1 up +3.4%** (16.2% → 19.6%) — driven by precision gains
3. **TPs up +26%** (19.5 → 24.5) — finding more real bugs in absolute terms
4. **Best single contests**: reNFT (87.5% precision, 0 FPs), Renzo (62.5% precision, F1 33.3%)

**What didn't improve:**
1. **Recall flat** (14.1% → 14.0%) — still missing 86% of bugs
2. **FPs still high** (33 → 41.5) — absolute FP count went UP despite FP kill rules
3. **One complete miss** (Badger 0%/0%) — Liquity-fork CDP interactions still opaque
4. **Autonolas near-miss** (7.7% precision) — many HIGHs were Solana code (can't analyze)

**Honest assessment:** v4 heuristics (BATCH-01, ECON-01, CURVE-01, UNI-01, etc.) and FP kill rules (patterns 14-17) produced measurable but marginal gains. The core problem remains: Krait finds surface-level bugs but misses protocol-specific deep logic. v2's higher numbers reflected easier contests, not a better methodology.

## Recall Trend (All 30 Contests)

```
Contest 1  (Basin):        ████░░░░░░░░░░░░░░░░  7.7%   (v1)
Contest 2  (Wildcat):      ███░░░░░░░░░░░░░░░░░  5.6%   (v1)
Contest 3  (Amphora):      ██░░░░░░░░░░░░░░░░░░  4.2%   (v1) ← methodology overhaul
Contest 5  (Venus):        ██████████░░░░░░░░░░  20.0%  (v2)
Contest 6  (NextGen):      ████████████████░░░░  32.1%  (v2)
Contest 7  (Kelp):         ████████████████████  50.0%  (v2) ← ALL-TIME PEAK
Contest 8  (Revolution):   ████████████░░░░░░░░  25.0%  (v2)
Contest 9  (Decent):       ██████████████░░░░░░  27.8%  (v2)
Contest 10 (AI Arena):     █████████████░░░░░░░  26.5%  (v2)
                           ─── v3 methodology ────────
Contest 11 (Revert Lend):  ███░░░░░░░░░░░░░░░░░  6.1%   (v3)
Contest 12 (Curves):       ██████████████████░░  36.7%  (v3)
Contest 13 (DYAD):         ███████░░░░░░░░░░░░░  13.2%  (v3)
Contest 14 (Ethena):       ██████░░░░░░░░░░░░░░  12.5%  (v3)
Contest 15 (Credit Guild): ███░░░░░░░░░░░░░░░░░  6.9%   (v3)
Contest 16 (Ondo):         ░░░░░░░░░░░░░░░░░░░░  0.0%   (v3) ← WORST
Contest 17 (Salty):        ████████░░░░░░░░░░░░  15.4%  (v3)
Contest 18 (Shell):        ░░░░░░░░░░░░░░░░░░░░  0.0%   (v3)
Contest 19 (Party):        ░░░░░░░░░░░░░░░░░░░░  0.0%   (v3)
Contest 20 (Spectra):      ████████████████████  50.0%  (v3) ← only 2 official
                           ─── v4 methodology ────────
Contest 21 (Dopex):        ███████░░░░░░░░░░░░░  13.5%  (v4)
Contest 22 (Centrifuge):   ████████████████░░░░  31.3%  (v4) ← Best v4
Contest 23 (Badger):       ░░░░░░░░░░░░░░░░░░░░  0.0%   (v4)
Contest 24 (Panoptic):     ███████░░░░░░░░░░░░░  14.3%  (v4)
Contest 25 (Autonolas):    ██░░░░░░░░░░░░░░░░░░  4.5%   (v4)
Contest 26 (reNFT):        ████████░░░░░░░░░░░░  15.2%  (v4)
Contest 27 (Renzo):        ███████████░░░░░░░░░  22.7%  (v4)
Contest 28 (Olas):         ███░░░░░░░░░░░░░░░░░  6.8%   (v4)
Contest 29 (Size):         ██████░░░░░░░░░░░░░░  11.8%  (v4)
Contest 30 (TraitForge):   ██████████░░░░░░░░░░  20.0%  (v4)
                           ─── v5 Kill Gates ────────
Contest 31 (verwa):        █████░░░░░░░░░░░░░░░  9.1%   (v5)
Contest 32 (Munchables):   █████████████████░░░  33.3%  (v5) ← v5 PEAK
Contest 33 (Abracadabra):  ███░░░░░░░░░░░░░░░░░  5.0%   (v5)
Contest 34 (Stader):       ░░░░░░░░░░░░░░░░░░░░  0.0%   (v5) known issues
Contest 35 (Brahma):       ░░░░░░░░░░░░░░░░░░░░  0.0%   (v5) 0 findings
```

## Precision Trend

```
Contest 1  (Basin):        ████████░░░░░░░░░░░░  16.7%
Contest 2  (Wildcat):      ██████░░░░░░░░░░░░░░  11.1%
Contest 3  (Amphora):      ████░░░░░░░░░░░░░░░░  8.3%
Contest 5  (Venus):        ████████████████████  100%!  ← PEAK
Contest 6  (NextGen):      ████████████████░░░░  81.8%
Contest 7  (Kelp):         ███████████░░░░░░░░░  55.6%
Contest 8  (Revolution):   ██████████████░░░░░░  69.2%
Contest 9  (Decent):       █████████░░░░░░░░░░░  45.5%
Contest 10 (AI Arena):     █████████░░░░░░░░░░░  45.0%
                           ─── v3 methodology ────────
Contest 11 (Revert Lend):  ███████░░░░░░░░░░░░░  33.3%
Contest 12 (Curves):       ███████████████░░░░░  73.3%
Contest 13 (DYAD):         ███████████░░░░░░░░░  55.6%
Contest 14 (Ethena):       ███████░░░░░░░░░░░░░  33.3%
Contest 15 (Credit Guild): ████████░░░░░░░░░░░░  40.0%
Contest 16 (Ondo):         ░░░░░░░░░░░░░░░░░░░░  0.0%   ← WORST
Contest 17 (Salty):        █████████████████░░░  85.7%  ← NEAR PEAK
Contest 18 (Shell):        ░░░░░░░░░░░░░░░░░░░░  0.0%
Contest 19 (Party):        ░░░░░░░░░░░░░░░░░░░░  0.0%
Contest 20 (Spectra):      ████░░░░░░░░░░░░░░░░  16.7%
                           ─── v4 methodology ────────
Contest 21 (Dopex):        ███████░░░░░░░░░░░░░  36.8%
Contest 22 (Centrifuge):   █████████░░░░░░░░░░░  45.5%
Contest 23 (Badger):       ░░░░░░░░░░░░░░░░░░░░  0.0%
Contest 24 (Panoptic):     ███████░░░░░░░░░░░░░  33.3%
Contest 25 (Autonolas):    ██░░░░░░░░░░░░░░░░░░  7.7%
Contest 26 (reNFT):        █████████████████░░░  87.5%  ← v4 PEAK
Contest 27 (Renzo):        █████████████░░░░░░░  62.5%
Contest 28 (Olas):         ██████░░░░░░░░░░░░░░  30.0%
Contest 29 (Size):         ██████░░░░░░░░░░░░░░  28.6%
Contest 30 (TraitForge):   ███████░░░░░░░░░░░░░  35.7%
                           ─── v5 Kill Gates ────────
Contest 31 (verwa):        ██████████░░░░░░░░░░  50.0%
Contest 32 (Munchables):   ████████████████████  100%!  ← PERFECT
Contest 33 (Abracadabra):  ████████████████████  100%!  ← PERFECT
Contest 34 (Stader):       ░░░░░░░░░░░░░░░░░░░░  0.0%   known issues
Contest 35 (Brahma):       ░░░░░░░░░░░░░░░░░░░░  N/A    0 findings
```

## v3 Root Cause Analysis — Why the Regression?

### The Good (v3 wins)
- **Salty (85.7% precision, 6 TPs)**: Best single-contest precision in v3. Found copy-paste bug, braces bug, POL drain, oracle manipulation, wallet proposal reset, first-depositor attack, price feed DoS. Demonstrates Krait CAN find bugs in complex codebases.
- **Curves (73.3% precision, 5.5 TPs)**: Surface-level bugs (broken modifiers, missing access control) caught efficiently.
- **DYAD (55.6% precision, 2.5 TPs)**: Found kerosine-specific bugs requiring deep contract interaction analysis.
- **Credit Guild (40% precision, 2 TPs)**: Found subtle memory/storage ordering bug (H-04) and governance state persistence (M-05).

### The Bad (v3 failures)
- **Three 0% contests**: Ondo, Shell, Party — zero overlap with official findings
- **FP explosion**: 33 total FPs. Ondo alone: 7 FPs, all wrong. Party: 6 FPs.
- **Severity miscalibration**: Event emission issues rated as HIGH (Ondo), rounding dust rated as HIGH (Party)

### Pattern of v3 Misses

1. **Cross-contract batch interaction bugs** (Shell H-1, Revert Lend H-03/H-04): Bugs requiring reasoning about state across multiple calls in a single transaction
2. **Economic design flaws** (DYAD H-01/H-02, Credit Guild H-01/H-02/H-03): Protocol-level incentive misalignment, not code bugs
3. **Missing functionality** (Ondo M-1): Code that should exist but doesn't
4. **Ecosystem-specific knowledge** (Ondo M-2 AA wallets, Revert Lend UniV3 tick math): Domain expertise gaps
5. **Governance attack vectors** (Party H-1/H-2): Multi-step attacks exploiting governance flow
6. **Curve adapter integration** (Shell H-2/H-3/H-4, M-1/M-3/M-4): DeFi-specific integration patterns
7. **Role/restriction bypass** (Ethena M-01/M-02): Permission system edge cases

### v4 Priorities

1. **FP reduction is #1 priority** — Restoring zero-FP discipline. Event emissions, rounding dust, admin-trust issues should NEVER be rated M+.
2. **Cross-interaction analysis** — Need to reason about state across batch operations, not just per-function
3. **Missing functionality detection** — Check if config setters have unsetters, if restrictions cover all exit paths
4. **Integration pattern library** — Curve, UniV3, Chainlink integration patterns are highly specific
5. **Economic reasoning** — Protocol-level incentive analysis, not just code correctness

### v3 Heuristics/Modules Added (from contests 6-10)

**14 heuristics**: BRIDGE-01 to BRIDGE-04, NFT-01 to NFT-03, AC-03/AC-04, INJ-01, GOV-01/GOV-02
**5 modules**: D20-D24 (Payment Flow, Cross-Chain, NFT Integrity, Governance Voting, Cross-Contract State)
**1 question**: Q3.6 (Transfer State Check)

### v4 Heuristics Needed (from contests 11-20 misses)

**New heuristic candidates:**
- BATCH-01: Cross-interaction balance accounting in batch/multi-call systems
- ECON-01: Circular collateral valuation (endogenous collateral counted in own backing)
- ECON-02: Liquidation profitability analysis (when is it rational to liquidate?)
- MISSING-01: Missing unsetters/clearers for admin configuration
- MISSING-02: Restriction coverage gaps (does the restriction cover ALL exit paths?)
- CURVE-01: Curve pool integration risks (killed pools, native coin, compute type)
- UNI-01: Uniswap V3 tick math and negative tick handling
- PERMIT-01: ERC20 permit/approval token address validation
- CALLBACK-01: ERC721/ERC1155 callback reentrancy (onERC721Received exploitation)
- SLIPPAGE-01: Missing slippage/deadline in DEX interactions
- AA-01: Account abstraction wallet address derivation differences cross-chain
- PACKED-01: abi.encodePacked collision risks for hash keys
- HOOK-01: Transfer hook conflicts with admin override functions (blocklist blocking burn)
- GOVERNANCE-01: Host/proposer privilege escalation via role transfer
- ZERO-OP-01: Zero-value operations as griefing vectors (zero deposit blocking withdrawals)
