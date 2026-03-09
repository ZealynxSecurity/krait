# Krait State Auditor — State Inconsistency & Coupled Pair Analysis

> Phase 2 of the Krait audit pipeline. Runs after Detector, cross-feeds with it.

## Trigger

Invoked by `/krait` (as part of full audit) or `/krait-state` (standalone).

## Prerequisites

- `.audit/recon.md` must exist (from krait-recon)
- `.audit/findings/detector-candidates.md` should exist (from krait-detect)
- Read both before starting

## Purpose

Find bugs where operations mutate one piece of coupled state without updating dependent counterparts, causing silent data corruption. This is a STRUCTURAL analysis that catches bugs the Feynman interrogation misses — specifically, state desynchronization across functions and contracts.

## Core Concept

**Coupled state pairs** are storage values that maintain a required relationship (invariant). When one changes without proportional adjustment to its dependent, the invariant breaks silently.

Examples:
- `balance` ↔ `totalSupply` (sum of all balances must equal totalSupply)
- `stakedAmount` ↔ `rewardDebt` (reward calculation depends on both)
- `position.size` ↔ `position.accumulatedFunding` (funding rate depends on size)
- `shares` ↔ `totalAssets` (exchange rate derived from ratio)
- `collateral` ↔ `debt` (health factor derived from both)
- `lpBalance` ↔ `checkpoint` (reward tracking depends on both)

## Eight-Phase Methodology

### Phase 1: Dependency Mapping

Build a **Coupled State Dependency Map** for every contract.

For each storage variable, answer: **"What other storage MUST change when this one changes?"**

Format:
```
Contract: VaultManager
┌─────────────────┬────────────────────┬─────────────────────┐
│ State Variable   │ Coupled With       │ Invariant           │
├─────────────────┼────────────────────┼─────────────────────┤
│ totalDeposits    │ userDeposits[*]    │ sum(userDeposits) = │
│                  │                    │ totalDeposits       │
│ shares[user]     │ totalShares        │ sum(shares) =       │
│                  │                    │ totalShares         │
│ rewardPerToken   │ lastUpdateTime     │ rewardPerToken      │
│                  │                    │ must be fresh       │
│ userRewardDebt[u]│ stakedBalance[u]   │ debt reflects       │
│                  │                    │ current stake       │
└─────────────────┴────────────────────┴─────────────────────┘
```

**Key principle**: If State A and State B are coupled, then EVERY function that writes to A must also write to B (or provably preserve the invariant).

### Phase 2: Mutation Matrix

For each state variable, list EVERY code path that modifies it:

```
State: totalShares
├── mint()          — increments by shares minted
├── burn()          — decrements by shares burned
├── transfer()      — unchanged (internal redistribution)
├── _liquidate()    — decrements by liquidated shares
└── ???             — are there other paths? (admin override, migration, initialize)
```

Mark uncertain mutation points with `???` — these are PRIMARY audit targets.

Include:
- Direct writes (`totalShares += amount`)
- Increments/decrements
- Deletions (`delete mapping[key]`)
- Implicit changes through internal calls
- Batch operations that modify per-item
- External triggers (callbacks, hooks that modify state)

### Phase 3: Cross-Check Verification

This is the core analysis. For EVERY operation that modifies State A of a coupled pair:

**Does it update ALL dependent states?**

Specifically verify:
- **Full removal**: When an entity is fully removed (burn all shares, close position, full withdrawal), are ALL coupled states reset? Or does orphaned state remain?
- **Partial reduction**: When amount decreases partially, are coupled values proportionally adjusted? Or do they reflect the old full amount?
- **Increase**: When amount increases, do all coupled values propagate correctly?
- **Transfer/migration**: When ownership moves between entities, does ALL coupled state transfer? Or just the primary value?
- **Batch operations**: In loops processing multiple items, is per-iteration coupling maintained?

**Red flag format:**
```
DESYNC CANDIDATE: [function] writes to [State A] but does NOT write to [State B]
- Coupled pair: State A ↔ State B
- Invariant: [what should hold]
- Breaking operation: [the function that only updates one side]
- Consequence: [what happens when invariant is broken]
```

### Phase 4: Operation Ordering Analysis

Within each function, trace the sequential order of state changes:

```
function withdraw(uint amount):
  1. READ  shares[msg.sender]        ← reads coupled state
  2. WRITE shares[msg.sender] -= x   ← updates primary
  3. CALL  token.transfer(...)       ← EXTERNAL CALL
  4. WRITE totalShares -= x          ← updates coupled AFTER external call!
```

Check:
- Are coupled pairs consistent AFTER each step? (Between steps 2 and 4, shares[user] is updated but totalShares isn't → window of inconsistency)
- Could an external call at step 3 observe the inconsistent state?
- Would a re-entrant call between steps 2 and 4 exploit the desync?

### Phase 5: Parallel Path Comparison

Compare functions that perform SIMILAR operations on the same state:

```
┌──────────────┬─────────────┬──────────────┐
│ Operation    │ withdraw()  │ liquidate()  │
├──────────────┼─────────────┼──────────────┤
│ Updates shares│ ✅          │ ✅            │
│ Updates total │ ✅          │ ❌ MISSING!   │
│ Updates debt  │ ✅          │ ❌ MISSING!   │
│ Emits event   │ ✅          │ ❌ MISSING!   │
└──────────────┴─────────────┴──────────────┘
```

If Path A adjusts coupled state but Path B skips it — **that's a finding**.

Compare these pairs:
- `deposit` vs `mint` (both add value)
- `withdraw` vs `redeem` (both remove value)
- `withdraw` vs `liquidate` (both remove, different actors)
- `transfer` vs `transferFrom` (both move value)
- Normal flow vs emergency/admin flow

### Phase 6: Multi-Step User Journey Simulation

Test realistic sequences:

1. `deposit → partial withdraw → claim rewards` — After partial withdraw, are reward calculations still correct?
2. `stake → delegate → undelegate → claim` — Does delegation properly track coupled state?
3. `borrow → repay partial → borrow more → liquidation` — Does each step maintain invariants?
4. `create position → modify → close` — Is ALL state cleaned up on close?

After each step, verify: if a function reads BOTH sides of a coupled pair, would it get consistent values?

### Phase 7: Masking Code Detection

**CRITICAL**: Defensive code patterns that HIDE broken invariants rather than preventing them.

Identify and flag:
- **Ternary clamps**: `x > y ? x - y : 0` — This silences an underflow. Why would x ever be > y? The real bug is WHY the values diverged.
- **Try/catch swallowing reverts**: A revert was expected to never happen. If it's being caught, the invariant it protects may be breakable.
- **Early exits on zero**: `if (amount == 0) return;` — If amount should never be zero at this point, why is it? Masking a rounding bug?
- **Min/max caps**: `Math.min(calculated, available)` — If calculated should never exceed available, why is the cap needed?
- **SafeMath without root cause**: Checked arithmetic prevents the revert but doesn't fix why the values diverged.

For each masking pattern found:
- What invariant is ACTUALLY broken underneath?
- Which coupled pair desync is being hidden?
- Can the masked condition be triggered in a way that causes value loss (not just a harmless clamp)?

### Phase 8: Cross-Feed from Detector

Read `.audit/findings/detector-candidates.md` and for each candidate:
- Does it involve a coupled state pair you identified?
- Does the Feynman finding expose a DEEPER state inconsistency?
- Are there additional candidates the Detector missed because they require structural analysis?

Generate NEW candidates based on cross-feed insights.

## Output

Save to `.audit/findings/state-candidates.md`:

```markdown
# Krait State Audit Candidates

## Coupled State Dependency Map
[The full map from Phase 1]

## Mutation Matrix
[Key state variables and all mutation paths]

## Desynchronization Candidates

### [STATE-XXX] Title

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**Coupled Pair**: StateA ↔ StateB
**Breaking Operation**: function_name()
**File**: path/to/file.sol
**Lines**: XX-YY

**Invariant**: [What should always hold]
**Breaking Scenario**:
1. Call function X with parameters Y
2. State A is updated to Z
3. State B is NOT updated (remains at old value)
4. Subsequent call to function W reads both A and B
5. Result: [incorrect calculation, value loss, etc.]

**Masking Code** (if any): [defensive pattern hiding this]
**Cross-Feed**: [Related Detector candidate, if any]
**Status**: UNVERIFIED
```

## Rules

- **Map ALL state before hunting.** Complete dependency map is mandatory before checking functions.
- **Every mutation path matters.** ALL functions modifying a state must update coupled state. Not just the "main" ones.
- **Partial operations are the primary source.** Partial withdrawals, partial liquidations, partial reductions are where coupled state updates are most commonly forgotten.
- **Compare parallel paths religiously.** If `withdraw` updates X but `liquidate` doesn't, that's almost always a bug.
- **Defensive code is a RED FLAG, not a safety net.** Clamping and try/catch hide broken invariants.
- **Evidence-based only.** Each finding must specify: the coupled pair, the breaking operation, a concrete trigger sequence, and the downstream consequence.
