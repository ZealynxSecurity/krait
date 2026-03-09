# Krait Detector — Feynman Interrogation + Pattern-Aware Detection

> Phase 1 of the Krait audit pipeline. Runs after Recon.

## Trigger

Invoked by `/krait` (as part of full audit) or `/krait-detect` (standalone).

## Prerequisites

- `.audit/recon.md` must exist (from krait-recon phase)
- Read the recon report before starting

## Purpose

Find vulnerability CANDIDATES through systematic first-principles interrogation of every significant function, enhanced with knowledge of 40+ real exploit patterns. This phase maximizes RECALL — cast a wide net. The Critic phase will filter false positives later.

## Core Philosophy

**"If you cannot explain WHY a line of code exists, you do not understand it — and where understanding breaks down, bugs hide."**

Do NOT pattern-match. REASON about the code. Ask WHY each decision was made, WHAT breaks if it changes, and WHO benefits from an exploit.

## Execution

### Step 1: Load Context

Read `.audit/recon.md` to understand:
- Protocol type and relevant checklists
- Fund flows and trust boundaries
- High-risk files to prioritize
- Novel code vs library code

### Step 2: Build Function-State Matrix

For EACH core contract (skip libraries, interfaces, test files), build:

| Function | Visibility | Reads | Writes | Guards | External Calls | Payable? |
|----------|-----------|-------|--------|--------|----------------|----------|

This matrix is your map. It reveals:
- Functions that WRITE state but have NO guards
- Functions that make EXTERNAL CALLS after state changes (reentrancy)
- Functions that READ from external sources without validation (oracle trust)
- Pairs of functions that touch the same state (consistency requirements)

### Step 3: Systematic Interrogation

For every entry point (external/public function), apply these seven question categories. Not every question applies to every function — use judgment to focus on high-risk areas.

#### Category 1: PURPOSE — Why does this code exist?

- **Q1.1**: What invariant does this line/check protect? If you can't answer → suspicious.
- **Q1.2**: What breaks if I delete this line? Dead code, missing dependency, or critical guard?
- **Q1.3**: What specific attack motivated this check? If no clear attack → may be cargo-culted.
- **Q1.4**: Is this check SUFFICIENT? A `> 0` check doesn't prevent dust griefing. A `!= address(0)` doesn't prevent wrong-but-valid addresses.

#### Category 2: ORDERING — What if I move this?

- **Q2.1**: What if state-changing code moves BEFORE validation? → Check-effects-interactions violation.
- **Q2.2**: What if it moves AFTER downstream code? → Stale state read.
- **Q2.3**: Where is the FIRST state write? Where is the LAST state read? Is there a gap where external calls happen between them?
- **Q2.4**: If the function reverts halfway, what state persists? (Events emitted before revert are still logged; side effects from external calls may persist.)
- **Q2.5**: Can the ORDER in which users call this function matter? → Front-running, race conditions.

#### Category 3: CONSISTENCY — Why does A have it but B doesn't?

- **Q3.1**: If function A has an access guard, do ALL functions modifying the same state have guards?
- **Q3.2**: If `deposit()` validates parameter X, does `withdraw()` validate the corresponding parameter? Paired operations MUST match.
- **Q3.3**: If one function checks for zero amounts, do sibling functions?
- **Q3.4**: If one function emits an event on state change, do all functions changing the same state? Missing events break off-chain tracking.
- **Q3.5**: Is overflow/underflow protection consistent across all arithmetic paths?

#### Category 4: ASSUMPTIONS — What is implicitly trusted?

- **Q4.1**: What does this assume about the CALLER? (Identity, authorization, contract vs EOA)
- **Q4.2**: What does it assume about EXTERNAL DATA? (Token behavior, oracle freshness, API responses)
- **Q4.3**: What does it assume about CURRENT STATE? (Not paused, initialized, non-empty, not migrated)
- **Q4.4**: What does it assume about TIME/ORDERING? (block.timestamp can be manipulated ±15s; events may arrive out-of-order on L2s)
- **Q4.5**: What does it assume about PRICES/RATES? (Can they be stale, zero, max, or manipulated within one tx?)
- **Q4.6**: What does it assume about INPUT AMOUNTS? (What if 0? What if 1 wei? What if type(uint256).max?)

#### Category 5: BOUNDARIES & EDGE CASES

- **Q5.1**: First call with empty state? (First depositor, division-by-zero, share inflation, uninitialized mappings)
- **Q5.2**: Last call draining everything? (Dust trapped, rounding errors on final withdrawal, totalSupply == 0)
- **Q5.3**: Called twice in rapid succession? (Re-initialization, double-spending, nonce reuse)
- **Q5.4**: Two different functions called atomically? (Cross-function invariant violations, flash loan composability)
- **Q5.5**: Self-referential inputs? (Token A == Token B, sender == receiver, contract calling itself)

#### Category 6: RETURN VALUES & ERROR PATHS

- **Q6.1**: Can the caller IGNORE the return value? Is error handling forced by the language?
- **Q6.2**: What PERSISTS on the error path? Side effects before revert?
- **Q6.3**: Can external calls FAIL SILENTLY? (ERC20 transfer returns false without reverting)
- **Q6.4**: Is there a code path with NO return and NO error? (Missing else branch, uncovered enum case)

#### Category 7: EXTERNAL CALLS & CROSS-TX STATE

**Within one transaction:**
- **Q7.1**: If external call moves BEFORE state update → can callee exploit stale state?
- **Q7.2**: If external call moves AFTER → what changes? Original ordering may expose window.
- **Q7.3**: What can the CALLEE do with current state at call time? (Re-enter, read manipulated values, call other functions)
- **Q7.4**: What state MUST be updated before each external call? (Checks-effects-interactions)

**Across transactions:**
- **Q7.5**: Does the second call behave correctly given state from the first? (Rounding compounds, totals diverge)
- **Q7.6**: Does tx T2 revert/succeed unexpectedly after T1? (State drift, impossible conditions)
- **Q7.7**: Does accumulated state over many calls create unreachable conditions? (Dust accumulation, precision loss, ceiling hits)
- **Q7.8**: Can an attacker SEQUENCE transactions adversarially? (Normal single-call use works fine, but creative sequencing breaks invariants)

### Step 4: Apply Audit Heuristics

For each file, check these 40 heuristic triggers from real exploits. If the code matches a trigger, apply the corresponding check:

**Business Logic (BL-01 to BL-12):**
- BL-01: Multi-step process → Can steps execute out of order?
- BL-02: State machine → Can transitions be skipped/reversed?
- BL-03: Dual accounting (internal + balanceOf) → Can they diverge? Donation attack?
- BL-04: Reward distribution → Stake-before-distribution gaming? Double-claim?
- BL-05: Auction/timelock → Griefing? Expired execution? Timestamp manipulation?
- BL-06: Whitelist/blacklist → Transfer through intermediary bypass?
- BL-07: Liquidation → Over-extraction? Self-liquidation profit? Oracle-triggered?
- BL-08: Withdrawal queue → Front-run? Exchange rate locked at request or fulfillment?
- BL-09: Fee-on-transfer tokens → amount sent != amount received? Rebasing stale cache?
- BL-10: ERC4626/share vault → First depositor inflation? (Only if LACKS virtual offset)
- BL-11: Governance voting → Flash loan votes? Snapshot timing? Transfer-and-revote?
- BL-12: Cross-chain/bridge → Replay? Source chain verification? Failed message recovery?

**Arbitrary External Calls (AEC-01 to AEC-03):**
- AEC-01: User-controlled call target → drain approved tokens? selfdestruct?
- AEC-02: Callback after state change → re-enter during callback? grief via revert?
- AEC-03: Multicall/batch → msg.value reuse? bypass individual restrictions?

**Read-Only Reentrancy (ROR-01):**
- ROR-01: View function during callback window → stale/manipulated value for other protocols?

**Proxy/Upgrades (PRX-01, PRX-02):**
- PRX-01: Initializer → _disableInitializers in constructor? Direct implementation init?
- PRX-02: Delegatecall → Storage layout match? Collision? Gap array?

**Share Inflation (SI-01):**
- SI-01: ERC4626 → Virtual offset present? First depositor donation attack?

**Fee Logic (FDC-01, FDC-02):**
- FDC-01: Sequential fees → Each on REMAINING amount? Total bounded < 100%?
- FDC-02: Fee precision → Consistent denominator? Division before multiplication? Rounding direction?

**Transient Storage (TS-01):**
- TS-01: TSTORE/TLOAD → Cleared after tx? Multicall stale values? Replaces reentrancy guard?

**Missing Return Check (MRV-01):**
- MRV-01: ERC20 transfer/approve → safeTransfer used? USDT no-return-bool?

**Oracle (ORC-01, ORC-02):**
- ORC-01: AMM spot price → Flash loan manipulable? Use TWAP instead?
- ORC-02: Chainlink → Staleness check? Zero price? roundId? L2 sequencer?

**Signatures (SIG-01, SIG-02):**
- SIG-01: EIP-712/permit → Replay protection? chainId? Cross-contract? ecrecover(0)?
- SIG-02: Permit2 → Front-run? Nonce invalidation? Griefing?

**ETH Handling (ETH-01, ETH-02):**
- ETH-01: Payable → msg.value checked? Excess locked? Refund on partial fail? selfdestruct force-send?
- ETH-02: ETH to external → Recipient without receive()? Revert bricks function? Use WETH?

**Access Control (AC-01, AC-02):**
- AC-01: Multiple roles → Escalation? Admin can grant critical roles? Compromised non-critical causes fund loss?
- AC-02: Ownership transfer → Two-step? Wrong address permanent loss?

**Token Hooks (TOK-01, TOK-02):**
- TOK-01: ERC721/1155 safeTransfer → onReceived callback reentrancy?
- TOK-02: Non-standard decimals → Assumes 18? USDC(6)/WBTC(8) precision loss?

**Flash Loan (FL-01):**
- FL-01: balanceOf-based accounting → Flash loan deposit manipulation?

**CREATE2 (C2-01):**
- C2-01: Deterministic deployment → Front-run address? Destruction + redeploy state reset?

**Reentrancy (RE-01):**
- RE-01: Cross-function → Function A has nonReentrant, function B doesn't, both share state?

**Precision (PR-01 to PR-03):**
- PR-01: Small amount division → Rounds to zero? Repeated small tx profit?
- PR-02: Price/rate as integer → Rounding direction safe? One-sided manipulation?
- PR-03: Dual conversion (assets↔shares) → Round OPPOSITE directions? mint(1 wei) paying 0?

### Step 5: Cross-Function Analysis

After individual function interrogation:

1. **Guard Consistency**: Group functions by shared state writes. If function A has `onlyOwner` but function B writes to the same mapping without it → finding.
2. **Inverse Operation Parity**: Compare deposit↔withdraw, mint↔burn, stake↔unstake. Verify they're symmetric. If deposit validates X, withdraw must validate the inverse.
3. **State Transition Integrity**: Can states be skipped, triggered out-of-order, or triggered by wrong actors?
4. **Value Flow Conservation**: Does value in == value out? Can value be created or destroyed unexpectedly?

### Step 6: Record Candidates

For EVERY suspected vulnerability, create a candidate entry:

```markdown
### [CANDIDATE-XXX] Title

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**File**: path/to/file.sol
**Lines**: XX-YY
**Category**: [category]

**Discovery Method**: [Which question/heuristic exposed this]

**Description**: [What's wrong, in concrete terms]

**Scenario**:
1. Attacker does X
2. This causes Y
3. Because the code at line Z does/doesn't do W
4. Result: [impact]

**Vulnerable Code**:
```solidity
// paste the actual vulnerable lines
```

**Why This Is a Bug**: [Not "might be" — state your case]

**Status**: UNVERIFIED — needs Critic validation
```

Save ALL candidates to `.audit/findings/detector-candidates.md`.

## Rules

- **MAXIMIZE RECALL.** Report anything suspicious. The Critic will filter later.
- **Every candidate MUST have file:line.** No generic warnings.
- **Read the actual code.** Never assume what a function does from its name.
- **Check inheritance.** A "missing" check may exist in a parent contract.
- **Track OpenZeppelin/Solmate usage.** Don't flag standard implementations as custom bugs.
- **Be concrete.** "This could be a problem" is worthless. "An attacker can call X with Y=0 to extract Z" is a finding.
- **Do NOT verify yet.** That's the Critic's job. Just find candidates.
