# Krait Critic — Verification Gate & False Positive Elimination

> Phase 3 of the Krait audit pipeline. Runs after Detector and State Auditor.

## Trigger

Invoked by `/krait` (as part of full audit) or `/krait-critic` (standalone).

## Prerequisites

- `.audit/findings/detector-candidates.md` (from krait-detect)
- `.audit/findings/state-candidates.md` (from krait-state)
- Read BOTH before starting

## Purpose

**Every CRITICAL, HIGH, and MEDIUM candidate must be VERIFIED before it reaches the user.** This phase is the devil's advocate — its job is to DISPROVE findings. Only findings that survive attempted falsification are TRUE POSITIVES.

The goal is **zero false positives** on H/M findings. A false positive wastes the auditor's time and destroys trust. Better to miss a real bug than report a fake one.

## Core Rule

**GUILTY UNTIL PROVEN INNOCENT does NOT apply here. INNOCENT UNTIL PROVEN GUILTY.**

For each candidate, you must:
1. Attempt to DISPROVE it through code trace or PoC
2. Only if disproof FAILS does the finding stand
3. If you cannot conclusively prove it's real, DOWNGRADE or DISCARD

## Verification Methods

### Method A: Deep Code Trace

For each candidate:

1. **Read the cited code.** Open the file, go to the exact lines. Does the code actually match what the candidate claims?

2. **Trace the full call chain.** Follow every internal call from the entry point to the final effect:
   - Does the function call other internal functions that apply the "missing" check?
   - Does a modifier or hook apply validation the candidate didn't see?
   - Does a parent contract (via inheritance) provide the protection?

3. **Check for mitigating code elsewhere:**
   - Is there a `require` in a called function that prevents the scenario?
   - Is there an access control modifier that limits who can trigger it?
   - Does a reentrancy guard exist that blocks the attack path?
   - Is there a time lock, pause mechanism, or rate limit?
   - Does the constructor/initializer set state that prevents the edge case?

4. **Confirm reachability end-to-end:**
   - Can an attacker actually reach this code path with the required parameters?
   - Are there economic constraints that make the attack unprofitable?
   - Does the gas cost of the attack exceed the extractable value?

### Method B: Proof-of-Concept Trace

For complex findings, construct a concrete attack trace:

```
1. Initial state: [exact values]
2. Attacker calls: function(param1, param2)
3. State changes to: [exact values]
4. Attacker calls: function2(param3)
5. State changes to: [exact values]
6. Result: [exact value extracted / state corrupted]
```

If you cannot construct a concrete trace with actual values → the finding is likely false.

### Method C: Hybrid

Code trace to confirm mechanism plausibility + concrete trace with values to verify impact.

## Verification Checklist

For EVERY CRITICAL, HIGH, and MEDIUM candidate, answer ALL of these:

```
[ ] Does the cited code actually exist at the stated lines?
[ ] Is the described mechanism correct? (Does the code actually do what the finding claims?)
[ ] Are there mitigating factors the finding missed?
    [ ] Access control in this or calling functions?
    [ ] Validation in parent contracts (check inheritance chain)?
    [ ] Reentrancy guards?
    [ ] Timelock or delay mechanisms?
    [ ] Economic infeasibility (attack cost > profit)?
    [ ] Language-level safety (Rust overflow panics, Move abort)?
[ ] Is severity accurate given actual impact?
    [ ] "Fund loss" = actual drain, or just a revert? (revert ≠ high)
    [ ] "Anyone can call" = true, or just permissioned actors?
    [ ] "All funds at risk" = really all, or dust amount?
[ ] Is the attack path actually reachable?
    [ ] Can you trace from a permissionless entry point to the exploit?
    [ ] Are all required preconditions achievable?
```

## Common False Positive Patterns

Eliminate these systematically:

### FP-1: Authorization Handled Elsewhere
The finding claims "missing access control" but auth is enforced by:
- The function that calls this one (external → internal flow)
- A modifier on a parent contract
- A router/proxy that gates access before delegation
- A factory pattern where only the factory can create instances

**Check**: Trace ALL callers of the function. If every path goes through auth, the finding is false.

### FP-2: Validation in Called Functions
The finding claims "unchecked input" but the called function validates:
- `_transfer` checks balance internally
- `_mint` checks for address(0) internally
- Library functions (SafeMath, SafeERC20) handle edge cases

**Check**: Read the implementation of every function called within the vulnerable function.

### FP-3: OpenZeppelin / Solmate Standard Protection
The finding reports a vulnerability in code that inherits from battle-tested libraries:
- ERC20 with built-in overflow protection (Solidity 0.8+)
- ERC4626 with virtual offset against share inflation
- ReentrancyGuard with nonReentrant modifier
- Ownable2Step with two-phase ownership transfer

**Check**: Verify the exact version of the library. Check if the contract overrides any protective virtual functions.

### FP-4: Rounding Drift Cleaned Downstream
The finding claims "precision loss" but:
- The protocol has a dust threshold that catches small remainders
- A periodic reconciliation function rebalances
- The rounding favors the protocol (safe direction)

**Check**: Is the rounding direction safe? Does dust accumulate dangerously or stay bounded?

### FP-5: Bounded Loops / Economic Constraints
The finding claims "unbounded loop DoS" but:
- The loop is bounded by design (max N participants, max M items)
- The economic cost of growing the loop exceeds griefing benefit
- An admin can prune the array

**Check**: What's the realistic maximum iteration count? Is it gas-feasible?

### FP-6: Severity Inflation
The finding claims CRITICAL but:
- A safety check catches the condition before value loss → MEDIUM at most
- The impact is value leakage, not value theft → MEDIUM
- Only an admin can trigger it (trusted role) → Context-dependent
- The edge case requires specific token types that aren't in scope

**Check**: Re-classify with accurate severity.

### FP-7: Solidity 0.8+ Arithmetic Safety
The finding claims overflow/underflow but:
- Solidity 0.8+ has built-in checked arithmetic
- The overflow would revert, not silently wrap
- This is a DoS (revert) not a value extraction → Lower severity

**Check**: Is the code in an `unchecked` block? If not, overflow reverts.

### FP-8: Read-Only / View Function Confusion
The finding claims state manipulation via a view function:
- View functions cannot modify state
- staticcall prevents state changes
- The "vulnerability" only affects off-chain reads

**Check**: Is the function actually view/pure? Does it matter if the value is temporarily wrong?

### FP-9: Test/Script/Interface-Only
The finding points to code in:
- Test files (test/, t/, .t.sol)
- Deploy scripts (script/, deploy/)
- Interfaces (no implementation)
- Mock contracts

**Check**: Is this production code? If not, discard.

### FP-10: Documented Design Decision
The behavior flagged is intentional:
- Comments explicitly explain why
- The documentation describes this as expected behavior
- It's a known trade-off (e.g., "we accept 1 wei rounding per operation")

**Check**: Read surrounding comments and documentation.

## Cross-Feed Iteration

After initial verification, check if any VERIFIED findings from the Detector reveal state inconsistencies that the State Auditor should re-examine, or vice versa.

If new insights emerge:
1. Flag them as new candidates
2. Apply the same verification process
3. Maximum 2 iteration cycles to prevent endless loops

## Verdict Format

For each candidate, assign ONE verdict:

- **TRUE POSITIVE (TP)**: Verified exploitable. Include proof trace.
- **LIKELY TRUE (LT)**: Mechanism confirmed but edge-case dependent. Include conditions.
- **DOWNGRADE**: Real issue but severity is wrong. Specify correct severity.
- **FALSE POSITIVE (FP)**: Disproven. Specify which FP pattern and why.
- **INSUFFICIENT EVIDENCE (IE)**: Cannot prove or disprove. Exclude from report.

## Output

Save to `.audit/findings/critic-verdicts.md`:

```markdown
# Krait Critic Verdicts

## Summary
- Total candidates reviewed: X
- True Positives: X
- Likely True: X
- Downgraded: X
- False Positives: X
- Insufficient Evidence: X

## Verified Findings

### [KRAIT-XXX] Title (was CANDIDATE-XXX / STATE-XXX)

**Verdict**: TRUE POSITIVE
**Severity**: HIGH (original: CRITICAL — downgraded because...)
**File**: path/to/file.sol:XX

**Verification Method**: Code trace / PoC trace / Hybrid

**Proof**:
[Concrete exploitation trace with values OR
complete code trace showing no mitigation exists]

**Impact**: [Precise impact statement]
**Root Cause**: [One-line root cause]

---

## Eliminated (False Positives)

### CANDIDATE-XXX: Title
**Verdict**: FALSE POSITIVE
**Reason**: FP-3 — OpenZeppelin ERC4626 provides virtual offset protection (line XX of parent contract)
```

## Rules

- **Read every line you cite.** Do not trust the candidate's description blindly.
- **Trace inheritance chains completely.** Most FPs come from ignoring parent contracts.
- **Be ruthless.** A finding that "might" be exploitable is NOT verified. Either prove it or discard it.
- **Never add new findings.** Your job is to verify/falsify existing candidates, not find new ones. (Exception: cross-feed iteration can generate new candidates for immediate verification.)
- **Downgrade aggressively.** Many "CRITICAL" findings are actually MEDIUM when you check the actual impact path.
- **Zero false positives on H/M is the goal.** Users trust the report. Every FP destroys credibility.
