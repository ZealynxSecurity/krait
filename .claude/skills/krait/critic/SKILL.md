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

**Devil's Advocate methodology** *(Source: PlamenTSV/plamen, MIT)*: For every finding, FIRST argue why it is NOT a bug — construct the strongest possible defense. Only if that defense fails does the finding stand. Before marking anything as FALSE POSITIVE, also ask: "Does ANY other finding in this audit enable the missing precondition?" A finding dismissed in isolation may become exploitable when combined with another.

The goal is **zero false positives** on H/M findings. A false positive wastes the auditor's time and destroys trust. Better to miss a real bug than report a fake one.

## Core Rule

**INNOCENT UNTIL PROVEN GUILTY. The burden of proof is on the FINDING, not on the code.**

For each candidate, you must:
1. Attempt to DISPROVE it through code trace
2. Only if disproof FAILS does the finding stand
3. If you cannot write a concrete exploit trace with actual values, the finding is KILLED
4. There is NO "likely true" or "insufficient evidence" — either you proved it or you didn't
5. **When in doubt, KILL it.** A missed real bug is unfortunate. A false positive destroys credibility.

## Step 0: AUTOMATIC KILL GATE (MANDATORY — run FIRST on every candidate)

**This gate runs FIRST. Any finding matching ANY of these 8 categories is IMMEDIATELY killed. No exploit trace is attempted. No further analysis. No exceptions. No "but in this case...". KILL IT.**

These 8 categories account for 95%+ of all false positives across 40 shadow audits and have NEVER produced a true positive. They are unconditional kills.

**GATE A — Generic Best Practice (kill immediately):**
"Use SafeERC20/safeTransfer" without naming specific failing token, "safeApprove" generically, "single-step ownership", "missing event emission", ".transfer() gas limit" without specific failing recipient, "weak on-chain randomness", "use a deadline" without concrete MEV profit calc, "centralization risk".
→ **KILL. Zero TPs in 40 contests.**

**GATE B — Theoretical But Not Exploitable (kill immediately):**
Requires exotic token behavior not in protocol's actual token list, oracle returning out-of-range values, overflow in practically bounded values, condition prevented by deployment/init. **TOKEN CONTEXT CHECK**: Finding relying on token behavior MUST name the SPECIFIC token from the protocol's actual list. "If a fee-on-transfer token is used" without naming which one = KILL. **DECIMAL/INTERFACE EDGE CASES**: Only matters if it affects actual token pairs the protocol uses.
→ **KILL. Zero TPs in 40 contests.**

**GATE C — Design Is Intentional (kill immediately):**
Code comments/docs indicate deliberate behavior, same pattern as reference implementation (Uniswap V3, Curve, etc.), function works as NatSpec describes. **FORK BEHAVIOR CHECK**: If Recon identified a fork, check if original has same behavior → inherited design, not bug. Only report code that DIFFERS from fork origin.
→ **KILL. Zero TPs in 40 contests.**

**GATE D — Speculative / No Concrete Exploit (kill immediately):**
"Could be an issue if...", cannot specify WHO/WHAT/HOW MUCH, vague "manipulation" without exact path, "stale data" without exploitable window.
→ Ask: "Can I write `1. Attacker calls X 2. State becomes Y 3. Profit Z`?" If no → **KILL.**

**GATE E — Admin Trust Boundary (kill immediately):**
Requires trusted admin/owner/governance to act maliciously. EXCEPTION: Missing timelock on irreversible destructive action may qualify as Medium.
→ **KILL. Zero TPs in 40 contests.**

**GATE F — Dust / Economically Insignificant (kill immediately):**
Rounding < $1/tx, bounded truncation dust, precision loss < gas costs. If max_loss × max_iterations < $100 = dust.
→ **KILL. Zero TPs in 40 contests.**

**GATE G — Out of Context (kill immediately):**
Token behaviors for tokens not in whitelist, chain-specific issues on unsupported chains, standards the protocol doesn't implement, external protocols not integrated with.
→ **KILL. Zero TPs in 40 contests.**

**GATE H — Publicly Known / Acknowledged Issue (kill immediately):**
Already listed in README "Known Issues", previous audit reports, or bot reports. **PRECISION REQUIREMENT**: Match on MECHANISM, not TOPIC. "SOFT_RESTRICTED bypass via open market" ≠ "SOFT_RESTRICTED bypass via withdraw()". Two bugs in same area with different exploit paths are different bugs. Only kill if known issue describes SAME entry point, SAME root cause, SAME impact.
→ **KILL if exact mechanism match. DO NOT KILL if only same topic but different path.**

**DoS SEVERITY EXCEPTION (applies to Gates A, B, D, F):**
If DoS permanently/repeatedly bricks a CORE lifecycle function (settlement, liquidation, withdrawal, unstaking, repayment, auction) AND unprivileged attacker can trigger at low cost AND effect is persistent → Medium minimum, survives A/B/D/F. 25% of missed findings were DoS bugs incorrectly killed.

---

**After Kill Gate, surviving candidates proceed to verification methods below.**

## Consensus-Aware Verification

Before applying verification methods, check the candidate's **consensus tag** from detection:

- **STRONG consensus (3+ sources)**: This finding was independently discovered by multiple analysis passes with different mindsets. If it passed kill gates A-H, fast-track to VERIFIED — write the exploit trace for documentation but the convergent evidence is strong.
- **MODERATE consensus (2 sources)**: Normal verification — full kill gate + exploit trace. The dual discovery adds confidence but doesn't skip any steps.
- **NO consensus (1 source only)**: Apply EXTRA scrutiny. Ask: why did the other 4 passes miss this? Acceptable reasons: different lens domain, file wasn't in that lens's scope. Suspicious reasons: it's in a Tier 1 file that all lenses analyzed. Require an especially concrete exploit trace with specific values.

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

**IMPORTANT EXCEPTION**: Explicit type casts like `uint128(someUint256)` do NOT revert in Solidity 0.8+. They silently truncate. Do NOT dismiss type-cast overflow findings with this FP pattern. These are real bugs that corrupt state silently.

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
