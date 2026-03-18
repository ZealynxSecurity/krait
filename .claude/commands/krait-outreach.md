# Krait Outreach — Zero-FP Audit for Business Development

Run a full Krait audit with an additional Outreach Verification pass that guarantees near-zero false positives. Output is a polished report suitable for sending to potential clients.

## Usage

```
/krait-outreach                    # Audit current directory
/krait-outreach src/contracts/     # Audit specific directory
```

## How It Works

1. Run the **full `/krait` audit pipeline** (Phases 0-4) — read the methodology from `~/.claude/commands/krait.md`
2. After Phase 4 produces the standard report, run **Phase 5: OUTREACH VERIFICATION** (below)
3. Generate a polished outreach report

## Why This Exists

When using Krait findings for business development outreach (emailing protocols with bugs we found in their public code), a SINGLE false positive destroys all credibility. The standard audit targets ~80% precision. Outreach requires ~100%.

The tradeoff is explicit: **outreach mode will report FEWER findings but every finding will be real.** Better to send a protocol 1 verified bug than 3 findings where 1 is fake.

---

## Phase 5: OUTREACH VERIFICATION

After the standard Phase 4 report is generated, apply these additional filters to every finding. **A finding must pass ALL 7 checks to be included in the outreach report. If it fails ANY check, it is CUT.**

### Check 1: Code Re-Verification (MANDATORY)

Re-read the EXACT file and lines cited in the finding one more time. Not from memory — actually open and read the file. Verify:
- The code exists at those exact lines
- The code does exactly what the finding claims
- The quoted snippets match the actual file character-for-character
- Read 100 lines above and below for ANY context that might invalidate the finding

If ANY mismatch → **CUT**.

### Check 2: Exploit Trace with Real Contract State (MANDATORY)

The exploit trace must use ACTUAL values derived from the contract code:
- Use real initial state values (read constructor, initializer, or deployment config)
- Use real parameter ranges (read the require/assert constraints)
- Show the exact function calls in the exact order a real attacker would use
- Calculate the actual profit/loss with real numbers

If the trace uses placeholder values ("some large amount") or hypothetical state → **CUT**.

### Check 3: The $1000 Bet Test

Ask yourself: **"Would I personally bet $1,000 that this finding is a real, exploitable vulnerability?"**

If there is ANY hesitation — any "well, it depends on..." or "probably, unless..." — **CUT**.

This is not about being aggressive. It's about certainty. The findings that pass this test are the ones where the code is clearly wrong and you can prove it line-by-line.

### Check 4: External Assumption Check

Does the finding depend on ANY assumption about:
- How an external protocol behaves (Uniswap, Aave, Chainlink)?
- What tokens will be used?
- What chain will be deployed on?
- What admin/governance behavior will be?
- What external oracle values will return?

If the finding requires external assumptions you haven't verified by reading the actual external contract code → **CUT**.

Exception: If you READ the external contract's code and confirmed the behavior, the finding survives.

### Check 5: Sibling Pattern Validation

Does a SIMILAR pattern exist elsewhere in the same codebase that works correctly? For example:
- If finding says "function X is missing access control" — check if sibling functions Y and Z have access control. If they do, the finding is more likely real (developer forgot on X).
- If finding says "function X uses wrong library" — check if similar functions use the correct library. If they do, confirms the bug.
- If the finding is about missing modifier — check sibling functions for the modifier.

If the same "bug" pattern exists in EVERY function in the contract → it's likely intentional design, not a bug → **CUT**.
If sibling functions do it correctly → finding is STRENGTHENED (developer inconsistency = real bug).

### Check 6: Impact Severity Floor

For outreach, only include findings that would make a protocol WANT to fix them:
- **Fund loss or theft** — include
- **Permanent DoS of core functionality** — include
- **Incorrect accounting that grows over time** — include (if provable)
- **Temporary DoS** — CUT (not compelling enough for outreach)
- **Missing event emissions** — CUT
- **Gas optimizations** — CUT
- **Admin-only issues** — CUT (they'll say "we trust our admin")
- **Theoretical token compatibility** — CUT (they'll say "we don't use that token")
- **Rounding dust** — CUT (they'll say "that's pennies")

The finding must make the reader think: "Oh no, we need to fix this."

### Check 7: Plain English Explainability

Can you explain this finding in 2 sentences that a non-technical founder would understand?

Example GOOD: "Anyone can call repayLoan with protocolFee set to 0 because the fee field isn't included in the verification hash. This means the protocol never collects fees on loan repayments."

Example BAD: "The EIP-712 typehash computation in Hash.sol omits the protocolFee field from the Loan struct encoding, allowing callers to pass arbitrary values for this field that will still validate against the stored hash, bypassing fee collection."

Both describe the same bug. The first wins deals. If you can't explain it simply, the recipient won't understand the value.

**Rewrite every surviving finding to be explainable in 2 sentences.**

---

## Outreach Report Format

Save to `.audit/krait-outreach-report.md`:

```markdown
# Security Findings — [Protocol Name]

**By**: Zealynx Security (using Krait automated detection)
**Date**: [date]
**Scope**: [brief description of what was analyzed]
**Methodology**: AI-assisted 4-phase security analysis with manual verification

---

> We ran our security analysis tool on your public codebase and found the following issues. These findings have been verified with concrete exploit traces. We're sharing them because we believe in responsible disclosure and building trust with the protocols we work with.
>
> If you'd like to discuss these findings or explore a full security engagement, reach out to us at [contact].

---

## Findings

### [1] [Plain English Title] — [HIGH/CRITICAL]

**What's wrong**: [2-sentence explanation a founder can understand]

**Where**: `[file:line]`

**Impact**: [Who loses what. Be specific.]

**How it works**:
1. [Step 1 in plain English]
2. [Step 2]
3. [Result: "X tokens are lost" or "Y function stops working"]

**Suggested fix**: [1-2 sentence recommendation]

<details>
<summary>Technical Details</summary>

**Vulnerable code**:
```solidity
[actual code]
```

**Exploit trace**:
```
[full technical trace with values]
```

**Root cause**: [technical explanation]

**Suggested code change**:
```solidity
[fixed code]
```
</details>

---

[Repeat for each finding]

---

*This report was generated by [Krait](https://github.com/ZealynxSecurity/krait), an AI-first security auditor by Zealynx Security. Findings have been verified through automated analysis with human-grade precision targeting. For a comprehensive manual audit, contact Zealynx Security.*
```

## Rules

- **If zero findings survive the outreach verification → report that.** An empty report with a note "We analyzed your code and found no critical issues — your security posture looks solid" is STILL valuable for outreach. It shows you did the work and are honest about results.
- **Never inflate severity** to make findings sound scarier. Protocols will verify and catch you.
- **Never include unverified findings** with caveats like "we think this might be an issue." Either it's verified or it's not in the report.
- **Maximum 5 findings per outreach report.** If you have more, pick the top 5 by impact. Quality over quantity.
- **Always include a suggested fix.** This shows you understand the code, not just the bug.
