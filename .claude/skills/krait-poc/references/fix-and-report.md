# Fix and report — after the falsification gate

This runs for findings that survived the Step 7 falsification gate — `[POC-PASS]` and
`[POC-PASS · FIX-INSUFFICIENT]`. `[POC-UNPINNED]`, `[CODE-TRACE]`, and `[POC-FAIL]` findings
do NOT get a fix here: an unpinned test has not proven a defect to fix, and the others have
nothing confirmed to fix.

Note that by the time you reach this step, the fix-efficacy control (gate Control 2) has
**already run the recommended fix against the exploit** — so you know whether it holds:

- **`[POC-PASS]`** — the fix killed the exploit. Report the verified fix (below).
- **`[POC-PASS · FIX-INSUFFICIENT]`** — the fix did NOT kill the exploit, but the finding is
  pinned and real. Report the bug, show the exploit surviving the proposed fix, and state
  what a correct fix must change — derived from the defect-mutation that *did* kill it (the
  mutation is the specification for a correct fix). Do NOT iterate a patch against the test
  to manufacture a green fix; hand the remediation to human review.

## Generate the fix (verified `[POC-PASS]` only)

You already hold deep context and the fix-efficacy control has confirmed the diff works.
Write the **minimal** diff that removes the defect — the smallest change that makes the PoC
no longer pass, which the gate has already demonstrated.

```diff
- uint256 shares = amount * totalShares / totalAssets;
+ uint256 shares = totalShares == 0
+     ? amount
+     : amount * totalShares / totalAssets;
```

Rules:

- **Minimal.** The smallest change that eliminates the vulnerability. Do not refactor
  surrounding code, rename things, or "improve" adjacent logic.
- **If the fix is non-trivial** (architectural, multi-file, or could introduce new issues),
  do NOT invent an inline diff. Write:
  `Fix: architectural change required — <one sentence>. No inline diff provided.`
- Never guess a fix you are unsure of. A wrong fix in a report is worse than "requires
  design change."

## Verify the fix (when the harness allows)

If you can apply the diff to the local source or a fork overlay, re-run the PoC with the fix
in place and confirm the harm assertion now **fails** (i.e. the exploit no longer works).

```
Verified: YES — re-ran the PoC with the fix applied; the harm assertion no longer triggers.
Verified: NO  — fix proposed but not mechanically re-tested (<reason>).
```

A mechanically-verified fix is a large credibility win at near-zero marginal cost, because
you already have the whole PoC in context.

## The report block

Attach this to the finding so the reporter can paste it verbatim:

```markdown
### PoC
- **Class**: fork | local | integration
- **File**: test/Victim_exp.sol
- **Command**: forge test --match-contract ExploitTest -vvv
- **Result**: PASS
- **Evidence**: [POC-PASS] | [POC-PASS · FIX-INSUFFICIENT]
- **Harm asserted**: <WHO lost WHAT — the exact assertion that passed>
- **Output**: <the profit / drain line from the run>
- **Pinned (defect-mutation)**: YES — <the one-line change to the defective line that killed the exploit>
- **Fix efficacy**: fix killed exploit (verified) | fix did NOT kill exploit (FIX-INSUFFICIENT)

### Suggested Fix
​```diff
<minimal diff>
​```
**Fix scope**: <one sentence>
**Verified**: YES | NO — <detail>
```

## Handing back to the pipeline

When invoked by the Krait audit pipeline's verification phase, the `[POC-PASS]` tag and the
harm assertion feed the critic's evidence axis: a `[POC-PASS]` is the only tag that supports
CONFIRMED as ground truth. A finding you could only bring to `[CODE-TRACE]` stays capped at
the pipeline's non-proof disposition — report it honestly as such.
