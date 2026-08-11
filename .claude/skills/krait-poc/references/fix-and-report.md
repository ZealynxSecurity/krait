# Fix and report — after a passing PoC

This runs only for `[POC-PASS]` findings. `[CODE-TRACE]` and `[POC-FAIL]` findings do NOT
get a fix — you have not proven there is anything to fix.

## Generate the fix

After a passing PoC confirms the bug, you already hold deep context. Write the **minimal**
diff that removes the defect — the smallest change that makes your PoC no longer pass.

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
- **Evidence**: [POC-PASS]
- **Harm asserted**: <WHO lost WHAT — the exact assertion that passed>
- **Output**: <the profit / drain line from the run>

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
