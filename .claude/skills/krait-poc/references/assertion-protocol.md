# Assertion Retry Protocol — one retry before FALSE_POSITIVE

*(Aligned with the Krait critic's Impact Premise gate and the Plamen-derived assertion
protocol.)*

When your harm assertion FAILS — the system behaved correctly, contradicting the finding —
do exactly one disciplined retry before concluding the bug is not real. The goal is to
distinguish "my test setup was wrong" from "the bug does not exist."

## Step 1 — self-diagnosis (no code changes yet)

Ask, honestly:

- Did I call the **exact** function at the **exact** location the finding names?
- Did my setup create the **exact** preconditions the finding requires?
- Is my assertion testing the **claimed harm**, or just a mechanism step?
- Did I use **realistic values** from the codebase, not invented constants?

If any answer is "no" → Step 2A (fix setup). If all are "yes" → Step 2B (accept the fail).

## Step 2A — fix the setup, ONE retry

Rewrite only the test setup / inputs. You MUST keep:

- the **same** target function call,
- the **same** harm assertion,
- the **same** finding location.

Recompile and run. Pass → `[POC-PASS]`. Fail again → Step 2B.

**Anti-gaming rules** (these turn a "pass" into `[CODE-TRACE]`, not `[POC-PASS]`):

- If the retry tests a **different function** than the finding's location → `[CODE-TRACE]`.
- If the retry asserts a **different harm** than the first attempt → `[CODE-TRACE]`.
- You may never weaken the assertion (loosen the delta, drop the victim-side check, assert
  a mechanism instead of harm) to force green.

## Step 2B — accept the failure

Conclude `[POC-FAIL]`. State plainly that the harm did not reproduce, and — briefly — what
the code actually did instead (the defense that held, the value that stayed correct). That
explanation is the evidence that the finding was a false positive.

## Variant exploration before declaring FALSE_POSITIVE

Before finalizing `[POC-FAIL]`, test **one** relaxed variant along the dimension that
caused the failure:

| Failure dimension | Relaxed variant |
|---|---|
| Timing | same-block → multi-block (`vm.roll`/`vm.warp`) |
| Amount | one specific amount → a range / boundary values |
| Ordering | A-then-B → B-then-A |
| Initial state | current → post-loss / paused / empty pool |

If the variant reproduces the harm → report the working variant as `[POC-PASS]`. After
2+ variant failures, `[POC-FAIL]` is justified and final.

## Why this matters

A `[POC-FAIL]` correctly kills a false positive — that protects the zero-FP bar. But a
`[POC-FAIL]` caused by a lazy setup **hides a real bug**. The one retry plus one variant is
the minimum diligence that separates the two. More than that is grinding; less than that is
negligent.
