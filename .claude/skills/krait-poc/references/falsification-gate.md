# Falsification gate — prove the PoC is pinned, not theater

**This is the most important step in the skill.** An AI-written PoC that passes proves
almost nothing on its own: the same reasoning that produced the finding produced the test,
so it will happily build the exact world where the finding is true and call it proof. A
passing exploit is a *hypothesis*, not a result, until it survives an attempt to falsify it.

Run this gate on **every** `[POC-PASS]` candidate before you record the verdict. It answers
two DIFFERENT questions with two DIFFERENT controls — do not conflate them.

| Question | Control | What it decides |
|----------|---------|-----------------|
| Is the bug real / is the test honest? | **Defect-mutation** | real vs. theater (pinning) |
| Does the *proposed fix* actually close it? | **Fix-efficacy** | remediation quality |

## Control 1 — Defect-mutation (the honest pin). MANDATORY.

Ignore the recommended fix entirely. Change the **defective line(s) themselves** to their
*correct* form — the minimal semantic inverse of the defect:

- a wrong constant → the value it should have been (copy-pasted coefficient → a distinct one)
- an 18-decimal constant → the 6-decimal value the real token needs
- a missing check → the `require`/guard added
- a `<` that should be `<=`, a flipped branch, a skipped state write → corrected

Re-run the **exact same exploit test, unchanged**. Then read the result:

- **Exploit still passes** → the test is **NOT pinned** to that defect. The harness is
  manufacturing the result independently of the vulnerable code. Record `[POC-UNPINNED]` and
  treat it as `[CODE-TRACE]` — reproduces, but not demonstrably caused by the cited defect.
  Flag for human review. **This is the confirmation-bias case you are hunting.**
- **Exploit now fails/reverts** → the test **is pinned** to a real defect. The bug is real,
  and this conclusion is **independent of any fix**. It is ground truth and it does not move
  when you later touch the remediation.

This is mutation testing inverted: the *correct* code is the mutant, and a genuine exploit
must be killed by it. It does not depend on getting the fix right — only on knowing what the
line *should* say, which for most defects (a constant, a missing check) is small and local.

**Why the defect-mutation and not the fix?** Because a failed *fix* is ambiguous — it can
mean the test is theater OR the bug is real and the fix is wrong. The defect-mutation is
unambiguous: it changes the exact cited line to correct, so a surviving exploit can only mean
the test was never testing that line.

### Cross-check: the negative / baseline control (do this for every Critical and every
### "sharp number" finding)

Independently of the mutation, run the **same attack flow under conditions where the bug
should not trigger** (correct decimals, honest actor, in-range parameter) and assert the harm
does **not** occur. If harm appears in both the buggy and the clean run, the harness is
producing it — the finding is not pinned regardless of what the mutation said. (This is the
C-01 control pattern generalized; it catches a mis-identified defect-mutation.)

## Control 2 — Fix-efficacy (remediation quality). Separate verdict.

Only after Control 1 has established the pin, apply the finding's **recommended fix** to the
source and re-run the exploit:

| Defect-mutation (Control 1) | Proposed fix (Control 2) | Verdict |
|---|---|---|
| exploit dies | fix survives the **fuzz sweep** | `[POC-PASS]` + verified fix. Real, pinned, fix closes the harm. |
| exploit dies | fix fails the sweep (a variant still reproduces) | `[POC-PASS]` **+ `FIX-INSUFFICIENT`**. Real, pinned, the proposed fix does NOT close the harm — a *higher*-value finding, never a demotion. |
| exploit survives | (not run) | `[POC-UNPINNED]` → `[CODE-TRACE]`. Theater. |

### Control 2 must FUZZ the fix, not just re-run the literal exploit (MANDATORY)

Re-running the exact exploit against the fix is **not sufficient** — and is often
*tautological*. When the fix constrains the very variable the exploit sets, re-running passes
by construction and tells you nothing. Example: a fix that rejects a **zero-amount** input,
tested against an exploit that used amount = 0, will always pass — yet a **1-wei** variant can
reproduce the identical harm because the fix closed the literal value, not the mechanism.

So evaluating the recommended fix requires a **variant sweep of the parameter(s) the fix
constrains**, not one re-run:

1. Identify what the fix bounds (an amount, a threshold, a timing window, an ordering).
2. Run the harm assertion across the **neighborhood** of that bound — boundary and just-past
   values (`0, 1, dust, threshold, threshold+1`), and the adjacent dimensions from
   `assertion-protocol.md` (timing, ordering, initial state).
3. If **any** variant still reproduces the harm → `FIX-INSUFFICIENT`, even though the literal
   exploit died against the fix. The fix masks the tested case; it does not close the harm.
4. Only if the **whole neighborhood is clean** is the fix `verified`.

This is the same fuzz discipline the recursion trap (below) demands of *candidate better-fixes*
— applied to the **original recommended fix** as well, because that is exactly where a fix that
"passes the test" but leaves the harm live slips through. A fix verified only against the literal
PoC value is not verified.

**`FIX-INSUFFICIENT` is a finding, not a failure.** "Here is the bug, and the obvious fix
does not close it" is one of the most valuable things an audit can deliver. Report it loudly;
do not let it read as doubt about the bug.

## The recursion trap — and the discipline that breaks it

It is tempting, on a `FIX-INSUFFICIENT`, to keep tweaking the fix until the exploit dies.
**Do not iterate a candidate fix against a single exploit test.** That is theater again — you
would converge on a patch that defeats *that one test*, possibly by masking the symptom rather
than fixing the defect. The rules:

1. **The pin is settled once, by Control 1, and is never re-derived while you touch the fix.**
   "Is the bug real" was decided before any remediation work and cannot be un-proven or
   re-proven by fiddling with a patch — because the patch is not what proved it.
2. **A better fix is derived from the defect-mutation, not searched for against the test.** The
   mutation that *killed* the exploit IS the specification for a correct fix — the real-code
   implementation of that semantic change. You are implementing known-correct semantics, not
   hunting a patch that beats a green light.
3. **Any candidate better-fix must survive a fuzz/variant sweep**, not just the literal PoC.
   Bound the finding's key inputs (amounts, timing, ordering) and run the neighborhood. A fix
   that closes the exact PoC values while a fuzzed variant still drains is masking — the sweep
   catches it. See `assertion-protocol.md` for the variant dimensions.
4. **Cap fix exploration and hand the mitigation to human review.** Proposing remediation is
   where over-fit risk is highest and auditor judgment most valuable. The tool proves the bug
   and stress-tests candidate fixes; it does not autonomously decide "the fix" by chasing green.
   Max 2 candidate fixes, then report `FIX-INSUFFICIENT` with what you learned and stop.

## Honest limits

- The defect-mutation is not infallible: if you misjudge the *correct* form of the line, the
  pin is wrong. The negative/baseline control cross-checks it, and a wrong-constant / missing-
  check mutation is a far smaller judgment than a whole fix — but neither control alone is a
  guarantee. Both together are strong.
- None of this replaces the auditor reading the PoC. These controls make that review faster and
  sharper by exposing exactly which findings are pinned and which fixes hold — they do not make
  it optional.

## Recording the verdict

Every `[POC-PASS]` row in the triage table now carries its gate result:

- `[POC-PASS]` — pinned (defect-mutation killed it), fix verified (fix-efficacy killed it).
- `[POC-PASS · FIX-INSUFFICIENT]` — pinned, but the proposed fix does not close it. Bug real;
  remediation flagged for human review.
- `[POC-UNPINNED]` — reproduced but NOT killed by the defect-mutation. Downgraded to
  `[CODE-TRACE]`; flag for human review — the mechanism may still be real, but this test does
  not prove it.

Include, for each, the one-line mutation you applied and the pass/fail of each control, so the
gate is auditable.
