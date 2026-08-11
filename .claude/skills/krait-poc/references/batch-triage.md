# Batch triage — verify a list of findings

Point the skill at a whole findings list and produce one consolidated **verdict table**.
This is the mode for "here are my N findings, tell me which hold up."

The governing principle, stated once and obeyed everywhere below:

> **A passing PoC promotes a finding. A failing PoC demotes it. Inability to PoC does
> neither.** "No PoC" is not a strike. Some valid findings are un-PoC-able by nature — the
> triage MUST keep them at their reasoned severity, not bury them.

## Input

Any of:

- a markdown file of findings (`/krait-poc findings.md`)
- `.audit/krait-findings.json` from a prior `/krait` run
- a pasted list

Parse each finding's **location**, **claimed harm**, and **severity**. If a finding has no
stated harm — only a mechanism ("the function is callable") — flag it: per the Impact
Premise it is not yet a body finding, and there is nothing to assert. Note that in the
table rather than manufacturing a harm for it.

## Step 1 — PoC-ability triage FIRST (before spending any compile budget)

Do not start writing tests down the list. First classify each finding into one of four
lanes. This is cheap (reasoning only) and it stops you burning attempts on findings a PoC
cannot speak to.

| Lane | Meaning | Action |
|------|---------|--------|
| **TESTABLE** | Concrete on-chain harm, reachable from an entry point, buildable env | Full 8-step workflow. Budget attempts. |
| **STRUCTURAL** | Real finding, but no executable on-chain harm assertion exists | Do NOT attempt a PoC. Record `[CODE-TRACE]` + the structural reason. Keep severity. |
| **BLOCKED** | Testable in principle, but this environment can't (no build, no fork RPC, external dep) | Record `[CODE-TRACE]` + the environmental blocker. Keep severity. Re-runnable elsewhere. |
| **NO-HARM** | Only a mechanism stated, no consequence | Flag for the author. Not a PoC target. |

### Structural reasons (a finding being here is NOT a mark against it)

- `TRUSTED_ACTOR` — harm requires governance/owner/admin to act maliciously. You cannot
  prove they will; the finding is about capability. (This is the same class kill-gate E
  and the A5 trust-downgrade already handle — a PoC is the wrong instrument.)
- `OFF_CHAIN_HARM` — corrupted events breaking an indexer, wrong data in a view a frontend
  consumes. No on-chain state delta to assert.
- `CROSS_CHAIN_DESTINATION` — the harmed leg is a consumer on another chain, not forkable
  in one node.
- `SPEC_DOCS_NO_STATE_DELTA` — a spec/documentation mismatch with no state consequence to
  reproduce.
- `LIVENESS_DENIAL` — the harm is denial/griefing, not theft; assert it only if the bricked
  action has a concrete, reproducible revert (many do — try before assigning this).
- `ECONOMIC_CONDITIONS` — unsound only under market conditions you cannot cheaply
  instantiate on a fork.

### Environmental blockers (BLOCKED lane)

`NO_BUILD_ENVIRONMENT` · `EXTERNAL_DEP_NO_FORK` · `NO_FORK_RPC` · `COMPILE_UNRESOLVED_AFTER_5`.
These say "not here, not now" — never "not real."

**Recall-safe default:** when unsure whether a finding is STRUCTURAL or TESTABLE, treat it
as TESTABLE and try. A PoC attempt that fails to build costs a little budget; wrongly filing
a testable finding as STRUCTURAL hides whether it was real.

## Step 2 — run the TESTABLE lane, severity-ordered

Process TESTABLE findings **Critical → High → Medium** (spend the budget where the stakes
are). For each, run the standard 8-step workflow from `SKILL.md` — **including the Step 7
falsification gate on every finding whose exploit passes.** A green exploit is not a
`[POC-PASS]` until the defect-mutation control has proven the test is pinned to the defect
(`references/falsification-gate.md`). This is what stops the batch from becoming a row of
self-confirming green checks.

**The "few runs" rule** — this is where multiple attempts are legitimate:

- Re-running a green `forge test` is pointless; the result is deterministic.
- Re-*attempting* a `[CODE-TRACE]` finding is valuable, for two reasons: (1) the
  assertion-retry protocol's variant exploration (different timing/amount/ordering/initial
  state) reproduces harm that the obvious attack missed; (2) PoC *construction* is
  LLM-non-deterministic — a finding you couldn't build on attempt 1 may compile on a fresh
  attempt with a different setup framing.
- So: on a finding that lands `[CODE-TRACE]` for a *construction* reason (not a structural
  one), a second independent attempt is worthwhile. Cap at **3 attempts per finding**, then
  leave it `[CODE-TRACE]` and move on. Never re-attempt a STRUCTURAL finding — the tool
  cannot speak to it no matter how many runs.

## Step 3 — emit the triage table

One row per finding. This is the deliverable.

```markdown
## PoC Triage — <N> findings

| Finding | Sev | Verdict | Evidence | Meaning / action |
|---------|-----|---------|----------|------------------|
| H-01 vault drain via reentrancy | High | PASS | [POC-PASS] | Pinned (fixing the guard kills it) + fix verified. Confirmed. Promote. |
| H-02 oracle staleness theft | High | FAIL | [POC-FAIL] | Harm did not reproduce after retry + variant. Likely false positive — re-read before dropping. |
| H-06 fee coefficient typo | High | PASS* | [POC-PASS · FIX-INSUFFICIENT] | Pinned (correct constant kills it), but the recommended fix does NOT close it. Bug real; remediation flagged for human review. |
| H-08 share inflation | High | ? | [POC-UNPINNED] → [CODE-TRACE] | Exploit passed but the defect-mutation did NOT kill it — test not pinned to the cited line. Downgraded; needs manual review. |
| M-03 governance timelock bypass | Med | — | [CODE-TRACE: TRUSTED_ACTOR] | VALID, un-PoC-able. Requires admin to act. Keep at Medium; PoC is not the right instrument. |
| M-04 wrong event on rebalance | Med | — | [CODE-TRACE: OFF_CHAIN_HARM] | VALID. Off-chain impact (indexer). No on-chain delta to assert. Keep severity. |
| H-05 liquidation rounding | High | — | [CODE-TRACE: COMPILE_UNRESOLVED_AFTER_5] | UNPROVEN, not disproven. Env couldn't build. Needs manual PoC / another environment. |

### Summary
- Confirmed + pinned + fix verified (POC-PASS): 1
- Confirmed + pinned, fix insufficient (FIX-INSUFFICIENT): 1   ← bug real, remediation flagged
- Disproven (POC-FAIL): 1        ← the only bucket that argues a finding is invalid
- Not pinned (POC-UNPINNED → CODE-TRACE): 1   ← reproduced but unproven; manual review
- Valid but un-PoC-able (STRUCTURAL): 2   ← severity unchanged
- Unproven (BLOCKED / construction): 1    ← still open, needs manual attention
```

Note that `[POC-UNPINNED]` and `[POC-PASS · FIX-INSUFFICIENT]` come out of the Step 7
falsification gate, not the initial exploit run. A batch report that shows only bare
`[POC-PASS]` rows for every finding — with no pin result — did not run the gate. Every PASS
row must state the defect-mutation it survived.

### Table rules (non-negotiable)

- **The `[POC-FAIL]` bucket is the ONLY one that counts against a finding.** Every other
  non-PASS outcome leaves the finding's validity and severity exactly where it was.
- **Never write a STRUCTURAL or BLOCKED finding as "invalid," "false positive," or
  "unverified."** Use `[CODE-TRACE: <reason>]` and say "valid, un-PoC-able" or "unproven."
- A `[POC-FAIL]` row must cite that the retry + one variant were tried (per
  `assertion-protocol.md`) — a lazy single-attempt fail is not a refutation.
- Attach the per-finding artifacts (the `.sol` files, the fix diffs for PASS rows) below the
  table or in `.audit/poc/`, so each verdict is auditable.

## Step 4 — hand back

If this ran standalone, the table IS the deliverable. If it ran inside the Krait pipeline,
feed each verdict to the critic: `[POC-PASS]` supports CONFIRMED; `[POC-FAIL]` triggers the
critic's false-positive path; `[CODE-TRACE]` leaves the finding at its reasoned disposition
untouched.

## What this mode is NOT

It is not a filter that keeps only PoC-backed findings. A report that dropped every
un-PoC-able finding would delete real governance, off-chain, and cross-chain issues — the
exact bugs manual auditors are paid to find. The table's job is to **add** an evidence
column, not to prune the list down to what happens to be forkable.
