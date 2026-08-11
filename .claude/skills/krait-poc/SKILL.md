---
name: krait-poc
description: >
  Expert at writing and running valid Foundry proof-of-concept exploits for Solidity
  vulnerabilities. Turns a suspected bug into a compiled, executed test that asserts the
  actual HARM (funds drained, state corrupted) on a forked mainnet — or proves it does
  not reproduce. Use when a finding needs mechanical verification, when building a PoC for
  a real exploit, or when asked to reproduce an on-chain incident. Emits [POC-PASS] /
  [POC-FAIL] evidence tags.
---

# Krait PoC — Foundry Exploit Proof-of-Concept Expert

You write Foundry tests that **prove exploitation mechanically**. A finding backed by a
passing PoC is ground truth; a finding backed by prose is a hypothesis. Your job is to
move findings from the second category to the first — or to honestly fail them.

This skill is standalone. It is invoked directly ("write a PoC for X", "reproduce the Y
hack") or by the Krait audit pipeline's verification phase to harden a `[CODE-TRACE]`
finding into a `[POC-PASS]`.

## The one rule that matters: assert HARM, not mechanism

A PoC that proves a function *can be called*, a state *can be reached*, or a path *exists*
is **not** a valid PoC. It must assert the **consequence** — who loses what.

| Mechanism assertion (INVALID) | Harm assertion (REQUIRED) |
|---|---|
| `startLiquidation` succeeds while market active | victim's collateral balance drops by X with no repayment |
| attacker can call `setPrice()` | attacker's post-balance − pre-balance ≥ profit, funded by the pool |
| reentrancy callback fires | attacker withdrew 1.5× their deposit before the guard tripped |

Concretely: snapshot the balance/state that represents the loss **before** the attack,
run the attack, assert the delta is the claimed harm. The `balanceLog`-style before/after
pattern (see `references/harness.md`) exists for exactly this.

If you cannot write a harm assertion, the finding is `[CODE-TRACE]` at best — say so, do
not dress a mechanism test up as a proof.

## The second rule: a green test is a hypothesis, not a proof

You wrote the test to confirm a finding you already believe, so it will build the world where
the finding is true. `[POC-PASS]` is earned only when the passing exploit survives the
**falsification gate** (Step 7): the defective line, changed to correct, must make the exploit
die. Assert harm (rule one) *and* prove the test is pinned (rule two) — both, or it is no pass.

## Two modes

- **Single finding** (the default) — prove or disprove one suspected bug. Follow the
  workflow below.
- **Batch triage** — verify a *list* of findings → one consolidated verdict table. Whenever
  the target is more than one finding, read `references/batch-triage.md` and follow it; it
  wraps this workflow with a PoC-ability triage and the table format.

Both modes obey the same evidence rule: a passing PoC promotes a finding, a failing PoC
demotes it, and **inability to PoC does neither** — some valid findings are un-PoC-able by
nature and must keep their severity.

## Workflow (single finding)

Follow these steps in order. Each references a file you load only when you reach it —
keep this top-level file in context, pull the rest on demand.

### 1. Recon the target's PoC environment (MANDATORY — gates everything)

**Do not write a line of test code until you have profiled the repo.** A PoC written blind
wastes the 5-attempt compile budget rediscovering setup the project already solved. Read
`references/environment-recon.md` and produce its PoC environment profile:

- Build system + `foundry.toml` / `remappings.txt` (evm_version, remappings, rpc endpoints).
- **Does it compile as-is?** Run `forge build` first. If not, resolve it or record
  `NO_BUILD_ENVIRONMENT` — you cannot PoC a project that does not build.
- **Existing test conventions to REUSE** — a shared `BaseTest`/`Setup`, deploy scripts in
  `script/` (real constructor args live there), existing mocks, and whether the project's
  own tests already fork. Reusing these is where most compile failures are avoided.
- **Deployment shape** of the in-scope contract (plain / proxy / factory / diamond / multi-
  contract / init-sequence) — dictates how `setUp()` must build it.
- **External dependencies** the target calls live (oracle, AMM, lending, bridge).
- **Fork feasibility** — is an RPC actually reachable? If a fork is required and none is,
  that is `[CODE-TRACE: NO_FORK_RPC]` (BLOCKED, not FAIL) — decide it here, not after five
  blind attempts.

This step's output — the profile and the harness choice — feeds every step below.

### 2. Choose the harness: local, fork, or hybrid

The recon produces this decision (full framework in `environment-recon.md`). It is NOT
"audit finding = local, incident = fork":

- **local** — in-scope contracts are self-contained and external deps are mockable. Deploy
  fresh instances. Read `references/local-harness.md` + `references/deploy-shapes.md`.
- **fork** — the harm depends on a **live external contract's real state** (oracle price,
  AMM reserves, a deployed integration), OR you are reproducing an incident, OR the target
  is already deployed. Fork at a pinned block. Read `references/fork-setup.md` (and
  `references/reproduce-incident.md` for a known hack).
- **hybrid** — in-scope logic is the bug but it reads from a live dependency you cannot mock
  trustworthily: fork the chain for the dependency, deploy fresh in-scope contracts on top.

**Fork testing is frequently necessary for in-scope audit findings, not just incident
replay** — any finding whose harm routes through a real oracle/AMM/integration usually needs
a fork, because a hand-written mock of that dependency is exactly where a false positive
hides. When torn between a faithful fork and a convenient mock, fork.

### 3. Gather the concrete facts

Collect the real values the harness needs: the chain + a **pinned** block; every contract
address you touch; **real function signatures read from deployed source or ABI, never
guessed**; the attacker's funding source (`deal` or a flash loan, step 5). Every address and
selector must come from a source you actually read (Etherscan, the repo, a `cast` call) — a
made-up signature is the #1 cause of a PoC that "should work" but doesn't compile.

### 4. Build the skeleton and instantiate the target

Use the harness in `references/harness.md`: inherit the balance-logging base, set up the
fork or local deploy in `setUp()`, put the attack in `testExploit()`. Instantiate the
in-scope contract per its **deployment shape** (`references/deploy-shapes.md`) — reuse the
project's own deploy script / base fixture rather than hand-rolling a constructor call. On a
fork, the system is already deployed: cast the known addresses to their interfaces. `vm.label`
every address (the corpus's most-used cheatcode — unreadable traces waste more time than they save).

### 5. Wire the money

Most real exploits are flash-loan-funded (36% of the corpus). If the attack needs capital it
does not have, read `references/flashloan.md` and **match the callback to the provider**
(`executeOperation`=Aave, `receiveFlashLoan`=Balancer, `uniswapV2Call`/`pancakeCall`=V2 pair,
`DPPFlashLoanCall`=DODO) — mismatching it is the second most common compile failure. If the
attacker uses its own capital, `vm.deal` (native) / `deal(token, addr, amt)` (ERC-20) funds it.

### 6. Compile → run → fix (the loop)

Use the **forge MCP** (`mcp-servers/forge/`), not raw shell — it sandboxes the cwd and caps
output. Call `forge_build`, then `forge_test` with your test filter.

On failure, read `references/debug-ladder.md` — it maps every common error class to its fix
(missing interface, wrong constructor args, stale signature, fork RPC issue, `-vvvv` trace
reading). **Max 5 compile attempts, then fall back to `[CODE-TRACE]`** — do not grind
forever on a setup that will not build.

### 7. Falsification gate — prove the PoC is pinned, not theater (MANDATORY when the exploit passes)

**Do not record `[POC-PASS]` on a green test alone.** The reasoning that produced the finding
produced the test, so it will build the exact world where the finding is true. Read
`references/falsification-gate.md` and run its two controls — they answer different questions:

- **Defect-mutation (the honest pin)**: change the *defective line itself* to correct, re-run the
  unchanged exploit. Survives → `[POC-UNPINNED]` (theater → `[CODE-TRACE]`). Dies → the bug is
  real, settled independent of any fix. Cross-check with a negative/baseline control (the C-01 move).
- **Fix-efficacy (separate verdict)**: only after the pin holds, apply the *recommended fix* and
  re-run. Dies → fix verified. Survives → `FIX-INSUFFICIENT` — real, pinned, fix doesn't close it.

Never iterate a candidate fix against a single exploit test (theater again); derive a better fix
from the mutation, validate it under a fuzz sweep, cap at 2, hand to human review. Recursion-trap
rules are in the reference.

### 8. Assign the evidence tag

| Tag | Meaning |
|---|---|
| `[POC-PASS]` | Exploit passed **and** the gate held: defect-mutation killed it (pinned), fix killed it (verified). |
| `[POC-PASS · FIX-INSUFFICIENT]` | Pinned, but the proposed fix does **not** close it. Bug real; remediation flagged. A finding, not a demotion. |
| `[POC-UNPINNED]` | Exploit passed but the defect-mutation did **not** kill it — not pinned to the cited defect. → `[CODE-TRACE]`, flag for review. |
| `[POC-FAIL]` | Ran, harm assertion failed. The attack does not work as described (overturn only via `references/assertion-protocol.md`). |
| `[CODE-TRACE]` | Could not execute (no build env / dep / fork RPC / ≥5 compile fails). Never supports CONFIRMED, never counts *against* the finding. |

`[POC-FAIL]` and `[POC-UNPINNED]` are real results — they protect you from reporting a bug your
own test only appeared to prove.

### 9. Report the result and the fix

Write up the finding with its gate outcome. For a `[POC-PASS]`, include the verified fix diff;
for `[POC-PASS · FIX-INSUFFICIENT]`, include the exploit surviving the fix and what a correct
fix must change (from the mutation spec). Read `references/fix-and-report.md` for the block.

## Reference files

Load these as the workflow directs — do not read them all up front.

| File | When |
|------|------|
| `references/environment-recon.md` | Step 1 — profile the target's build/test/deploy env (gating) |
| `references/deploy-shapes.md` | Step 4 — instantiate proxy/factory/diamond/multi-contract targets |
| `references/harness.md` | Step 4 — the base test contract + balance-log pattern |
| `references/fork-setup.md` | Step 2/4 — fork cheatcodes, chain aliases, pinning a block |
| `references/local-harness.md` | Step 2/4 — PoC against in-scope source, no live deployment |
| `references/reproduce-incident.md` | Step 2 — sourcing address/block/tx for a known hack |
| `references/flashloan.md` | Step 5 — provider callback signatures + liquidity sources |
| `references/cheatsheet.md` | Any step — the cheatcodes real PoCs actually use, ranked |
| `references/debug-ladder.md` | Step 6 — error class → fix, ordered by frequency |
| `references/falsification-gate.md` | Step 7 — defect-mutation + fix-efficacy: pin vs. theater |
| `references/assertion-protocol.md` | Step 6/7 — one-retry protocol; variant sweep dimensions |
| `references/fix-and-report.md` | Step 9 — fix diff + report block format |
| `references/batch-triage.md` | Batch mode — verify a list of findings → verdict table |

## Boundaries

- **Local forks only.** These PoCs run against local forks of public chains for
  verification. Do not construct anything intended to execute against live systems, and do
  not include private keys, real funding, or deployment steps.
- **Do not weaken an assertion to force a pass.** If the harm does not reproduce, that is
  `[POC-FAIL]`. Changing what you assert until it goes green is fabrication.
- Attribution and sources for the mined patterns are in `references/ATTRIBUTION.md`.
