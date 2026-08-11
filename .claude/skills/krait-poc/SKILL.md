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

## Workflow

Follow these steps in order. Each references a file you load only when you reach it —
keep this top-level file in context, pull the rest on demand.

### 1. Establish the target

Determine which mode you are in — it changes everything downstream:

- **Live incident / on-chain exploit** → fork the real chain at a pinned block just before
  the exploit. Read `references/fork-setup.md`. This is the DeFiHackLabs shape.
- **In-scope audit finding** (local source, no deployment) → build against the project's
  own contracts in a local test. Read `references/local-harness.md`.
- **Reproducing a known hack** → read `references/reproduce-incident.md` for the address /
  block / tx sourcing workflow.

### 2. Gather the concrete facts

You cannot write a fork PoC from names. Collect real values:

- Chain + block number (pin it — an un-pinned fork is not reproducible)
- Addresses of every contract you touch (victim, tokens, pools, oracles)
- Real function signatures — **read the deployed source or ABI, never guess a signature**
- The attacker's funding source (own capital via `deal`, or a flash loan — see step 4)

Anti-hallucination rule: every address and every selector in your PoC must come from a
source you actually read (Etherscan source, the project repo, a cast call). A made-up
signature is the #1 cause of a PoC that "should work" but doesn't compile.

### 3. Write the skeleton

Use the harness in `references/harness.md`: inherit the balance-logging base, set up the
fork in `setUp()`, put the attack in `testExploit()`. Label every address with `vm.label`
so traces are readable (this is the single most-used cheatcode in the real corpus — 2,363
uses across 844 PoCs, because unreadable traces waste more time than they save).

### 4. Wire the money

Most real exploits are flash-loan-funded (36% of the corpus). If the attack needs capital
it does not have:

- Read `references/flashloan.md` — it has the exact callback signature and liquidity
  source for each major provider (Balancer, DODO, Aave V3, Uniswap V2/V3, Morpho, Pancake).
- Match the callback to the provider. `executeOperation` is Aave; `receiveFlashLoan` is
  Balancer; `uniswapV2Call`/`pancakeCall` is a V2 pair; `DPPFlashLoanCall` is DODO. Getting
  this wrong is the second most common compile failure.

If the attacker uses its own capital, `vm.deal` (native) or a `deal(token, addr, amt)`
cheat (ERC-20) funds it — no flash loan needed.

### 5. Compile → run → fix (the loop)

Use the **forge MCP** (`mcp-servers/forge/`), not raw shell — it sandboxes the cwd and caps
output. Call `forge_build`, then `forge_test` with your test filter.

On failure, read `references/debug-ladder.md` — it maps every common error class to its fix
(missing interface, wrong constructor args, stale signature, fork RPC issue, `-vvvv` trace
reading). **Max 5 compile attempts, then fall back to `[CODE-TRACE]`** — do not grind
forever on a setup that will not build.

### 6. Assign the evidence tag

| Tag | Meaning |
|---|---|
| `[POC-PASS]` | Compiled, ran, the **harm assertion** passed. Ground truth. |
| `[POC-FAIL]` | Compiled, ran, the harm assertion failed. Default: the attack does not work as described. To overturn, prove the failure is a setup error (see the Assertion Retry Protocol in `references/assertion-protocol.md`), not a real defense. |
| `[CODE-TRACE]` | Could not execute (no build env, unavailable external dep, ≥5 failed compiles). Fallible — never supports CONFIRMED on its own. |

A `[POC-FAIL]` is a real result, not a failure of yours. Reporting a bug that a passing PoC
would have disproven is worse than reporting `[POC-FAIL]`.

### 7. (When the PoC passes) generate the fix

For `[POC-PASS]` only: write the minimal diff that removes the defect, and — if the harness
allows — re-run the PoC with the fix applied to confirm it no longer triggers. Read
`references/fix-and-report.md` for the diff format and the report block.

## Reference files

Load these as the workflow directs — do not read them all up front.

| File | When |
|------|------|
| `references/harness.md` | Step 3 — the base test contract + balance-log pattern |
| `references/fork-setup.md` | Step 1/2 — fork cheatcodes, chain aliases, pinning a block |
| `references/local-harness.md` | Step 1 — PoC against in-scope source, no live deployment |
| `references/reproduce-incident.md` | Step 1 — sourcing address/block/tx for a known hack |
| `references/flashloan.md` | Step 4 — provider callback signatures + liquidity sources |
| `references/cheatsheet.md` | Any step — the cheatcodes real PoCs actually use, ranked |
| `references/debug-ladder.md` | Step 5 — error class → fix, ordered by frequency |
| `references/assertion-protocol.md` | Step 6 — the one-retry protocol before FALSE_POSITIVE |
| `references/fix-and-report.md` | Step 7 — fix diff + report block format |

## Boundaries

- **Local forks only.** These PoCs run against local forks of public chains for
  verification. Do not construct anything intended to execute against live systems, and do
  not include private keys, real funding, or deployment steps.
- **Do not weaken an assertion to force a pass.** If the harm does not reproduce, that is
  `[POC-FAIL]`. Changing what you assert until it goes green is fabrication.
- Attribution and sources for the mined patterns are in `references/ATTRIBUTION.md`.
