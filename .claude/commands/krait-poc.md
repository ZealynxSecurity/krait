# Krait PoC — Foundry Exploit Proof-of-Concept

Write and run a valid Foundry proof-of-concept that proves (or disproves) a Solidity
exploit by asserting the actual harm on a forked chain or against local source.

## Usage

```
/krait-poc                          # Build a PoC for the finding(s) in .audit/, or ask what to prove
/krait-poc src/Vault.sol:142        # Build a PoC for a suspected bug at a location
/krait-poc reproduce <incident>     # Reproduce a known on-chain hack from its post-mortem
/krait-poc triage findings.md       # Batch: verify a LIST of findings → one verdict table
/krait-poc triage .audit/krait-findings.json
```

**Single finding** → follow the 8-step workflow. **A list of findings** (the `triage` form,
a `.md`/`.json` of findings, or more than one pasted) → read and follow
`~/.claude/skills/krait-poc/references/batch-triage.md`, which produces a consolidated
verdict table.

## Instructions

Read and follow `~/.claude/skills/krait-poc/SKILL.md`, then work through its 8-step
workflow, loading the referenced files under `~/.claude/skills/krait-poc/references/` only
as each step directs.

**Non-negotiables:**

- **Assert HARM, not mechanism.** A PoC that proves a function is callable or a state is
  reachable is not valid. It must assert who loses what — snapshot the loss-bearing
  balance/state before, run the attack, assert the delta.
- **Every address and function signature must come from a source you read** (deployed
  source, ABI via `cast`, or the in-scope repo). Never invent a selector.
- **Pin the fork block.** An un-pinned fork is not reproducible.
- **Use the forge MCP** (`forge_build` / `forge_test`) to compile and run, not raw shell.
- **Max 5 compile attempts**, then fall back to `[CODE-TRACE]` with the specific blocker.
- **Never weaken an assertion to force a pass.** If the harm does not reproduce, that is
  `[POC-FAIL]` — a real result.
- **Inability to PoC is not a refutation.** Only `[POC-FAIL]` (a harm-asserting test that
  ran and did not reproduce) argues a finding is invalid. A finding that is un-PoC-able by
  nature (trusted-actor, off-chain, cross-chain) or un-buildable here keeps its severity as
  `[CODE-TRACE]` — never mark it "invalid" for lack of a PoC.

Local forks only, for verification of past/public incidents and in-scope findings. Do not
target live systems, include real funding keys, or add deployment steps.

## Output

- The PoC test file (e.g. `test/Victim_exp.sol`) plus the run command.
- An evidence tag: `[POC-PASS]` / `[POC-FAIL]` / `[CODE-TRACE]`.
- For `[POC-PASS]`: the harm assertion that passed, the profit/drain output, and a minimal
  fix diff (verified against the PoC when the harness allows).

When invoked by the Krait audit pipeline's verification phase, hand the evidence tag and
harm assertion back to the critic — `[POC-PASS]` is the only tag that supports CONFIRMED as
ground truth.
