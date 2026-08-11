# Reproduce a known on-chain incident

Workflow for turning a real hack into a runnable PoC. This is the DeFiHackLabs shape:
fork the chain just before the exploit, replay the attack, assert the drain.

## Step 1 — gather the five facts

Every incident PoC needs these, and every one must come from a source you read:

| Fact | Where to find it |
|------|------------------|
| **Chain** | The post-mortem / explorer domain (bscscan → bsc, etherscan → mainnet). |
| **Attack tx hash** | Rekt / post-mortem / the project's disclosure. |
| **Block number** | The attack tx's block on the explorer. Pin to `block − 1`. |
| **Victim contract address** | The "Vulnerable Contract" in the post-mortem; the tx's `To` or an internal call target. |
| **Token / pool addresses** | The tx's token-transfer list on the explorer. |

Good post-mortem sources: Rekt News, BlockSec/SlowMist writeups, the project's own incident
report, `bitfinding.com`, security researchers' threads. The explorer's decoded tx and
token-transfer tabs give you the concrete addresses and amounts.

## Step 2 — get the victim's real interface

Never hand-write the victim's function signatures from a description. Pull them:

```
# Generate an interface from the verified ABI
cast interface 0xVICTIM -c mainnet -o IVictim.sol -n IVictim

# Or pull the full verified source
cast etherscan-source 0xVICTIM -c mainnet -d ./external
```

If the contract is unverified, decode the attack tx's input on the explorer to recover the
selectors, or reconstruct from the post-mortem's function-level description — and mark the
signatures as reconstructed.

## Step 3 — fork and replay

```solidity
function setUp() public {
    vm.createSelectFork("bsc", 34_000_000 - 1);   // block just before the attack
    // label victim, tokens, pools
}

function testExploit() public balanceLog {
    // Replicate the attack tx's sequence of calls, in order.
    // Fund via flash loan if the real attacker did (check the tx's first internal calls).
}
```

Reproduce the **sequence** from the attack tx's internal-calls trace, not your guess at how
it "should" work. The explorer's internal-transactions / state-diff view is the ground
truth for what actually happened.

## Step 4 — assert the real loss

Assert the profit matches the reported loss (within tolerance — gas, rounding, and price
movement between your fork and the real tx cause small deltas):

```solidity
emit log_named_decimal_uint("recovered", profit, 18);
assertApproxEqRel(profit, 86_000e18, 0.05e18, "did not reproduce the ~86k loss");
```

Matching the reported number within a few percent is strong evidence you reproduced the
actual mechanism rather than a lookalike.

## Attribution when you keep the PoC

If you save an incident PoC into the repo, credit the original researcher / post-mortem in
the file header (the DeFiHackLabs entries do this — attacker, tx, post-mortem link). See
`ATTRIBUTION.md` for the corpus this workflow was distilled from.

## Boundary

This reproduces a **past, public** incident against a **local fork** for learning and
verification. Do not adapt it toward any live target, and do not include real funding keys
or deployment steps.
