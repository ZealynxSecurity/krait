# Foundry cheatcode cheatsheet — ranked by real PoC usage

Every cheatcode below is ranked by how often it actually appears across the 844 real
exploit PoCs in DeFiHackLabs. Signatures are from `forge-std`'s `Vm.sol` (authoritative).
Don't reach for an exotic cheat when a common one does the job.

## The vital few (used in almost every PoC)

| Cheatcode | Uses | Purpose |
|-----------|------|---------|
| `vm.label(addr, "Name")` | 2363 | Name an address so `-vvvv` traces are readable. Label EVERYTHING. |
| `vm.createSelectFork("chain", block)` | 581 | Fork a chain at a pinned block and select it. The backbone of a fork PoC. |
| `vm.startPrank(addr)` / `vm.stopPrank()` | 272 | Send subsequent calls as `addr` until stopped. |
| `vm.prank(addr)` | 135 | Send the *next* call as `addr` (one call only). |
| `vm.deal(addr, amount)` | 70 | Set an address's native balance. Fund the attacker with ETH/BNB. |

## Common (reach for these next)

| Cheatcode | Uses | Purpose |
|-----------|------|---------|
| `vm.warp(timestamp)` | 53 | Set `block.timestamp`. For time-gated logic (vesting, auctions, TWAP windows). |
| `vm.roll(blockNumber)` | 45 | Set `block.number`. For multi-block attacks and snapshot boundaries. |
| `vm.etch(addr, bytecode)` | 19 | Replace code at an address. Inject a malicious implementation. |
| `vm.load(addr, slot)` | 12 | Read a raw storage slot. Recover a private/packed value. |
| `vm.rollFork(block)` | 7 | Move an existing fork to another block (keeps the fork id). |

## Occasional

| Cheatcode | Uses | Purpose |
|-----------|------|---------|
| `vm.addr(privateKey)` | 5 | Derive an address from a key (signature PoCs). |
| `vm.expectRevert(...)` | 4 | Assert the next call reverts. For "this SHOULD fail but does not" bugs. |
| `vm.sign(pk, digest)` | — | Produce a signature (permit / EIP-712 replay PoCs). |
| `vm.store(addr, slot, val)` | — | Write a raw storage slot. Force a precondition that has no setter. |
| `vm.mockCall(addr, data, ret)` | — | Force an external call to return a value. Model a compromised dependency. |

## ERC-20 funding — `deal`

`deal` from `forge-std/Test` (not `vm.deal`) funds ERC-20 balances:

```solidity
deal(address(USDC), address(this), 1_000_000e6);   // give this contract 1M USDC
```

It writes the `balanceOf` slot directly. For rebasing or non-standard tokens it may not
update internal accounting — prefer acquiring the token through the protocol (swap, flash
loan) when `deal` produces wrong behavior.

## Assertions that state harm

```solidity
assertGt(token.balanceOf(attacker), startBal, "no profit");      // attacker gained
assertLt(pool.totalAssets(), startAssets, "pool not drained");   // victim lost
assertEq(victim.balanceOf(user), 0, "user funds not stolen");    // exact theft
assertApproxEqRel(got, expected, 0.01e18, "off by >1%");         // tolerate dust
```

Log a human-readable number alongside:

```solidity
emit log_named_decimal_uint("profit (USDC)", profit, 6);
```

## Gotchas

- **`prank` affects only the very next call**; `startPrank` persists until `stopPrank`.
  Mixing them up sends calls from the wrong `msg.sender` and the attack silently no-ops.
- **`deal` on a token with a transfer hook** can desync internal supply. If a fee-on-
  transfer or rebasing token misbehaves, obtain it the way a real attacker would.
- **Pin the fork block.** `vm.createSelectFork("mainnet")` without a block uses latest,
  which changes daily and makes the PoC non-reproducible.
- **Label before you trace.** Running `-vvvv` on unlabeled addresses is how you lose an
  hour. `vm.label` is the highest-ROI line in the file.
