# Fork setup — cheatcodes, chains, pinning

Fork PoCs run against a local copy of a public chain's state at a chosen block. This is how
you reproduce a real deployment without touching anything live.

## The core cheatcodes

```solidity
// Create a fork AND select it as the active EVM. The 99%-case for a PoC.
uint256 forkId = vm.createSelectFork("mainnet", 18_000_000);

// Create without selecting (multi-fork tests). Select later.
uint256 f = vm.createFork("arbitrum", 150_000_000);
vm.selectFork(f);

// Move the active fork to another block (keeps the fork id).
vm.rollFork(18_000_050);

// Keep an address's state when switching between forks.
vm.makePersistent(address(attacker));
```

Signatures (from `forge-std` `Vm.sol`):

- `createSelectFork(string calldata urlOrAlias, uint256 block) returns (uint256)`
- `createFork(string calldata urlOrAlias, uint256 block) returns (uint256)`
- `selectFork(uint256 forkId)`
- `rollFork(uint256 block)`
- `makePersistent(address)`

## Chain aliases

`createSelectFork("mainnet", ...)` resolves `mainnet` through `[rpc_endpoints]` in
`foundry.toml`, falling back to Foundry's built-in alias list. Common aliases used across
the real corpus (by frequency): `bsc` (367), `mainnet` (328), `arbitrum` (41), `base` (35),
`polygon` (22), `avalanche` (13), `optimism` (12), `fantom` (5).

Provide RPCs in `foundry.toml` so aliases resolve offline-ish (still needs network to pull
state):

```toml
[rpc_endpoints]
mainnet  = "${MAINNET_RPC_URL}"
bsc      = "${BSC_RPC_URL}"
arbitrum = "${ARBITRUM_RPC_URL}"
base     = "${BASE_RPC_URL}"
```

An env var with no value set makes the fork fail with a clear RPC error — see
`debug-ladder.md`.

## Pin the block — always

**Never fork at latest.** `vm.createSelectFork("mainnet")` with no block uses the chain
head, which:

- changes every run, so the PoC is not reproducible;
- may be *after* a fix was deployed, so a real bug no longer reproduces;
- may be *after* the exploit, so the drained pool no longer has funds to steal.

For a known incident, pin to **the block just before the attack tx**. The attack tx's block
number minus 1 is the safe default; the exploit itself often spans one block.

## State persistence across forks (the gotcha)

When you `selectFork` to a different fork, contracts you deployed on the previous fork are
**gone** unless you marked them `makePersistent`. Test accounts and their balances also
reset per fork. If a multi-fork PoC "loses" its attacker contract after a fork switch, this
is why — make the attacker (and any helper it needs) persistent before switching.

Single-fork PoCs (the overwhelming majority) never hit this.

## EVM version

State forked from a recent block may contain opcodes your default EVM version rejects
(e.g. `MCOPY`/transient storage → needs `cancun`). If a fork PoC fails to execute with an
opcode error, set the version to match the chain at that block:

```
forge test --match-contract ExploitTest --evm-version cancun -vvv
```

Pass this through the forge MCP's `forge_test` args.
