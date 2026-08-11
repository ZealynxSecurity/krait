# Deployment shapes — instantiating the target for each pattern

A plain `new Vault(token)` is the exception in real audit targets, not the rule. The
in-scope contract's **deployment shape** (identified in environment-recon step 6) dictates
how `setUp()` must build it. Build it the way production does, or the PoC runs against a
contract that behaves nothing like the real one.

**Always prefer the project's own deploy script / fixture** over hand-rolling any of these.
`script/*.s.sol` and `test/` base contracts already encode the correct args and wiring —
read them first (see `environment-recon.md` step 5).

## Plain constructor

The easy case. Read the real constructor signature from source; pass realistic args.

```solidity
Vault vault = new Vault(address(token), owner, feeBps);
```

## Proxy (UUPS / Transparent)

The logic contract is deployed, then a proxy points at it, and state is set by an
**`initialize()`** call — **not** the constructor (constructors don't run in proxy storage).
Calling the constructor path here gives you an uninitialized contract that behaves wrongly.

```solidity
Vault impl = new Vault();                                  // logic
ERC1967Proxy proxy = new ERC1967Proxy(
    address(impl),
    abi.encodeCall(Vault.initialize, (address(token), owner))
);
Vault vault = Vault(address(proxy));                       // interact through the proxy
```

Transparent proxies additionally need a ProxyAdmin. If the project uses OZ's upgrades or a
custom proxy, mirror their deploy script exactly. On a **fork**, the proxy is already
deployed — just cast the known proxy address to the interface and call it.

## Factory-deployed instance

The contract only exists once a factory creates it; a directly-`new`'d instance may miss
factory-set wiring (registry entry, access grant, init).

```solidity
Factory factory = new Factory(/* args */);   // or, on a fork, the deployed factory
address created = factory.createPool(tokenA, tokenB, fee);
Pool pool = Pool(created);
```

Read the factory's `create*` function for what it wires — often the bug lives in that gap.

## Diamond (EIP-2535)

State and logic are split across facets behind one address. You cannot test a facet in
isolation for anything touching shared diamond storage. Deploy the diamond with its facets
(reuse the project's diamond deploy script — hand-assembling a diamond cut is error-prone),
then call through the diamond address cast to the relevant facet interface.

## Multi-contract system

The target is one node in a system that must be wired together (a lending protocol:
comptroller + markets + oracle + interest model). A single contract in isolation reverts or
misbehaves. Reproduce the **minimal** wiring the finding needs — reuse the deploy script and
prune to the contracts on the attack path.

## Required init sequence

The contract deploys fine but is inert until a sequence runs: roles granted, params set,
liquidity seeded, a market listed, an oracle registered. The finding's preconditions tell
you which steps matter. Perform exactly those — an unrealistic shortcut (e.g. `vm.store`ing
a role you could grant properly) can create a state production never reaches, which is a
false-positive risk.

```solidity
vault.grantRole(vault.MANAGER(), manager);
vm.prank(manager);
vault.setCap(1_000_000e18);
deal(address(token), address(vault), 500_000e18);   // seed the pool the finding assumes
```

## The recurring rule

If you have to invent an unrealistic precondition to make the target deploy or the attack
work — an owner you granted yourself, a state no real sequence reaches — the finding is
weaker than claimed. Note that honestly rather than papering over it; it is the difference
between a real bug and a PoC-shaped artifact.

## On a fork, most of this collapses

When the harness is a **fork**, the target and its whole system are **already deployed** at
the pinned block. You do not re-instantiate — you cast the known addresses to their
interfaces and interact. Deployment shape only matters for the **local** and **hybrid**
harnesses where you build in-scope contracts fresh. This is one more reason a fork is often
the *simpler* choice for a system with heavy wiring, not just the more faithful one.
