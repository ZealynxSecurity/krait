# Environment recon — profile the target BEFORE writing any test

**This runs first, and it gates everything.** A PoC written before you understand the
target's build system, test conventions, and deployment shape wastes your 5-attempt compile
budget rediscovering setup the project already solved. Reading the repo for ten minutes is
cheaper than five failed `forge build`s.

Do not write a line of test code until you can fill in the **PoC environment profile**
below. Every field is read from the repo, never guessed.

## The PoC environment profile

Produce this before construction. Keep it terse — it is scaffolding for you, not a report.

```
BUILD SYSTEM   : foundry | hardhat | both | raw-sol(no harness)
FORGE CONFIG   : evm_version=<...>  solc=<...>  remappings=<source>  ffi=<t/f>
FORK FEASIBLE  : yes(<alias>→<rpc source>) | no(no RPC / no alias)   [gates fork PoCs]
COMPILES AS-IS : yes | no(<blocker>)
TEST CONVENTION: shared base=<BaseTest/Setup/none>  forks already?=<y/n>  mocks=<dir/none>
DEPLOY SCRIPTS : <script/*.s.sol paths, or none>   ← real constructor args + wiring live here
TARGET SHAPE   : plain | proxy(UUPS/transparent) | factory | diamond | multi-contract | init-sequence
EXTERNAL DEPS  : <live oracle/AMM/lending/bridge the target calls, or none>  [drives fork-vs-local]
HARNESS CHOICE : local | fork | hybrid   ← the decision this recon produces
```

## What to read, and why each matters

### 1. Build system
`ls foundry.toml hardhat.config.* truffle-config.*`. Determines the commands. Foundry is the
target for these PoCs; a Hardhat-only project may need a fork of its deploy fixtures or a
minimal Foundry harness added. Raw `.sol` with no harness → likely `NO_BUILD_ENVIRONMENT`
unless you can stand one up.

### 2. Foundry config (`foundry.toml` + `remappings.txt`)
Read them fully. The fields that break a PoC when ignored:

- **`evm_version`** — a fork at a recent block may use opcodes an older EVM version rejects
  (`cancun` for transient storage / `MCOPY`). Match it or the fork PoC fails at runtime.
- **`remappings`** (file or `[profile]` key) — your imports MUST match the project's. This
  is the #1 "won't compile" cause. Use `import "src/..."` / `@oz/...` exactly as they do.
- **`[rpc_endpoints]` / `[etherscan]`** — presence decides fork feasibility (see 3).
- **`solc_version`, `ffi`, `fs_permissions`, `[profile.*]`** — a PoC that needs `ffi` or a
  non-default profile must invoke it the way the project does.

### 3. Fork feasibility (do this explicitly — it changes the verdict)
A fork PoC needs a reachable RPC. Check, in order:
- Is there a `[rpc_endpoints]` alias for the chain you need?
- Does its URL resolve (env var actually set, endpoint reachable)?

If the finding **requires** a fork and no RPC is available, the correct outcome is
`[CODE-TRACE: NO_FORK_RPC]` — **BLOCKED, not FAIL**. The bug is unproven here, not disproven.
Do not silently downgrade it. Record it as re-runnable in an environment with an RPC.

### 4. Does it compile as-is?
Run `forge build` (via the forge MCP) before writing anything. If the project does not build
out of the box — missing submodules (`forge install`), unresolved remappings, a wrong solc —
resolve that first (within reason) or record `NO_BUILD_ENVIRONMENT`. You cannot PoC a project
that does not compile.

### 5. Existing test conventions — REUSE, do not reinvent
This is where most compile failures die. Grep the `test/` tree:

- **Shared base / setup**: a `BaseTest`, `Setup`, or `Fixture` contract others inherit?
  Inherit it — it already wires tokens, actors, and often a fork.
- **Do they already fork?** `grep -rn "createSelectFork\|rollFork" test/`. If the project's
  own tests fork a chain at a block, copy that exact incantation — alias, block, evm_version.
- **Deploy scripts** (`script/*.s.sol`): the real constructor arguments, initializer calls,
  and wiring order live here. Reading one script saves you from guessing constructor args
  (a top-3 failure). Reuse the deploy function if it is callable from a test.
- **Existing mocks** (`test/mocks/`): reuse them before hand-rolling. A project's own mock
  of its oracle behaves the way the code expects.

### 6. Deployment shape of the in-scope contract
How the target is *instantiated* dictates how `setUp()` must build it — a plain `new X()` is
rare in real audit targets. Identify which pattern applies and read `deploy-shapes.md` for
the instantiation recipe:

- plain constructor · proxy (UUPS/transparent, needs an initializer not a constructor) ·
  factory-deployed instance · diamond (facets) · a multi-contract system that must be wired
  together · a required init sequence (grant roles, set params, seed liquidity).

Getting this wrong produces a contract that deploys but behaves nothing like production, so
the PoC "passes" or "fails" against a fiction.

### 7. External dependencies → the fork-vs-local decision
List every live external contract the in-scope code calls (oracle, AMM router/pair, lending
market, bridge, another protocol's vault). This drives the harness choice below.

## Harness decision — local vs fork vs hybrid

The recon above produces this choice. It is NOT "audit finding = local, incident = fork" —
that is too crude. The real rule:

| Situation | Harness | Why |
|-----------|---------|-----|
| In-scope contracts are self-contained; external deps are mockable or absent | **local** | Deploy fresh instances; fastest, most controllable. |
| The harm depends on a **live external contract's real behavior/state** (oracle price, AMM reserves, a specific deployed integration) that a mock cannot faithfully represent | **fork** | Fork the chain at a block where that dependency is live. |
| Reproducing a real on-chain incident | **fork** | Replay against the real deployed state. See `reproduce-incident.md`. |
| The target is already deployed and you are testing the live instance | **fork** | Fork; interact with the real address. |
| In-scope logic is the bug, but it reads from a live dependency you cannot mock trustworthily | **hybrid** | Fork the chain for the dependency, deploy fresh in-scope contracts on top. |

**Yes, fork testing is frequently necessary for in-scope audit findings — not just for
incident replay.** Any finding whose harm routes through a real oracle, AMM, or external
integration usually needs a fork, because a hand-written mock of that dependency is exactly
where a false positive (or false negative) hides. When in doubt between a faithful fork and a
convenient mock, fork.

## Output of this step

The filled profile + the harness choice. Hand both to the harness step — the skeleton,
the deploy recipe, and the fork setup all read from it. If the profile says the environment
cannot support the PoC (no build, no fork RPC for a fork-only finding), stop here and record
the `[CODE-TRACE: <blocker>]` verdict — do not write a blind test that cannot run.
