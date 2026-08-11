# Local harness — PoC against in-scope source (no live deployment)

When the target is an audit codebase — Solidity source in a repo, not a deployed address —
you build the PoC against the project's own contracts in a local test. No fork, no real
addresses. This is the shape the Krait audit pipeline's verification phase uses.

## Setup

Deploy the in-scope contracts in `setUp()` the way the project's own tests or deploy
scripts do — reuse their fixtures rather than reinventing the wiring.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import {Vault} from "src/Vault.sol";
import {MockERC20} from "test/mocks/MockERC20.sol";

contract ExploitTest is Test {
    Vault vault;
    MockERC20 token;
    address attacker = makeAddr("attacker");
    address victim   = makeAddr("victim");

    function setUp() public {
        token = new MockERC20("Token", "TKN", 18);
        vault = new Vault(address(token));
        // reproduce the exact preconditions the finding requires
        token.mint(victim, 100e18);
        vm.prank(victim);
        token.approve(address(vault), type(uint256).max);
        vm.prank(victim);
        vault.deposit(100e18);
    }

    function testExploit() public {
        uint256 attackerStart = token.balanceOf(attacker);

        vm.startPrank(attacker);
        // ... execute the finding's attack path ...
        vm.stopPrank();

        // Harm assertion — attacker extracted victim's deposit
        assertGt(token.balanceOf(attacker) - attackerStart, 0, "no theft occurred");
        assertLt(vault.balanceOf(victim), 100e18, "victim did not lose funds");
    }
}
```

## Sourcing the preconditions

The finding's `missingPrecondition` / attack path tells you what state to build. Set up the
**exact** preconditions it names — no more, no less. If you have to add an unrealistic
precondition to make the attack work (e.g. "assume the attacker is already the owner"), the
finding is weaker than claimed; note that rather than papering over it.

## Reuse the project's own test infrastructure

Before writing mocks from scratch, look for:

- `test/` fixtures, `BaseTest` / `setUp` helpers the project already has
- deploy scripts in `script/` that show the real constructor args and wiring order
- existing mocks in `test/mocks/`

Reproducing the project's real deployment shape catches bugs that a hand-rolled setup
hides, and avoids false positives from an unrealistic environment.

## When there is no build environment

If the project does not compile locally (missing deps, unresolved remappings you cannot
fix within 5 attempts), you cannot produce a `[POC-PASS]`. Record `[CODE-TRACE]` with the
specific blocker — `NO_BUILD_ENVIRONMENT` — and hand back the manual trace. Do not claim a
proof you did not execute.

## Fork variant for external dependencies

If the in-scope contract depends on a real external protocol (a live oracle, a specific
AMM) that a mock cannot faithfully represent, switch to a **fork** PoC pinned at a block
where that dependency is deployed, and instantiate only the in-scope contracts fresh on top
of the fork. See `fork-setup.md`.
