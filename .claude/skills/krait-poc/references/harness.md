# PoC Harness — the base test contract

The skeleton every PoC uses. Derived from the DeFiHackLabs `basetest.sol` pattern
(Apache-2.0), simplified and self-contained.

## The base contract

Inherit this instead of `Test` directly. It snapshots your profit token(s) before and
after `testExploit()` and logs the delta — which is exactly the harm assertion you need.

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";

/// Base for exploit PoCs. Logs profit-token balance before and after the attack so the
/// test output states the harm directly. Single-asset by default; set `multiAssetLog`
/// and fill `fundingTokens` for multi-asset attacks.
contract BaseTestWithBalanceLog is Test {
    // Single-asset mode: token you profit in. address(0) = native coin.
    address fundingToken = address(0);
    // Multi-asset mode: every token to track.
    address[] fundingTokens;
    bool multiAssetLog = false;
    // Address whose profit is measured. address(0) resolves to address(this).
    address attacker = address(0);

    modifier balanceLog() {
        address who = attacker == address(0) ? address(this) : attacker;
        (address[] memory toks) = _tokens();
        int256[] memory before = new int256[](toks.length);
        for (uint256 i; i < toks.length; ++i) before[i] = _bal(toks[i], who);

        _;

        for (uint256 i; i < toks.length; ++i) {
            int256 delta = _bal(toks[i], who) - before[i];
            emit log_named_decimal_int(
                string.concat("profit ", _sym(toks[i])), delta, _dec(toks[i])
            );
        }
    }

    function _tokens() internal view returns (address[] memory) {
        if (multiAssetLog) return fundingTokens;
        address[] memory one = new address[](1);
        one[0] = fundingToken;
        return one;
    }

    function _bal(address token, address who) internal view returns (int256) {
        if (token == address(0)) return int256(who.balance);
        return int256(IERC20(token).balanceOf(who));
    }

    function _dec(address token) internal view returns (uint256) {
        if (token == address(0)) return 18;
        try IERC20Meta(token).decimals() returns (uint8 d) { return d; } catch { return 18; }
    }

    function _sym(address token) internal view returns (string memory) {
        if (token == address(0)) return "NATIVE";
        try IERC20Meta(token).symbol() returns (string memory s) { return s; } catch { return "?"; }
    }
}

interface IERC20 { function balanceOf(address) external view returns (uint256); }
interface IERC20Meta is IERC20 {
    function decimals() external view returns (uint8);
    function symbol() external view returns (string memory);
}
```

## A complete fork PoC skeleton

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "forge-std/Test.sol";
import "./BaseTestWithBalanceLog.sol";

contract ExploitTest is BaseTestWithBalanceLog {
    // Real addresses — every one must come from a source you read, never invented.
    IVulnerable constant VICTIM = IVulnerable(0x...);
    IERC20      constant USDC   = IERC20(0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48);

    function setUp() public {
        // Pin the block. An un-pinned fork is not reproducible.
        vm.createSelectFork("mainnet", 18_000_000);
        fundingToken = address(USDC);           // profit is measured in USDC
        vm.label(address(VICTIM), "Victim");
        vm.label(address(USDC), "USDC");
    }

    function testExploit() public balanceLog {
        // 1. fund the attacker (deal or flash loan)
        // 2. execute the attack against VICTIM
        // 3. the balanceLog modifier prints the profit delta

        // Explicit harm assertion — do NOT rely on the log alone:
        // assertGt(USDC.balanceOf(address(this)), startBalance, "no profit extracted");
    }
}
```

## Why the explicit assertion AND the log

The `balanceLog` modifier makes the harm **visible** in the output; the `assertGt` /
`assertEq` makes the test **fail loudly** if the harm does not materialize. A PoC that
only logs can "pass" while proving nothing. Always assert, not just log.

For the profit direction, assert the sign that represents the loss to the victim class:
attacker balance goes **up**, or victim/pool balance goes **down** by the claimed amount.

## Filenames and commands

- Name the test file for the target: `Victim_exp.sol`, test function `testExploit`.
- Run via the forge MCP `forge_test` with filter `--match-contract ExploitTest` (or
  `--match-test testExploit`).
- If the attack needs a specific EVM version (some 2024+ mainnet PoCs need cancun):
  pass `--evm-version cancun`. See `debug-ladder.md`.
