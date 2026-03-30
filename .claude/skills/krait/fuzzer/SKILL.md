# Krait Fuzzer — Invariant Extraction & Testing Methodology

This skill defines how to extract invariants from smart contracts and generate Foundry fuzz tests to verify them.

## Core Principle

The LLM does NOT audit for vulnerabilities. It:
1. **Understands** the code deeply
2. **Documents** all invariants (properties that must always hold)
3. **Generates** Foundry tests to verify those invariants
4. **Iterates** on test failures to distinguish test bugs from real violations

---

## Invariant Categories

| Category | Description | Example |
|----------|-------------|---------|
| **accounting** | Balance/supply consistency | `totalSupply == sum(balances[i])` |
| **access-control** | Permission boundaries | `onlyOwner can call pause()` |
| **state-transition** | Valid state machine flows | `state can only go ACTIVE → PAUSED → ACTIVE` |
| **economic** | Price/rate/value bounds | `exchangeRate >= 1e18` (never decreases) |
| **token-conservation** | No token creation/destruction | `tokensBefore + deposited == tokensAfter` |
| **ordering** | Temporal constraints | `withdrawTime > depositTime` |
| **bounds** | Value range constraints | `fee <= MAX_FEE` |
| **relationship** | Multi-variable relationships | `debt <= collateral * ltv / 1e18` |

---

## Invariant Extraction Methodology

### Step 1: State Variable Analysis

For each contract:
1. List ALL storage variables
2. Group related variables (e.g., `totalSupply` and `balances` mapping)
3. Identify computed relationships: does variable A depend on variable B?
4. Check constructor/initializer: what invariants are established at deployment?

### Step 2: Require/Assert Mining

Every `require()` and `assert()` is a developer-stated invariant:
```solidity
require(balances[msg.sender] >= amount, "insufficient");  // INV: balance >= withdrawal
assert(totalSupply == _computeTotal());                     // INV: supply consistency
```

Also check modifiers — `onlyOwner`, `whenNotPaused`, `nonReentrant` all encode invariants.

### Step 3: Function-Level Invariants

For each state-changing function:
1. What are the preconditions? (checks at the top)
2. What are the postconditions? (state after execution)
3. What changes and what must stay the same?
4. Are there implicit invariants? (e.g., mapping doesn't have negative values)

### Step 4: Cross-Contract Invariants

When multiple contracts interact:
1. Do balances sum correctly across contracts?
2. If Contract A calls Contract B, does B's postcondition guarantee A's invariant?
3. Are there re-entrancy concerns that break invariants during callbacks?
4. Do oracle/price feed assumptions hold across the protocol?

### Step 5: Economic Invariants

For DeFi protocols:
1. Exchange rates: can they be manipulated? Do they only go in one direction?
2. Fee collection: are fees always collected? Never double-counted?
3. Liquidity: does the pool always have enough tokens to cover withdrawals?
4. Slippage: are bounds respected?

---

## Test Generation Patterns

### Basic Invariant Test

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import {Vault} from "../src/Vault.sol";

contract InvariantTest_Vault is Test {
    Vault vault;

    function setUp() public {
        vault = new Vault();
        targetContract(address(vault));
    }

    function invariant_totalDepositsSolvent() public view {
        assertGe(
            address(vault).balance,
            vault.totalDeposits(),
            "INV-001: vault balance must cover total deposits"
        );
    }
}
```

### Handler Pattern (for bounded inputs)

```solidity
contract VaultHandler is Test {
    Vault vault;
    IERC20 token;

    constructor(Vault _vault, IERC20 _token) {
        vault = _vault;
        token = _token;
    }

    function deposit(uint256 amount) public {
        amount = bound(amount, 1, 1e24);
        deal(address(token), address(this), amount);
        token.approve(address(vault), amount);
        vault.deposit(amount);
    }

    function withdraw(uint256 amount) public {
        uint256 max = vault.balanceOf(address(this));
        if (max == 0) return;
        amount = bound(amount, 1, max);
        vault.withdraw(amount);
    }
}

contract InvariantTest_Vault is Test {
    Vault vault;
    VaultHandler handler;

    function setUp() public {
        vault = new Vault(address(token));
        handler = new VaultHandler(vault, token);
        targetContract(address(handler));
    }

    function invariant_conservesTokens() public view {
        assertEq(
            token.balanceOf(address(vault)),
            vault.totalDeposits(),
            "INV-002: vault token balance == totalDeposits"
        );
    }
}
```

### Multi-Contract Invariant Test

```solidity
contract InvariantTest_Protocol is Test {
    Router router;
    Vault vault;
    Oracle oracle;

    function setUp() public {
        oracle = new Oracle();
        vault = new Vault(address(oracle));
        router = new Router(address(vault));
        targetContract(address(router));
    }

    function invariant_debtBelowCollateral() public view {
        for (uint i = 0; i < vault.userCount(); i++) {
            address user = vault.userAt(i);
            uint256 debt = vault.debt(user);
            uint256 collateral = vault.collateral(user);
            uint256 price = oracle.getPrice();
            assertLe(
                debt,
                collateral * price / 1e18,
                "INV-003: debt must not exceed collateral value"
            );
        }
    }
}
```

---

## Iterative Fix Loop

When a test fails, follow this decision tree:

1. **Compilation error?**
   - Check import paths against `remappings.txt`
   - Check constructor arguments match source
   - Check Solidity version compatibility
   - Fix and re-run

2. **setUp() reverts?**
   - Check deployment order (deploy dependencies first)
   - Check constructor arguments
   - Check initialization calls (e.g., `initialize()` for proxies)
   - Check permissions (does setUp need to grant roles?)
   - Fix and re-run

3. **Invariant assertion fails?**
   - Read the counterexample/call sequence
   - Ask: "Is this call sequence possible in production?"
   - If the fuzzer is calling functions in impossible combinations → add `targetSelector()` restrictions or handler bounds
   - If the call sequence is legitimate → **REAL VIOLATION** — report it

4. **Max iterations reached?**
   - Mark as INCONCLUSIVE
   - Document what went wrong
   - The user may need to manually inspect

---

## Priority Guidelines

- **high**: Core protocol invariant. If broken, funds at risk or protocol fundamentally broken.
- **medium**: Important correctness property. Violation causes incorrect behavior but not immediate fund loss.
- **low**: Defensive check. Violation is unlikely or has minimal impact.

Extract 5-20 invariants per non-trivial contract. Err on the side of more.
