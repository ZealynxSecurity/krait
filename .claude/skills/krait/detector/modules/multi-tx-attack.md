# Multi-Transaction Attack Sequences Module

> **Trigger**: Protocol has deposit+withdraw, staking+claiming, or any operations that can be sequenced
> **Inject into**: Lens B (Value/Economic), Lens C (External/Cross-contract)
> **Priority**: MEDIUM-HIGH — single-tx analysis misses sequence-dependent exploits

## 1. Sandwich Attacks

For the protocol's key value-transferring operations:

| Victim Operation | Front-run | Back-run | Attacker Profit |
|------------------|-----------|----------|----------------|
| `swap()` | Large swap same direction | Reverse swap | Price impact diff |
| `deposit()` | Inflate share price | Withdraw | Share dilution |
| `liquidate()` | Move price to threshold | Seize + profit | Liquidation bonus |

## 2. Flash Loan Escalation

For EVERY rounding/edge-case finding:
- Can a flash loan FORCE the edge condition?
- Flash loan fees: Aave 0.09%, dYdX 0%, Balancer 0%
- If `attacker_profit > flash_fee + gas` → viable

## 3. Sequence-Dependent State

Can calling functions in a specific ORDER create exploitable state?

Test sequences:
- `deposit → claim → withdraw` (same block)
- `stake → delegate → unstake` (immediate)
- `borrow → repay → borrow` (bypass cooldown?)
- `approve → transferFrom → approve` (race condition)

## 4. Cross-Function Reentrancy

If function A makes an external call:
- What functions are reachable from the callback?
- Is the reentrancy guard per-function or contract-wide?
- Read-only reentrancy: can a view function return stale state during the callback window?

## 5. Time-Based Attacks

- Block timestamp manipulation: miners can shift ±15 seconds
- Multi-block MEV: can an attacker control consecutive blocks?
- Epoch boundaries: what happens at the exact transition point?
- Reward rate changes: can an attacker front-run rate updates to claim at the old (better) rate?
