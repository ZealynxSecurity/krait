# Flash Loan Interaction Module

> **Trigger**: Protocol reads `balanceOf(address(this))`, uses spot prices, has deposit/withdraw in same tx, or integrates with flash-loan-capable protocols
> **Inject into**: Lens B (Value/Economic), Lens C (External/Cross-contract)
> **Priority**: HIGH — flash loans amplify every rounding/edge-case bug into a critical exploit

## 0. External Flash Susceptibility

Before analyzing the protocol's OWN flash paths, check external manipulability:

| External Protocol | Interaction | State Read | Flash-Manipulable? |
|-------------------|-------------|------------|-------------------|
| {DEX/pool/vault} | {swap/deposit/query} | {reserves, price, balance} | {YES if spot / NO if TWAP} |

For each YES: model the attack — flash borrow → manipulate external state → call our protocol → restore.

## 1. Flash-Accessible State Inventory

| State | Location | Read By | Write Path | Flash-Accessible? | Manipulation Cost |
|-------|----------|---------|------------|-------------------|-------------------|
| `balanceOf(this)` | {contract} | {functions} | Direct transfer | YES | 0 (donation) |
| `totalSupply` | {contract} | {functions} | mint/burn | YES if permissionless | Deposit amount |
| `getReserves()` | {pool} | {functions} | Swap | YES | Slippage cost |
| Oracle spot price | {oracle} | {functions} | Trade on source | YES | Market depth |

## 2. Balance-Dependent Logic

For every function that reads `balanceOf(address(this))`:
- Is this the ONLY source of truth for token amounts? (vs tracked internal accounting)
- Can donations inflate this balance? → First depositor inflation, exchange rate manipulation
- Is there a `skim()` or `sync()` to reconcile? If not → permanent accounting divergence

## 3. Exchange Rate Manipulation

For share-based systems (ERC-4626, LP tokens):
- `shares = deposit * totalShares / totalAssets`
- If `totalShares = 1` and attacker donates to inflate `totalAssets` → new depositors get 0 shares
- **First depositor check**: Does the protocol enforce a minimum first deposit or dead shares?

## 4. Amplification Check

For EVERY rounding/edge-case finding from other modules:
- Can an attacker use a flash loan to FORCE the edge condition?
- What's the cost? If `profit > flash_loan_fee` → viable exploit
- Flash loan fees: Aave 0.09%, dYdX 0%, Balancer 0% → assume essentially free

## 5. Defense Audit

| Defense | Present? | Location | Bypass? |
|---------|----------|----------|---------|
| Minimum deposit | | | |
| Dead shares | | | |
| TWAP (not spot) | | | |
| Same-block deposit+withdraw blocked | | | |
| Reentrancy guard | | | |
