# ERC-4626 Vault Deep Analysis Module

> **Trigger**: Protocol implements ERC-4626 or custom share-based vault
> **Inject into**: Lens B (Value/Economic) + Lens D (Edge/Math/Standards)
> **Priority**: HIGH — share-based vaults are the #1 source of accounting bugs in DeFi
> <!-- Vectors from pashov/skills (MIT) -->

## 1. Inflation Attack Vectors

Check ALL entry points that increase totalAssets without proportional share minting:
- **Direct donation**: Transfer tokens directly to vault → inflates share price → next depositor rounds to 0 shares
- **Harvest/compound**: If yield accrual inflates totalAssets → front-runner deposits before harvest, gets disproportionate yield
- **Different entry points**: If `deposit()`, `mint()`, `stake()`, and `directTransfer()` all exist — do they ALL update shares consistently?
- **Virtual shares/offset**: Does vault use `_decimalsOffset()` or dead shares? If not → classic inflation possible

## 2. Round-Trip Profit Extraction

- Trace: `deposit(X) → redeem(shares) → received`. Is `received <= X` always? Test at: X=1, X=1e6, X=MAX
- Check: `convertToAssets(convertToShares(X)) <= X` (rounding favors vault)
- Check: `convertToShares(convertToAssets(S)) <= S` (rounding favors vault)
- If ANY round-trip produces profit → drain via repeated operations

## 3. Withdrawal Queue Ordering

- Are withdrawals FIFO, pro-rata, or priority-based?
- Can large withdrawal requests block smaller ones?
- Does the exchange rate lock at REQUEST time or FULFILLMENT time? (rate lock-in arbitrage)
- Can an attacker request withdrawal, wait for rate increase, cancel and re-request?

## 4. Fee Asymmetries

- Are deposit fees and withdrawal fees applied symmetrically?
- If management fee accrues to `totalAssets` but performance fee is deducted from yield → deposit before yield, withdraw after management fee accrues
- Do fees round in favor of the vault or the user?
- What happens when fee = 0? Is `transfer(0)` attempted?

## 5. Virtual Shares Edge Cases

If vault uses virtual shares/offset (OZ 4626 `_decimalsOffset`):
- Does the offset actually prevent inflation? Test: donate before any deposits
- At extreme ratios (1 share : 1e18 assets), does math overflow?
- Does `maxDeposit()` / `maxMint()` correctly account for the offset?

## 6. Paused State Compliance

- When vault is paused: do `maxDeposit()` and `maxMint()` return 0? (ERC-4626 spec requires this)
- Does `previewDeposit()` still return a value when deposits are actually blocked? (misleading)
- Can `withdraw()` proceed during pause? (users should be able to exit)

## 7. Preview vs Actual Discrepancy

- Is `previewDeposit(assets)` == actual shares received? Always? Or can it differ due to fees, slippage, or state changes?
- Is `previewRedeem(shares)` == actual assets received? These MUST match per ERC-4626 spec
- If `preview*` and actual diverge → integrating protocols make wrong decisions
