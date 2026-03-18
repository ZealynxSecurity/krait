# Krait Detection Primer: DEX / AMM / Liquidity Pool

> Distilled from 150 verified checks across Uniswap, Swap/Trading, Liquidity Pool, and AMM Oracle checklists (Zealynx audit-readiness platform). Attack-framed for Krait detection.

## CRITICAL — Must Check Every DEX/AMM Audit

### 1. First Depositor Share Inflation
If ERC4626 or LP share calculation lacks virtual offset/dead shares: attacker mints 1 share, donates large amount, inflates share price. Next depositor loses funds to rounding.
**Check**: First mint path. Is there `_mint(address(0), MINIMUM_LIQUIDITY)` or virtual offset? If not → candidate.

### 2. Round-Trip Swap Token Gain
Swap token0→token1→token0. If attacker ends with MORE than they started → invariant math is broken. Drain pool by repeating.
**Check**: Trace swap math. Does k-invariant hold after round-trip? Are fees applied on BOTH legs?

### 3. Flash Loan Price Manipulation
If ANY pricing function reads `balanceOf(pool)` or pool reserves directly → flash loan can inflate/deflate within one tx.
**Check**: Every price calculation. Does it use TWAP or external oracle? Or raw reserve/balance? Raw = manipulable.

### 4. Missing Slippage Protection
Every function that swaps, adds liquidity, or removes liquidity MUST have `minAmountOut`/`amountOutMinimum` parameter. `amountOutMin=0` or hardcoded = sandwich attack.
**Check**: Every swap/addLiquidity/removeLiquidity call. Is there a user-supplied minimum? Is deadline != `block.timestamp`?

### 5. Factory Owner Drains Router Approvals
If router has blanket token approvals and factory owner can deploy malicious pools → factory owner drains user funds via crafted pool.
**Check**: What does router approve? Can factory deploy arbitrary pool logic? If both → candidate.

### 6. Incorrect Fee Decimal Scaling
If pool has tokens with different decimals (USDC=6, WETH=18), fee math must normalize. If fee uses wrong decimal basis → orders of magnitude wrong.
**Check**: Every fee calculation. Does it account for `token.decimals()`? Are fees on REMAINING amount (not gross)?

### 7. LP Token Pricing via slot0/spot
If LP token value uses `slot0` sqrtPriceX96 or spot reserves → flash-loan manipulable. Must use TWAP.
**Check**: How is LP token valued? Any `slot0()` call in pricing path = manipulable.

## HIGH — Check If Relevant to Codebase

### 8. Fee-on-Transfer Token Accounting
If `amount` transferred != `amount` received (FoT tokens), internal accounting drifts from actual balance. Pool drains over time.
**Check**: Does contract assume `transfer(amount)` delivers `amount`? Or does it use balance-before/after pattern?

### 9. Reentrancy During LP Mint/Burn
ERC777 tokens, native ETH `.call{value}`, and ERC721/1155 callbacks give recipient execution during transfer. Can they re-enter mint/burn/swap?
**Check**: Is `nonReentrant` on ALL state-changing functions? Is CEI pattern followed for every external call?

### 10. Withdrawal DoS via Queue/Balance Manipulation
Attacker manipulates deposit queue, asset balance, or pool state to prevent legitimate withdrawals. Users' funds trapped.
**Check**: Can withdrawal revert based on external-controllable state? Can attacker front-run to change balance/queue?

### 11. Incorrect Liquidation Price Calculations
Wrong formula, stale oracle, or missing decimal normalization in liquidation math → positions liquidated incorrectly or under-collateralized positions survive.
**Check**: Trace liquidation price calc end-to-end. Compare against oracle. Test at boundary CR values.

### 12. Reward Distribution Timing Exploit
Stake → claim reward → unstake in same block. If no minimum lock or time-weighted distribution → flash loan steals rewards.
**Check**: Can rewards be claimed instantly after staking? Is there a minimum staking period or snapshot?

### 13. Admin Pool Parameter Manipulation
If admin can change fee %, amplification factor, or oracle source without timelock → instant sandwich + parameter change = drain.
**Check**: Every admin setter for pool params. Is there a timelock? Min/max bounds? Multi-sig?

### 14. Stale TWAP from Infrequent Updates
If TWAP oracle hasn't been updated recently, price is stale. On L2 with fast blocks, even short staleness windows are exploitable.
**Check**: What's the TWAP observation window? Is there a freshness check? What happens during low activity?

### 15. Incorrect Rounding Direction
Deposits should round DOWN (user gets fewer shares). Withdrawals should round UP (user pays more per share). If reversed → systematic drain via repeated small ops.
**Check**: Every share↔asset conversion. Which direction does it round? Is it consistent across deposit/withdraw/mint/redeem?

### 16. Order Splitting Exploitation
If price impact is sublinear (10 swaps of $100 cost less than 1 swap of $1000) → attacker splits orders to pay less impact/fees.
**Check**: Is cumulative fee/impact tracked? Or does each small swap get independent pricing?

### 17. Pool Initialization Front-Running
If `initialize()` is a separate tx from `deploy()` → attacker can front-run with malicious params (wrong price, wrong tokens).
**Check**: Is deploy+initialize atomic? Or can anyone call initialize() between deploy and intended init?

### 18. Token Reserve Manipulation via Direct Transfer
If accounting uses `balanceOf(address(this))` → attacker sends tokens directly to inflate reserves without going through swap logic.
**Check**: Does pool use internal accounting (`reserve0`, `reserve1`) or `balanceOf`? Direct transfer bypasses `balanceOf`-based accounting.

### 19. Amplification Parameter Attack (StableSwap)
Changing `A` parameter in StableSwap pools affects pricing curve. Ramping too fast or without validation → attacker front-runs the ramp.
**Check**: Is A-parameter ramping gradual? Is there a max rate of change? Timelock?

### 20. Missing Collection-Pool Validation (NFT Swaps)
If NFT swap doesn't verify the collection matches the pool → attacker swaps against wrong pool, draining funds.
**Check**: Does swap validate `nft.collection == pool.collection`? Or can arbitrary NFTs be swapped?

## PROTOCOL-SPECIFIC INTEGRATION CHECKS

### Uniswap V3 Integration
- Negative ticks are valid (`int24`). Does tick math handle sign correctly?
- `tickLower < tickUpper` enforced?
- `sqrtPriceX96` bounded at min/max tick?
- All `NonfungiblePositionManager` calls have slippage + deadline?
- `pool.slot0()` used for pricing? → manipulable

### Curve/StableSwap Integration
- Killed/paused pools handled? (`pool.is_killed()`)
- Native ETH vs WETH distinction (different pool addresses/IDs)
- Tricrypto index order differs from 2pool
- `get_dy` return value properly used?

### Chainlink Oracle Integration
- Stale price check (`updatedAt + heartbeat < block.timestamp`)
- Zero/negative price rejected?
- `roundId` completeness verified?
- L2 sequencer uptime feed checked?
- BTC feed used for WBTC? (depeg risk)

## FROM MISS ANALYSIS — Patterns Krait Has Missed in Real Contests

### 21. External Call to User-Controlled Address Reverts = HoneyPot
If fee transfer uses `.call` to a user-set address (referralFeeDestination, royaltyRecipient) → user sets it to a reverting contract → all sells/transfers blocked → buyers trapped.
**Check**: For every `.call{value: ...}` where the target is user-controlled: what happens if it reverts? Is there try/catch? Can it block core operations?

### 22. Buy vs Sell Fee Asymmetry
If `_buyCurvesToken` sends protocolFee to treasury but `_sellCurvesToken` doesn't → fees accumulate in contract on sells with no withdrawal path.
**Check**: Compare buy and sell paths line by line. Does every fee that's sent on buy also get sent on sell? Where does each fee component go in each direction?

### 23. Fee Parameter Change Breaks Accounting
If `holderFeePercent` changes from >0 to 0, and fee tracking (onBalanceChange) is conditional on fee>0 → new buyers never get offset set → can claim all historical fees.
**Check**: For every conditional fee path (`if feePercent > 0`), what happens when the condition changes? Do all dependent state variables still get updated?

### 24. Bonding Curve Math at Supply=0
If pricing formula uses `(supply - 1 + amount)` → underflows when supply=0 and amount>1, forcing single-token purchases → enables frontrun sniping.
**Check**: What happens at the very first purchase (supply=0)? Can only 1 token be bought? Is this exploitable via frontrunning?

### 25. Zero-Amount Operations Inflate State
If `withdraw(subject, 0)` passes validation (0 >= 0 is true for `>` check but false, varies) and still triggers side effects (deploy ERC20, reset names, push to arrays) → griefing.
**Check**: For every function that takes an amount parameter, what happens when amount=0? Does it still execute side effects?

---
*Source: Zealynx audit-readiness checklists (uniswap-security: 45 checks, swap-trading-security: 40 checks, liquidity-pool-security: 35 checks, amm-price-oracle-security: 30 checks). Updated with 5 patterns from Curves miss analysis (v6.4).*
