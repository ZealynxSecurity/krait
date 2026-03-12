# Krait Detection Primer: Lending / CDP / Borrowing

> Built from Krait's 35-contest shadow audit miss analysis + AMM/oracle checklist patterns applied to lending. No dedicated checklist exists yet — this is synthesized from real audit findings.

## CRITICAL — Must Check Every Lending Audit

### 1. Oracle Price Manipulation → Bad Liquidations
If collateral/debt pricing uses spot AMM price or stale oracle → flash loan manipulates price → trigger false liquidation → steal collateral at discount.
**Check**: What oracle is used? TWAP or spot? Chainlink staleness check? Zero/negative price handling? L2 sequencer check?

### 2. First Depositor Share Inflation (Vault-Based)
If lending vault uses share-based accounting (like ERC4626) without virtual offset → first depositor inflates share price, subsequent depositors lose funds to rounding.
**Check**: Does vault have dead shares or virtual offset? Test: deposit 1 wei, donate large amount, deposit again. Does second depositor get 0 shares?

### 3. Liquidation Profitability Threshold
At what collateral ratio does liquidation become unprofitable? If gas + slippage > liquidation bonus → nobody liquidates → bad debt accumulates.
**Check**: What's the liquidation incentive? At extreme collateral ratios, is it still profitable to liquidate? Is there a backstop mechanism?

### 4. Interest Rate Calculation Precision
If interest accrues per-second but compounds infrequently → rounding error accumulates. If `interestRatePerSecond * elapsedSeconds` truncates → borrowers pay less than expected → protocol insolvency over time.
**Check**: How does interest compound? Per-block? Per-second? Is precision loss bounded? Test at 1-year horizon.

### 5. Borrow-Repay Atomicity Exploit
If user can borrow and repay in same transaction → flash loan: borrow → use funds → repay → no interest paid. Only matters if there's a benefit (governance, airdrop, etc.)
**Check**: Can borrow + repay happen in same block/tx? Is there minimum borrow duration?

## HIGH — Check If Relevant

### 6. Collateral Factor Misconfiguration
If all collaterals use same factor but volatilities differ → volatile collateral becomes under-collateralized faster than factor accounts for.
**Check**: Are collateral factors per-asset? Do they reflect actual volatility? What's the most volatile accepted collateral?

### 7. Circular Collateral Valuation
If protocol's own token is accepted as collateral AND its value depends on TVL that includes itself → reflexive death spiral risk.
**Check**: Can the protocol's governance/native token be used as collateral? Does its price depend on protocol TVL?

### 8. Permissionless Reward Claim Front-Running
If `claimRewards()` is callable by anyone on behalf of any user → attacker front-runs user's intended claim, breaking assumed state.
**Check**: Can `getReward(userAddress)` or `claimRewards(userAddress)` be called by anyone? Does it matter?

### 9. Debt Token Decimal Mismatch
If debt tracking uses different decimals than the borrowed asset → scaling error in interest, repayment, or liquidation calculations.
**Check**: Does debt token have same decimals as underlying? Are all conversions correct?

### 10. Health Factor Stale During Callback
If health factor is checked BEFORE a transfer that triggers a callback → during callback, health factor is stale → attacker borrows more than allowed.
**Check**: Is health factor recalculated AFTER all transfers? Or checked before transfers complete?

### 11. Missing Liquidation Path for All Collateral Types
If liquidator receives collateral but can't handle one type (e.g., NFT collateral without a market) → position becomes unliquidatable.
**Check**: Can every collateral type be liquidated? Does liquidator receive usable assets? Is there a fallback?

### 12. Interest Accrual Skip on Zero Utilization
If interest only accrues when `accrue()` is called, and nobody calls it during zero-utilization period → interest clock pauses → protocol loses revenue.
**Check**: Does interest accrue automatically? Or only on interaction? What happens during idle periods?

### 13. Borrow Cap Bypass via Flash Loan
If borrow cap checks `totalBorrowed` but attacker can temporarily repay other borrows via flash loan → borrow cap artificially lowered → attacker borrows excess.
**Check**: Can borrow caps be manipulated by temporarily changing `totalBorrowed`?

### 14. External Protocol Shutdown
If lending protocol integrates with Aave/Compound/Curve for yield and the external protocol pauses/deprecates → users can't withdraw.
**Check**: What external protocols does the lending pool depend on? Is there a migration or fallback if they shut down?

### 15. Reserve Factor Inconsistency
If protocol takes a reserve cut from interest but the cut is applied inconsistently between accrue/withdraw/liquidate → accounting drift.
**Check**: Is reserve factor applied in ALL interest-bearing code paths? Compare accrual in deposit vs withdraw vs liquidate.

## FROM MISS ANALYSIS — Patterns Krait Has Missed in Real Contests

### 16. Debt Ceiling / Borrow Cap Math Errors (Credit Guild: 5 findings from ONE function)
If debt ceiling calculation uses `min()` of multiple values but implements the comparison chain incorrectly → ceiling is wrong → over-borrowing OR blocked borrows. **TRACE the math with concrete values** — don't just read and judge.
**Check**: Pick 3 sets of inputs (normal, zero, adversarial) and manually compute each step of the debt ceiling formula. Does the code produce the same result?

### 17. Bad Debt Cascade via Multiplier/Index Update During Auction
If bad debt marks down a global multiplier (creditMultiplier, exchangeRate) AND loans in auction have frozen debt amounts → the recalculated principal using new multiplier exceeds frozen callDebt → bidders can't cover → more bad debt.
**Check**: When a global rate/multiplier changes, what happens to in-flight operations (auctions, pending withdrawals, active loans)? Do they use the old or new value?

### 18. Reward Index Not Set on First Stake
If `claimRewards()` returns 0 when user has 0 weight WITHOUT setting the user's profit index → attacker stakes AFTER profit is distributed, claims full reward.
**Check**: When a new user first interacts (stake, vote, deposit), is their reward index initialized to the CURRENT global index? Or does it default to 0?

### 19. Self-Transfer Breaks Rebasing Math
If transfer function caches `from` and `to` states in memory, and sender==receiver → storage update to `from` doesn't propagate to cached `to` → shares inflated.
**Check**: Does the transfer function handle `from == to`? Are memory-cached values stale after storage writes?

### 20. Gauge Weight Escape Before Slashing
If stakers can decrement gauge weight in the window between offboarding and loss application → they escape slashing, shifting losses to passive holders.
**Check**: After a negative event (offboard, loss, slash trigger), can affected users exit before the penalty is applied? Is there a lock period?

### 21. Singleton Reference in Multi-Market Architecture
If a token stores a single `profitManager` / `rewardController` address but the system is designed for multiple markets → the second market's loss/profit notifications always revert.
**Check**: If the system can have multiple instances (markets, pools, vaults), does every shared contract support multiple callers? Or is it hardcoded to one?

### 22. Unbounded Loop DoS in Reward Distribution
If `getRewards()` loops over all user gauges/positions and the array is user-growable → attacker creates many positions → function OOGs → user can't unstake/claim.
**Check**: Does any reward/claim function loop over a user-growable array? Is there a max length?

---
*Source: Synthesized from Krait's 40-contest miss analysis + AMM/oracle checklist patterns applied to lending context. Updated with 7 patterns from Credit Guild + Wildcat miss analysis (v6.4).*
