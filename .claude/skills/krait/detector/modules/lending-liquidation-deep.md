# Lending & Liquidation Deep Analysis Module

> **Trigger**: Protocol has lending/borrowing/liquidation mechanics
> **Inject into**: Lens B (Value/Economic) + Lens C (External/Cross-contract)
> **Priority**: HIGH — liquidation bugs cause cascading bad debt and protocol insolvency
> <!-- Vectors from pashov/skills (MIT) -->

## 1. Partial Liquidation Loops

- After partial liquidation, is the remaining position HEALTHIER or SICKER?
- If partial liquidation leaves a position with worse health factor → cascading partial liquidations → bad debt
- Check: `healthFactor(afterPartialLiquidation) > healthFactor(beforePartialLiquidation)`?
- Minimum position size after partial liquidation — can dust positions avoid liquidation entirely?

## 2. Bad Debt Socialization Ordering

When a position has more debt than collateral:
- Is bad debt deducted from insurance fund FIRST, then socialized to LPs?
- Or is it socialized immediately, then insurance fund topped up?
- Wrong ordering: liquidator pays less → insurance fund absorbs more → depletes faster
- Check: trace the exact bad debt flow when `collateralValue < debtValue`

## 3. Interest at 100% Utilization

- When utilization = 100%: can new deposits earn interest? Can existing borrowers repay?
- Does the interest rate curve have a kink/jump at high utilization? If rate jumps to 1000% APR → existing borrowers may never be able to repay
- Is there a cap on the interest rate? What happens if rate * time overflows?

## 4. Self-Liquidation Profit

- Can a borrower liquidate their own position for profit?
- Borrow → price moves slightly → self-liquidate → receive liquidation bonus → net positive
- Check: is `liquidator != borrower` enforced? If not, is self-liquidation profitable at any health factor?

## 5. Health Factor During Callbacks

- Is health factor checked BEFORE or AFTER token transfers?
- During ERC721/ERC1155 `onReceived` callback: health factor reflects pre-transfer state → borrow more than allowed
- Check: is health factor revalidated AFTER all transfers complete?

## 6. Pause Blocking Liquidations

- If protocol has `whenNotPaused` modifier on `liquidate()` → pausing = freezing all liquidations
- During a crash: admin pauses (for safety), bad debt accumulates because nobody can liquidate
- Check: can liquidations proceed during pause? They MUST for solvency

## 7. Accrued Interest in Health Factor

- Is accrued (but unsettled) interest included in the health factor calculation?
- If health factor only counts principal debt → positions appear healthier than they are
- Especially dangerous with infrequent `accrue()` calls — hours of unsettled interest can push positions underwater

## 8. Collateral Withdrawal Race

- Between health check and actual withdrawal: can another tx change the price?
- Attacker: manipulate oracle → victim's withdrawal passes stale health check → position is actually underwater
- Check: is the health check in the same tx as the oracle read? Is there a price delay?

## 9. Liquidation with Multiple Collateral Types

- If user has collateral A (volatile) and collateral B (stable), can liquidator choose which to seize?
- Rational liquidator always seizes the most valuable collateral → user left with the worst collateral → remaining position is riskier
- Check: does the liquidation function allow collateral selection? Is it fair?

## 10. Interest Rate Manipulation

- If interest rate depends on utilization, and utilization can be temporarily changed via flash loan:
  - Flash borrow → utilization drops → interest rate drops → attacker borrows at low rate → flash repay
- Check: is interest rate sampled at a point-in-time or time-weighted?

## 11. Reward Accrual on Borrowed Amounts

- If borrowers earn protocol rewards proportional to their borrow → borrow more to earn more rewards
- When reward value > interest cost → rational to borrow maximum, creating systemic risk
- Check: do borrowers earn rewards? Is `reward_rate > interest_rate` possible?
