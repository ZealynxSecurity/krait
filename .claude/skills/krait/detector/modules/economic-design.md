# Economic Design Module

> **Trigger**: Protocol has token economics, fee structures, liquidation mechanics, or incentive systems
> **Inject into**: Lens B (Value/Economic)
> **Priority**: MEDIUM-HIGH — economic design flaws are protocol-level, not function-level

## 1. Circular Collateral

Is the protocol's own token counted as collateral in TVL that determines the token's value?
- If `token_value = f(TVL)` and `token IN TVL` → reflexive death spiral risk
- On downturn: TVL drops → token value drops → TVL drops further → cascade

## 2. Liquidation Profitability

At what collateral ratio does liquidation become unprofitable?
- `liquidator_profit = seized_collateral * price - repaid_debt - gas - slippage`
- At what point does this go negative? → Bad debt accumulates silently
- Is the liquidation bonus fixed or dynamic? Fixed bonus + volatile collateral = guaranteed bad debt zone

## 3. First/Last Mover

- **First depositor**: Can they inflate share price? (Classic ERC-4626 attack)
- **Last withdrawer**: Gets all remaining dust? Or gets nothing because of rounding?
- **Early staker advantage**: Time-weighted rewards = first staker gets disproportionate share?

## 4. Fee-Free Arbitrage

Map ALL fee-charging paths:
| Operation | Fee | Alternative Path | Alternative Fee |
|-----------|-----|-----------------|----------------|
| {swap via router} | 0.3% | {direct pool call} | 0% |
| {mint via frontend} | 1% | {mint via contract} | 0% |

If any pair has fee mismatch → rational users bypass the fee → protocol loses revenue.

## 5. Incentive Misalignment

When is it rational to NOT do what the protocol expects?
- Staking rewards < opportunity cost → no stakers → protocol breaks
- Liquidation bonus < gas cost → no liquidators → bad debt
- Governance participation cost > benefit → no voters → proposals pass with minimal quorum

## 6. Advanced Economic Design Vectors
<!-- Vectors from pashov/skills (MIT) -->

- **Derivatives funding rate manipulation**: If funding rate is calculated from a single trade price or manipulable mark price → attacker pushes mark price via large trade → extracts funding from counterparty → reverses trade. Check: is funding rate based on TWAP or spot? Is there a max funding rate cap?
- **Mark vs index price exploitation**: If liquidation uses mark price but settlement uses index → position can be profitable on one metric while appearing liquidatable on the other. Check: are mark and index prices used consistently across operations?
- **Insurance fund / bad debt socialization ordering**: When bad debt occurs, is it socialized BEFORE or AFTER liquidation incentive is paid? Wrong ordering → liquidator profit increases bad debt → death spiral. Check: trace bad debt handling flow — who pays first?
- **Reward rate changed without settling accumulator**: If admin calls `setRewardRate()` without first calling `accrue()`, the new rate retroactively applies to the unsettled period → over/under-distribution. Check: does every rate-changing function settle first?
- **Withdrawal queue rate lock-in**: If exchange rate at withdrawal REQUEST time differs from FULFILLMENT time → arbitrage. Request when rate is high, fulfill when tokens are worth more (or vice versa). Check: which rate is used — request-time or fulfillment-time?
- **Open interest tracked with pre-fee size**: If open interest is updated with the position size BEFORE fees are deducted → OI is systematically overstated → capacity limits hit prematurely. Check: is OI updated with pre-fee or post-fee amounts?
