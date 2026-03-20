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
