# AMM & MEV Deep Analysis Module

> **Trigger**: Protocol is DEX/AMM or deeply integrates with liquidity pools
> **Inject into**: Lens B (Value/Economic) + Lens C (External/Cross-contract)
> **Priority**: HIGH — MEV extraction is the primary economic attack on DEXes
> <!-- Vectors from pashov/skills (MIT) -->

## 1. JIT Liquidity Attacks

- **Mechanism**: Attacker sees pending swap in mempool → adds concentrated liquidity around the price → earns fees from the swap → removes liquidity. All in same block.
- **Detection**: Can liquidity be added and removed in the same block/tx? Is there a minimum lock period for LP positions?
- **Impact**: LP fee dilution — existing LPs earn less because JIT captures the highest-fee trades

## 2. Tick Crossing Fee Manipulation

For concentrated liquidity (UniV3-style):
- When price crosses a tick boundary, accumulated fees are distributed. Can an attacker:
  - Add liquidity just below the tick → price crosses → collect fees → remove liquidity?
  - Force tick crossings via small trades to trigger fee events?
- Check: are fee accumulation and tick crossing atomic? Can they be separated?

## 3. First-Swap Extraction

- On a new pool: the first swap sets the price. If pool is initialized at wrong ratio → first swapper extracts the difference
- Check: is pool initialization price validated? Can anyone provide initial liquidity at arbitrary ratio?
- Is there a minimum initial liquidity requirement?

## 4. TWAP Multi-Block Manipulation

- Single-block TWAP manipulation is expensive. Multi-block is cheaper per block but requires sustained capital
- **Cost calculation**: To move TWAP by X%, attacker needs `capital * blocks` of exposure
- Check: what's the TWAP observation window? At `window=5 blocks`, manipulation cost is 5x lower than single-block
- Is the TWAP window configurable? Can it be shortened by admin?

## 5. LP Migration MEV

- When liquidity migrates between pools/versions (V2→V3, pool→pool): tokens are in transit
- **Window**: Between remove-from-old and add-to-new, price can be manipulated in either pool
- Check: is migration atomic? Or are there separate remove + add transactions?

## 6. Concentrated Liquidity Sandwich

- Standard sandwich: buy before victim, sell after. With concentrated liquidity:
  - Attacker can also manipulate the active tick range → victim's swap crosses into a range with no liquidity → massive slippage
- Check: does the protocol have slippage protection? Is it enforced at the pool level or only at the router?

## 7. Hardcoded Zero Slippage

- If `amountOutMinimum = 0` is hardcoded in any swap path → 100% sandwich-able
- Check: grep for `amountOutMin`, `minAmountOut`, `sqrtPriceLimitX96`. Any hardcoded to 0?
- Router contracts that don't pass through user's slippage params are especially dangerous

## 8. Loss-Versus-Rebalancing (LVR)

- Active LP management strategies that rebalance positions are systematically exploited:
  - Arbitrageur trades against the LP at the old price after a price move → LP always on the losing side
- Check: does the protocol have an active LP management strategy? Does it rebalance based on price? Is there MEV protection on rebalances?
