# Flash loans — provider callbacks and liquidity sources

36% of real exploit PoCs are flash-loan funded. The single most common compile failure in
this class is **mismatching the callback to the provider**. This file is the lookup table
that prevents it.

Usage frequency across the 844-PoC corpus is shown so you reach for the common providers
first — but always match the provider the *victim's* ecosystem actually has deep liquidity
in on the target chain.

## Match the callback to the provider

| Provider | Callback you must implement | Corpus uses | Notes |
|----------|-----------------------------|-------------|-------|
| **DODO** (DPP/DVM pools) | `DPPFlashLoanCall(address,uint256,uint256,bytes)` | 85 | Deepest single-token flash liquidity; fee-free. Very common on BSC. |
| **Balancer V2 Vault** | `receiveFlashLoan(IERC20[],uint256[],uint256[],bytes)` | 75 | Fee-free. Vault at `0xBA12222222228d8Ba445958a75a0704d566BF2C8` (same address most chains). |
| **Uniswap V2 pair / fork** | `uniswapV2Call(address,uint256,uint256,bytes)` | 36 | Any V2 pair. `pancakeCall(...)` (83) is the PancakeSwap-fork variant — identical shape, different name. |
| **Aave V3 Pool** | `executeOperation(address[],uint256[],uint256[],address,bytes)` | 71 | Has a fee (~0.05%); repay principal + premium. |
| **Uniswap V3 pool** | `uniswapV3FlashCallback(uint256,uint256,bytes)` | — | `flash()` on a V3 pool. Swap callback is different — see below. |
| **Morpho Blue** | `onMorphoFlashLoan(uint256,bytes)` | 25 | Fee-free single-asset. |
| **Maker / ERC-3156** | `onFlashLoan(address,address,uint256,uint256,bytes)` | 14 | The EIP-3156 standard interface. DAI flash mint. |

## Swap callbacks are NOT flash-loan callbacks

A frequent confusion: `uniswapV3SwapCallback(int256,int256,bytes)` (39 uses) fires on a
**swap**, not `flash()`. `algebraSwapCallback` is the Algebra/QuickSwap-fork equivalent. If
your attack manipulates price via a swap you implement the swap callback; if it borrows
capital you implement the flash callback. They can both appear in one PoC.

## Shape of a flash-loan attack

```solidity
function testExploit() public balanceLog {
    // Trigger the borrow. Control returns to your callback mid-transaction.
    DODO_POOL.flashLoan(borrowAmount, 0, address(this), abi.encode(/* params */));
    // After the callback returns and the loan is repaid, profit remains here.
}

// The provider calls this back with the borrowed funds in hand.
function DPPFlashLoanCall(address sender, uint256 baseAmount, uint256 quoteAmount, bytes calldata data) external {
    // 1. you now hold `baseAmount` — run the actual exploit
    _attack();
    // 2. repay the loan (+ premium for Aave-style providers)
    IERC20(token).transfer(msg.sender, baseAmount);
    // profit stays with you
}
```

## Rules

- **Repay exactly what the provider requires.** Fee-free providers (DODO, Balancer, Morpho,
  Maker) want principal back. Aave wants principal + premium. Under-repaying reverts the
  whole tx and the PoC "fails" for the wrong reason.
- **Verify the callback selector against the provider's real interface** before assuming.
  Pull it from the deployed source if unsure — a one-character-off callback name compiles
  (it is just a function) but never gets called, so the attack silently does nothing.
- **Pick a provider with real liquidity for the borrowed token on the target chain.** A
  flash loan of 10M TOKEN only works if a pool actually holds it at the pinned block.
- If the required amount is small and the attacker could plausibly hold it, skip the flash
  loan and `deal` the capital — simpler PoCs fail less.
