# Official Findings — v4 Shadow Audits (Contests 21-30)

## dopex

### HIGH
- H-2083: Improper precision of strike price calculation can result in broken protocol
- H-1584: Put settlement can be anticipated and lead to user losses and bonding DoS
- H-1227: The settle feature will be broken if attacker arbitrarily transfer collateral tokens to the PerpetualAtlanticVaultLP
- H-935: `UniV3LiquidityAMO::recoverERC721` will cause `ERC721` tokens to be permanently locked in `rdpxV2Core`
- H-867: Users can get immediate profit when deposit and redeem in `PerpetualAtlanticVaultLP`
- H-756: Bond operations will always revert at certain time when `putOptionsRequired` is true
- H-549: Incorrect precision assumed from RdpxPriceOracle creates multiple issues related to value inflation/deflation
- H-239: The peg stability module can be compromised by forcing lowerDepeg to revert.
- H-143: `ReLPContract` wrongfully assumes protocol owns all of the liquidity in the UniswapV2 pool

### MEDIUM
- M-2210: Bonding WETH discounts can drain WETH reserves of RdpxV2Core contract to zero
- M-2130: The vault allows "free" swaps from WETH to RDPX
- M-1956: No mechanism to settle out-of-money put options even after Bond receipt token is redeemed. 
- M-1805: reLP() mintokenAAmount the calculations are wrong.
- M-1558: _curveSwap: getDpxEthPrice and getEthPrice is in wrong order
- M-1032: Missing slippage parameter on Uniswap `addLiquidity()` function
- M-1030: The owner of RPDX Decaying Bonds is not updated on token transfers
- M-976: `reLPContract.reLP()` is susceptible to sandwich attack due to user control over `bond()`
- M-863:  A malicious early depositor can manipulate the `LP-Token` price per share to take an unfair share of future user deposits 
- M-850: Change of `fundingDuration` causes "time travel" of `PerpetualAtlanticVault.nextFundingPaymentTimestamp()`
- M-780: User that delegate eth to `RdpxV2Core` will incur loss if his delegated eth fulfilled by decaying bonds
- M-761: User can avoid paying high premium price by correctly timing his bond call
- M-750: Can not withdraw RDPX if WETH withdrawn is zero
- M-598: No slippage protection for bonders
- M-269: `sync` function in `RdpxV2Core.sol` should be called in multiple scenarios to account for the balance changes that occurs
- M-153: Inaccurate swap amount calculation in ReLP leads to stuck tokens and lost liquidity
- M-6: The RdpxV2Core contract allows anyone to call redeem tokens even if the contract is paused.

---

## centrifuge

### HIGH

### MEDIUM
- M-779: The Restriction Manager does not completely implement ERC1404 which leads to account that are supposed to be restricted actually have access to do with their tokens as they see fit
- M-537: onlyCentrifugeChainOrigin() can't require msg.sender equal axelarGateway
- M-227: `LiquidityPool::requestRedeemWithPermit` transaction can be front run with the different liquidity pool
- M-146: Cached `DOMAIN_SEPARATOR` is incorrect for tranche tokens potentially breaking permit integrations
- M-143: You can deposit for other users really small amount to DoS them
- M-118: Investors claiming their maxDeposit by using the LiquidityPool.deposit() will cause that other users won't be able to claim their maxDeposit/maxMint
- M-92: DelayedAdmin Cannot `PauseAdmin.removePauser`
- M-34: ```trancheTokenAmount``` should be rounded UP when proceeding to a withdrawal or previewing a withdrawal.

---

## badger

### HIGH
- H-323: Stormy - Lost of user funds, as LeverageMacroReferences can't do an arbitrary system call to the function claimsSurplusCollShare in order to claim the extra surplus collateral gained from their liquidated or fully redeemed Cdps.

### MEDIUM
- M-310: `fetchPrice` can return different prices in the same transaction
- M-199: Redemptions are inconsistent with other cdp's operations
- M-173: Attacker can utilize function `CdpManager.redeemCollateral()` to break the order of sortedCdps
- M-155: The way fees are accounted can break the sorted list order
- M-152: When calling LeverageMacroBase.doOperation to open a CDP, the POST CALL CHECK may use the wrong cdpId
- M-36: Batched liquidations doesn't distribute bad debt on next batches in the list 

---

## panoptic

### HIGH
- H-448: Attacker can steal all fees from SFPM in pools with ERC777 tokens.
- H-256: Partial transfers are still possible, leading to incorrect storage updates, and the calculated account premiums will be significantly different from what they should be

### MEDIUM
- M-520: premia calculation can cause DOS
- M-516: removedLiquidity can be underflowed to lock other user's deposits
- M-437: The Main Invariant "Fees paid to a given user should not exceed the amount of fees earned by the liquidity owned by that user." can be broken due to slight difference when computing collected fee
- M-355: Premium owed can be calculated as a very big number due to reentrancy on uninitialized pools
- M-247: ` validateCallback()` is vulnerable to a birthday attack

---

## autonolas

### HIGH
- H-445: Permanent DOS in `liquidity_lockbox` for under $10
- H-437: CM can `delegatecall` to any address and bypass all restrictions
- H-386: Wrong invocation of Whirpools's updateFeesAndRewards will cause it to always revert
- H-373: Bonds created in year cross epoch's can lead to lost payouts 
- H-341: Withdrawals can be frozen by creating null deposits

### MEDIUM
- M-452: Withdraw amount returned by `getLiquidityAmountsAndPositions` may be incorrect
- M-444: LP rewards in `liquidity_lockbox` can be arbitraged
- M-443: Griefing attack on `liquidity_lockbox` withdrawals due to lack of minimum deposit
- M-377: Possible DOS when withdrawing liquidity from Solana Lockbox
- M-339: Missing slippage protection in `liquidity_lockbox::withdraw`
- M-7: `block.number` means different things on different L2s

---

## renft

### HIGH
- H-614: All orders can be hijacked to lock rental assets forever by tipping a malicious ERC20
- H-593: An attacker is able to hijack any ERC721 / ERC1155 he borrows because guard is missing validation on the address supplied to function call `setFallbackHandler()`
- H-588: An attacker can hijack any ERC1155 token he rents due to a design issue in reNFT via reentrancy exploitation
- H-565: Incorrect `gnosis_safe_disable_module_offset` constant leads to removing the rental safe's `module` without verification
- H-418: Malicious actor can steal any actively rented NFT and freeze the rental payments (of the affected rentals) in the `escrow` contract
- H-387: Escrow contract can be drained by creating rentals that bypass execution invariant checks
- H-203: Attacker can lock lender NFTs and ERC20 in the safe if the offer is set to partial

### MEDIUM
- M-600: A malicious lender can freeze borrower's ERC1155 tokens indefinitely because the guard can't differentiate between rented and non-rented ERC1155 tokens in the borrower's safe.
- M-587: A malicious borrower can hijack any NFT with `permit()` function he rents.
- M-538: Risk of DoS when stoping large rental orders due to block gas limit
- M-501: DoS of Rental stopping mechanism
- M-487: DOS possible while stopping a rental with erc777 tokens
- M-466: Incorrect ordering for deletion allows to flash steal rented NFT's
- M-397: Upgrading modules via `executeAction()` will brick all existing rentals
- M-323: Assets in a Safe can be lost
- M-292: `Guard::checkTransaction` restricts native ETH transfer from user's safes
- M-267: The owners of a rental safe can continue to use the old guard policy contract for as long as they want, regardless of a new guard policy upgrade
- M-239: Protocol does not implement EIP712 correctly on multiple occasions
- M-220: paused ERC721/ERC1155 could cause stopRent to revert, potentially causing issues for the lender.
- M-162: `RentPayload`'s signature can be replayed
- M-65: Lender of a PAY order lending can grief renter of the payment
- M-64:  Blocklisting in payment ERC20 can cause rented NFT to be stuck in Safe
- M-43: Blacklisted extensions can't be disabled for rental safes

---

## renzo

### HIGH
- H-612: Withdrawals can be locked forever if recipient is a contract
- H-395: Incorrect calculation of queued withdrawals can deflate TVL and increase ezETH mint rate
- H-368: ETH withdrawals from EigenLayer always fail due to `OperatorDelegator`'s nonReentrant `receive()`
- H-326: Withdrawals logic allows MEV exploits of TVL changes and zero-slippage zero-fee swaps
- H-282: Withdrawals of rebasing tokens can lead to insolvency and unfair distribution of protocol reserves
- H-145: The amount of `xezETH` in circulation will not represent the amount of `ezETH` tokens 1:1
- H-87: DOS of `completeQueuedWithdrawal` when ERC20 buffer is filled
- H-28: Incorrect withdraw queue balance in TVL calculation

### MEDIUM
- M-604: Withdrawals can fail due to deposits reverting in `completeQueuedWithdrawal()`
- M-569: Withdrawals and Claims are meant to be pausable, but it is not possible in practice
- M-563: Fixed hearbeat used for price validation is too stale for some tokens
- M-519: Price updating mechanism can break
- M-514: `calculateTVL` may run out of gas for modest number of operators and tokens breaking deposits, withdrawals, and trades
- M-502: L1::xRenzoBridge and L2::xRenzoBridge uses the block.timestamp as dependency, which can cause issue.
- M-484: Lack of slippage and deadline during withdraw and deposit
- M-373: Not handling the failure of cross chain messaging
- M-198: Deposits will always revert if the amount being deposited is less than the bufferToFill value
- M-135: Potential Arbitrage Opportunity in the xRenzoDeposit L2 contract
- M-117: Fetched price from the oracle is not stored in `xRenzoDeposit`
- M-113: Incorrect exchange rate provided to Balancer pools
- M-103: Pending withdrawals prevent safe removal of collateral assets
- M-13: stETH/ETH Feed being used opens up to 2 way deposit<->withdrawal arbitrage

---

## olas

### HIGH
- H-36: `pointsSum.slope` Not Updated After Nominee Removal and Votes Revocation
- H-22: Arbitrary tokens and data can be bridged to `GnosisTargetDispenserL2` to manipulate staking incentives

### MEDIUM
- M-89: checkpoint function is not called before staking which can cause loss of rewards for already staked services.
- M-64: Less active nominees can be left without rewards after an year of inactivity
- M-62: Adding staking instance as nominee before it is created
- M-61: Loss of incentives if total weight in an epoch is zero
- M-59: Changing VoteWeighting contract can result in lost staking incentives
- M-57: Unstake function reverts because of use of outdated/stale serviceIds array
- M-56: In retain function checkpoint nominee function is not called which can cause zero amount of tokens being retained.
- M-51: StakingToken.sol doesn't properly handle FOT, rebasing tokens or those with variable which will lead to accounting issues downstream.
- M-38: Removed nominee doesn't receive staking incentives for the epoch in which they were removed which is against the intended behaviour
- M-33: Attacker can make claimed staking incentives irredeemable on Gnosis Chain
- M-32: Refunds for unconsumed gas will be lost due to incorrect refund chain ID
- M-31: Blocklisted or paused state in staking token can prevent service owner from unstaking
- M-29: Attacker can cancel claimed staking incentives on Arbitrum
- M-27: Unauthorized claiming of staking incentives for retainer
- M-26: Non-normalized amounts sent via Wormhole lead to failure to redeem incentives
- M-23: Staked service will be irrecoverable by owner if not an ERC721 receiver
- M-20: Users will lose all ETH sent as `cost` parameter in transactions to and from Optimism
- M-16: Incorrect Handling of Last Nominee Removal in `removeNominee` Function
- M-5: The `refundAccount` is erroneously set to `msg.sender` instead of `tx.origin` when `refundAccount` specified as `address(0)`
- M-4: The `msg.value` - `cost` for multiple cross-chain bridges are not refunded to users

---

## size

### HIGH
- H-288: When `sellCreditMarket()` is called to sell credit for a specific cash amount, the protocol might receive a lower swapping fee than expected.
- H-181: Risk of Overpayment Due to Race Condition Between repay and liquidateWithReplacement Transactions
- H-70: The collateral remainder cap is incorrectly calculated during liquidation
- H-21: Users won't liquidate positions because the logic used to calculate the liquidator's profit is incorrect

### MEDIUM
- M-238: Multicall does not work as intended
- M-224: Users can not to buy/sell minimum credit allowed due to exactAmountIn condition
- M-218: Size uses wrong source to query available liquidity on Aave, resulting in borrow and lend operations being bricked upon mainnet deployment
- M-209: Inadequate checks to confirm the correct status of the sequecnce/sequecncerUptimeFeed in `PriceFeed.getPrice()` contract. 
- M-197: Users may incur an unexpected fragmentation fee in the `compensate()`  call
- M-184: Neither `sellCreditMarket‎()` nor `compensate‎()` checks whether the credit position to be sold is allowed for sale
- M-179: Credit can be sold forcibly as `forSale` setting can be ignored via Compensate
- M-152: Sandwich attack on loan fulfillment will temporarily prevent users from accessing their borrowed funds
- M-107: Borrower is not able to compensate his lenders if he is underwater
- M-88: withdraw() users may can't withdraw underlyingBorrowToken properly
- M-53: LiquidateWithReplacement does not charge swap fees on the borrower
- M-15: `executeBuyCreditMarket` returns the wrong amount of cash and overestimates the amount that needs to be checked in the variable pool
- M-10: Fragmentation fee is not taken if user compensates with newly created position

---

## traitforge

### HIGH
- H-231: Wrong minting logic based on total token count across generations
- H-227: Griefing attack on seller's airdrop benefits
- H-221: Incorrect Percentage Calculation in NukeFund and EntityForging when `taxCut` is Changed from Default Value
- H-219: Number of entities in generation can surpass the 10k number
- H-217: The maximum number of generations is infinite
- H-213: `mintToken()`, `mintWithBudget()`, and `forge()` in the `TraitForgeNft` Contract Will Fail Due to a Wrong Modifier Used in `EntropyGenerator.initializeAlphaIndices()`

### MEDIUM
- M-1086: Potential Uninitialized `entropySlots` Reading in `getNextEntropy`, Causing 0 Entropy Mint
- M-1078: Funds can be locked indefinitely in NukeFund.sol
- M-1060: A dev will lose rewards if after claiming his rewards he mints an NFT
- M-1050:  Lack of Slippage Protection in Dynamic Pricing Mint Function
- M-927: Incorrect check against golden entropy value in the first two batches
- M-656: TraitForgeNft: Generations without a golden god are possible
- M-564: Discrepancy between nfts minted, price of nft when a generation changes & position of `_incrementGeneration()` inside `_mintInternal()` & `_mintNewEntity()`
- M-378: Lack of ability to make an some external function calls makes the DAO stage unreachable.
- M-229: `Golden God` Tokens can be minted twice per generation
- M-223: Imprecise token age calculation results in an incorrect nuke factor, causing users to claim the wrong amount
- M-222: Duplicate NFT generation via repeated forging with the same parent
- M-216: NFTs mature too slowly under default settings.
- M-212: Pause and unpause functions are inaccessible
- M-211:  Forger Entities can forge more times than intended
- M-172: Users' ability to nuke will be DoSed for three days after putting NFTs up for sale and cancelling the sale
- M-165: There is no slippage check in the `nuke()` function.
- M-159: Incorrect `isApprovedForAll` check in the `NukeFund.nuke()` function.
- M-41: Excess ETH from `forgingFee` can get stuck in `EntityForging` under certain situations
- M-30: Each generation should have 1 "Golden God" NFT, but there could be 0

---
