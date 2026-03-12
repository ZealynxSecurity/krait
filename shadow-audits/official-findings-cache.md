# Official Findings Cache (for scoring)

## NextGen (4H + 10M = 14 total)
- H-01: Attacker can reenter to mint all the collection supply
- H-02: Attacker can drain all ETH from AuctionDemo when block.timestamp == auctionEndTime
- H-03: Adversary can block claimAuction() due to push-strategy to transfer assets to multiple bidders
- H-04: Multiple mints can brick any form of salesOption 3 mintings
- M-01: payArtist can result in double the intended payout
- M-02: RandomizerVRF and RandomizerRNG not produce hash value
- M-03: Vulnerability in burnToMint function allowing double use of NFT
- M-04: On Descending Sale Model, user minting on last block.timestamp mints at unexpected price
- M-05: Auction payout goes to AuctionDemo contract owner, not the token owner
- M-06: Artist signatures can be forged to impersonate artist
- M-07: Auction winner can prevent payments via safeTransferFrom callback
- M-08: If airdrop happens before mint the price could skyrocket
- M-09: getPrice salesOption 2 can round down to lower barrier, skipping last period
- M-10: Bidder Funds Can Become Unrecoverable Due to 1 second Overlap in participateToAuction() and claimAuction()

## Kelp DAO (3H + 2M = 5 total)
- H-01: Possible arbitrage from Chainlink price discrepancy
- H-02: Protocol mints less rsETH on deposit than intended
- H-03: Price of rsETH could be manipulated by first staker
- M-01: Update in strategy will cause wrong issuance of shares
- M-02: Lack of slippage control on LRTDepositPool.depositAsset

## Revolution (4H + 14M = 18 total)
- H-01: Incorrect amounts of ETH transferred to DAO treasury in buyToken(), causing value leak
- H-02: totalVotesSupply and quorumVotes incorrectly calculated due to inaccessible voting powers of auctioned NFT
- H-03: VerbsToken.tokenURI() vulnerable to JSON injection attacks
- H-04: Malicious delegatees can block delegators from redelegating and sending NFTs
- M-01: Bidder can use donations to get VerbsToken from ended auction
- M-02: Violation of ERC-721 Standard in VerbsToken:tokenURI
- M-03: Malicious user can manipulate topVotedPiece to DoS CultureIndex and AuctionHouse
- M-04: quorumVotes can be bypassed
- M-05: buyToken has no slippage checking
- M-06: ERC20TokenEmitter will not work after certain period of time
- M-07: positionMapping for last element in heap not updated when extracting max
- M-08: Already extracted tokenId may be extracted again
- M-09: Anyone can pause AuctionHouse in _createAuction
- M-10: buyToken mints more tokens to users than it should
- M-11: Art pieces' size not limited, attacker may block AuctionHouse
- M-12: Once EntropyRateBps set too high, leads to DoS
- M-13: May be possible to DoS AuctionHouse by specifying malicious creators
- M-14: encodedData argument of hashStruct not calculated for EIP712

## Decent (4H + 5M = 9 total)
- H-01: Anyone can update Router address in DcntEth to any address
- H-02: Missing checks on minimum gas through LayerZero, executions can fail on destination
- H-03: When DecentBridgeExecutor.execute fails, funds sent to random address
- H-04: Users lose cross-chain tx if destination router has insufficient WETH reserves
- M-01: Permanent loss of tokens if swap data gets outdated
- M-02: Users can use protocol freely without paying fees by calling bridgeWithPayload directly
- M-03: Missing access control on UTB:receiveFromBridge
- M-04: Potential loss of capital due to fixed fee calculations
- M-05: Refunded ETH stuck in DecentBridgeAdapter

## AI Arena (8H + 9M = 17 total)
- H-01: Locked fighter can be transferred; leads to game server issues and unstoppable fighters
- H-02: Non-transferable GameItems can be transferred with safeBatchTransferFrom
- H-03: Players can customize fighter NFT when calling redeemMintPass, redeem rare attributes
- H-04: Can reroll with different fighterType, bypassing maxRerollsAllowed
- H-05: Malicious user can stake amount causing zero curStakeAtRisk on loss but equal rewardPoints on win
- H-06: FighterFarm reroll won't work for nft id > 255 due to uint8 input
- H-07: Fighters cannot be minted after initial generation due to uninitialized numElements
- H-08: Player can mint more fighter NFTs by reentrancy on claimRewards()
- M-01: Almost all rarity rank combinations cannot be generated
- M-02: Minter/Staker/Spender roles can never be revoked
- M-03: Fighter from mintFromMergingPool can have arbitrary weight/element
- M-04: DoS in MergingPool::claimRewards and RankedBattle::claimNRN after many rounds
- M-05: Can mint NFT with desired attributes by reverting transaction
- M-06: NFTs can be transferred even if StakeAtRisk remains
- M-07: Erroneous probability calculation in physical attributes
- M-08: Burner role can not be revoked
- M-09: Constraints of dailyAllowance can be bypassed via alias accounts & safeTransferFrom
