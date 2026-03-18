# Krait Detection Primer: GameFi / NFT / Play-to-Earn

> Distilled from 55 verified checks (Zealynx gamefi-security checklist). Attack-framed for Krait detection.

## CRITICAL — Must Check Every GameFi/NFT Audit

### 1. Mint Supply Cap Bypass
If ANY mint path (admin mint, batch mint, special mint, airdrop) doesn't check `totalSupply + amount <= maxSupply` → attacker mints unlimited NFTs, crashes economy.
**Check**: Find EVERY function that calls `_mint` or `_safeMint`. Does each one enforce the supply cap?

### 2. Transfer Hook Missing Game State Update
When NFT transfers between users, if game state (staking, rewards, scores, cooldowns, equipment slots) doesn't update → new owner gets clean slate while old owner keeps benefits, or old owner's state persists as ghost data.
**Check**: Read `_beforeTokenTransfer` / `_afterTokenTransfer` / `_update`. Does it reset/transfer ALL associated game state?

### 3. Cross-Contract State Desync
If NFT ownership is in Contract A but game logic is in Contract B, and they can go out of sync → player uses item they sold, or new owner can't use item they bought.
**Check**: When NFT transfers in the NFT contract, does the game contract get notified? Is there a callback or sync mechanism?

### 4. Reward Loop Exploit
If `claimReward()` can be called multiple times for the same action, or reentered during reward distribution → infinite reward extraction.
**Check**: Is there a `claimed[user][actionId]` mapping? Is `nonReentrant` on claim functions? Does claim update state BEFORE transfer?

### 5. On-Chain Randomness Manipulation
If attributes/loot use `block.timestamp`, `blockhash`, or `prevrandao` → player can revert and retry until they get desired result.
**Check**: Where does randomness come from? Is it Chainlink VRF (safe) or on-chain (manipulable)?

### 6. Atomic Swap Failure
If marketplace trade has partial execution (NFT transferred but payment fails, or payment succeeds but NFT fails) → player loses asset without payment.
**Check**: Is the trade atomic (all-or-nothing)? Can the NFT transfer succeed while the payment reverts?

## HIGH — Check If Relevant

### 7. User-Controlled NFT Attributes
If `mint(customAttributes)` lets user choose rarity/stats → they'll always pick the rarest/best.
**Check**: Do any mint/reroll/craft functions accept user-supplied attribute parameters?

### 8. Reward Farming via Flash Loan
If staking rewards are claimable instantly after staking → flash loan: borrow → stake → claim → unstake → repay.
**Check**: Is there a minimum staking duration? Time-weighted distribution? Snapshot-based rewards?

### 9. Marketplace Front-Running
If orders are visible in mempool before execution → MEV bot buys rare item before legitimate buyer.
**Check**: Is there commit-reveal for orders? Batch auctions? Or plain visible-mempool order execution?

### 10. Asset Locking Bypass via External Marketplace
If NFT is "locked" in game (staked, in-battle, upgrading) but `transferFrom` still works → player sells locked item on OpenSea.
**Check**: Does `_beforeTokenTransfer` check lock status? Does `approve` check lock status?

### 11. Inflation via Uncapped Emissions
If token reward rate has no decay or hard cap → infinite token generation → economy collapse.
**Check**: Is there a `maxSupply` for the reward token? Does emission rate decrease over time? What's total possible emission?

### 12. Sybil Reward Multiplication
If creating new accounts multiplies reward access (no minimum stake, no identity verification) → bots create 1000 accounts.
**Check**: What prevents the same person from creating multiple accounts and farming rewards?

### 13. Cooldown Bypass via Reentrancy
If cooldown is checked BEFORE an external call that allows re-entry → attacker bypasses cooldown during callback.
**Check**: Is cooldown check + action atomic? Can reentrancy during a callback skip the cooldown?

### 14. Metadata Injection
If `tokenURI` concatenates user-controlled strings (item names, descriptions) without escaping → JSON injection → malicious metadata, broken marketplaces.
**Check**: Does `tokenURI` include any user-input data? Is it properly escaped for JSON?

### 15. Compound Interest Overflow
If staking reward uses compound math without bounds → at extreme values (long duration, high rate), calculation overflows or generates astronomical rewards.
**Check**: What happens to reward calculation at `maxStakeDuration`? At `maxRate`? Does it overflow uint256?

### 16. Cross-Chain Asset Duplication
If game has cross-chain asset transfers, can an asset exist on BOTH chains simultaneously? Insufficient finality check = double-spend.
**Check**: Is the source-chain asset locked/burned before minting on destination? What's the finality check?

### 17. Emergency Pause Traps User Assets
If pause blocks ALL functions including withdrawals → user assets trapped during emergency.
**Check**: Can users withdraw/rescue their NFTs/tokens when contract is paused? Is there an emergency exit path?

---
*Source: Zealynx gamefi-security checklist (55 checks). Distilled to top 17 attack patterns.*
