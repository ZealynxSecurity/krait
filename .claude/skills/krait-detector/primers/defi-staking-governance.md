# Krait Detection Primer: Staking / Governance / Voting

> Distilled from GameFi tokenomics/access-control checks + liquidity pool rewards checks + Krait's 35-contest shadow audit miss analysis. Attack-framed for detection.

## CRITICAL — Must Check Every Staking/Governance Audit

### 1. Flash Loan Vote/Stake Manipulation
If governance voting or staking rewards use current balance (not time-weighted snapshot) → flash loan: borrow → stake/vote → claim/pass proposal → unstake → repay.
**Check**: Does voting use snapshot-based power? Does staking have minimum lock period? Can someone stake and claim in same block?

### 2. Reward Harvest Before State Change
If `setLockDuration()`, `delegate()`, `increaseStake()`, or ANY function that changes a user's position doesn't call `_updateReward(user)` FIRST → user loses accrued rewards or games the system.
**Check**: For EVERY function that modifies stake/balance/lock/delegation: does it checkpoint rewards BEFORE the change?

### 3. Epoch Boundary Exploitation
If rewards are per-epoch but no minimum participation time → user stakes at last second of epoch, earns full epoch reward, unstakes at first second of next.
**Check**: Must a user be staked for a FULL epoch to earn rewards? What happens at exactly the epoch boundary? Can user act after lock expires but before checkpoint?

### 4. Phantom Voting Power
If governance NFTs are burned/auctioned/transferred but their voting power stays in `totalVotesSupply` → quorum becomes unreachable, governance is permanently bricked.
**Check**: When tokens are burned/transferred, is `totalVotesSupply` decremented? Are burned tokens excluded from quorum calculations?

### 5. Missing Unstake/Undelegate/Unlock
If `stake()` exists but `unstake()` doesn't, or `delegate()` exists but `undelegate()` doesn't, or has different constraints → user's funds permanently locked.
**Check**: For every lock/stake/delegate function, does the inverse exist? Does it have symmetric access/timing constraints?

## HIGH — Check If Relevant

### 6. Delegation Griefing
If delegatee accumulates many checkpoints → delegator trying to redelegate runs out of gas iterating checkpoints. Permanent delegation lock.
**Check**: Is there a max checkpoints limit? Can delegation change cause unbounded gas consumption?

### 7. Reward Double-Claim via Transfer
If staker transfers position/NFT but associated reward debt doesn't transfer → both old and new owner can claim rewards, or new owner claims without having earned.
**Check**: When staking position transfers, does `rewardDebt[user]` transfer with it? Is `earned()` zero for new owner?

### 8. Compound Interest Overflow
If staking yield uses compound formula without bounds → at high rates or long durations, calculation overflows or generates astronomical rewards.
**Check**: What happens at `maxDuration` with `maxRate`? Does the math overflow? Is there a cap on total rewards?

### 9. Vesting Schedule Bypass
If team/investor tokens are vested but vesting contract has a withdrawal path that bypasses the schedule → early dump.
**Check**: Can vested tokens be transferred before cliff? Is `emergencyWithdraw` restricted? Can admin change vesting params?

### 10. Supply Oracle Manipulation
If circulating supply affects staking rewards or governance power → flash loan can temporarily inflate supply to extract disproportionate rewards.
**Check**: Does any calculation use `totalSupply()` as denominator? Can `totalSupply` be temporarily inflated?

### 11. Activity Validation for Rewards
If rewards require specific on-chain activity but validation is weak → bots generate fake activity to farm rewards.
**Check**: Is activity verified on-chain? Can reward-eligible events be triggered by anyone cheaply?

### 12. Missing Timelock on Parameter Changes
If admin can instantly change reward rate, lock period, or slashing conditions → front-run the change for profit.
**Check**: Every admin setter for reward/staking params. Is there a timelock? Minimum delay? Multi-sig?

### 13. Counter Consistency Across Paths
If `pendingRewards`, `totalStaked`, or `rewardPerToken` are updated in some paths but not others (deposit vs transfer vs claim vs admin-mint) → counters drift from reality.
**Check**: List every function that changes user stake. Does each one update ALL related counters? Compare paths side by side.

### 14. Zero-Supply Quorum
If quorum is calculated as `% of totalSupply` and `totalSupply` can reach 0 → quorum = 0 → any proposal passes with 0 votes.
**Check**: What happens to governance quorum when `totalSupply == 0`? Is there a minimum quorum floor?

### 15. Cooldown/Lock Bypass via Reentrancy
If lock period is checked BEFORE an external call that allows re-entry → attacker bypasses lock during callback.
**Check**: Is lock check + state update atomic? Can reentrancy during a callback skip the lock enforcement?

## FROM MISS ANALYSIS — Patterns Krait Has Missed in Real Contests

### 16. Quorum Manipulation via Token Supply Inflation
If quorum is snapshot at piece/proposal creation time but token supply grows after → legitimate proposals can have unreachable quorum. Attacker creates proposal when supply is low, then supply grows, quorum can't be met.
**Check**: Is quorum calculated against current supply or snapshot supply? Can supply grow independently of voting power delegation?

### 17. JSON/Metadata Injection via tokenURI
If `createPiece()` or similar doesn't sanitize `metadata.image`/`metadata.animationUrl` → user-controlled data flows into base64-encoded tokenURI → JSON injection → XSS in frontends displaying the NFT.
**Check**: Does tokenURI include any user-controlled string without escaping? Trace data from input to output.

### 18. Gas Manipulation to Force try/catch Failure
If a core function uses `try/catch` with a `_pause()` in the catch block → attacker sends transaction with just enough gas for the outer call but not enough for the inner call → catch executes → protocol paused.
**Check**: Does any function use try/catch where the catch block has a destructive action (pause, lock, revert state)?

### 19. Parameter Change Breaks In-Flight Operations
If admin changes `reservePrice`, `cooldownDuration`, `interestRate`, or `entropyRateBps` while operations are in flight → existing auctions/cooldowns/loans may brick or produce incorrect results. Ethena M-03: setting cooldownDuration=0 didn't release existing cooldowns.
**Check**: For EVERY admin setter, ask: what happens to operations that started under the old value?

### 20. Permissionless Dust Calls Reset Timers
If `distribute(amount)` is permissionless and resets a distribution timer → attacker calls `distribute(1 wei)` repeatedly to extend distribution period indefinitely.
**Check**: Can any permissionless function be called with dust (0, 1 wei) to manipulate timing state?

### 21. Cross-Contract Call Chain Modifier Propagation
If `unstake()` calls `getRewards()` which calls `mint()` which has `whenNotPaused` → pausing the minter blocks unstaking even though unstaking should always be available.
**Check**: For every user-facing function, trace the FULL call chain. Does any downstream call have a modifier that could block the upstream user operation?

### 22. Base Contract Override Side Effects
If a contract overrides a base function (e.g., `delegates()` returning `self` when `_delegatee == address(0)`) → the override changes behavior that other base functions depend on → `_moveDelegateVotes` underflows.
**Check**: When a contract overrides a virtual function, what OTHER functions in the base class call it? Does the override break their assumptions?

---
*Source: Zealynx gamefi-security (tokenomics, access-control sections) + liquidity-pool-security (rewards section) + Krait shadow audit miss analysis (40 contests). Updated with 7 patterns from Revolution + Ethena + Credit Guild miss analysis (v6.4).*
