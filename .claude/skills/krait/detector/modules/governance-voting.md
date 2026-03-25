# Governance Voting Integrity Module

> **Trigger**: Protocol has voting, proposals, delegation, quorum, or governance tokens
> **Inject into**: Lens A (Access/State/Governance)
> **Priority**: MEDIUM-HIGH — governance attacks enable protocol takeover

## 1. Voting Power Source

| Source | Mechanism | Snapshot? | Flash-Loan Resistant? |
|--------|-----------|-----------|----------------------|
| Token balance | `balanceOf(voter)` | YES/NO | NO if no snapshot |
| Delegation | `getVotes(delegate)` | YES/NO | Depends on checkpoint |
| NFT-based | `ownerOf(tokenId)` | YES/NO | N/A |
| Staking | `stakedBalance(voter)` | YES/NO | Depends |

**If no snapshot**: Flash-loan voting is possible — borrow tokens, vote, return in same tx.

## 2. Phantom Voting Power

When governance NFTs/tokens are burned, transferred, or auctioned:
- Is voting power removed from `totalVotesSupply` / quorum denominator?
- If inaccessible tokens retain voting power → quorum becomes unreachable → governance DoS

## 3. Delegation Griefing

- Can a delegatee prevent the delegator from re-delegating?
- If delegatee accumulates many checkpoints → gas exhaustion on redelegate
- Can delegation be used to exceed individual voting caps?

## 4. Quorum Edge Cases

- At `totalSupply = 0`: quorum = 0 → any proposal passes with 0 votes
- At very low participation: is there a minimum absolute quorum (not just %)?
- Can quorum be changed while proposals are active?

## 5. Proposal Lifecycle

- Can proposals be created, voted on, and executed in the same block?
- Is there a time delay between vote end and execution?
- Can a proposal be canceled after passing but before execution?
- Front-running: can someone submit a counter-proposal that executes first?

## 6. Advanced Governance Vectors
<!-- Vectors from pashov/skills (MIT) -->

- **Timelock collision**: If timelock uses `keccak256(target, value, data)` as key, identical proposals can collide — second proposal silently overwrites first. Check: is proposal ID unique beyond just the call data?
- **Vote buying via flash-loaned delegation**: Attacker flash-loans governance tokens → delegates to self → votes → undelegates → returns tokens. All in one tx if no snapshot. Check: is voting power snapshot-based or live?
- **Quorum racing**: If quorum is from live supply (not snapshot), attacker can mint/burn to manipulate the threshold mid-vote. Check: quorum calculated from snapshot or `totalSupply()`?
- **Cancellation front-running**: Attacker sees a proposal they oppose about to pass → front-runs with a cancel tx (if cancel requires only proposer threshold and they meet it). Check: who can cancel? When?
- **Voting dust inflation**: Creating many tiny governance positions to increase checkpoint gas, griefing redelegate operations. Check: minimum governance token position size?
- **Self-delegation doubling**: If delegating to self counts as both holder AND delegatee voting power → 2x votes. Check: does `_delegate(msg.sender)` double-count?
- **Same-block deposit-withdraw-vote**: Deposit to get tokens, vote (snapshot not yet updated), withdraw. Check: does deposit update voting power in same block?
- **Proposal executable before voting ends**: If `execute()` checks `state == Succeeded` but state transitions are based on `block.number >= endBlock` and execution is in same block as end → race condition. Check: is there a gap between vote end and execution start?
