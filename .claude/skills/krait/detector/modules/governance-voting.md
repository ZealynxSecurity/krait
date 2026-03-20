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
