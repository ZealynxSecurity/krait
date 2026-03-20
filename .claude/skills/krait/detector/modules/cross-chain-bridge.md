# Cross-Chain Bridge Security Module

> **Trigger**: Protocol bridges assets/messages across chains, uses LayerZero, CCIP, Wormhole, Axelar, Hyperlane, or custom relayers
> **Inject into**: Lens C (External/Cross-contract)
> **Priority**: HIGH — bridge exploits cause the largest fund losses in DeFi

## 1. Message Integrity

- Can a message be replayed on the same chain? (nonce/hash uniqueness)
- Can a message be replayed on a different chain? (chainId in message)
- Is the message sender verified on the destination? (trusted source check)
- Can message content be modified by the relayer?

## 2. Destination Gas

| Bridge | Min Gas Enforced? | Configured Value | Sufficient? |
|--------|-------------------|-----------------|-------------|
| LayerZero | adapterParams minDstGas? | | |
| CCIP | gasLimit in message? | | |
| Custom | {mechanism} | | |

If insufficient gas → message arrives but execution fails → tokens stuck.

## 3. Destination Liquidity

- Does destination contract assume tokens exist for fulfillment?
- If destination needs WETH/USDC to complete but reserves are empty → user's tx fails
- Is there a refund mechanism for failed destination execution?

## 4. Parameter Staleness

Cross-chain has latency (minutes to hours).
- Swap params set on source may be stale on destination
- Is there slippage protection at the destination?
- Is there an expiry/deadline?
- What's the recovery path if params are too stale?

## 5. Refund Routing

When destination execution fails:
- Refund goes to adapter? → stuck forever
- Refund goes to msg.sender on destination? → wrong person
- Refund goes back to user on source? → correct but complex
- No refund? → permanent loss

## 6. Bridge Token Access Control

Bridge token contracts (wrapped tokens, DcntEth, etc.):
- Setter functions for router/bridge addresses — access controlled?
- Can a compromised bridge address mint unlimited tokens?
- Is there a supply cap on the bridge token?
