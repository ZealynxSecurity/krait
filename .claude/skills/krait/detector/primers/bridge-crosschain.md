# Krait Detection Primer: Cross-Chain Bridge

> Distilled from 17 verified checks (Zealynx bridge-security checklist). Attack-framed for Krait detection.

## CRITICAL — Must Check Every Bridge Audit

### 1. Message Replay Attack
If cross-chain messages don't have unique nonces per-chain → attacker replays a valid message on another chain or re-executes on same chain.
**Check**: Does every message include `(sourceChain, nonce, sender)` tuple? Is nonce incremented atomically? Is there a `processedMessages[hash]` mapping?

### 2. Lock-Mint Supply Conservation Violation
If minted tokens on destination can exceed locked tokens on source → infinite mint. Attacker mints without locking, or mints more than locked.
**Check**: Is `totalMinted[destinationChain]` tracked? Does it equal `totalLocked[sourceChain]`? Can mint authority be called by anyone?

### 3. Insufficient Finality Check
If bridge processes message before source chain transaction is final → chain reorg reverts the lock but mint already happened on destination.
**Check**: How many confirmations are required? Is it appropriate for the source chain? (1 for Ethereum is dangerous, 12+ for Bitcoin)

### 4. Validator Set Compromise (Threshold Too Low)
If validator threshold is less than 2/3+ → attacker compromising minority of validators can forge messages.
**Check**: What's the multi-sig threshold? How many validators total? Can validators be added/removed without timelock?

### 5. Signature Malleability
If signature validation doesn't handle ECDSA malleability (s-value in upper half) → same message, different signature = bypass `processedMessages` check.
**Check**: Does signature verification use OpenZeppelin's ECDSA (handles malleability)? Or raw `ecrecover`?

## HIGH — Check If Relevant

### 6. LayerZero: Missing Minimum Destination Gas
If `adapterParams` doesn't enforce `minDstGas` → message arrives on destination but execution fails silently due to OOG. User loses funds with no refund.
**Check**: Is `minDstGas` set in `adapterParams`/`options`? Is it sufficient for the destination function's gas needs?

### 7. LayerZero: Untrusted Remote
If `trustedRemote[chainId]` is not set or set to wrong address → attacker deploys fake contract on source chain, sends messages that destination accepts.
**Check**: Is `trustedRemote` set for ALL supported chains? Can it be changed? By whom?

### 8. Destination Liquidity Assumption
If destination contract assumes it has WETH/tokens to complete the operation but liquidity pool is empty → user's tx reverts, funds stuck on source chain.
**Check**: Does destination check balance before attempting transfer? Is there a refund/retry path?

### 9. Stale Swap Parameters
Cross-chain messages have latency (minutes to hours). Swap params (`amountOutMin`, `deadline`) set on source may be stale on arrival.
**Check**: Is there slippage protection on destination? What happens if swap fails — is there recovery?

### 10. Bridge Token Access Control
Bridge token contracts (wrapped tokens, bridge tokens like `DcntEth`) often have `setRouter()` or `setMinter()` functions.
**Check**: Are `setRouter`, `setMinter`, `setBridge` access-controlled? If anyone can call them → total bridge compromise.

### 11. Circuit Breaker Missing
If no volume/velocity limits → attacker who finds any exploit can drain entire bridge in one tx.
**Check**: Is there a max transfer amount per tx? Per time period? Does unusual volume trigger a pause?

### 12. Refund Routing on Failure
When destination execution fails, where do refunds go? If to the adapter/router contract (not the user) → funds stuck forever.
**Check**: Trace the full refund path. Does the user get their funds back on source chain? Or are they stuck in a contract?

## STATISTICAL CONTEXT — Protocol-Type Enrichment

From analysis of 833 bridge findings across real audits:
- **#1 root cause**: Access control failures (unauthorized message processing, missing trusted remote verification) — 40%+ of bridge audits
- **#2 root cause**: Message replay (missing nonce, weak uniqueness, cross-chain replay) — 35%+
- **#3 root cause**: Supply invariant violations (minted > locked, burn-without-unlock) — 30%+
- **Gas griefing**: Relayer underpaying gas, message arrives but execution fails with no refund, destination OOG
- **Signature validation**: Malleability, missing expiry, aggregation bypass
- **Most missed**: Cross-chain state synchronization failures — source and destination diverge during partial failures

*(Source: forefy/.context, MIT)*

---
*Source: Zealynx bridge-security checklist (17 checks). Distilled to top 12 attack patterns.*
