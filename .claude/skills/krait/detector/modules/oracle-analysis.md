# Oracle Analysis Module

> **Trigger**: Protocol uses Chainlink, TWAP, Pyth, Band, or any external price feed
> **Inject into**: Lens B (Value/Economic), Lens C (External/Cross-contract)
> **Priority**: HIGH — oracle issues are the #1 source of HIGH/CRITICAL findings in DeFi

## 1. Oracle Inventory

For EVERY external data source the protocol reads:

| Oracle | Type | Source | Functions Called | Consumers | Heartbeat |
|--------|------|--------|-----------------|-----------|-----------|
| {name} | Chainlink/TWAP/Spot/Pyth | {address/contract} | {latestRoundData/observe} | {list all consumer functions} | {documented or UNKNOWN} |

**Key question**: What decision does the protocol make based on this data? (pricing, liquidation, reward rate, rebase trigger?)

## 2. Staleness Analysis

For EACH oracle:

| Check | Code Location | Status |
|-------|--------------|--------|
| `updatedAt` checked? | | YES/NO |
| Max staleness enforced? | | YES/NO |
| Staleness threshold appropriate? | | {seconds} |
| `answeredInRound >= roundId`? | | YES/NO |
| `price > 0` validated? | | YES/NO |
| `updatedAt != 0`? | | YES/NO |
| L2 sequencer uptime feed? (L2 only) | | YES/NO/N/A |

**If NO staleness check**: Trace impact — stale price used for liquidations? minting? swaps?

## 3. Decimal Normalization

For each oracle → consumer path:
- Oracle returns N decimals. Consumer expects M decimals. Is conversion correct?
- Is `10**decimals()` queried or hardcoded? (Feeds can change decimals on upgrade)
- Multi-hop: If price A is USD/ETH (8 dec) and price B is ETH/TOKEN (18 dec), is the combined calculation correct?

## 4. Manipulation Resistance

- **Spot price**: Can be manipulated via flash loan in same transaction. Is the protocol using spot or time-weighted?
- **TWAP window**: How long? Short TWAP (< 30 min) is still manipulable with sustained capital.
- **Multi-block MEV**: Even TWAP can be manipulated across multiple blocks. What's the cost?

## 5. Failure Modes (WHERE HIGH/CRIT FINDINGS HIDE)

- What if oracle returns 0? Does the protocol revert or use 0 as a valid price?
- What if oracle reverts? Does the protocol have a fallback? Is the fallback itself safe?
- What if oracle returns a negative price? (`int256` from Chainlink — checked?)
- **Circuit breaker**: Does the protocol detect extreme deviations? What happens at 50% price drop in 1 block?

## 6. Solodit Corroboration

If MCP available, call `mcp__krait-solodit__search_similar_findings` with the specific oracle pattern found (e.g., "chainlink staleness lending liquidation"). Cross-reference with the check.
