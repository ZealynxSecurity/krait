# Krait Core Heuristics — 43 Trigger-Based Detection Checks

> Loaded by the Detector during Pass 1 (Step 4). Companion to `heuristics-extended.md`
> (58 further vectors from open-source community sources — see `../ATTRIBUTION.md`).

Each heuristic was extracted from a real missed finding in a blind shadow audit, or from
a real exploit. They are **triggers**, not a checklist to recite: match the trigger
against the code in front of you, and only then apply the check.

Heuristics with a "missed in N shadow audits" note earned their place by costing Krait a
real finding. Treat those as mandatory whenever their trigger appears.

---


**Business Logic (BL-01 to BL-12):**
- BL-01: Multi-step process → Can steps execute out of order?
- BL-02: State machine → Can transitions be skipped/reversed?
- BL-03: Dual accounting (internal + balanceOf) → Can they diverge? Donation attack?
- BL-04: Reward distribution → Stake-before-distribution gaming? Double-claim?
- BL-05: Auction/timelock → Griefing? Expired execution? Timestamp manipulation?
- BL-06: Whitelist/blacklist → Transfer through intermediary bypass?
- BL-07: Liquidation → Over-extraction? Self-liquidation profit? Oracle-triggered?
- BL-08: Withdrawal queue → Front-run? Exchange rate locked at request or fulfillment?
- BL-09: Fee-on-transfer tokens → amount sent != amount received? Rebasing stale cache?
- BL-10: ERC4626/share vault → First depositor inflation? (Only if LACKS virtual offset)
- BL-11: Governance voting → Flash loan votes? Snapshot timing? Transfer-and-revote?
- BL-12: Cross-chain/bridge → Replay? Source chain verification? Failed message recovery?

**Arbitrary External Calls (AEC-01 to AEC-03):**
- AEC-01: User-controlled call target → drain approved tokens? selfdestruct?
- AEC-02: Callback after state change → re-enter during callback? grief via revert?
- AEC-03: Multicall/batch → msg.value reuse? bypass individual restrictions?

**Read-Only Reentrancy (ROR-01):**
- ROR-01: View function during callback window → stale/manipulated value for other protocols?

**Proxy/Upgrades (PRX-01, PRX-02):**
- PRX-01: Initializer → _disableInitializers in constructor? Direct implementation init?
- PRX-02: Delegatecall → Storage layout match? Collision? Gap array?

**Share Inflation (SI-01):**
- SI-01: ERC4626 → Virtual offset present? First depositor donation attack?

**Fee Logic (FDC-01, FDC-02):**
- FDC-01: Sequential fees → Each on REMAINING amount? Total bounded < 100%?
- FDC-02: Fee precision → Consistent denominator? Division before multiplication? Rounding direction?

**Transient Storage (TS-01):**
- TS-01: TSTORE/TLOAD → Cleared after tx? Multicall stale values? Replaces reentrancy guard?

**Missing Return Check (MRV-01):**
- MRV-01: ERC20 transfer/approve → safeTransfer used? USDT no-return-bool?

**Oracle (ORC-01, ORC-02):**
- ORC-01: AMM spot price → Flash loan manipulable? Use TWAP instead?
- ORC-02: Chainlink → Staleness check? Zero price? roundId? L2 sequencer?

**Signatures (SIG-01, SIG-02):**
- SIG-01: EIP-712/permit → Replay protection? chainId? Cross-contract? ecrecover(0)?
- SIG-02: Permit2 → Front-run? Nonce invalidation? Griefing?

**ETH Handling (ETH-01, ETH-02):**
- ETH-01: Payable → msg.value checked? Excess locked? Refund on partial fail? selfdestruct force-send?
- ETH-02: ETH to external → Recipient without receive()? Revert bricks function? Use WETH?

**Access Control (AC-01, AC-02):**
- AC-01: Multiple roles → Escalation? Admin can grant critical roles? Compromised non-critical causes fund loss?
- AC-02: Ownership transfer → Two-step? Wrong address permanent loss?

**Token Hooks (TOK-01 to TOK-03):**
- TOK-01: ERC721/1155 safeTransfer → onReceived callback reentrancy?
- TOK-02: Non-standard decimals → Assumes 18? USDC(6)/WBTC(8) precision loss?
- TOK-03: Wrapper token decimals ≠ underlying decimals → In Compound forks, cToken/vToken has 8 decimals but underlying has 18. Any code using `vToken.decimals()` to scale the UNDERLYING amount is wrong by 10^10. Check: is `token.decimals()` being used for the token itself, or incorrectly for its underlying?

**Flash Loan (FL-01):**
- FL-01: balanceOf-based accounting → Flash loan deposit manipulation?

**CREATE2/CREATE (C2-01, C2-02):**
- C2-01: CREATE2 deterministic deployment → Front-run address? Destruction + redeploy state reset?
- C2-02: CREATE (nonce-based) deployment → Reorg attack? If factory uses `new Contract()` (not CREATE2), address depends on nonce. During chain reorg, attacker can front-run deployment and steal the address. Higher risk on L2s/Polygon. Check: does the factory use CREATE or CREATE2?

**Loop Control Flow (LOOP-01):**
- LOOP-01: Manual loop increment with `continue` → Does `continue` skip the increment? In `for(uint i=0; i < len;) { ... unchecked { i++; } }` patterns, `continue` bypasses the increment → infinite loop. Check every `continue` and `break` in loops with manual increments.

**Reentrancy (RE-01):**
- RE-01: Cross-function → Function A has nonReentrant, function B doesn't, both share state?

**Cross-Chain / Bridge (BRIDGE-01 to BRIDGE-04):**
- BRIDGE-01: LayerZero integration → Minimum gas enforced for destination execution? If not, cross-chain message arrives but execution fails silently. Check adapterParams/options for minDstGas.
- BRIDGE-02: Destination liquidity → Does the destination contract assume sufficient token balance (WETH, bridged tokens) exists? If destination router has insufficient WETH, user's cross-chain TX fails with no refund path.
- BRIDGE-03: Stale swap parameters → Cross-chain messages have latency. Swap params (amountOutMin, deadline) may be stale on arrival. Is there a recovery path when destination swap fails?
- BRIDGE-04: Refund routing → When bridge/swap fails, where does the refund go? To the adapter contract (stuck forever) or back to user? Trace the full refund flow.

**NFT/Gaming Attributes (NFT-01 to NFT-03):**
- NFT-01: Attribute manipulation via user-controlled params → Can users choose/influence their NFT attributes during mint/redeem? If params like weight/element come from user input → they'll pick the rarest.
- NFT-02: Randomness manipulation via revert → If attributes are assigned from on-chain randomness, can users revert and retry until they get desired attributes? Only safe with commit-reveal or VRF.
- NFT-03: Type/category mismatch in limits → If per-type limits exist (e.g., maxRerolls per fighterType), can users pass a DIFFERENT type than the actual to bypass the check?

**Access Control Extended (AC-03, AC-04):**
- AC-03: Periphery contract access control → Main contracts may have proper access control, but check EVERY helper/adapter/bridge token contract. DcntEth.setRouter() with no access control = anyone takes over.
- AC-04: Role irrevocability → If roles can be GRANTED (addMinter, addStaker) but NEVER REVOKED (no removeMinter), compromised or malicious role holders persist forever. Check every role: is there a symmetric revoke function?

**Injection (INJ-01):**
- INJ-01: On-chain metadata injection → Does tokenURI, contractURI, or any on-chain string concatenation include user-controlled data without escaping? JSON injection via art piece names/descriptions → malicious metadata, broken marketplaces.

**Governance (GOV-01, GOV-02):**
- GOV-01: Phantom voting power → When governance tokens are burned/auctioned/locked, is the voting power properly removed from quorum denominators? Inaccessible tokens inflating totalVotesSupply → quorum unreachable.
- GOV-02: Delegation griefing → Can a malicious delegatee prevent the delegator from redelegating? If delegatee's checkpoint manipulation causes gas exhaustion on redelegate → permanent delegation lock.

**Precision (PR-01 to PR-03):**
- PR-01: Small amount division → Rounds to zero? Repeated small tx profit? **Can attacker FORCE rounding to zero via flash loan (inflate denominator)?** If division uses totalSupply or reserve as denominator, and attacker can inflate it → zero-amount exploit.
- PR-02: Price/rate as integer → Rounding direction safe? One-sided manipulation?
- PR-03: Dual conversion (assets↔shares) → Round OPPOSITE directions? mint(1 wei) paying 0?

**External Protocol Integration (EXT-01 to EXT-03):**
- EXT-01: Permissionless external calls → Can anyone call getReward/claim/harvest on behalf of the contract? If yes → front-running breaks assumed state.
- EXT-02: External shutdown/migration → What if Convex pool shuts down? What if operator changes? What if Aave market is deprecated? Does the contract have a fallback?
- EXT-03: Silent external failures → Does the external call silently return without effect (instead of reverting)? If contract assumes effect happened → wrong state.

**Batch/Multi-Call Interaction (BATCH-01):**
- BATCH-01: Cross-interaction balance accounting → In batch/multicall systems with intra-transaction balance deltas, can a user reference balances from earlier interactions that haven't been finalized? Can wrapped token balances be spent before they exist? Trace the delta accounting across the full batch — this is NOT visible from single-function analysis.

**Economic Design (ECON-01, ECON-02):**
- ECON-01: Circular/endogenous collateral valuation → Is a token's value derived from TVL that includes the token itself? (e.g., kerosine valued by TVL but counted as collateral in TVL.) If yes → reflexive death spiral on downturn.
- ECON-02: Liquidation profitability → Is it ALWAYS profitable to liquidate? Check: does liquidator receive ALL collateral types? Is there a minimum position size? Can positions become so large that no one has enough debt token to liquidate? If liquidation is ever unprofitable → bad debt accumulates.

**Missing Functionality (MISSING-01, MISSING-02):**
- MISSING-01: Missing unsetters/clearers → For every admin setter function (addChain, setOracle, addAsset), does a corresponding REMOVER exist? If config can only be added, never removed → permanent misconfiguration risk.
- MISSING-02: Restriction coverage gaps → If a restriction system exists (blocklist, pause, role restrictions), does it cover ALL exit paths? Check every function that moves value out — if even one path bypasses the restriction, it's useless. (e.g., blocklist blocks transfer() but not unstake() → restricted users exit via unstake.)

**DeFi Integration Specific (CURVE-01, UNI-01, CHAINLINK-01):**
- CURVE-01: Curve pool integration → Does the adapter correctly handle: (a) killed/paused pools, (b) native coin vs WETH distinction, (c) ETH ocean ID vs WETH ocean ID, (d) tricrypto vs 2pool differences in indexing? Check every adapter's token index mapping against the actual pool.
- UNI-01: UniV3 tick math → For negative tick deltas, does the price calculation round UP? `tickCumulativesDelta / period` must use different rounding for negative values. Also check: slippage protection on all NonfungiblePositionManager calls, deadline != block.timestamp, and sqrtRatioAtTick for boundary ticks.
- CHAINLINK-01: Chainlink feed assumptions → Does the code check: (a) staleness (updatedAt + heartbeat < now), (b) zero/negative price, (c) roundId completeness, (d) L2 sequencer uptime? Also: does it use BTC feed for WBTC (depeg risk)?

**Callback Exploitation (CALLBACK-01):**
- CALLBACK-01: ERC721/1155 callback as attack vector → onERC721Received and onERC1155Received give the RECIPIENT execution control during safeTransfer. Can the recipient: (a) re-enter to manipulate collateral configs, (b) prevent liquidation by reverting in the callback, (c) exploit stale state during the callback window? This is a recurring HIGH in audits.

**Hook Conflicts (HOOK-01):**
- HOOK-01: Transfer hook blocks admin actions → If _beforeTokenTransfer blocks transfers from/to restricted addresses, can admin still burn tokens FROM restricted addresses? The burn function is internally a transfer(from, address(0)), so the hook may block the admin burn that exists specifically to handle restricted addresses.

**Zero-Value Operations (ZERO-OP-01):**
- ZERO-OP-01: Zero-value operations as griefing → Can a zero-value deposit, transfer, or approval be used to grief? Common pattern: deposit(0) updates lastDepositBlock, preventing same-block withdrawals. Attacker front-runs withdrawal with deposit(0) to block it permanently.

**Hash Collision (PACKED-01):**
- PACKED-01: abi.encodePacked collision → If abi.encodePacked is used for hash keys with multiple dynamic-length or address+uint parameters, different inputs can produce the same hash. Especially dangerous for bridge txnHash (different senders + amounts can collide if nonce is global not per-sender).

**Permit/Approval (PERMIT-01):**
- PERMIT-01: ERC20 permit token validation → When a contract accepts permit signatures, does it verify the token address matches the expected asset? A permit for the wrong token may still produce a valid ecrecover result, letting an attacker use a permit from a different token.

**Modifier Sibling Diff (MODIFIER-01) — catches 20% of missed findings:**
- For each contract, extract ALL modifiers used by state-changing functions. List them: `| Function | Modifiers |`. Flag any function MISSING a modifier that its siblings have. Example: if `bond()`, `unbond()`, `transferBond()` all have `autoCheckpoint` but `withdrawFees()` doesn't → candidate. Mechanical check — don't rely on judgment.

**Library Precision Mismatch (LIB-01):**
- Two math libraries with similar names but different precision? (MathUtils 1e6 vs PreciseMathUtils 1e27). Wrong library at any call site = silent precision loss or underflow.

**Cross-Chain Decimal (CHAIN-01):**
- When values cross chains, is token decimal normalized? Same token can have different decimals on different chains (USDC: 6 on ETH, 18 on BSC).

**External Skim/Sweep Destination (EXT-SKIM-01):**
- When calling external `skim()`, `sweep()`, `rescue()`, `claimRewards()`: where do tokens ACTUALLY go? To caller or external treasury? Read the external code.

**Hash Field Completeness (HASH-01):**
- If a struct is hashed for verification, does hash include ALL struct fields? Compare field-by-field. Missing field = anyone can substitute arbitrary values.

**ID Mutability (ID-01):**
- Can a loan/position/order ID change after creation (merge, refinance)? Do ALL consumers handle ID changes? Stale ID = broken accounting.

**TVL Staked Balance (TVL-01):**
- Does TVL calculation account for tokens staked in external gauges/farms, not just `balanceOf(this)`? Missing staked tokens = understated TVL = wrong share prices.

**Zero-Weight Actor (ZERO-WEIGHT-01):**
- Can an actor with 0 weight/stake still trigger state changes affecting other users? Slashed validator voting, 0-balance user distributing, etc.

**Wrong Constant / Magic Number (CONST-01) — missed in 2 shadow audits:**
- For EVERY named constant (WAD, RAY, ONE_HUNDRED_WAD, BPS, PRECISION, etc.), verify: (1) its value matches its name — `ONE_HUNDRED_WAD` should be `100 * 1e18` not `1e20` (these ARE different if WAD != 1e18 in the codebase), (2) it's used in the correct context — a percentage constant used where an absolute constant is needed, or vice versa, (3) compare every usage site — if the same formula uses WAD in one function and ONE_HUNDRED_WAD in another, one is wrong. This is mechanical: `grep` for all constant definitions, verify values, trace every usage.

**Gauge/Voting Removal Safety (GAUGE-01) — missed in 1 shadow audit:**
- When a gauge, market, pool, or entity can be REMOVED or DEACTIVATED: can users who interacted with it before removal still unwind their positions? Check: (1) Can users withdraw votes/stake/liquidity from removed entities? (2) Does the removal function properly update all user-facing state (voting power, rewards, balances)? (3) Is there a contradiction between "allow cleanup on removed entity" guards and "entity must exist" guards that prevents unwinding? If users' voting power, staked tokens, or rewards get permanently locked when an entity is removed → HIGH.

**Cross-Chain Replay / Domain Separation (REPLAY-01):**
- For multi-chain deployments: (1) Is chainId included in ALL signature domains? (2) Can a UserOperation/signature executed on chain A be replayed on chain B? (3) Are nonces chain-specific or global? (4) Does account creation use CREATE2 with chain-dependent salt? If cross-chain replay is possible with user funds at risk → HIGH.

