# Krait Security Check Index

Total: 845 checks across 39 verticals

## Account Abstraction (account-abstraction) — 10 checks

### CRITICAL (5)
- **AA-01**: Is the UserOperation signature validation complete and non-bypassable?
- **AA-02**: Is the Paymaster properly validating which operations it sponsors?
- **AA-04**: Is the account initialization protected against front-running?
- **AA-06**: Is the EntryPoint address verified against the canonical deployment?
- **AA-10**: Is the account upgrade mechanism properly guarded?

### HIGH (4)
- **AA-03**: Are storage access patterns compliant with ERC-4337 restrictions?
- **AA-05**: Are social recovery guardians properly configured and secured?
- **AA-07**: Are batch operations properly validated individually?
- **AA-09**: Are session keys properly scoped with time and value limits?

### MEDIUM (1)
- **AA-08**: Is the gas estimation accurate for all execution paths?

## Airdrop (airdrop) — 8 checks

### CRITICAL (2)
- **AD-01**: Is the Merkle tree construction correct and the root verified?
- **AD-02**: Are claims tracked to prevent double-claiming?

### HIGH (3)
- **AD-05**: Is the airdrop protected against Sybil attacks?
- **AD-06**: Are token amounts in the Merkle tree verified against total allocation?
- **AD-08**: Are vesting schedules correctly applied to airdropped tokens?

### MEDIUM (3)
- **AD-03**: Is the claim window properly bounded with start and end times?
- **AD-04**: Are Merkle proof verifications gas-efficient for large trees?
- **AD-07**: Is the claim function protected against front-running?

## Auction (auction) — 10 checks

### HIGH (6)
- **AU-01**: Is the auction settlement mechanism resistant to last-block sniping?
- **AU-02**: Are sealed-bid auctions properly using commit-reveal schemes?
- **AU-04**: Are auction proceeds correctly distributed to sellers?
- **AU-06**: Are Dutch auction price decay curves correctly implemented?
- **AU-07**: Is the auction finalization atomic to prevent partial settlements?
- **AU-09**: Is the refund mechanism for outbid participants reliable?

### MEDIUM (4)
- **AU-03**: Is the bid withdrawal mechanism safe against griefing?
- **AU-05**: Is the reserve price mechanism resistant to manipulation?
- **AU-08**: Are batch auctions resistant to information leakage?
- **AU-10**: Are auction parameters (duration, increment, reserve) properly access-controlled?

## Balancer V3 (balancer-v3) — 10 checks

### CRITICAL (5)
- **BL-01**: Are weighted pool join/exit calculations protected against sandwich attacks?
- **BL-02**: Is the BPT (Balancer Pool Token) pricing oracle manipulation-resistant?
- **BL-03**: Are custom pool hooks properly sandboxed?
- **BL-06**: Is the invariant calculation correct for all pool types?
- **BL-07**: Are rate providers for yield-bearing tokens validated?

### HIGH (5)
- **BL-04**: Is the weight change mechanism resistant to front-running?
- **BL-05**: Are flash loan fees correctly calculated and collected?
- **BL-08**: Is the swap fee mechanism resistant to dynamic fee manipulation?
- **BL-09**: Are nested pool compositions correctly unwound for pricing?
- **BL-10**: Is the pool recovery mode properly restricted?

## Bridges (bridges) — 40 checks

### HIGH (10)
- **BR-01**: Is your validator set security implemented securely?
- **BR-02**: Is your consensus mechanisms implemented securely?
- **BR-03**: Is your cross-chain communication implemented securely?
- **BR-05**: Is your asset custody implemented securely?
- **BR-11**: Is your relayer incentives implemented securely?
- **BR-12**: Is your message delivery guarantees implemented securely?
- **BR-15**: Is your protocol differences implemented securely?
- **BR-27**: Is your message processing implemented securely?
- **BR-28**: Is your finality requirements implemented securely?
- **BR-38**: Is your key management implemented securely?

### MEDIUM (30)
- **BR-04**: Is your payload validation implemented securely?
- **BR-06**: Is your minting/burning mechanisms implemented securely?
- **BR-07**: Is your pool management implemented securely?
- **BR-08**: Is your cross-chain arbitrage implemented securely?
- **BR-09**: Is your oracle integration implemented securely?
- **BR-10**: Is your light client security implemented securely?
- **BR-13**: Is your gas limit differences implemented securely?
- **BR-14**: Is your chain id validation implemented securely?
- **BR-16**: Is your cross-chain fee structure implemented securely?
- **BR-17**: Is your economic incentives implemented securely?
- **BR-18**: Is your capital efficiency implemented securely?
- **BR-19**: Is your dispute resolution implemented securely?
- **BR-20**: Is your monitoring & detection implemented securely?
- **BR-21**: Is your circuit breakers implemented securely?
- **BR-22**: Is your recovery mechanisms implemented securely?
- **BR-23**: Is your endpoint configuration implemented securely?
- **BR-24**: Is your message handling implemented securely?
- **BR-25**: Is your oft (omnichain fungible token) implemented securely?
- **BR-26**: Is your router configuration implemented securely?
- **BR-29**: Is your network isolation implemented securely?
- **BR-30**: Is your historical validation implemented securely?
- **BR-31**: Is your cross-chain call security implemented securely?
- **BR-32**: Is your defi integration implemented securely?
- **BR-33**: Is your network simulation implemented securely?
- **BR-34**: Is your economic testing implemented securely?
- **BR-35**: Is your end-to-end flows implemented securely?
- **BR-36**: Is your multi-chain governance implemented securely?
- **BR-37**: Is your upgrade coordination implemented securely?
- **BR-39**: Is your incident response implemented securely?
- **BR-40**: Is your regulatory compliance implemented securely?

## CCTP (cctp) — 10 checks

### CRITICAL (4)
- **CC-01**: Is the attestation verification fully validated before minting?
- **CC-02**: Are nonces properly tracked to prevent message replay?
- **CC-03**: Is the domain mapping between chains correctly configured?
- **CC-06**: Is the MessageTransmitter address validated against the official deployment?

### HIGH (3)
- **CC-04**: Is the burn-mint flow atomic and resistant to partial execution?
- **CC-05**: Are token amounts correctly converted between chains with different decimals?
- **CC-09**: Are destination callers properly restricted to prevent unauthorized claiming?

### MEDIUM (3)
- **CC-07**: Are rate limits respected to prevent large unauthorized transfers?
- **CC-08**: Is the attestation fetch mechanism resilient to API failures?
- **CC-10**: Is the integration tested against CCTP version upgrades?

## Cross-Function Analysis (cfa) — 61 checks

### CRITICAL (2)
- **CS-01**: Does your protocol protect liquidity redeployment functions from sandwich attacks using TWAP validation?
- **SP-09**: Do your price-sensitive operations use TWAP validation instead of spot prices from pool.slot0()?

### HIGH (16)
- **CS-02**: Does your protocol properly validate input arrays to prevent token theft through array manipulation?
- **CS-04**: Does your protocol maintain critical invariants like totalSupply() == calcLpTokenSupply(reserves) to prevent arithmetic overflow?
- **CS-05**: Do all swap operations implement proper slippage protection with user-specified minimum output amounts?
- **CS-07**: Are your fee distribution mechanisms protected against precision loss that causes permanently stuck tokens?
- **CS-08**: Are your view functions protected against read-only reentrancy that can manipulate return values?
- **FM-01**: Are your fee structure changes protected against retrospective application that can steal pending rewards?
- **MO-01**: Does your protocol maintain critical invariants like totalSupply() == calcLpTokenSupply(reserves) to prevent arithmetic overflow?
- **AC-03**: Are your privileged functions properly protected against unauthorized access and parameter manipulation?
- **DP-04**: Are your external calls protected against DoS attacks through malicious contract interactions?
- **FM-04**: Are your fee collection mechanisms protected against manipulation through timing attacks?
- **MO-05**: Do your protocol functions use consistent rounding direction to prevent invariant violations?
- **SP-01**: Do your swap functions reject zero amountOutMinimum parameters to prevent unlimited slippage?
- **SP-11**: Do your price-sensitive calculations implement manipulation resistance beyond basic TWAP checks?
- **SM-02**: Are your view functions protected against read-only reentrancy that can manipulate return values?
- **TH-03**: Are your fee distribution mechanisms protected against precision loss that causes permanently stuck tokens?
- **TH-04**: Does your protocol properly manage token approvals when updating external contract addresses?

### MEDIUM (43)
- **CS-03**: Are your mathematical operations protected against uint128 overflow in large amount calculations?
- **CS-06**: Does your protocol handle fee-on-transfer tokens correctly by measuring actual received amounts?
- **CS-09**: Do your order management functions validate direction parameters to prevent unauthorized cancellations?
- **CS-10**: Are your upkeep functions protected against gas griefing attacks that can prevent order fulfillment?
- **CS-11**: Do your order management functions validate direction parameters to prevent unauthorized cancellations?
- **DP-01**: Are your upkeep functions protected against gas griefing attacks that can prevent order fulfillment?
- **SM-01**: Does your order book implementation prevent state conflicts that can block legitimate operations?
- **AC-01**: Do your order management functions validate direction parameters to prevent unauthorized cancellations?
- **AC-02**: Do your functions properly validate array lengths and bounds to prevent out-of-bounds access?
- **AC-04**: Do your state-changing functions validate that state transitions are valid and authorized?
- **AC-05**: Do your functions validate all input parameters to prevent invalid values and edge case exploits?
- **DP-02**: Do your batch processing functions implement proper limits to prevent resource exhaustion attacks?
- **DP-03**: Are your loops properly bounded to prevent infinite or excessive iterations?
- **DP-05**: Does your protocol implement mechanisms to prevent state bloat attacks that can degrade performance?
- **FM-02**: Do your fee distribution mechanisms ensure complete and fair allocation without remainder loss?
- **FM-03**: Are your fee parameters properly bounded and validated to prevent excessive fee extraction?
- **FM-05**: Do your fee accounting systems accurately track and reconcile all collected fees?
- **MO-02**: Are your mathematical operations protected against uint128 overflow in large amount calculations?
- **MO-03**: Are your percentage calculations protected against uint128 overflow in large amount operations?
- **MO-04**: Do your mathematical calculations perform multiplication before division to minimize precision loss from integer arithmetic?
- **SP-02**: Are your transaction deadlines properly implemented instead of using block.timestamp?
- **SP-03**: Do your functions use user-specified slippage parameters instead of hardcoded values?
- **SP-04**: Are your fee collection swaps protected with proper slippage controls?
- **SP-05**: Do your multi-hop swaps validate final output amounts rather than just intermediate steps?
- **SP-06**: Do your external AMM interactions include proper deadline parameters?
- **SP-07**: Do your functions validate deadline parameters instead of accepting block.timestamp?
- **SP-08**: Are your user-facing functions properly validating deadline constraints?
- **SP-10**: Are your liquidity deployment functions protected with onlyCalmPeriods or similar modifiers?
- **SP-12**: Are your flash loan vulnerable operations protected against price dependency attacks?
- **SP-13**: Do your external AMM interactions validate return values and handle failures gracefully?
- **SP-14**: Are your Uniswap V3 interactions properly handling deadline and slippage parameters?
- **SP-15**: Do your order fulfillment functions implement proper time constraints and validation?
- **SP-16**: Are your swap aggregation functions implementing end-to-end protection across multiple DEXs?
- **SP-17**: Do your route optimization algorithms consider slippage impact in path selection?
- **SP-18**: Are your complex swap paths validated for intermediate token compatibility and risks?
- **SP-19**: Do your MEV protection mechanisms account for different attack vectors beyond sandwich attacks?
- **SP-20**: Are your slippage calculations properly handling different token decimals and precision requirements?
- **SM-03**: Do your multi-step operations maintain state consistency throughout the entire transaction?
- **SM-04**: Do your related functions maintain consistent state when called in sequence or concurrently?
- **SM-05**: Does your protocol implement proper state recovery mechanisms for emergency situations?
- **TH-01**: Does your protocol handle fee-on-transfer tokens correctly by measuring actual received amounts?
- **TH-02**: Does your protocol properly handle tokens that revert on zero-value transfers?
- **TH-05**: Does your protocol implement token sweep functions to recover accidentally sent or accumulated dust tokens?

## Chainlink (chainlink) — 10 checks

### CRITICAL (5)
- **CL-01**: Is the price feed staleness check implemented with appropriate heartbeat?
- **CL-02**: Is the L2 sequencer uptime feed checked before using price data?
- **CL-03**: Are price feed decimal conversions handled correctly?
- **CL-06**: Is the min/max price check implemented to detect circuit breaker triggers?
- **CL-08**: Is the price feed address verified against Chainlink's official registry?

### HIGH (4)
- **CL-04**: Is the round completeness check implemented (answeredInRound >= roundId)?
- **CL-05**: Are multi-hop price derivations (e.g., TOKEN/ETH * ETH/USD) correctly calculated?
- **CL-07**: Are fallback oracles configured for critical price feeds?
- **CL-09**: Are negative prices handled correctly?

### MEDIUM (1)
- **CL-10**: Is the price update frequency appropriate for the use case?

## Chainlink Functions (chainlink-functions) — 8 checks

### CRITICAL (2)
- **FN-01**: Is the JavaScript source code hardcoded or properly validated?
- **FN-02**: Are secrets properly encrypted and not exposed in the request?

### HIGH (4)
- **FN-03**: Is the response properly validated for expected format and range?
- **FN-05**: Are error responses handled gracefully without blocking the protocol?
- **FN-07**: Are request/response pairs properly tracked to prevent confusion?
- **FN-08**: Is the subscription owner properly access-controlled?

### MEDIUM (2)
- **FN-04**: Is the request properly bounded to prevent expensive computation costs?
- **FN-06**: Is the DON (Decentralized Oracle Network) selection appropriate for the data sensitivity?

## Concentrated Liquidity (clm) — 22 checks

### CRITICAL (10)
- **CLM-01**: Does your protocol protect liquidity redeployment functions from sandwich attacks using TWAP validation?
- **CLM-03**: Does your protocol prevent malicious hooks from bypassing reentrancy guards?
- **CLM-05**: Does your protocol prevent reward token overflow in uint96 casting operations?
- **CLM-07**: Does your protocol validate token contract existence to prevent exploitation?
- **CLM-09**: Does your protocol prevent DoS attacks through unbounded array growth?
- **HOOK-01**: Does your protocol prevent malicious hooks from bypassing reentrancy guards?
- **ORACLE-01**: Does your protocol apply TWAP validation consistently across ALL price-sensitive operations?
- **REWARD-01**: Does your protocol prevent reward token overflow in uint96 casting operations?
- **REWARD-03**: Does your protocol prevent DoS attacks through unbounded array growth in reward systems?
- **TOKEN-01**: Does your protocol validate token contract existence to prevent exploitation?

### HIGH (6)
- **CLM-02**: Does your protocol prevent price manipulation outside intended liquidity ranges?
- **CLM-04**: Does your protocol validate hook callback selectors to prevent spoofing attacks?
- **CLM-06**: Does your protocol track user pool participation accurately to prevent reward manipulation?
- **CLM-10**: Does your protocol include proper slippage protection on all swap operations?
- **REWARD-02**: Does your protocol track user pool participation accurately to prevent reward manipulation?
- **HOOK-02**: Does your protocol validate hook callback selectors to prevent spoofing attacks?

### MEDIUM (4)
- **HOOK-03**: Does your protocol correctly identify the actual sender in multicall contexts for hook callbacks?
- **ORACLE-02**: Does your protocol handle TWAP tick rounding correctly to prevent manipulation?
- **ORACLE-03**: Does your protocol prevent retrospective fee application to historical rewards?
- **TOKEN-03**: Does your protocol handle missing token symbol() methods gracefully?

### LOW (2)
- **CLM-08**: Does your protocol handle fee-on-transfer tokens correctly in accounting?
- **TOKEN-02**: Does your protocol handle fee-on-transfer tokens correctly in accounting?

## Common (all protocols) (common) — 103 checks

### CRITICAL (8)
- **EE-02**: Are your reward/fee calculations protected against decimal precision overflow when downcasting to smaller uint types?
- **EE-06**: Are your protocol functions protected against cross-function reentrancy attacks that can manipulate state between external calls?
- **LE-06**: Are maximum and minimum limits properly enforced to prevent overflow, underflow, and out-of-bounds values?
- **ORACLE-01**: Does your protocol apply TWAP validation consistently across ALL price-sensitive operations?
- **REWARD-01**: Does your protocol prevent reward token overflow in uint96 casting operations?
- **REWARD-03**: Does your protocol prevent DoS attacks through unbounded array growth in reward systems?
- **SP-09**: Do your price-sensitive operations use TWAP validation instead of spot prices from pool.slot0()?
- **TOKEN-01**: Does your protocol validate token contract existence to prevent exploitation?

### HIGH (17)
- **AC-02**: Do your access control mechanisms enforce permissions completely without allowing bypass scenarios?
- **AC-23**: Can users bypass intended access patterns?
- **AC-33**: Can modifiers be bypassed through reentrancy?
- **AC-36**: Are there timing-based bypass opportunities?
- **DP-04**: Are your external calls protected against DoS attacks through malicious contract interactions?
- **EE-03**: Are your governance/voting functions protected against flash loan manipulation attacks?
- **EE-07**: Do your delegation and voting systems prevent users from bypassing access restrictions through delegation mechanisms?
- **EE-08**: Are your reward distribution mechanisms protected against manipulation through timing attacks, duplicate entries, or calculation errors?
- **EE-09**: Are your protocol functions protected against denial-of-service attacks through gas limit exploitation or resource exhaustion?
- **EE-10**: Are your token handling functions protected against malicious tokens that can bypass validation or cause unexpected behavior?
- **FM-04**: Are your fee collection mechanisms protected against manipulation through timing attacks?
- **MO-05**: Do your protocol functions use consistent rounding direction to prevent invariant violations?
- **SP-01**: Do your swap functions reject zero amountOutMinimum parameters to prevent unlimited slippage?
- **SP-11**: Do your price-sensitive calculations implement manipulation resistance beyond basic TWAP checks?
- **SM-02**: Are your view functions protected against read-only reentrancy that can manipulate return values?
- **TH-03**: Are your fee distribution mechanisms protected against precision loss that causes permanently stuck tokens?
- **TH-04**: Does your protocol properly manage token approvals when updating external contract addresses?

### MEDIUM (77)
- **AC-01**: Do your functions properly validate array lengths and bounds to prevent out-of-bounds access?
- **AC-03**: Do your functions validate state transitions to prevent invalid state changes and ensure system integrity?
- **AC-04**: Do your functions validate all input parameters to prevent invalid values and edge case exploits?
- **AC-05**: Are roles clearly defined with specific purposes?
- **AC-06**: Do roles have appropriate permission boundaries?
- **AC-07**: Are there overlapping or redundant roles?
- **AC-08**: Is there a clear hierarchy of permissions?
- **AC-09**: How are roles initially assigned?
- **AC-10**: Can roles be transferred or revoked?
- **AC-11**: Are there checks for role assignment authorization?
- **AC-12**: Is there protection against unauthorized role changes?
- **AC-13**: Are functions using appropriate visibility (public/external/internal/private)?
- **AC-14**: Are internal functions accidentally exposed?
- **AC-15**: Are external functions properly restricted?
- **AC-16**: Is there unnecessary public access to sensitive functions?
- **AC-17**: Do critical functions have access control modifiers?
- **AC-18**: Are modifiers consistently applied across similar functions?
- **AC-19**: Are there functions missing access control?
- **AC-20**: Do access modifiers properly validate permissions?
- **AC-21**: Can external users call administrative functions?
- **AC-22**: Are initialization functions properly protected?
- **AC-24**: Are there unprotected state-changing functions?
- **AC-25**: Are custom modifiers implemented correctly?
- **AC-26**: Do modifiers have proper error handling?
- **AC-27**: Are there race conditions in modifier checks?
- **AC-28**: Do modifiers validate all necessary conditions?
- **AC-29**: Are modifier conditions implemented correctly?
- **AC-30**: Do modifiers check all necessary conditions?
- **AC-31**: Are there logical errors in permission validation?
- **AC-32**: Do modifiers handle edge cases properly?
- **AC-34**: Are there race conditions in access checks?
- **AC-35**: Do modifiers validate state consistently?
- **AC-37**: Do modifiers provide appropriate error messages?
- **AC-38**: Are error messages information-secure?
- **AC-39**: Do failed checks revert properly?
- **AC-40**: Are there gas-related denial of service risks?
- **AC-41**: Is modifier ordering significant and correct?
- **AC-42**: Are composed modifiers gas-efficient?
- **DP-02**: Do your batch processing functions implement proper limits to prevent resource exhaustion attacks?
- **DP-03**: Are your loops properly bounded to prevent infinite or excessive iterations?
- **DP-05**: Does your protocol implement mechanisms to prevent state bloat attacks that can degrade performance?
- **FM-02**: Do your fee distribution mechanisms ensure complete and fair allocation without remainder loss?
- **FM-03**: Are your fee parameters properly bounded and validated to prevent excessive fee extraction?
- **FM-05**: Do your fee accounting systems accurately track and reconcile all collected fees?
- **LE-02**: Is operator precedence handled properly in your mathematical expressions to ensure calculations execute in the intended order?
- **LE-03**: Are rounding and precision issues properly handled in your calculations to prevent loss of accuracy or exploitable precision attacks?
- **LE-04**: Do your calculations match the intended business logic and requirements as specified in the documentation?
- **LE-05**: Are zero values properly handled in your calculations to prevent division by zero and unexpected behavior?
- **MO-02**: Are your mathematical operations protected against uint128 overflow in large amount calculations?
- **MO-03**: Are your percentage calculations protected against uint128 overflow in large amount operations?
- **MO-04**: Do your mathematical calculations perform multiplication before division to minimize precision loss from integer arithmetic?
- **ORACLE-02**: Does your protocol handle TWAP tick rounding correctly to prevent manipulation?
- **ORACLE-03**: Does your protocol prevent retrospective fee application to historical rewards?
- **SP-02**: Are your transaction deadlines properly implemented instead of using block.timestamp?
- **SP-03**: Do your functions use user-specified slippage parameters instead of hardcoded values?
- **SP-04**: Are your fee collection swaps protected with proper slippage controls?
- **SP-05**: Do your multi-hop swaps validate final output amounts rather than just intermediate steps?
- **SP-06**: Do your external AMM interactions include proper deadline parameters?
- **SP-07**: Do your functions validate deadline parameters instead of accepting block.timestamp?
- **SP-08**: Are your user-facing functions properly validating deadline constraints?
- **SP-10**: Are your liquidity deployment functions protected with onlyCalmPeriods or similar modifiers?
- **SP-12**: Are your flash loan vulnerable operations protected against price dependency attacks?
- **SP-13**: Do your external AMM interactions validate return values and handle failures gracefully?
- **SP-14**: Are your Uniswap V3 interactions properly handling deadline and slippage parameters?
- **SP-15**: Do your order fulfillment functions implement proper time constraints and validation?
- **SP-16**: Are your swap aggregation functions implementing end-to-end protection across multiple DEXs?
- **SP-17**: Do your route optimization algorithms consider slippage impact in path selection?
- **SP-18**: Are your complex swap paths validated for intermediate token compatibility and risks?
- **SP-19**: Do your MEV protection mechanisms account for different attack vectors beyond sandwich attacks?
- **SP-20**: Are your slippage calculations properly handling different token decimals and precision requirements?
- **SM-03**: Do your multi-step operations maintain state consistency throughout the entire transaction?
- **SM-04**: Do your related functions maintain consistent state when called in sequence or concurrently?
- **SM-05**: Does your protocol implement proper state recovery mechanisms for emergency situations?
- **TH-01**: Does your protocol handle fee-on-transfer tokens correctly by measuring actual received amounts?
- **TH-02**: Does your protocol properly handle tokens that revert on zero-value transfers?
- **TH-05**: Does your protocol implement token sweep functions to recover accidentally sent or accumulated dust tokens?
- **TOKEN-03**: Does your protocol handle missing token symbol() methods gracefully?

### LOW (1)
- **TOKEN-02**: Does your protocol handle fee-on-transfer tokens correctly in accounting?

## Crowdfunding (crowdfunding) — 8 checks

### HIGH (4)
- **CF-01**: Is the funding goal validation properly enforced?
- **CF-03**: Is the refund mechanism safe against reentrancy?
- **CF-04**: Are milestone-based fund releases properly gated?
- **CF-07**: Is the vesting schedule for funded tokens properly implemented?

### MEDIUM (4)
- **CF-02**: Are contribution limits properly enforced per user?
- **CF-05**: Is the token distribution after successful funding fair and correct?
- **CF-06**: Are campaign deadlines enforced immutably?
- **CF-08**: Are contribution pausing mechanisms properly access-controlled?

## DAO Governance (dao) — 12 checks

### CRITICAL (2)
- **DA-01**: Is the voting power snapshot taken before proposal creation to prevent flash loan attacks?
- **DA-06**: Is the governance token's transfer restricted during active voting?

### HIGH (8)
- **DA-02**: Is the timelock delay sufficient to allow response to malicious proposals?
- **DA-03**: Are quorum requirements set appropriately to prevent minority takeover?
- **DA-04**: Is the proposal execution function protected against reentrancy?
- **DA-05**: Are vote delegation and undelegation properly time-bounded?
- **DA-07**: Are treasury spending proposals properly bounded?
- **DA-09**: Are emergency proposals handled with appropriate security checks?
- **DA-11**: Are defeated proposals properly prevented from re-execution?
- **DA-12**: Is cross-chain governance properly synchronized?

### MEDIUM (2)
- **DA-08**: Is the proposal creation threshold set to prevent spam?
- **DA-10**: Is the voting period long enough for all stakeholders to participate?

## DEX/AMM (full DASF) (dasf) — 165 checks

### CRITICAL (13)
- **EE-02**: Are your reward/fee calculations protected against decimal precision overflow when downcasting to smaller uint types?
- **EE-06**: Are your protocol functions protected against cross-function reentrancy attacks that can manipulate state between external calls?
- **DS-01**: Does your protocol protect liquidity redeployment functions from sandwich attacks using TWAP validation?
- **DS-08**: Are your liquidity pool deposits protected against share inflation attacks that can steal funds from first depositors?
- **DS-10**: Are composition fee calculations protected against share inflation attacks that can steal depositor funds?
- **DS-13**: Are your token transfer hooks protected against cross-function reentrancy that can manipulate delegation and voting power?
- **DS-14**: Are your external calls protected against gas limit manipulation that can cause selective balance update failures?
- **DS-17**: Are your reward calculations protected against overflow when downcasting to smaller integer types?
- **DS-23**: Are pool price updates properly synchronized with tick state changes to maintain price-tick consistency?
- **DS-29**: Are your reentrancy protections immune to bypass through malicious hooks or external contracts?
- **DS-30**: Are your order execution functions protected against WETH drainage when swaps fail but ETH transfers still occur?
- **LE-06**: Are maximum and minimum limits properly enforced to prevent overflow, underflow, and out-of-bounds values?
- **LE-07**: Are your calculations protected against overflow and underflow conditions that could cause incorrect results or reverts?

### HIGH (14)
- **EE-03**: Are your governance/voting functions protected against flash loan manipulation attacks?
- **EE-07**: Do your delegation and voting systems prevent users from bypassing access restrictions through delegation mechanisms?
- **EE-08**: Are your reward distribution mechanisms protected against manipulation through timing attacks, duplicate entries, or calculation errors?
- **EE-09**: Are your protocol functions protected against denial-of-service attacks through gas limit exploitation or resource exhaustion?
- **EE-10**: Are your token handling functions protected against malicious tokens that can bypass validation or cause unexpected behavior?
- **DS-06**: Do your swap functions implement proper MEV protection with user-specified slippage and transaction deadlines?
- **DS-07**: Are your price feeds protected against manipulation and do you validate price freshness and deviation limits?
- **DS-24**: Are your reward calculations protected against voting power dilution through against-vote inclusion?
- **DS-25**: Are your quorum calculations protected against manipulation through static NFT power or total supply changes?
- **AC-20**: Can the owner bypass security mechanisms?
- **AC-27**: Can the owner manipulate reward distributions?
- **AC-43**: Can users bypass intended access patterns?
- **AC-53**: Can modifiers be bypassed through reentrancy?
- **AC-56**: Are there timing-based bypass opportunities?

### MEDIUM (138)
- **DS-02**: Does your protocol properly save and synchronize pool state during liquidity operations to prevent underflow conditions?
- **DS-03**: Are position updates properly returned and applied to prevent state corruption and liquidity duplication?
- **DS-04**: Does your protocol prevent double counting of liquidity in both active pool and tick deltas?
- **DS-05**: Do all swap/trade functions implement proper slippage protection with user-specified minimum output amounts?
- **DS-09**: Do your fee calculations handle liquidity conversion correctly for two-sided positions to prevent fee circumvention?
- **DS-11**: Do your callback functions validate that the caller is a legitimate pool contract to prevent approval theft?
- **DS-12**: Are your pool initialization functions properly protected against unauthorized reinitialization?
- **DS-15**: Do your mathematical calculations perform multiplication before division to minimize precision loss from integer arithmetic?
- **DS-16**: Do your token operations validate decimal precision instead of making hardcoded assumptions?
- **LE-01**: Are your mathematical formulas implemented correctly according to the intended business logic and mathematical principles?
- **LE-11**: Are dependent states properly managed to prevent partial updates and maintain consistency?
- **LE-16**: Is the overall calculation sequence logical and mathematically sound?
- **LE-17**: Are input parameters properly validated before use in calculations and logic?
- **LE-18**: Are there checks for invalid parameter combinations that could cause unexpected behavior?
- **LE-20**: Are there sanity checks on calculation results to detect obviously wrong values?
- **LE-47**: Are sequence-dependent operations properly ordered?
- **LE-48**: Do deadline mechanisms prevent stale transactions?
- **DS-18**: Does your protocol properly handle fee-on-transfer tokens by measuring actual received amounts rather than assuming full transfer amounts?
- **DS-19**: Do your treasury and delegation functions verify actual token transfers instead of trusting return values?
- **DS-20**: Does your protocol handle non-standard token behaviors like rebasing, fee-on-transfer, and approval race conditions?
- **DS-21**: Are your multi-step operations properly synchronized to prevent state inconsistencies during complex transactions?
- **DS-22**: Are your tick crossing mechanisms protected against skipping ticks with stashed liquidity?
- **DS-26**: Are your claim validation mechanisms protected against null positions that can brick entire pools?
- **DS-27**: Are your tick mapping and cross tick calculations protected against rounding issues that prevent swaps?
- **DS-28**: Are your slippage validation functions protected against parameter errors that completely break protection?
- **AC-17**: What powers does the owner/admin have?
- **AC-18**: Can the owner drain user funds directly?
- **AC-19**: Are there limits on parameter changes?
- **AC-21**: Are critical changes subject to timelocks?
- **AC-22**: Is multi-signature required for sensitive operations?
- **AC-23**: Are there community governance mechanisms?
- **AC-24**: Is there transparency in administrative actions?
- **AC-25**: Can the owner set extreme parameter values?
- **AC-26**: Are there bounds on fee changes?
- **AC-28**: Are there checks on configuration changes?
- **AC-29**: What emergency powers does the owner have?
- **AC-30**: Are emergency actions time-limited?
- **AC-31**: Can emergency powers be abused?
- **AC-32**: Is there oversight of emergency usage?
- **AC-01**: Are roles clearly defined with specific purposes?
- **AC-02**: Do roles have appropriate permission boundaries?
- **AC-03**: Are there overlapping or redundant roles?
- **AC-04**: Is there a clear hierarchy of permissions?
- **AC-05**: How are roles initially assigned?
- **AC-06**: Can roles be transferred or revoked?
- **AC-07**: Are there checks for role assignment authorization?
- **AC-08**: Is there protection against unauthorized role changes?
- **AC-09**: Are critical functions properly protected?
- **AC-10**: Do functions check for appropriate roles?
- **AC-11**: Are there functions accessible by multiple roles?
- **AC-12**: Is there consistent access control across similar functions?
- **AC-13**: Are there overprivileged roles (admin/owner)?
- **AC-14**: Can single entities control critical protocol functions?
- **AC-15**: Are there emergency controls and their limitations?
- **AC-16**: Is there a path to decentralization?
- **AC-33**: Are functions using appropriate visibility (public/external/internal/private)?
- **AC-34**: Are internal functions accidentally exposed?
- **AC-35**: Are external functions properly restricted?
- **AC-36**: Is there unnecessary public access to sensitive functions?
- **AC-37**: Do critical functions have access control modifiers?
- **AC-38**: Are modifiers consistently applied across similar functions?
- **AC-39**: Are there functions missing access control?
- **AC-40**: Do access modifiers properly validate permissions?
- **AC-41**: Can external users call administrative functions?
- **AC-42**: Are initialization functions properly protected?
- **AC-44**: Are there unprotected state-changing functions?
- **AC-45**: Are custom modifiers implemented correctly?
- **AC-46**: Do modifiers have proper error handling?
- **AC-47**: Are there race conditions in modifier checks?
- **AC-48**: Do modifiers validate all necessary conditions?
- **AC-49**: Are modifier conditions implemented correctly?
- **AC-50**: Do modifiers check all necessary conditions?
- **AC-51**: Are there logical errors in permission validation?
- **AC-52**: Do modifiers handle edge cases properly?
- **AC-54**: Are there race conditions in access checks?
- **AC-55**: Do modifiers validate state consistently?
- **AC-57**: Do modifiers provide appropriate error messages?
- **AC-58**: Are error messages information-secure?
- **AC-59**: Do failed checks revert properly?
- **AC-60**: Are there gas-related denial of service risks?
- **AC-61**: Do multiple modifiers work together correctly?
- **AC-62**: Are there conflicts between different modifiers?
- **AC-63**: Is modifier ordering significant and correct?
- **AC-64**: Are composed modifiers gas-efficient?
- **LE-02**: Is operator precedence handled properly in your mathematical expressions to ensure calculations execute in the intended order?
- **LE-03**: Are rounding and precision issues properly handled in your calculations to prevent loss of accuracy or exploitable precision attacks?
- **LE-04**: Do your calculations match the intended business logic and requirements as specified in the documentation?
- **LE-05**: Are zero values properly handled in your calculations to prevent division by zero and unexpected behavior?
- **LE-08**: Are edge cases properly tested and handled in your calculations and logic flows?
- **LE-09**: Are state changes properly validated to ensure they follow business rules and maintain consistency?
- **LE-10**: Are state transitions properly sequenced to prevent race conditions and ensure correct ordering?
- **LE-39**: Do loop exit conditions handle all possible scenarios?
- **LE-12**: Do state changes properly integrate with access controls to prevent unauthorized transitions?
- **LE-13**: Is multiplication performed before division to preserve precision and avoid truncation errors?
- **LE-14**: Are parentheses used correctly to ensure calculations execute in the intended order?
- **LE-15**: Are there dependency issues between calculations that could cause incorrect sequencing?
- **LE-19**: How are negative values handled to prevent unexpected behavior or calculation errors?
- **LE-21**: Are boolean expressions implemented correctly to match the intended logic?
- **LE-22**: Are logical operators (&&, ||, !) used properly to create the intended conditional behavior?
- **LE-23**: Are there De Morgan's law violations that could lead to incorrect logical behavior?
- **LE-24**: Do conditional expressions match the intended behavior as specified in requirements?
- **LE-25**: Are all possible cases and code paths properly handled in conditional logic?
- **LE-26**: Are there missing else clauses that could lead to unhandled conditions?
- **LE-27**: Do conditional statements cover all edge cases and boundary conditions?
- **LE-28**: Are there unreachable code paths that indicate logical errors?
- **LE-29**: Are similar conditions implemented consistently across different functions?
- **LE-30**: Do related functions use the same logical patterns and validation approaches?
- **LE-31**: Are there contradictory conditions that could cause logical conflicts?
- **LE-32**: Is the conditional logic maintainable, clear, and easy to understand?
- **LE-33**: How are boundary values handled in edge case scenarios?
- **LE-34**: What happens with unexpected inputs that fall outside normal parameters?
- **LE-35**: Are error conditions properly managed with appropriate responses?
- **LE-36**: Is there graceful degradation when systems encounter edge cases?
- **LE-37**: Do loop termination conditions prevent infinite loops?
- **LE-38**: Are loop bounds properly validated to prevent gas limit issues?
- **LE-40**: Are nested loops optimized to prevent excessive gas consumption?
- **LE-41**: Are error conditions properly identified and handled?
- **LE-42**: Do error messages provide sufficient information for debugging?
- **LE-43**: Are exception scenarios handled without breaking contract state?
- **LE-44**: Do recovery mechanisms work correctly after errors?
- **LE-45**: Are timestamp dependencies handled securely?
- **LE-46**: Do time-based operations handle block time variations correctly?
- **LE-49**: Are memory allocations and deallocations handled correctly?
- **LE-50**: Do resource cleanup operations execute in all exit paths?
- **LE-51**: Are gas consumption patterns predictable and bounded?
- **LE-52**: Do resource limits prevent denial of service attacks?
- **LE-53**: Are external contract interactions properly validated?
- **LE-54**: Do interface implementations handle all required methods correctly?
- **LE-55**: Are cross-contract dependencies managed securely?
- **LE-56**: Do integration points handle version compatibility correctly?
- **LE-57**: Are algorithmic complexities optimized for gas efficiency?
- **LE-58**: Do caching mechanisms prevent redundant calculations?
- **LE-59**: Are data structures chosen appropriately for their use cases?
- **LE-60**: Do batch operations minimize transaction overhead efficiently?
- **LE-61**: Are access control checks comprehensive and consistent?
- **LE-62**: Do input sanitization mechanisms prevent injection attacks?
- **LE-63**: Are cryptographic operations implemented securely?
- **LE-64**: Do security assumptions remain valid under all conditions?

## EigenLayer / Restaking (eigenlayer) — 12 checks

### CRITICAL (4)
- **EL-01**: Is the restaking delegation properly validated against operator sets?
- **EL-02**: Are slashing conditions correctly implemented per AVS?
- **EL-03**: Is withdrawal queuing resistant to front-running the slashing oracle?
- **EL-10**: Are beacon chain oracle proofs validated for native ETH restaking?

### HIGH (7)
- **EL-04**: Are shares correctly calculated when restaking across multiple strategies?
- **EL-05**: Is the operator's committed stake properly locked during active validation?
- **EL-06**: Are AVS reward distributions correct when stakers serve multiple AVSs?
- **EL-07**: Is the middleware correctly forwarding slashing proofs to the core contracts?
- **EL-09**: Is the undelegation flow correctly handling queued withdrawals?
- **EL-11**: Is the protocol safe against operator griefing attacks?
- **EL-12**: Are nonce and salt values correctly handled in withdrawal roots?

### MEDIUM (1)
- **EL-08**: Are strategy deposit caps enforced to prevent concentration risk?

## ETF / Index Funds (etf) — 12 checks

### CRITICAL (2)
- **ET-01**: Is the basket composition rebalancing resistant to front-running?
- **ET-02**: Is the NAV (Net Asset Value) calculation accurate and manipulation-resistant?

### HIGH (7)
- **ET-03**: Are creation/redemption mechanisms protected against arbitrage attacks?
- **ET-04**: Is the weight normalization mathematically correct after rebalancing?
- **ET-06**: Is the protocol safe against toxic asset inclusion in the basket?
- **ET-07**: Are share price calculations consistent between mint and redeem?
- **ET-08**: Is the rebalancing trigger mechanism resistant to manipulation?
- **ET-09**: Are oracle sources for each basket asset validated independently?
- **ET-11**: Are concentrated redemptions handled without causing cascade failures?

### MEDIUM (3)
- **ET-05**: Are management fees accrued correctly over time?
- **ET-10**: Is the maximum deviation between NAV and market price bounded?
- **ET-12**: Is the basket update governance properly time-locked?

## Gaming (gaming) — 10 checks

### CRITICAL (2)
- **GM-01**: Are in-game random outcomes verifiably fair using VRF?
- **GM-02**: Is the game economy resistant to inflation from item duplication?

### HIGH (6)
- **GM-03**: Are play-to-earn reward rates sustainable and bounded?
- **GM-04**: Is the asset crafting/combining mechanism atomic?
- **GM-05**: Are marketplace trades protected against oracle manipulation for in-game currency?
- **GM-07**: Are tournament/competition results committed before rewards are distributed?
- **GM-08**: Is the season/epoch reset mechanism safe for player assets?
- **GM-09**: Are cross-game asset transfers validated against both game contracts?

### MEDIUM (2)
- **GM-06**: Is the energy/stamina system resistant to time manipulation?
- **GM-10**: Is the anti-cheat mechanism enforceable on-chain?

## Interest Rate Derivatives (ird) — 10 checks

### CRITICAL (2)
- **IR-01**: Is the fixed-rate calculation resistant to underlying rate manipulation?
- **IR-09**: Is the protocol resistant to rate oracle manipulation before settlement?

### HIGH (5)
- **IR-02**: Are swap settlement amounts calculated atomically?
- **IR-03**: Is the yield curve construction resistant to stale data?
- **IR-04**: Are margin requirements for rate positions correctly calculated?
- **IR-05**: Is the notional amount properly tracked for floating-rate positions?
- **IR-10**: Are accrued but unsettled interest amounts properly accounted for?

### MEDIUM (3)
- **IR-06**: Are rate caps and floors enforced to prevent extreme payouts?
- **IR-07**: Is the compounding frequency calculation consistent?
- **IR-08**: Are early termination clauses properly implemented?

## L2 / ZK Rollups (l2-zk) — 12 checks

### CRITICAL (5)
- **ZK-01**: Is the ZK proof verification complete and not skippable?
- **ZK-02**: Is the data availability layer resistant to withholding attacks?
- **ZK-03**: Are L1-L2 message passing nonces correctly tracked?
- **ZK-05**: Are withdrawal proofs validated against the correct state root?
- **ZK-09**: Are ZK circuit constraints consistent with the EVM execution spec?

### HIGH (6)
- **ZK-04**: Is the sequencer censorship-resistant with forced transaction inclusion?
- **ZK-06**: Is the proof generation bounded to prevent DoS via complex transactions?
- **ZK-08**: Is the escape hatch mechanism functional if the sequencer goes offline?
- **ZK-10**: Is the batch submission mechanism resistant to reorg attacks?
- **ZK-11**: Are precompile implementations in the ZK context fully equivalent?
- **ZK-12**: Is the fraud proof window sufficient for challenge submission?

### MEDIUM (1)
- **ZK-07**: Are L2 gas costs correctly estimated and bounded?

## LayerZero (layerzero) — 10 checks

### CRITICAL (4)
- **LZ-01**: Is the endpoint address verified against LayerZero's official deployment?
- **LZ-02**: Are trusted remote addresses correctly set and verified?
- **LZ-08**: Are cross-chain token transfers protected against double-spending?
- **LZ-10**: Are admin functions (like setting trusted remotes) properly access-controlled?

### HIGH (6)
- **LZ-03**: Is the message payload size validated to prevent DoS?
- **LZ-04**: Are gas limits for destination execution properly configured?
- **LZ-05**: Is the OApp implementation protected against message ordering attacks?
- **LZ-06**: Are failed messages handled with a retry mechanism?
- **LZ-07**: Is the DVN (Decentralized Verifier Network) configuration appropriate?
- **LZ-09**: Is the composed message flow secure against reentrancy?

## Lending / Borrowing (lending) — 41 checks

### HIGH (3)
- **LN-29**: Is your dos prevention implemented securely?
- **LN-34**: Is your price manipulation implemented securely?
- **LN-35**: Is your voting manipulation implemented securely?

### MEDIUM (38)
- **LN-01**: Is your collateral validation implemented securely?
- **LN-02**: Is your health factor calculations implemented securely?
- **LN-03**: Is your rate calculation accuracy implemented securely?
- **LN-04**: Is your economic incentives implemented securely?
- **LN-05**: Is your borrow mechanics implemented securely?
- **LN-06**: Is your repayment safety implemented securely?
- **LN-07**: Is your health monitoring implemented securely?
- **LN-08**: Is your liquidation incentives implemented securely?
- **LN-09**: Is your partial vs full liquidation implemented securely?
- **LN-10**: Is your liquidation protection implemented securely?
- **LN-11**: Is your oracle reliability implemented securely?
- **LN-12**: Is your price update mechanisms implemented securely?
- **LN-13**: Is your cross-asset calculations implemented securely?
- **LN-14**: Is your compound interest implemented securely?
- **LN-15**: Is your fee structure implemented securely?
- **LN-16**: Is your protocol reserves implemented securely?
- **LN-17**: Is your parameter updates implemented securely?
- **LN-18**: Is your risk assessment implemented securely?
- **LN-19**: Is your circuit breakers implemented securely?
- **LN-20**: Is your ctoken/atoken implementation implemented securely?
- **LN-21**: Is your reward distribution implemented securely?
- **LN-22**: Is your voting mechanisms implemented securely?
- **LN-23**: Is your leverage calculations implemented securely?
- **LN-24**: Is your margin calls implemented securely?
- **LN-25**: Is your portfolio margining implemented securely?
- **LN-26**: Is your flash loan implementation implemented securely?
- **LN-27**: Is your attack prevention implemented securely?
- **LN-28**: Is your liquidator rewards implemented securely?
- **LN-30**: Is your liquidation math implemented securely?
- **LN-31**: Is your role-based access implemented securely?
- **LN-32**: Is your upgrade mechanisms implemented securely?
- **LN-33**: Is your external protocol risks implemented securely?
- **LN-36**: Is your market scenarios implemented securely?
- **LN-37**: Is your operational testing implemented securely?
- **LN-38**: Is your cross-protocol testing implemented securely?
- **LN-39**: Is your compliance requirements implemented securely?
- **LN-40**: Is your real-time metrics implemented securely?
- **LN-41**: Is your health indicators implemented securely?

## Leverage Trading (leverage) — 15 checks

### CRITICAL (3)
- **LV-01**: Are margin requirements correctly enforced before opening leveraged positions?
- **LV-02**: Is the liquidation price calculation correct for all position types?
- **LV-04**: Is the collateral valuation resistant to flash loan manipulation?

### HIGH (9)
- **LV-03**: Are borrowing costs properly accrued on leveraged positions?
- **LV-05**: Are position close operations protected against sandwich attacks?
- **LV-07**: Are liquidation bonuses calibrated to prevent gaming?
- **LV-08**: Is margin withdrawal protected against rendering positions under-collateralized?
- **LV-09**: Are multi-collateral positions valued correctly during price fluctuations?
- **LV-10**: Is the protocol protected against oracle front-running for leveraged trades?
- **LV-11**: Are stop-loss orders executed reliably during high volatility?
- **LV-12**: Is the debt tracking consistent across position modifications?
- **LV-13**: Are isolated positions truly isolated from cross-position risk?

### MEDIUM (3)
- **LV-06**: Is the maximum leverage dynamically adjusted based on asset volatility?
- **LV-14**: Is the take-profit execution resistant to manipulation?
- **LV-15**: Are borrowing rate calculations resistant to utilization manipulation?

## Lottery (lottery) — 8 checks

### CRITICAL (3)
- **LT-01**: Is the winning number generation truly random using Chainlink VRF?
- **LT-02**: Are ticket purchases locked before the random number is generated?
- **LT-05**: Is the VRF callback protected against reverting to re-roll the randomness?

### HIGH (3)
- **LT-03**: Is the prize distribution mathematically correct for all scenarios?
- **LT-06**: Are ticket purchases protected against front-running the draw transaction?
- **LT-07**: Is the rollover mechanism for jackpots correctly accumulated?

### MEDIUM (2)
- **LT-04**: Are unclaimed prizes handled with proper time limits?
- **LT-08**: Are referral/affiliate reward calculations correct?

## Migration (migration) — 8 checks

### CRITICAL (2)
- **MG-01**: Is the state migration from v1 to v2 atomic or safely resumable?
- **MG-02**: Are user balances preserved exactly during token migration?

### HIGH (4)
- **MG-03**: Is the old contract properly deprecated after migration?
- **MG-05**: Is the exchange rate between old and new tokens fair and fixed?
- **MG-07**: Is the migration contract's admin access properly limited and time-bounded?
- **MG-08**: Are LP tokens and staked positions migrated correctly?

### MEDIUM (2)
- **MG-04**: Are migration deadlines clearly communicated and enforced?
- **MG-06**: Are approval migrations handled to prevent old approvals from being exploited?

## NFT (nft) — 10 checks

### CRITICAL (1)
- **NF-01**: Is the minting mechanism protected against reentrancy during batch mints?

### HIGH (5)
- **NF-04**: Is the reveal mechanism for unrevealed NFTs truly random and fair?
- **NF-05**: Are whitelist/allowlist mechanisms protected against proof reuse?
- **NF-06**: Is the maximum supply cap truly immutable?
- **NF-08**: Is the lazy minting mechanism safe against front-running?
- **NF-10**: Is the Dutch auction mint mechanism correctly declining?

### MEDIUM (4)
- **NF-02**: Is the metadata URI generation safe against injection attacks?
- **NF-03**: Are royalty payments (EIP-2981) correctly calculated and enforced?
- **NF-07**: Are approval mechanisms correctly implemented for marketplace compatibility?
- **NF-09**: Are soulbound tokens properly non-transferable?

## Perpetuals (perpetuals) — 20 checks

### CRITICAL (4)
- **PP-01**: Is the funding rate calculation resistant to manipulation?
- **PP-02**: Is the mark price oracle protected against manipulation?
- **PP-04**: Is the liquidation engine resistant to cascading liquidation attacks?
- **PP-20**: Is the protocol's total exposure bounded relative to available liquidity?

### HIGH (11)
- **PP-03**: Are position sizes validated against open interest caps?
- **PP-05**: Are profit and loss calculations atomic and consistent?
- **PP-06**: Is the insurance fund properly managed and funded?
- **PP-07**: Are leverage limits enforced consistently across all operations?
- **PP-08**: Is the ADL (Auto-Deleveraging) mechanism fair and resistant to gaming?
- **PP-09**: Are cross-margin and isolated margin modes correctly isolated?
- **PP-10**: Is the order matching engine resistant to front-running?
- **PP-12**: Is delayed order execution protected against oracle manipulation?
- **PP-13**: Are partial liquidations implemented correctly?
- **PP-16**: Is the maximum price impact properly bounded per trade?
- **PP-18**: Is the protocol safe against price gap attacks between epochs?

### MEDIUM (5)
- **PP-11**: Are fees calculated correctly on leveraged positions?
- **PP-14**: Is the protocol resistant to market manipulation via self-trading?
- **PP-15**: Are keeper incentives aligned to prevent delayed liquidations?
- **PP-17**: Are position modifications (increase/decrease) handled atomically?
- **PP-19**: Are withdrawal cooldowns enforced after depositing to vault/LP?

## Privacy (privacy) — 10 checks

### CRITICAL (5)
- **PV-01**: Are ZK-SNARK proof verifications complete and sound?
- **PV-02**: Is the nullifier mechanism preventing double-spending?
- **PV-03**: Is the commitment scheme binding and hiding?
- **PV-04**: Are Merkle tree updates for the commitment set correct?
- **PV-10**: Are ZK circuits audited for under-constrained signals?

### HIGH (3)
- **PV-05**: Is the protocol resistant to the trusted setup compromise (if applicable)?
- **PV-06**: Are denomination amounts fixed to maintain the anonymity set?
- **PV-07**: Is the relayer mechanism preventing deanonymization?

### MEDIUM (2)
- **PV-08**: Are compliance features (view keys, audit keys) properly implemented?
- **PV-09**: Is the protocol resistant to statistical deanonymization?

## Risk Oracle (risk-oracle) — 8 checks

### CRITICAL (1)
- **RO-02**: Are risk parameter updates properly time-locked?

### HIGH (6)
- **RO-01**: Is the risk scoring model transparent and verifiable?
- **RO-03**: Is the risk data aggregated from multiple sources?
- **RO-04**: Are extreme risk events (black swan) properly handled?
- **RO-05**: Is the oracle update frequency aligned with market volatility?
- **RO-06**: Are protocol actions gated on risk score thresholds properly?
- **RO-07**: Is the risk oracle resistant to data poisoning attacks?

### MEDIUM (1)
- **RO-08**: Are risk oracle consumers properly authorized?

## Real World Assets (rwa) — 10 checks

### CRITICAL (3)
- **RW-01**: Is the off-chain asset attestation properly verified on-chain?
- **RW-02**: Are compliance requirements (KYC/AML) enforced in token transfers?
- **RW-05**: Is the token supply correctly pegged to verified underlying assets?

### HIGH (6)
- **RW-03**: Is the redemption mechanism guaranteed against issuer default?
- **RW-04**: Are interest/yield distributions from underlying assets correctly calculated?
- **RW-06**: Are transfer restrictions properly implemented for regulatory compliance?
- **RW-07**: Is the oracle for off-chain asset valuation reliable and timely?
- **RW-09**: Is the token compatible with DeFi protocols while maintaining compliance?
- **RW-10**: Are forced transfer/freeze mechanisms limited to authorized regulators?

### MEDIUM (1)
- **RW-08**: Are maturity dates and coupon payments handled correctly for debt instruments?

## Social / SocialFi (social) — 8 checks

### HIGH (3)
- **SN-01**: Is the identity/profile system resistant to impersonation?
- **SN-03**: Is the reputation system resistant to Sybil attacks?
- **SN-07**: Is the token-gated access mechanism properly implemented?

### MEDIUM (5)
- **SN-02**: Are content creation and storage costs properly bounded?
- **SN-04**: Are tipping/payment mechanisms protected against front-running?
- **SN-05**: Is content moderation properly decentralized with appeal mechanisms?
- **SN-06**: Are follower/subscriber relationships properly stored and queryable?
- **SN-08**: Are creator revenue shares calculated correctly?

## Stablecoins (stablecoins) — 43 checks

### HIGH (1)
- **SC-34**: Is your collateral manipulation implemented securely?

### MEDIUM (42)
- **SC-01**: Is your peg maintenance strategy implemented securely?
- **SC-02**: Is your stabilization mechanisms implemented securely?
- **SC-03**: Is your collateral types & validation implemented securely?
- **SC-04**: Is your collateralization ratios implemented securely?
- **SC-05**: Is your supply expansion/contraction implemented securely?
- **SC-06**: Is your rebase mechanisms implemented securely?
- **SC-07**: Is your reference price sources implemented securely?
- **SC-08**: Is your price staleness & validation implemented securely?
- **SC-09**: Is your deviation detection implemented securely?
- **SC-10**: Is your mint authorization implemented securely?
- **SC-11**: Is your collateral handling implemented securely?
- **SC-12**: Is your redemption mechanics implemented securely?
- **SC-13**: Is your exit fee & penalties implemented securely?
- **SC-14**: Is your health monitoring implemented securely?
- **SC-15**: Is your liquidation incentives implemented securely?
- **SC-16**: Is your liquidation process implemented securely?
- **SC-17**: Is your policy implementation implemented securely?
- **SC-18**: Is your governance integration implemented securely?
- **SC-19**: Is your circuit breakers implemented securely?
- **SC-20**: Is your recovery mechanisms implemented securely?
- **SC-21**: Is your arbitrage incentives implemented securely?
- **SC-22**: Is your economic attack resistance implemented securely?
- **SC-23**: Is your fee types & calculations implemented securely?
- **SC-24**: Is your price tracking accuracy implemented securely?
- **SC-25**: Is your collateral management implemented securely?
- **SC-26**: Is your leveraged positions implemented securely?
- **SC-27**: Is your cross-chain consistency implemented securely?
- **SC-28**: Is your bridge integration implemented securely?
- **SC-29**: Is your stablecoin regulations implemented securely?
- **SC-30**: Is your reserve management implemented securely?
- **SC-31**: Is your protocol composability implemented securely?
- **SC-32**: Is your standard compliance implemented securely?
- **SC-33**: Is your peg breaking attacks implemented securely?
- **SC-35**: Is your protocol governance implemented securely?
- **SC-36**: Is your market scenarios implemented securely?
- **SC-37**: Is your operational testing implemented securely?
- **SC-38**: Is your model validation implemented securely?
- **SC-39**: Is your key metrics implemented securely?
- **SC-40**: Is your risk indicators implemented securely?
- **SC-41**: Is your reserve operations implemented securely?
- **SC-42**: Is your rebase mechanics implemented securely?
- **SC-43**: Is your seigniorage distribution implemented securely?

## Staking (staking) — 31 checks

### HIGH (23)
- **LS-01**: Is your validator registration & selection implemented securely?
- **LS-02**: Is your delegation safety implemented securely?
- **LS-03**: Is your token exchange rate implemented securely?
- **LS-05**: Is your validator rewards implemented securely?
- **LS-06**: Is your auto-compounding implemented securely?
- **LS-08**: Is your withdrawal processing implemented securely?
- **LS-09**: Is your liquidity provision implemented securely?
- **LS-10**: Is your risk mitigation implemented securely?
- **LS-11**: Is your chain-specific validation implemented securely?
- **LS-12**: Is your asset bridging implemented securely?
- **LS-13**: Is your validator performance data implemented securely?
- **LS-15**: Is your parameter updates implemented securely?
- **LS-16**: Is your upgrade safety implemented securely?
- **LS-17**: Is your inflation control implemented securely?
- **LS-18**: Is your liquidity incentives implemented securely?
- **LS-19**: Is your operator incentives implemented securely?
- **LS-22**: Is your emergency procedures implemented securely?
- **LS-24**: Is your transaction ordering implemented securely?
- **LS-25**: Is your atomic transaction risks implemented securely?
- **LS-27**: Is your network conditions implemented securely?
- **LS-28**: Is your economic stress tests implemented securely?
- **LS-30**: Is your beacon chain integration implemented securely?
- **LS-31**: Is your proof-of-stake variants implemented securely?

### MEDIUM (8)
- **LS-04**: Is your share-to-asset conversion implemented securely?
- **LS-07**: Is your protocol fees implemented securely?
- **LS-14**: Is your exchange rate oracles implemented securely?
- **LS-20**: Is your technical requirements implemented securely?
- **LS-21**: Is your role-based permissions implemented securely?
- **LS-23**: Is your defi protocol integration implemented securely?
- **LS-26**: Is your staking service compliance implemented securely?
- **LS-29**: Is your cross-protocol interactions implemented securely?

## Payment Streaming (streaming) — 8 checks

### HIGH (5)
- **ST-01**: Is the payment stream rate calculation resistant to manipulation?
- **ST-02**: Are stream cancellations properly settling remaining balances?
- **ST-06**: Are claimable amounts correctly calculated at any point in time?
- **ST-07**: Is the protocol safe against reentrancy during claim operations?
- **ST-08**: Are stream modifications (rate change, pause) properly time-bounded?

### MEDIUM (3)
- **ST-03**: Is the per-second token distribution mathematically correct?
- **ST-04**: Are multi-recipient streams correctly splitting payments?
- **ST-05**: Is the stream deposit mechanism safe against front-running?

## Token Flow Analysis (tfa) — 5 checks

### CRITICAL (1)
- **TFA-05**: Do your mathematical operations protect against overflow with extreme weight ratios and large balances?

### MEDIUM (3)
- **TFA-01**: Do your multi-slot token storage systems correctly handle index boundary conditions for tokens 4-7?
- **TFA-02**: Do your weight calculation functions maintain correct multiplier-to-token index mapping across storage slots?
- **TFA-04**: Do your storage formats maintain consistency for weights and multipliers across all slots?

### LOW (1)
- **TFA-03**: Do your weight calculations properly handle negative multipliers without silent overflow?

## Vaults / Yield (vaults) — 41 checks

### HIGH (17)
- **VT-01**: Is your exchange rate calculations implemented securely?
- **VT-03**: Is your deposit security implemented securely?
- **VT-04**: Is your withdrawal safety implemented securely?
- **VT-07**: Is your yield source integration implemented securely?
- **VT-08**: Is your risk management implemented securely?
- **VT-13**: Is your asset custody implemented securely?
- **VT-14**: Is your administrative controls implemented securely?
- **VT-15**: Is your protocol risk assessment implemented securely?
- **VT-16**: Is your liquidation protection implemented securely?
- **VT-21**: Is your sandwich attacks implemented securely?
- **VT-22**: Is your flash loan attacks implemented securely?
- **VT-23**: Is your strategy parameters implemented securely?
- **VT-25**: Is your circuit breakers implemented securely?
- **VT-30**: Is your external calls implemented securely?
- **VT-32**: Is your role-based permissions implemented securely?
- **VT-34**: Is your operational scenarios implemented securely?
- **VT-38**: Is your system health implemented securely?

### MEDIUM (24)
- **VT-02**: Is your total assets calculation implemented securely?
- **VT-05**: Is your standard implementation implemented securely?
- **VT-06**: Is your edge case handling implemented securely?
- **VT-09**: Is your compound execution implemented securely?
- **VT-10**: Is your fee distribution implemented securely?
- **VT-11**: Is your asset allocation implemented securely?
- **VT-12**: Is your price oracle integration implemented securely?
- **VT-17**: Is your leverage controls implemented securely?
- **VT-18**: Is your debt token handling implemented securely?
- **VT-19**: Is your fee types & calculations implemented securely?
- **VT-20**: Is your fee distribution implemented securely?
- **VT-24**: Is your upgrade procedures implemented securely?
- **VT-26**: Is your defi composability implemented securely?
- **VT-27**: Is your oracle dependencies implemented securely?
- **VT-28**: Is your erc-20 compatibility implemented securely?
- **VT-29**: Is your wrapper token security implemented securely?
- **VT-31**: Is your mathematical operations implemented securely?
- **VT-33**: Is your market conditions implemented securely?
- **VT-35**: Is your cross-protocol testing implemented securely?
- **VT-36**: Is your performance monitoring implemented securely?
- **VT-37**: Is your risk indicators implemented securely?
- **VT-39**: Is your lending integration implemented securely?
- **VT-40**: Is your liquidity provision implemented securely?
- **VT-41**: Is your validator management implemented securely?

## Vesting (vesting) — 8 checks

### HIGH (5)
- **VS-01**: Is the cliff period correctly enforced before any tokens are releasable?
- **VS-02**: Is the linear vesting calculation mathematically correct?
- **VS-03**: Are revocation mechanics properly implemented for revocable grants?
- **VS-04**: Is the vesting schedule immutable once created?
- **VS-08**: Is the vesting start time correctly set and not manipulable?

### MEDIUM (3)
- **VS-05**: Are multiple vesting schedules per beneficiary handled independently?
- **VS-06**: Is the total vested amount capped at the grant amount?
- **VS-07**: Are vesting tokens properly locked and not transferable before vesting?

## VRF / Randomness (vrf) — 8 checks

### CRITICAL (2)
- **VR-02**: Is the VRF callback function protected against revert attacks?
- **VR-08**: Is the VRF coordinator address verified against the official deployment?

### HIGH (4)
- **VR-01**: Is the VRF subscription adequately funded to prevent request failures?
- **VR-03**: Is the callback gas limit set high enough for all execution paths?
- **VR-04**: Is the request ID properly mapped to prevent result confusion?
- **VR-05**: Are VRF results used exactly once to prevent replay?

### MEDIUM (2)
- **VR-06**: Is the block confirmation count set appropriately to prevent reorg attacks?
- **VR-07**: Are randomness consumers properly authorized?

## Wormhole (wormhole) — 10 checks

### CRITICAL (5)
- **WH-01**: Is the VAA (Verified Action Approval) signature threshold correctly validated?
- **WH-02**: Are guardian set updates properly verified against the current set?
- **WH-03**: Is VAA replay prevented with proper nonce/hash tracking?
- **WH-04**: Are emitter addresses verified per chain?
- **WH-08**: Are governance VAAs (contract upgrades) properly gated?

### HIGH (3)
- **WH-05**: Is the consistency level appropriate for the security requirement?
- **WH-06**: Are token transfer amounts correctly converted between chains?
- **WH-10**: Are batch VAA operations handled atomically?

### MEDIUM (2)
- **WH-07**: Is the relayer integration protected against fee extraction?
- **WH-09**: Is the integration tested against Wormhole's testnet with real guardian behavior?

## Yield Optimization (yield) — 10 checks

### CRITICAL (1)
- **YF-01**: Is the reward rate calculation resistant to deposit/withdrawal manipulation?

### HIGH (6)
- **YF-02**: Are compounding intervals correctly calculated without rounding exploits?
- **YF-03**: Is the protocol protected against reward token dilution attacks?
- **YF-04**: Are multiple reward tokens handled independently?
- **YF-05**: Is the harvest/claim function protected against reentrancy?
- **YF-07**: Is the staking balance snapshot mechanism resistant to manipulation?
- **YF-09**: Is the protocol safe against reward token price manipulation?

### MEDIUM (3)
- **YF-06**: Are emission schedules correctly implemented with proper decay?
- **YF-08**: Are boosted yield mechanisms correctly calculating the boost?
- **YF-10**: Are pending rewards correctly accounted for during emergency withdrawals?

