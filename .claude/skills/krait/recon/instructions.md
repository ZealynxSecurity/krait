# Krait Recon — Architecture & Attack Surface Mapping

> Phase 0 of the Krait audit pipeline. Run before any vulnerability detection.

## Trigger

Invoked by `/krait` or `/krait-recon` on a target codebase.

## Purpose

Build a complete mental model of the protocol BEFORE looking for bugs. This phase identifies:
1. What the protocol does and what's worth stealing
2. How contracts relate to each other (trust boundaries, fund flows)
3. Where novel/custom logic lives (vs battle-tested library code)
4. What attack surfaces exist

## Execution

### Step 1: Project Identification

Read the project root for context:
- README.md, docs/, any documentation
- Package manifests (package.json, foundry.toml, Cargo.toml, hardhat.config)
- Deployment scripts, configuration files

Determine:
- **Protocol type**: DEX/AMM, Lending, Stablecoin, Yield Vault, Governance/DAO, NFT Marketplace, Oracle, Staking, Bridge, or hybrid
- **Protocol name** and brief description
- **Key dependencies**: OpenZeppelin, Chainlink, Uniswap, Aave, Compound, Solmate, etc.
- **Compiler version** and any pragma constraints

### Step 2: AST Fact Extraction (Solidity Only)

Before manually reading code for risk scoring, extract compiler-verified structural facts.

**Run this command:**
```bash
bash ~/.claude/skills/krait-recon/ast-extract.sh <project-root> .audit/ast-facts.md
```

This script will:
1. Check for `forge` availability and attempt compilation with AST output
2. If compilation succeeds: parse AST JSON via `jq` for verified inheritance trees, function signatures, call graphs, state variables, modifier usage
3. If compilation fails (missing deps, wrong solc): fall back to regex-based extraction from raw `.sol` files
4. Save all facts to `.audit/ast-facts.md` with sections: Inheritance Tree, Function Registry, State Variables, Call Graph, Modifier Definitions, Risk Score Inputs

**If extraction succeeds:**
- Use the "Risk Score Inputs" table for EXACT counts in the RISK_SCORE formula (Step 3)
- Use the "Call Graph" during Detection Pass 2 to know exactly which contracts to read
- Use the "Inheritance Tree" to verify modifier presence before reporting "missing modifier" findings
- Use the "Function Registry" to pre-populate the Function-State Matrix in Detection

**If extraction fails completely** (not a Solidity project, script not found):
- Proceed with manual approach in Step 3 as before
- Note in recon.md: "AST extraction: FAILED — using manual counts (non-deterministic)"

**CRITICAL: AST facts are SUPPLEMENTS, not replacements.** You still MUST read every file. The AST tells you WHAT exists; only reading the code tells you WHY it exists and whether it's correct.

### Step 2b: Slither Pre-Scan (Optional, Solidity Only)

If `slither` is available on PATH and the project has a Solidity compilation setup:

```bash
# Check if slither is available, run it, and extract summary
which slither && slither <project-root> --json .audit/slither-results.json 2>/dev/null && \
  bash ~/.claude/skills/krait-recon/slither-summary.sh .audit/slither-results.json .audit/slither-summary.md || true
```

**If Slither runs successfully:**
- Raw JSON saved to `.audit/slither-results.json`
- Summary extracted to `.audit/slither-summary.md` with: detector name, severity, file:line, and one-line description for each H/M finding
- These findings serve as ADDITIONAL SIGNAL during Detection Phase — they are NOT automatically reported
- Slither findings that overlap with Krait candidates increase confidence
- Slither findings that Krait missed should be investigated (potential recall boost)
- **IMPORTANT**: Many Slither detectors produce informational/low noise (reentrancy-benign, naming-convention, etc.). Only extract HIGH and MEDIUM severity Slither findings for the summary.

**If Slither is not available or fails:**
- Skip silently. Note in recon.md: "Slither pre-scan: SKIPPED (not available)"
- This is purely optional — Krait works without it

### Step 3: File Inventory & Deterministic Risk Scoring

Scan all source files. **SKIP**: test files, scripts, mocks, interfaces-only files (no function bodies), node_modules, lib/, build artifacts, files >90% comments.

**SCOPE EXPANSION — Base/Parent Contracts**: If a core contract inherits from a non-library contract in the project (e.g., `base/`, `abstract/`, `common/`, `protocol-rewards/`), that base contract MUST be included in scope and scored. Any file imported and inherited by a Tier 1 file gets auto-promoted to minimum Tier 2. Standard library imports (OpenZeppelin, Solmate) are excluded — only project-specific base contracts.

**For each remaining file, compute a RISK SCORE:**

**If `.audit/ast-facts.md` exists**: Use the exact counts from the "Risk Score Inputs" table for `external_calls`, `state_writing_functions`, `payable_functions`, `assembly_blocks`, `unchecked_blocks`, and `LOC`. Only `novel_code_bonus` and `value_handling_bonus` require manual judgment from reading the code.

**If `.audit/ast-facts.md` does NOT exist**: Fall back to manual counting by reading each file.

```
RISK_SCORE = (external_calls × 5) + (state_writing_functions × 4) + (payable_functions × 4)
           + (assembly_blocks × 6) + (unchecked_blocks × 3) + (LOC × 0.05)
           + (novel_code_bonus)      # +15 if NOT from OpenZeppelin/Solmate/standard library
           + (value_handling_bonus)   # +10 if handles ETH/token transfers
           + (immaturity_bonus)       # +10 if contract has NO prior audit coverage or is newly written
```

Where:
- **external_calls**: Count of `.call`, `.transfer`, `.safeTransfer`, interface method calls, `delegatecall`
- **state_writing_functions**: Count of public/external functions that write storage (use `sstore` or assign to state variables)
- **payable_functions**: Count of `payable` functions
- **assembly_blocks**: Count of `assembly { }` blocks
- **unchecked_blocks**: Count of `unchecked { }` blocks
- **novel_code_bonus**: +15 if the contract is NOT a standard OpenZeppelin/Solmate contract (check imports — if it inherits from OZ but adds significant custom logic, it gets the bonus)
- **value_handling_bonus**: +10 if the contract transfers ETH or ERC20 tokens
- **immaturity_bonus**: +10 if the contract meets ANY of: (a) not present in any prior audit report linked in docs/README, (b) added/significantly modified after the last audit (check git history if available), (c) has no test coverage file (no corresponding test file in test/ directory), (d) contains TODO/FIXME/HACK comments indicating unfinished work. If prior audit reports exist, contracts NOT in the audit scope are immature by default.

**RANK all files by RISK_SCORE descending and assign tiers:**
- **TIER 1 (DEEP)**: Top 5 files by score — get full 3-pass treatment in Detection
- **TIER 2 (STANDARD)**: Next 10 files — get standard Pass 1 analysis
- **TIER 3 (SCAN)**: Remaining files — quick scan only (function signatures + obvious patterns)

For SMALL codebases (≤15 files), all files are effectively Tier 1.

**This tier table is the CONTRACT between Recon and Detection. Detection MUST follow these tiers.**

### Step 3: Architecture Map

Build the following artifacts by reading the actual code:

#### 3a. Contract Role Map

For each core contract, identify:
- **Purpose**: What does this contract do in one sentence?
- **Risk level**: HIGH (handles funds, critical state), MEDIUM (access control, configuration), LOW (view-only, events)
- **Key state variables**: What persistent state does it manage?
- **External dependencies**: What does it call? What calls it?

#### 3b. Fund Flow Map

Trace how value moves through the system:
- Where do tokens/ETH enter? (deposit, mint, swap functions)
- Where do they exit? (withdraw, redeem, claim, liquidate)
- What intermediate state do they pass through?
- Who can trigger each flow?

#### 3c. Trust Boundary Map

Identify trust assumptions:
- Which addresses are trusted (owner, admin, oracle, keeper)?
- What can each trusted role do? Can they rug?
- Which functions are permissionless? What can any user trigger?
- Where does the protocol trust external data? (oracles, callbacks, user input)

#### 3d. Contract Maturity Assessment

For each core contract, assess maturity to inform the `immaturity_bonus` in RISK_SCORE:

| Contract | Prior Audit? | Test File? | TODO/FIXME? | Maturity |
|----------|-------------|------------|-------------|----------|

Check:
- **Prior audit coverage**: Does README or docs reference previous audits? Which contracts were in scope? Contracts NOT in any prior audit scope = immature.
- **Test coverage**: Is there a corresponding test file in `test/` or `tests/`? Untested contracts = immature.
- **Unfinished markers**: Search each file for `TODO`, `FIXME`, `HACK`, `XXX`, `TEMP`, `WORKAROUND` comments. Any present = immature.
- **Git recency** (if git history available): Was the contract recently added or significantly modified? `git log --oneline -5 <file>` shows recent changes.

Contracts flagged as immature get `immaturity_bonus = +10` in the RISK_SCORE formula, which may promote them to a higher tier.

#### 3e. Inheritance & Import Graph

Map which contracts inherit from which, and what they import. Flag:
- Contracts that override virtual functions (modified behavior vs base)
- Multiple inheritance (diamond problem potential)
- Custom implementations of standard interfaces (ERC20, ERC721, ERC4626)

### Step 3b: Fee Path Mapping

List EVERY function that charges a fee. For each:
- What type of fee? (protocol fee, user fee, royalty, flash fee, change fee)
- How is it calculated? (basis points on gross? on net? flat amount? scaled by decimals?)
- Where is it sent? (factory, pool, recipient, burned)
- What happens when fee is 0?

This map is critical for cross-checking fee consistency in the Detection phase.

### Step 3c: Untrusted Recipient Map

List every ETH/token transfer where the recipient is NOT msg.sender and NOT a hardcoded protocol address:
- Royalty recipients (from ERC-2981 registry)
- Callback receivers (onFlashLoan, onERC721Received)
- Fee recipients from external registries
- Oracle/external data sources

These are reentrancy and DOS surfaces.

### Step 4: Attacker Mindset Recon

Answer these four questions:

1. **What's worth stealing?** List all value stores — token balances, LP positions, collateral, reward pools, governance power, NFT ownership.

2. **What's the kill chain?** For each value store, what's the shortest path from "anyone can call this" to "value is extracted"? Identify the gates (access control, validation, timelocks) an attacker must bypass.

3. **What's novel?** What code was written specifically for this protocol (not copied from OpenZeppelin/Solmate/etc.)? Novel code = novel bugs. Flag any non-standard implementations of standard patterns.

4. **What's complex?** Which functions have: deep nesting, multiple external calls, state reads + writes + external interactions in one tx, callback patterns, assembly blocks?

### Step 5: Protocol-Specific Checklist Selection

Based on protocol type, select the relevant vulnerability checklist:

**DEX/AMM**: Price manipulation (flash loan spot price), LP accounting (first depositor), slippage/MEV (deadline, min output), fee-on-transfer tokens.

**Lending**: Oracle manipulation (stale price, flash loan inflate), liquidation logic (self-liquidate, bonus calc), interest rate rounding, bad debt scenarios.

**Stablecoin**: Peg mechanism gaming, undercollateralized minting, cascading liquidation death spirals.

**Yield Vault / ERC4626**: Share inflation (first depositor), deposit/withdraw rounding direction, donation attacks, strategy compromise.

**Governance/DAO**: Flash loan voting, snapshot manipulation, proposal replay, timelock bypass.

**NFT Marketplace**: Order replay, royalty bypass, ERC721 callback reentrancy, approval scope.

**Oracle**: Staleness checks, zero/negative price, L2 sequencer uptime, manipulation resistance.

**Staking**: Reward gaming (stake before distribution), unbonding bypass, dust precision loss.

**Chainlink Integration**: stale price (updatedAt + heartbeat), zero/negative answer, roundId validation, L2 sequencer feed.

**Uniswap Integration**: slot0 is manipulable (never use as oracle), use TWAP via observe(), price impact/slippage, tick rounding on concentrated liquidity.

### Step 6: Module Selection (Trigger Flag System)

Based on what you discovered in Steps 1-5, evaluate each detection module's trigger condition and select the ones that apply. **This is deterministic — if the trigger condition is met, the module is selected.**

Evaluate each module file in `~/.claude/skills/krait/detector/modules/` against what you found:

**Module tier hierarchy:**
- **Tier 0 (always-load)**: `access-control-state.md` — always active for every audit
- **Tier 1 (protocol-type)**: Core domain modules — selected when protocol matches a specific type (lending, DEX, vault, etc.)
- **Tier 2 (feature-detected)**: Specialized modules — selected when specific features/patterns are detected in code

| Module File | Tier | Trigger Condition | Select If... |
|---|---|---|---|
| `access-control-state.md` | 0 | Always active | Always selected — every protocol has access control |
| `oracle-analysis.md` | 1 | Protocol uses Chainlink, TWAP, Pyth, Band, or any external price feed | You found oracle imports, `latestRoundData`, `getPrice`, TWAP calls, or price-dependent logic |
| `erc4626-vault-deep.md` | 1 | Protocol implements ERC-4626 or custom share-based vault | You found ERC4626 inheritance, `convertToShares`, `convertToAssets`, share-based deposit/withdraw |
| `lending-liquidation-deep.md` | 1 | Protocol has lending/borrowing/liquidation mechanics | You found `borrow`, `repay`, `liquidate`, health factor checks, or interest accrual |
| `amm-mev-deep.md` | 1 | Protocol is DEX/AMM or deeply integrates with liquidity pools | You found swap functions, liquidity provision, tick math, or pool interaction |
| `economic-design.md` | 1 | Protocol has token economics, fee structures, liquidation mechanics, or incentive systems | You found fee calculations, reward distributions, liquidation logic, or tokenomics |
| `governance-voting.md` | 1 | Protocol has voting, proposals, delegation, quorum, or governance tokens | You found governance contracts, voting functions, delegation, or quorum logic |
| `flash-loan-interaction.md` | 2 | Protocol reads `balanceOf(address(this))`, uses spot prices, has deposit/withdraw, or integrates with flash-loan-capable protocols | You found `balanceOf(address(this))`, spot price reads, or deposit+withdraw in same-tx-capable flows |
| `token-flow-tracing.md` | 2 | Any `transfer`, `transferFrom`, `safeTransfer`, `mint`, `burn`, `balanceOf(this)` | You found token transfers (virtually always selected for DeFi) |
| `external-protocol-integration.md` | 2 | Protocol integrates with Uniswap, Aave, Compound, Curve, Chainlink, Convex, Lido, or any external DeFi protocol | You found external protocol imports or interface calls to known DeFi protocols |
| `eip-standard-compliance.md` | 2 | Protocol implements ERC-20, ERC-721, ERC-4626, ERC-1155, ERC-2981, ERC-3156, EIP-712 | You found ERC/EIP interface implementations or standard compliance claims |
| `cross-chain-bridge.md` | 2 | Protocol bridges assets/messages across chains | You found LayerZero, CCIP, Wormhole, Axelar, Hyperlane, or custom bridge/relayer code |
| `multi-tx-attack.md` | 2 | Protocol has deposit+withdraw, staking+claiming, or sequenceable operations | You found operations that can be called in sequence within the same block |
| `eip7702-delegation.md` | 2 | Protocol uses EIP-7702 or handles delegated EOAs | You found `EXTCODESIZE` checks for EOA detection, `tx.origin` usage, or EIP-7702 delegation handling |
| `account-abstraction-erc4337.md` | 2 | Protocol implements ERC-4337 or handles UserOperations | You found `validateUserOp`, `IEntryPoint`, `UserOperation` struct, paymaster logic, or bundler interaction |

**Selection rules:**
- Select ALL modules whose trigger condition is met — do not cap the count
- `access-control-state.md` is ALWAYS selected
- For DeFi protocols, `token-flow-tracing.md` and `economic-design.md` are almost always selected
- Record the trigger evidence (what you found that triggered the module)

## Output

Save to `.audit/recon.md` with:

```markdown
# Krait Recon Report

## Protocol Overview
- Name: [name]
- Type: [type(s)]
- Dependencies: [list]
- Compiler: [version]
- Scope size: [X files, Y total LOC]

## File Risk Table (MANDATORY — Detection phase follows this)
| Rank | File | RISK_SCORE | Tier | LOC | Ext Calls | State Writers | Notes |
|------|------|-----------|------|-----|-----------|---------------|-------|
| 1 | Core.sol | 87 | DEEP | 450 | 12 | 8 | Handles all funds |
| 2 | ... | ... | ... | ... | ... | ... | ... |

Codebase size category: SMALL (≤15) / MEDIUM (16-40) / LARGE (40+)

## Fund Flows
[How value moves through the system]

## Trust Boundaries
[Who is trusted, what can they do, permissionless surfaces]

## Attack Surface Priority
1. [Highest-risk area and why]
2. [Second-highest]
3. ...

## Novel Code (not from libraries)
[Custom implementations to scrutinize]

## Detection Primer
Loaded: [primer filename(s)]

## Activated Modules
| Module | Trigger Evidence |
|--------|-----------------|
| access-control-state.md | Always active |
| oracle-analysis.md | Found Chainlink latestRoundData in PriceFeed.sol |
| token-flow-tracing.md | Found safeTransfer in Vault.sol, Pool.sol |
| ... | ... |

## Relevant Checklists
[Protocol-specific checks to apply]
```

## Rules

- **Read actual code, not just file names.** Open every core contract and understand it.
- **Do NOT start looking for bugs yet.** This phase is strictly reconnaissance.
- **Be honest about complexity.** If you don't understand a piece of code, flag it as needing deep analysis.
- **Track inheritance carefully.** Many "missing" checks exist in parent contracts. Use the AST Inheritance Tree if available.
- **AST facts override manual counts.** If `.audit/ast-facts.md` exists, its Risk Score Inputs are ground truth for the RISK_SCORE formula. Do not re-count manually.
