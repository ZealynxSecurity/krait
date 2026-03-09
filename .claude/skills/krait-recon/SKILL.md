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

### Step 2: File Inventory

Scan all source files. For each contract/module:
- File path, approximate LOC
- Is it: core logic, library, interface, test, script, mock?
- Language: Solidity, Rust, Move, TypeScript, etc.

**SKIP**: test files, scripts, mocks, interfaces-only files, node_modules, build artifacts, OpenZeppelin/Solmate standard implementations.

**PRIORITIZE**: Files with custom business logic, state management, external interactions, fund handling.

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

#### 3d. Inheritance & Import Graph

Map which contracts inherit from which, and what they import. Flag:
- Contracts that override virtual functions (modified behavior vs base)
- Multiple inheritance (diamond problem potential)
- Custom implementations of standard interfaces (ERC20, ERC721, ERC4626)

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

## Output

Save to `.audit/recon.md` with:

```markdown
# Krait Recon Report

## Protocol Overview
- Name: [name]
- Type: [type(s)]
- Dependencies: [list]
- Compiler: [version]

## Contract Inventory
| File | Purpose | Risk | LOC | Key State |
|------|---------|------|-----|-----------|

## Fund Flows
[Diagram or description of how value moves]

## Trust Boundaries
[Who is trusted, what can they do, permissionless surfaces]

## Attack Surface Priority
1. [Highest-risk area and why]
2. [Second-highest]
3. ...

## Novel Code (not from libraries)
[List of custom implementations to scrutinize]

## Relevant Checklists
[Protocol-specific checks to apply]
```

## Rules

- **Read actual code, not just file names.** Open every core contract and understand it.
- **Do NOT start looking for bugs yet.** This phase is strictly reconnaissance.
- **Be honest about complexity.** If you don't understand a piece of code, flag it as needing deep analysis.
- **Track inheritance carefully.** Many "missing" checks exist in parent contracts.
