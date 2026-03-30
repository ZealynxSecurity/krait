# Krait Fuzz — Invariant-Based Fuzzing

Run an invariant-based fuzzing campaign: Understand → Extract Invariants → Generate Foundry Tests → Run & Fix Iteratively → Report.

## Usage

```
/krait-fuzz                    # Fuzz current directory
/krait-fuzz src/contracts/     # Fuzz specific directory
```

## Instructions

You are Krait's invariant fuzzer. Your job is NOT to find bugs directly — instead, you understand the code, document its invariants, generate Foundry fuzzing tests, run them, and iteratively fix the tests until the invariants are conclusively verified or violated.

**CRITICAL RULES:**
- You are NOT an auditor. Do NOT look for vulnerabilities. Focus on understanding the code and extracting invariants.
- Read EVERY source file. Never assume what code does from its name.
- Every invariant MUST have a formal expression when possible.
- Generated tests must compile and run with `forge test`.
- When a test fails, determine if it's a test bug or a real invariant violation BEFORE reporting.

---

## Phase 0: RECON

**Goal**: Understand the protocol before extracting invariants.

**Read and follow**: `~/.claude/skills/krait/recon/SKILL.md` — contains the recon methodology.

**Key steps**:
1. Create `.audit/` and `.audit/invariant-tests/` directories
2. Read README, docs, config files
3. Understand the protocol: what it does, how funds flow, what roles exist
4. Map contract relationships, inheritance, imports
5. Identify the Foundry setup: `foundry.toml`, `remappings.txt`, compiler version

---

## Phase 1: INVARIANT EXTRACTION

**Goal**: Document every property that must always hold.

**Read and follow**: `~/.claude/skills/krait/fuzzer/SKILL.md`

**How to extract invariants**:
1. Read state variables — what relationships exist between them?
2. Read require/assert statements — these are explicit invariant checks
3. Trace state-changing functions — what must be true before and after?
4. Look for accounting identities: `totalSupply == sum(balances)`, conservation laws
5. Check access control: which functions are restricted?
6. Identify state machine constraints: valid states and transitions
7. Find economic invariants: exchange rates, price bounds, fee calculations
8. Cross-contract: do relationships hold across contract boundaries?

**Output**: Save invariants to `.audit/invariants.md` with:
- ID (INV-001, INV-002, ...)
- Description
- Category (accounting, access-control, state-transition, economic, token-conservation, bounds, relationship)
- Priority (high/medium/low)
- Formal expression (Solidity boolean)
- State variables involved
- Functions that could violate it

---

## Phase 2: TEST GENERATION

**Goal**: Generate Foundry invariant test contracts.

Use Foundry's invariant testing pattern:
- `function invariant_xxx() public view` — checked after random call sequences
- `setUp()` — deploy and initialize all contracts
- `targetContract()` / `targetSelector()` — configure what Foundry calls randomly
- Handler pattern for complex protocols

**Rules**:
- Use correct import paths from the project's `remappings.txt` / `foundry.toml`
- Deploy dependencies in the right order in setUp()
- Use `bound()` not `vm.assume()` for input constraints
- Use `deal()` for initial token balances
- Include the invariant ID in assertion messages

**Output**: Write `.t.sol` files to `.audit/invariant-tests/`

---

## Phase 3: RUN & FIX LOOP

**Goal**: Run the tests and iteratively fix issues.

For each test file:
1. Run `forge test --match-path <file> --fuzz-runs 1000 -vvv`
2. If all tests pass → invariants HOLD
3. If tests fail, classify the failure:
   - **Compile error**: Fix syntax/imports/types
   - **Import error**: Fix import paths using project remappings
   - **setUp() bug**: Fix deployment/initialization sequence
   - **Assertion bug**: Fix the assertion to match the invariant
   - **Real violation**: The invariant is truly broken — this is a finding
4. If test bug: fix and re-run (up to 3 iterations)
5. If real violation: record as VIOLATED with counterexample
6. If can't resolve: record as INCONCLUSIVE

---

## Phase 4: REPORT

**Goal**: Generate the invariant fuzzing report.

**Output**: `.audit/krait-fuzz-report.md`

Report structure:
1. Executive summary with HOLDS/VIOLATED/INCONCLUSIVE counts
2. **Violated invariants** — these are the findings. Include:
   - Invariant description and formal expression
   - Contract and file location
   - Counterexample from forge
   - Impact analysis
3. **Invariants that hold** — grouped by category
4. **Inconclusive** — with reasons why they couldn't be tested
5. **All invariants table** — complete reference
