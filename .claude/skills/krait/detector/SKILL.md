# Krait Detector — Feynman Interrogation + Pattern-Aware Detection

> Phase 1 of the Krait audit pipeline. Runs after Recon.

## Trigger

Invoked by `/krait` (as part of full audit) or `/krait-detect` (standalone).

## Prerequisites

- `.audit/recon.md` must exist (from krait-recon phase)
- Read the recon report before starting

## Purpose

Find vulnerability CANDIDATES through systematic first-principles interrogation of every significant function, enhanced with knowledge of 40+ real exploit patterns. This phase maximizes RECALL — cast a wide net. The Critic phase will filter false positives later.

## Core Philosophy

**"If you cannot explain WHY a line of code exists, you do not understand it — and where understanding breaks down, bugs hide."**

Do NOT pattern-match. REASON about the code. Ask WHY each decision was made, WHAT breaks if it changes, and WHO benefits from an exploit.

## Execution

### Step 1: Load Context

Read `.audit/recon.md` and `.audit/known-issues.md` to understand:
- **File Risk Table** — The ranked table of files with RISK_SCORE and Tier assignments. This is your execution contract. Follow the tiers.
- Protocol type and relevant checklists
- Fund flows and trust boundaries
- **Known/acknowledged issues** — Do NOT generate candidates for these (Gate H)
- **Fork origin** — If this is a fork, what is the original? Inherited behavior = intentional design (Gate C)
- **Token context** — What SPECIFIC tokens does this protocol use? Every token-behavior finding must name a specific token from this list (Gate B)
- **Detection primer** — Read the protocol-specific primer from `primers/` directory (loaded during Recon). The primer's CRITICAL checks are your DEEP DIVE priorities. Primers: `defi-dex-amm.md`, `defi-lending.md`, `defi-staking-governance.md`, `gamefi-nft.md`, `bridge-crosschain.md`, `proxy-upgrades.md`, `wallet-safe-aa.md`.
- **Protocol-targeted modules** — Which 6 modules from Step 5 are marked DEEP DIVE in recon.md? Spend 2-3x more time on these.

**Also read `.audit/ast-facts.md` if it exists** — these are compiler-verified structural facts (ground truth):
- **Inheritance Tree**: Use to verify modifier presence. A "missing" modifier may exist in a parent listed here. Do NOT report missing modifiers without checking the full inheritance chain.
- **Function Registry**: Use to pre-populate the Function-State Matrix (Step 2). Copy verified function signatures, visibility, mutability, and modifiers — don't re-derive from scratch.
- **Call Graph**: Use during Pass 2 cross-contract reads to identify EXACTLY which files to open for each external call. Do NOT guess from interface names.
- **Modifier Definitions**: Cross-reference which functions use which modifiers. Siblings missing a modifier that others have = candidate.
- Do NOT override AST facts with your own inference. If the AST says function X has modifier Y, it has modifier Y.

**Also read `.audit/slither-summary.md` if it exists** — these are static analysis findings from Slither:
- Use as ADDITIONAL SIGNAL, not as auto-reported findings
- If a Slither finding overlaps with one of your candidates → increased confidence
- If Slither flagged something you missed → investigate that area during Pass 2 lenses (reentrancy → Lens C, access control → Lens A, precision → Lens D)
- Focus on HIGH/MEDIUM Slither findings only; ignore informational/low

### Step 1b: Live Solodit Enrichment (if MCP available)

If the `krait-solodit` MCP server is available, use it to enrich detection with real-time Solodit data:

1. **Protocol enrichment** — Call `mcp__krait-solodit__get_enrichment` with the protocol type from recon (e.g., "DEX / AMM", "Lending"). This returns 10-15 HIGH-severity findings from real audits of similar protocols. Use these as additional reference when analyzing code — they show what went wrong in production.

2. **During detection** — When you identify a suspected vulnerability, call `mcp__krait-solodit__search_similar_findings` with a description. If Solodit returns similar findings, this is strong corroboration. Note the match count in your candidate output.

3. **During verification (optional)** — Call `mcp__krait-solodit__validate_hypothesis` to check historical precedent. HIGH confidence from Solodit = the bug pattern is real. LOW confidence = either novel or false positive — verify more carefully.

**IMPORTANT**: MCP tools can fail (timeout, API down, no API key). If any call fails, continue without it — the static patterns and heuristics are sufficient. MCP enrichment is additive, never blocking.

### ADAPTIVE PASS STRATEGY

**The codebase size determines analysis depth. Count scope files from the recon.md risk table:**

#### SMALL codebase (≤15 scope files): Full 3-Pass
All files get Tier 1 treatment. Every file gets full analysis + cross-contract read + what's-missing sweep.

#### MEDIUM codebase (16-40 scope files): Tiered 3-Pass
Follow the Tier 1/2/3 assignments from recon.md risk table exactly.
- **Tier 1** (top 5 by RISK_SCORE): Full 3-pass treatment with cross-contract reads
- **Tier 2** (next 10): Standard Pass 1 analysis only
- **Tier 3** (remaining): Quick scan — function signatures + obvious patterns only

#### LARGE codebase (40+ scope files): Budget-Controlled Triage
**You CANNOT deeply analyze 40+ files. Do not try. Instead:**
1. **Tier 3 files**: Read the FULL file but only analyze: function signatures, modifiers, access control, state-writing lines. ~1 min per file.
2. **Tier 2 files**: Standard Pass 1 (Function-State Matrix + Feynman on public/external only). ~2 min per file.
3. **Tier 1 files** (top 5): Full deep dive with cross-contract reads, line-by-line, all modules. **Spend 80% of total analysis time here.**
4. **CRITICAL promotion rule**: After Tier 1 analysis, check if any Tier 2/3 file is called by a Tier 1 file. If yes, promote to Tier 1 for cross-contract read. Max 3 promotions.

**FILE COVERAGE GUARANTEE**: Every scope file MUST be read at least once. Never skip a file because it "looks like a simple wrapper." 28% of missed findings in shadow audits were in files the agent never opened.

---

**Pass 1 — Tiered Scan:**
For Tier 1/2 files: apply Function-State Matrix (Step 2), Feynman Interrogation (Step 3), and Heuristic Triggers (Step 4). For Tier 3 files: scan function signatures and flag obvious patterns only. Record candidates.

**Pass 1→2 Handoff — Compile the Pass 1 Brief (MANDATORY):**

Before starting Pass 2, compile ALL Pass 1 candidates into a structured brief:
```
PASS 1 BRIEF:
- Candidates found: [list with file, line, severity, one-line summary]
- Files with NO candidates: [list — these need extra scrutiny in Pass 2]
- Suspicious areas flagged but not promoted to candidate: [list]
- Slither findings NOT yet covered by a candidate: [list from slither-summary.md]
```

This brief is the INPUT to every Pass 2 lens. It ensures Pass 2 is INFORMED, not blind. The highest-impact findings in competitive benchmarks came from informed second passes (Ross 21-tool study: the "composite super-prompt" that fed prior results into a second pass found the single highest-severity finding that no individual tool caught alone).

**ANTI-ANCHORING RULE**: The brief tells you what was found — it does NOT tell you what is safe. If Pass 1 marked an area "no issues found," Pass 2 MUST NOT skip that area. Pass 1's "safe" verdicts are HYPOTHESES, not facts. 13% of all missed findings were in areas explicitly marked safe. Treat "no candidates in file X" as "file X is UNDER-ANALYZED," not "file X is clean."

**Pass 2 — Parallel Lens Deep Dive (Tier 1 files ONLY, max 5):**

Re-read the Tier 1 files from the recon.md risk table. Each lens receives the **Pass 1 Brief** as context. Each lens has TWO jobs:
1. **Validate & deepen**: For Pass 1 candidates in this lens's domain, re-examine with fresh eyes. Can you strengthen the exploit trace? Find a deeper root cause? Identify a more severe impact?
2. **Find what Pass 1 missed**: The brief tells you what was already found. Focus your time on areas/files where Pass 1 found NOTHING — those are the blind spots.

Analyze through **4 independent focused lenses**. Each lens looks at the SAME code but with a DIFFERENT mental model. This catches bugs that a single-pass analysis misses because it's impossible to hold all attack models simultaneously.

**Protocol-specific lens loading**: Check recon.md for the DEEP DIVE modules selected in Phase 0 (D1-D30 numbers). Map each to the correct lens:
- **Lens A**: D8, D17, D23, D28(partial), D29 (Ownership, Derived Class, Governance, Missing Functionality, Restrictions)
- **Lens B**: D4, D9, D11, D14, D16, D20, D27 (Fees, Weight, Economic Attack, Params, Multi-Tx, Payment, Economic Design)
- **Lens C**: D1, D3, D13, D15, D21, D24, D25, D26 (Recipients, Transfer Order, Token Compat, External Protocol, Bridge, State Transfer, Batch, DeFi Integration)
- **Lens D**: D2, D5, D6, D7, D10, D12, D18, D19, D22, D30 (Type Cast, Standards, Token Compat, Factory, Assembly, Infra, State Lifecycle, DoS, NFT, Version Compliance)
If a DEEP DIVE module maps to a lens, that lens MUST execute it fully (not just skim).

**Run all 4 lenses, then merge candidates. Each lens produces its own candidate list.**

#### Lens A: Access Control, State Integrity & Governance
**From Pass 1 Brief**: Check which files had NO access-control candidates. Prioritize those.
**Mandatory modules**: H (Ownership/Permission Persistence), L (Derived Class/Override Completeness), R (Governance Voting Integrity), W (Missing Functionality — missing unsetters/pause)
**Mandatory heuristics**: MODIFIER-01, AC-01 to AC-04, GOV-01, GOV-02, MISSING-01, MISSING-02, ZERO-WEIGHT-01

**Multi-Mindset Analysis** — For each function, ask ALL FOUR questions:
1. **[Attacker]** How would I exploit these permissions to drain funds or escalate privilege?
2. **[Accountant]** Do the access checks match the value at risk? Is a low-privilege function guarding high-value state?
3. **[Spec Auditor]** Do the modifiers/roles match what docs, comments, and NatSpec promise?
4. **[Edge Case]** What happens if caller is the contract itself, address(0), the owner, or a self-delegating governance token?

Focus EXCLUSIVELY on:
- WHO can call each function? Is that the right set of callers?
- Can functions execute in an order that breaks invariants?
- Are state transitions valid? Can states be skipped/reversed?
- Missing access modifiers — compare sibling functions (MODIFIER-01)
- Permissionless functions that should be restricted
- Cross-function state consistency (if A guards state X, do all writers of X have guards?)
- **Governance invariants (GOV-01)**: When tokens are burned/auctioned/locked, is voting power removed from quorum denominators? Inaccessible voting power → quorum unreachable.
- **Delegation integrity (GOV-02)**: Can a delegatee prevent redelegation? Checkpoint gas exhaustion?
- **Zero-supply edge (GOV-01 variant)**: What happens when totalSupply=0? Quorum=0 → anything passes.

#### Lens B: Value Flow & Economic Logic
**From Pass 1 Brief**: Check which value-handling functions had NO candidates. Trace those first.
**Mandatory modules**: D (Fee Consistency), I (Weight/Proportionality), K (Multi-Transaction Attacks), O (Payment/Distribution), V (Economic Design)
**Mandatory heuristics**: ECON-01, ECON-02, FDC-01, FDC-02, PR-01 to PR-03, FL-01, SI-01, TVL-01

**Multi-Mindset Analysis** — For each value-handling function, ask ALL FOUR questions:
1. **[Attacker]** How would I extract more value than I put in? Flash loan paths? Fee manipulation?
2. **[Accountant]** Trace every wei: entry amount → fees → shares → exit amount. Do debits equal credits?
3. **[Spec Auditor]** Do fee percentages, distribution ratios, and reward rates match what docs/comments specify?
4. **[Edge Case]** What happens with amount=0, amount=1 wei, amount=type(uint256).max, or first/last depositor?

Focus EXCLUSIVELY on:
- Where does value enter and exit? Trace every ETH/token transfer
- Fee calculations: consistent basis? consistent destination? zero-fee edge case?
- Rounding direction: who benefits? Can attacker force rounding to zero via flash loan?
- First depositor / share inflation attacks
- Liquidation profitability boundaries
- Circular collateral / reflexive valuation
- Payment-on-failure: are refunds correct?
- **Payment destination correctness (Module O)**: Is `owner()` (deployer) vs `ownerOf(tokenId)` (NFT holder) correct? Double payout? Conditional payment with unconditional cost?

#### Lens C: External Interactions & Cross-Contract
**From Pass 1 Brief**: Check which external calls were NOT investigated. Prioritize uncovered cross-contract interactions.
**Mandatory modules**: A (Untrusted Recipient), C (Transfer Order/Implicit Flash Loans), J (External Protocol Integration), P (Cross-Chain Bridge), S (Cross-Contract State on Transfer)
**Mandatory heuristics**: AEC-01 to AEC-03, ROR-01, RE-01, EXT-01 to EXT-03, CALLBACK-01, HOOK-01, BRIDGE-01 to BRIDGE-04

**Multi-Mindset Analysis** — For each external call, ask ALL FOUR questions:
1. **[Attacker]** Can I deploy a malicious contract at the target address? What callbacks can I trigger?
2. **[Accountant]** Does value sent out match value expected back? Are return values checked and used correctly?
3. **[Spec Auditor]** Does the integration match the external protocol's documented interface and assumptions?
4. **[Edge Case]** What if the external contract reverts, returns empty data, self-destructs, or is upgraded?

Focus EXCLUSIVELY on:
- **MANDATORY Cross-Contract Read**: For each external call in Tier 1 files, ACTUALLY open and read the target. **FIRST**: Check the Call Graph in `.audit/ast-facts.md` for exact targets. Then read each target and check: state modifications, callbacks, permissionless functions, ignored return values.
- CEI violations: ALL state updates BEFORE external calls?
- Reentrancy via callbacks (ERC721/1155 onReceived, ETH receive)
- External protocol integration: permissionless claims, shutdown, silent failures
- Version compatibility: Safe version, OZ version, Solidity version
- **This lens addresses the #1 structural reason for missed findings** — 14% of misses from analyzing contracts in isolation.

#### Lens D: Edge Cases, Math & Standards
**From Pass 1 Brief**: Check which math-heavy functions and standard implementations had NO candidates. Those are likely under-analyzed.
**Mandatory modules**: B (Type Cast Safety), E (EIP/Standard Compliance), F (Token Compatibility), G (Factory/Deployment), M (State Variable Lifecycle), X (Version & Standard Compliance)
**Mandatory heuristics**: SIG-01, SIG-02, TOK-01 to TOK-03, ETH-01, ETH-02, PRX-01, PRX-02, INJ-01, PACKED-01, PERMIT-01, HASH-01, ID-01, LIB-01, CHAIN-01

**Multi-Mindset Analysis** — For each math-heavy or standards function, ask ALL FOUR questions:
1. **[Attacker]** Can I craft inputs that cause overflow, underflow, or division by zero to extract value?
2. **[Accountant]** Trace 3 concrete value sets through the arithmetic — does the output match what's expected?
3. **[Spec Auditor]** Does this ERC implementation match the EIP spec exactly? Character-by-character for EIP-712.
4. **[Edge Case]** What happens at param=0, param=1, param=MAX, empty array, sender==receiver, tokenA==tokenB?

Focus EXCLUSIVELY on:
- Parameter boundary testing: param=0, param=1, param=MAX, input=0
- Type cast safety: every uint128(x), uint96(x) — can source exceed target max?
- EIP-712 typehash verification: character-by-character comparison
- Epoch/period boundary behavior
- Division by zero paths
- Assembly correctness (if any): bounds, slot arithmetic, bit operations
- Standard compliance (ERC20/721/4626/3156): actual vs spec
- **JSON/metadata injection (INJ-01)**: Does tokenURI or any string concatenation include user-controlled data without escaping?
- **State variable lifecycle (Module M)**: Trace every user-state variable through mint/burn/re-mint cycles. Admin functions update ALL related variables?
- **Mechanical arithmetic verification**: For the TOP 3 most complex arithmetic functions (by operator count), do NOT just read and judge. TRACE with concrete values: pick 3 sets of inputs (normal case, zero/boundary case, adversarial case) and manually compute each step. Compare your result with what the code produces. If they diverge → candidate. This catches bugs like `debtCeiling()` where 5 findings hid in one function that "looked correct."
- **Self-transfer / self-referential edge case**: For every transfer/swap function, check: what happens when sender==receiver, tokenA==tokenB, from==to? Memory-cached state may not reflect storage updates within the same call.

**After all 4 lenses complete — Consensus Merge:**
1. Merge all candidates from Pass 1 + all 4 lenses
2. Deduplicate: same file + same function + same root cause → keep the most detailed version
3. **Cross-lens amplification**: If Lens A found a missing guard AND Lens B found a value extraction on the same function → the combined finding is stronger than either alone. Combine into a single high-confidence candidate.
4. **Consensus scoring** — count how many independent sources (Pass 1 + 4 lenses) found each candidate:
   - **STRONG consensus (3+ sources)**: Almost certainly real. Tag as `consensus: strong`. Fast-track through critic.
   - **MODERATE consensus (2 sources)**: Confidence boost. Tag as `consensus: moderate`. Normal critic scrutiny.
   - **NO consensus (1 source)**: Tag as `consensus: single`. Critic applies extra scrutiny — why did the other passes miss it?
   - The consensus tag travels with the finding into state analysis and critic phases.
5. **Multi-mindset convergence bonus**: If the SAME finding was discovered by different mindset questions across lenses (e.g., Lens A's [Attacker] question and Lens B's [Accountant] question both found the same drain path), this is the strongest possible signal — independent reasoning paths converged on the same bug.

**SAFE Verdict Challenge (applies to ALL lenses):** For every area verified as "safe," you MUST write: (a) the SPECIFIC invariant verified, (b) at least 3 edge cases explicitly checked. If you can't name 3 edge cases → not verified thoroughly enough. **13% of missed findings were in areas explicitly marked "safe."**

**Parameter flow tracing (during Lens C or D):** Pick 3 most critical params. Trace from entry through ALL internal calls. Where is validation missing?

Record any additional candidates from the deep dive.

**Pass 3 — Mechanical "What's Missing" Sweep (Tier 1 + Tier 2 files):**
Separate pass focused exclusively on MISSING code. Do NOT combine with Pass 1/2:
1. **Missing inverse operations**: For every `set*`/`add*`/`grant*`/`lock*`/`delegate*`, search for corresponding `remove*`/`revoke*`/`unset*`/`unlock*`/`undelegate*`. If missing → candidate.
2. **Missing access control**: List every public/external function writing storage. Does each have an access modifier? If a state-writer has NO access control and isn't explicitly permissionless → candidate.
3. **Missing reward checkpoint**: For every function modifying stake/balance/lock/delegation, does it call reward update/checkpoint BEFORE the change? If not → candidate.
4. **Missing restriction coverage**: If protocol has pause/blocklist/freeze, list ALL value-exit functions. Does EVERY exit path enforce it? If one doesn't → candidate.
5. **Missing validation on paired operations**: For every deposit/lock/stake, find the corresponding withdraw/unlock/unstake. Compare parameter validation — if one validates but the other doesn't → candidate.
6. **Parameter transition safety**: For every admin setter (`setFee`, `setCooldown`, `setRate`, `setReserveRatio`, `setDuration`), ask: "What happens to IN-FLIGHT operations when this parameter changes?" If a user started an action (cooldown, auction, loan, vote) under old parameters, does the new value retroactively break them? If yes → candidate.
7. **DoS on core functions**: For every core lifecycle function (settle, liquidate, withdraw, claim, repay, unstake), check: (a) Does it loop over a user-controlled array? If unbounded → candidate. (b) Does it make an external call to a user-controlled address that can revert? If yes and no try/catch → candidate. (c) Can a permissionless function be called with dust (0, 1 wei) to grief state (reset timers, inflate arrays, block others)? If yes → candidate.

### Step 2: Build Function-State Matrix

**If `.audit/ast-facts.md` exists**: Start from its Function Registry table. Copy the verified function signatures, visibility, mutability, and modifiers. You only need to ADD: which state variables each function reads/writes (not in AST) and any guards beyond modifiers (require/assert statements).

**If no AST facts**: Build from scratch by reading each contract.

For EACH core contract (skip libraries, interfaces, test files), build:

| Function | Visibility | Reads | Writes | Guards | External Calls | Payable? |
|----------|-----------|-------|--------|--------|----------------|----------|

This matrix is your map. It reveals:
- Functions that WRITE state but have NO guards
- Functions that make EXTERNAL CALLS after state changes (reentrancy)
- Functions that READ from external sources without validation (oracle trust)
- Pairs of functions that touch the same state (consistency requirements)

### Step 3: Systematic Interrogation

For every entry point (external/public function), apply these seven question categories. Not every question applies to every function — use judgment to focus on high-risk areas.

#### Category 1: PURPOSE — Why does this code exist?

- **Q1.1**: What invariant does this line/check protect? If you can't answer → suspicious.
- **Q1.2**: What breaks if I delete this line? Dead code, missing dependency, or critical guard?
- **Q1.3**: What specific attack motivated this check? If no clear attack → may be cargo-culted.
- **Q1.4**: Is this check SUFFICIENT? A `> 0` check doesn't prevent dust griefing. A `!= address(0)` doesn't prevent wrong-but-valid addresses.

#### Category 2: ORDERING — What if I move this?

- **Q2.1**: What if state-changing code moves BEFORE validation? → Check-effects-interactions violation.
- **Q2.2**: What if it moves AFTER downstream code? → Stale state read.
- **Q2.3**: Where is the FIRST state write? Where is the LAST state read? Is there a gap where external calls happen between them?
- **Q2.4**: If the function reverts halfway, what state persists? (Events emitted before revert are still logged; side effects from external calls may persist.)
- **Q2.5**: Can the ORDER in which users call this function matter? → Front-running, race conditions.
- **Q2.6 [CEI MANDATORY CHECK]**: For EVERY external call (transfer, safeTransfer, call, delegatecall), list ALL state updates. Are ALL state updates BEFORE the external call? If ANY state update (burn, balance decrement, flag reset) happens AFTER an external call → CEI violation → reentrancy candidate. This is the #1 missed HIGH across shadow audits.

#### Category 3: CONSISTENCY — Why does A have it but B doesn't?

- **Q3.1**: If function A has an access guard, do ALL functions modifying the same state have guards?
- **Q3.2**: If `deposit()` validates parameter X, does `withdraw()` validate the corresponding parameter? Paired operations MUST match.
- **Q3.3**: If one function checks for zero amounts, do sibling functions?
- **Q3.4**: If one function emits an event on state change, do all functions changing the same state? Missing events break off-chain tracking.
- **Q3.5**: Is overflow/underflow protection consistent across all arithmetic paths?
- **Q3.6 [TRANSFER STATE CHECK]**: When a token/NFT/position transfers between users, does ALL associated state (staking, rewards, risk, cooldowns) transfer or properly reset? If `transfer()` moves the token but not the staking data → desync.
- **Q3.7 [ACCESS CONTROL EXHAUSTIVE CHECK]**: List EVERY public/external function that writes state. For each: WHO can call it? Is that the right set of callers? Especially check: checkpoint/sync functions (often accidentally permissionless), functions that should be admin-only but aren't, functions that should validate msg.sender against a parameter but don't.
- **Q3.8 [REWARD HARVEST CHECK]**: For EVERY function that changes a user's stake, balance, lock duration, or position — does it harvest/checkpoint accrued rewards FIRST? If `setLockDuration()` changes the lock but doesn't harvest pending rewards → user loses accrued rewards or games the system.
- **Q3.9 [PAIRED OPERATION SYMMETRY]**: For every setter, is there an inverse? `lock`↔`unlock`, `delegate`↔`undelegate`, `approve`↔`disapprove`, `add`↔`remove`. If one side is missing or has different constraints → stuck state.

#### Category 4: ASSUMPTIONS — What is implicitly trusted?

- **Q4.1**: What does this assume about the CALLER? (Identity, authorization, contract vs EOA)
- **Q4.2**: What does it assume about EXTERNAL DATA? (Token behavior, oracle freshness, API responses)
- **Q4.3**: What does it assume about CURRENT STATE? (Not paused, initialized, non-empty, not migrated)
- **Q4.4**: What does it assume about TIME/ORDERING? (block.timestamp can be manipulated ±15s; events may arrive out-of-order on L2s)
- **Q4.5**: What does it assume about PRICES/RATES? (Can they be stale, zero, max, or manipulated within one tx?)
- **Q4.6**: What does it assume about INPUT AMOUNTS? (What if 0? What if 1 wei? What if type(uint256).max?)

#### Category 5: BOUNDARIES & EDGE CASES

- **Q5.1**: First call with empty state? (First depositor, division-by-zero, share inflation, uninitialized mappings)
- **Q5.2**: Last call draining everything? (Dust trapped, rounding errors on final withdrawal, totalSupply == 0)
- **Q5.3**: Called twice in rapid succession? (Re-initialization, double-spending, nonce reuse)
- **Q5.4**: Two different functions called atomically? (Cross-function invariant violations, flash loan composability)
- **Q5.5**: Self-referential inputs? (Token A == Token B, sender == receiver, contract calling itself)
- **Q5.6 [MATH BOUNDARY CHECK]**: For every formula with configurable parameters (alpha, multiplier, weight), verify behavior at ALL boundary values: parameter=0, parameter=1, parameter=MAX, input=0, input=1. Especially: `x^0 should always be 1` (not 0), `x^1 should be x`, and division by zero should be impossible. Early-exit conditions like `if (x == 0) return 0` may be WRONG at specific parameter values.
- **Q5.7 [EPOCH/PERIOD BOUNDARY CHECK]**: For time-based systems (voting, rewards, locks): what happens at EXACTLY the epoch boundary? What if a user acts in the last second of an epoch vs the first second of the next? Can a user get rewards for an epoch they weren't active in? Can they vote/act after their lock expires but before the checkpoint runs? Is the epoch length enforced or just assumed (e.g., must a deposit last a FULL epoch to earn rewards)?

#### Category 6: RETURN VALUES & ERROR PATHS

- **Q6.1**: Can the caller IGNORE the return value? Is error handling forced by the language?
- **Q6.2**: What PERSISTS on the error path? Side effects before revert?
- **Q6.3**: Can external calls FAIL SILENTLY? (ERC20 transfer returns false without reverting)
- **Q6.4**: Is there a code path with NO return and NO error? (Missing else branch, uncovered enum case)

#### Category 7: EXTERNAL CALLS & CROSS-TX STATE

**Within one transaction:**
- **Q7.1**: If external call moves BEFORE state update → can callee exploit stale state?
- **Q7.2**: If external call moves AFTER → what changes? Original ordering may expose window.
- **Q7.3**: What can the CALLEE do with current state at call time? (Re-enter, read manipulated values, call other functions)
- **Q7.4**: What state MUST be updated before each external call? (Checks-effects-interactions)

**Across transactions:**
- **Q7.5**: Does the second call behave correctly given state from the first? (Rounding compounds, totals diverge)
- **Q7.6**: Does tx T2 revert/succeed unexpectedly after T1? (State drift, impossible conditions)
- **Q7.7**: Does accumulated state over many calls create unreachable conditions? (Dust accumulation, precision loss, ceiling hits)
- **Q7.8**: Can an attacker SEQUENCE transactions adversarially? (Normal single-call use works fine, but creative sequencing breaks invariants)

#### Category 8: EXTERNAL PROTOCOL INTEGRATION

When the contract integrates with external protocols (Convex, Aave, Uniswap, Chainlink, etc.):

- **Q8.1**: Can ANYONE call the external protocol's functions on behalf of this contract? (e.g., Convex getReward is permissionless — anyone can claim rewards for any address. If the contract assumes only IT triggers reward claims, an attacker can front-run and break the flow.)
- **Q8.2**: What happens if the external protocol SHUTS DOWN? (Pool shutdown, market deprecation, contract pause.) Does our function revert? Is there a recovery path?
- **Q8.3**: What happens if the external protocol CHANGES OPERATORS or MIGRATES? (e.g., CVX.mint() silently returns without minting if operator changes. If the contract calculates expected mint amount and then tries to transfer it → revert.)
- **Q8.4**: Does the contract ASSUME a return value or side effect from the external protocol? What if that side effect silently doesn't happen? (Silent no-ops are worse than reverts — the contract continues with wrong assumptions.)
- **Q8.5**: Is the external protocol UPGRADEABLE? If yes, ANY assumption about its behavior can break after an upgrade. Flag hardcoded assumptions.

#### Category 9: DERIVED CLASS & OVERRIDE COMPLETENESS

When a contract inherits from a base or implements hooks/callbacks:

- **Q9.1**: Does the derived class enforce ALL invariants from the parent? List every invariant the parent establishes and verify the child maintains each one.
- **Q9.2**: If the parent has N hook points, does the child implement ALL of them? A missing hook means that code path bypasses the child's logic.
- **Q9.3**: For authorization patterns: if function A checks `isAuthorized`, do ALL similar functions (B, C, D) also check? Compare every function in the same category.
- **Q9.4**: For fixed-term/time-locked patterns: can operations happen AFTER the term expires that shouldn't? Check every state-changing function against time boundaries.

### Step 4: Apply Audit Heuristics

For each file, check these 40 heuristic triggers from real exploits. If the code matches a trigger, apply the corresponding check:

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

### Step 5: Targeted Analysis Modules (MANDATORY)

These modules address specific bug classes consistently missed by general interrogation. Apply each relevant module.

**Deep module files** are in `modules/` directory. When a trigger pattern matches, READ the full module file for the detailed methodology:

| Module File | Trigger | When to Read |
|-------------|---------|-------------|
| `modules/oracle-analysis.md` | Chainlink, TWAP, Pyth, price feeds | Protocol uses any external data feed |
| `modules/flash-loan-interaction.md` | `balanceOf(this)`, spot prices, deposit+withdraw | Any balance-dependent or share-based logic |
| `modules/token-flow-tracing.md` | `transfer`, `mint`, `burn`, `balanceOf` | Any token handling (always) |
| `modules/external-protocol-integration.md` | Uniswap, Aave, Curve, Convex, Lido | DeFi composability |
| `modules/economic-design.md` | Fees, liquidation, incentives, tokenomics | Protocol has economic mechanics |
| `modules/eip-standard-compliance.md` | ERC-20, ERC-721, ERC-4626, EIP-712 | Any standard implementation |
| `modules/governance-voting.md` | Voting, proposals, delegation, quorum | Governance features |
| `modules/cross-chain-bridge.md` | LayerZero, CCIP, Wormhole, relayers | Cross-chain messaging |
| `modules/access-control-state.md` | State-writing functions, roles, admin | Always (core module) |
| `modules/multi-tx-attack.md` | Deposit+withdraw, staking, sequenced ops | Multi-operation protocols |

Read the trigger-matched module files for the FULL methodology with tables and step-by-step analysis. The inline modules below are the quick-reference summaries.

#### Module A: Untrusted Recipient Analysis
For every ETH/token transfer to an address that is NOT msg.sender or a known trusted protocol address:
1. Can the recipient reenter during the transfer callback? Map reachable functions and stale state.
2. Can the recipient revert and permanently DOS the function?
3. Is the same external source queried twice in one function? Can the value change between queries?
4. If a fee is added to a cost variable, does the corresponding transfer ALWAYS execute? Or is it conditional (e.g., `if recipient != address(0)`) while the cost is unconditional?

#### Module B: Type Cast Safety
Check EVERY explicit downcast: `uint128(x)`, `uint96(x)`, `int128(x)`, etc. Solidity 0.8+ does NOT revert on explicit type casts — they silently truncate. For each:
- What is the maximum possible value of the source?
- Can it exceed the target type's max? (uint128.max ≈ 3.4e38, uint96.max ≈ 7.9e28)
- What breaks on truncation? (corrupted reserves, wrong prices, broken invariants)

#### Module C: Transfer Order / Implicit Flash Loans
For functions involving both incoming and outgoing transfers:
1. Are assets transferred OUT before payment comes IN?
2. During the callback window, can the recipient use the asset (as collateral, for voting, etc.)?
3. Compare cost of this implicit flash loan vs explicit flashLoan() fee. If cheaper → bypass.

#### Module D: Fee Consistency Cross-Check
List ALL fee-charging functions. For each, compare:
- Fee calculation basis (gross amount? net? feeAmount?)
- Fee destinations (factory? pool? burned?)
- Decimal scaling method
- Zero-fee edge case handling (transfer of 0 attempted?)
Flag ANY inconsistency between functions.

#### Module E: EIP/Standard Compliance
For every implemented standard: compare actual implementation against spec. Check:
- ERC-3156: Fee from receiver, not msg.sender. Callback return value checked.
- ERC-721: tokenURI checks token exists. safeTransferFrom triggers onReceived.
- ERC-2981: Royalties actually paid at correct amounts.
- ERC-4626: Conversion rounding directions correct.
- **EIP-712 (CRITICAL — #1 missed standard compliance bug)**: For EVERY typehash, compare the keccak256 string EXACTLY against the struct definition: field names must match character-by-character, types must be canonical Solidity types (e.g., `uint256` not `uint`), order must match struct order. Check nested structs are encoded per spec. Check domain separator fields.

#### Module F: Token Compatibility
- setApprovalForAll: Some tokens revert if already set to same value. Check loops.
- 0-value transfers: Check if fee/amount can be 0, and a transfer still happens.
- Tokens with < 4/6 decimals: Check all `decimals() - N` calculations for underflow.

#### Module G: Factory/Deployment Patterns
- CREATE2 with user-controlled salt: frontrun deployment? pre-deployment deposits?
- Gap between deploy and initialize: can someone else initialize?

#### Module H: Ownership/Permission Persistence
- After ownership transfer, do approvals from old owner persist?
- Can old owner still execute pending/queued operations?

#### Module I: Weight/Proportionality
- When operations involve multiple weighted items: are fees/royalties per-item by weight, or averaged?
- If averaged: high-value items subsidize low-value → underpayment to fee recipients.

#### Module J: External Protocol Integration Audit (MANDATORY for DeFi composability)

For EVERY external protocol the contract integrates with (Convex, Aave, Uniswap, Curve, Compound, Chainlink, etc.):

1. **Permissionless function check**: For each external function the contract calls, ask: can ANYONE call this function on behalf of the contract's address? Read the external protocol's code/docs. Convex `getReward(address,bool)` is callable by anyone. Aave `claimRewards` is callable by anyone. If yes → the contract cannot assume it's the only caller.
2. **Shutdown/deprecation check**: What happens if the external pool/market/vault is shut down? Does the contract's function revert, silently fail, or handle it? If revert → users are bricked with no recovery path. Check: is there a governance function to update/migrate the dependency?
3. **Silent failure check**: Does the external function ever return without effect instead of reverting? (e.g., CVX.mint() returns silently when operator != msg.sender.) If the contract calculates an expected amount and then tries to transfer it, but the external call didn't actually produce that amount → revert or wrong accounting.
4. **Assumed return value check**: Does the contract use a calculated/expected value instead of the actual return value or post-call balance? If `earned()` is read before `getReward()`, but someone front-runs `getReward()`, then `earned()` returns 0 but tokens are in the contract.

#### Module K: Multi-Transaction Attack Sequences

Go beyond single-call analysis. For the protocol's key operations:

1. **Front-run + back-run**: Can an attacker sandwich a victim's transaction? What's the profit? (deposit large → victim's tx → withdraw large.)
2. **Flash loan escalation**: For every rounding/edge-case finding from other modules, ask: can an attacker use a flash loan to FORCE the edge condition? Inflate a denominator, drain a pool temporarily, manipulate a price within one tx.
3. **Sequence-dependent state**: Can calling functions in a specific ORDER create a state that single-call analysis misses? (e.g., deposit → claim rewards → withdraw in the same block creates different outcome than each individually.)
4. **Cross-function reentrancy paths**: If function A makes an external call, can the callee re-enter function B? Map all reachable functions during each external call window.

#### Module L: Derived Class / Override Completeness

When the protocol uses inheritance, hooks, or plugin patterns:

1. **Hook coverage**: List ALL hook points in the base contract. For each hook, verify the derived contract implements it. A missing hook = bypassed logic.
2. **Invariant inheritance**: List ALL invariants the base contract establishes (access control, time locks, balance checks). For each, verify the derived contract maintains it across ALL its functions.
3. **Authorization consistency**: Extract the authorization check from one function. Search for ALL functions that should have the same check. Flag any that don't.
4. **Time boundary enforcement**: If the protocol has time-bounded operations (fixed terms, vesting, lock periods), check EVERY state-changing function: does it enforce the time boundary? Functions added in derived classes often forget.

#### Module M: State Variable Lifecycle Tracing (MANDATORY for token/scoring systems)

For EVERY storage variable that tracks user state (balances, scores, timestamps, flags):

1. **Full lifecycle map**: Trace the variable through ALL code paths: creation → update → reset → deletion. For each admin function (issue, burn, upgrade, migrate), verify whether this variable is correctly handled.
2. **Mint/Burn/Re-mint cycle**: If a user can lose and regain their position (token burned then re-minted, account deactivated then reactivated), does the variable persist across the gap? Stale timestamps, unreset flags, or leftover balances can be exploited.
3. **Admin function side effects**: When governance issues/burns/upgrades a user's position, are ALL related state variables updated? The `issue()` function might set tokens[user].exists but forget to reset stakedAt, or the `burn()` function might reset score but not accrued interest.
4. **Counter consistency**: If there are counters (pendingUpdates, totalRequired), verify they stay in sync across ALL code paths. `claim()` might increment totalRevocable without updating pendingScoreUpdates.

#### Module N: DoS-to-Exploit Escalation

For EVERY DoS vulnerability found (gas griefing, revert conditions, infinite loops):

1. **Economic weapon**: Can the DoS be combined with another mechanism to create an economic exploit? (e.g., DoS of score updates → attacker keeps favorable old score → accrues outsized rewards)
2. **Selective targeting**: Can the attacker DoS SPECIFIC users while leaving themselves unaffected? (e.g., front-running updateScores for certain users)
3. **Time-sensitive exploitation**: Is there a time window during which the DoS creates a profit opportunity? (e.g., blocking liquidations during a price crash, blocking score updates after alpha change)

#### Module O: Payment/Distribution Flow Tracing (MANDATORY)

For EVERY function that distributes ETH or tokens to multiple recipients:

1. **Trace each payment**: For every `.call{value:}`, `.transfer()`, `.send()`, `safeTransfer()` — WHO is the actual recipient? Is it `owner()` (contract deployer), `ownerOf(tokenId)` (NFT holder), `msg.sender`, or a configured address? Verify the recipient is semantically correct (e.g., auction proceeds should go to token OWNER, not contract OWNER).
2. **Double payout check**: Can the same recipient receive payment twice? If function pays royalties to artists AND separately pays creators, can the same address appear in both lists?
3. **Payment-on-failure**: When a target call fails, are tokens/ETH properly refunded? Check: is the refund to the right address? Does the refund include ALL tokens (not just native ETH)?
4. **Conditional payment with unconditional cost**: If payment is conditional (`if (recipient != address(0))`) but the cost was already deducted unconditionally, funds are silently lost.

#### Module P: Cross-Chain Bridge Security (MANDATORY for bridge/cross-chain protocols)

1. **Minimum destination gas**: Does the bridge enforce minimum gas for destination chain execution? LayerZero requires adapterParams with minDstGas. Without it, messages arrive but execution fails.
2. **Destination liquidity**: Does the destination contract assume tokens exist? If it needs WETH to complete but router is empty, user's TX fails with no refund.
3. **Parameter staleness**: Cross-chain has latency. Swap params set on source chain may be stale when message arrives. Is there slippage protection? A recovery path?
4. **Refund routing**: When destination execution fails, where do refunds go? To the adapter (stuck), to msg.sender on destination (wrong), or back to user on source (correct)?
5. **Access control on bridge tokens**: Bridge token contracts (like DcntEth, wrapped tokens) often have setter functions for router/bridge addresses. Are these access-controlled?

#### Module Q: NFT Attribute & Randomness Integrity

For NFT/Gaming protocols with attribute assignment:

1. **User-controlled attributes**: Can users influence their NFT attributes via function parameters? If `redeemMintPass(customAttributes)` lets users pick rarity → they'll always pick the best.
2. **Revert-to-reroll**: If attributes come from on-chain randomness (blockhash, prevrandao), can users revert if they don't like the result? Safe only with commit-reveal or VRF callback.
3. **Type parameter validation**: If per-type limits exist, verify the type parameter matches the actual item type. `reRoll(tokenId, wrongFighterType)` bypassing per-type limits.
4. **Initialization for new generations/collections**: When new NFT collections/generations are created, are ALL required mappings initialized? (numElements, maxSupply, etc.)

#### Module R: Governance Voting Integrity

For governance/voting protocols:

1. **Phantom voting power**: When governance NFTs are burned/auctioned/transferred, is their voting power removed from totalVotesSupply/quorum calculations? Inaccessible voting power → quorum becomes unreachable.
2. **Delegation griefing**: Can a delegatee prevent the delegator from redelegating? If delegatee accumulates many checkpoints → gas exhaustion on redelegate.
3. **Supply-dependent quorum**: If quorum is % of totalSupply, what happens at totalSupply=0? Quorum=0 means any piece/proposal passes with 0 votes.

#### Module S: Cross-Contract State on Transfer

When NFTs or positions transfer between users:

1. **Associated state follows?**: When an NFT transfers, does ALL associated state (stake amounts, reward debt, risk, cooldowns, attributes) transfer with it? If staking state stays with old owner → new owner has clean slate.
2. **Underflow on associated state**: If old owner had stakeAtRisk and NFT transfers, does new owner's win try to reduce old owner's stakeAtRisk? → underflow revert.
3. **Counter/points persistence**: Do accumulated points/counters for the old token holder persist? Can they sell the NFT but keep accrued benefits?

#### Module T: Cross-Interaction Batch Analysis

For protocols with batch/multicall/router patterns:

1. **Intra-batch balance deltas**: In multicall systems, can a user reference token balances from earlier interactions that haven't been finalized? If the batch wraps tokens in step 1 but spends them in step 2, can step 2 reference the wrapped balance before step 1's transfer settles?
2. **Ocean-style delta accounting**: If the system tracks deltas rather than absolute balances, verify net settlement is correct. Can a user generate negative deltas in one interaction and positive in another, netting to zero cost but extracting real tokens?
3. **Shared state mutation order**: If batch operations A and B both read/write the same storage slot, does the order matter? Can reordering interactions within a batch create a different (exploitable) outcome?
4. **Balance snapshot timing**: When are balances snapshotted for each operation in the batch? Before the batch starts (stale for later ops) or inline (affected by earlier ops)?

#### Module U: DeFi Integration Library

For protocols integrating with external DeFi primitives:

1. **Curve pool specifics**: Does the adapter handle killed/paused pools? Does it distinguish native ETH vs WETH (Ocean ID mismatch)? Does tricrypto indexing differ from 2pool? Is `get_dy` vs `exchange` return value properly used?
2. **Uniswap V3 tick math**: Negative ticks are valid. Does `int24` handling account for sign extension? Are `tickLower < tickUpper` always enforced? Is sqrtPriceX96 properly bounded? Missing slippage/deadline params?
3. **Chainlink feed assumptions**: Stale price check (how old is too old)? Zero/negative price handling? L2 sequencer uptime feed checked? Decimals assumption matches actual feed?
4. **Aave/Compound integration**: Are aToken/cToken exchange rates queried correctly? Can permissionless `claimRewards` front-run the protocol's claim? Is the health factor calculation current?
5. **Lido/stETH rebasing**: Is stETH balance tracked correctly (changes between blocks)? Should wstETH be used instead? Does the protocol account for rebasing in its accounting?

#### Module V: Economic Design Reasoning

For protocol-level economic analysis:

1. **Circular collateral valuation**: Is the protocol's own token counted as collateral in the TVL that determines the token's value? If kerosine value = f(TVL) and kerosine is IN the TVL → reflexive death spiral risk on downturn.
2. **Liquidation profitability**: At what collateral ratio does liquidation become unprofitable? If liquidator must repay debt to seize collateral, and gas + slippage > profit margin → bad debt accumulates.
3. **First/last mover advantage**: Can the first depositor or last withdrawer extract disproportionate value? Classic: first depositor inflates share price. Less obvious: last withdrawer gets all remaining dust.
4. **Fee-free arbitrage paths**: If operation A has a fee but the equivalent via B+C doesn't → rational users bypass A → protocol loses revenue.
5. **Incentive misalignment**: When is it rational to NOT do what the protocol expects? If staking rewards < opportunity cost → no stakers → protocol breaks.

#### Module W: Missing Functionality Detection

For identifying what SHOULD exist but doesn't:

1. **Missing unsetters**: For every admin setter (addChain, setOracle, addAsset, addOperator), does a corresponding REMOVER exist? If not → permanent misconfiguration.
2. **Missing pause/emergency**: For high-value operations (withdraw, liquidate, bridge), is there an emergency pause? Can the protocol respond to an active exploit?
3. **Missing migration path**: If the protocol upgrades (new oracle, new pool, new token), can existing positions migrate? Or are they permanently locked to the old integration?
4. **Incomplete restriction coverage**: If address X is restricted/blocklisted, check ALL exit paths: transfer, burn, withdraw, bridge, delegate. If ANY path is unrestricted → the restriction is useless.
5. **Missing return value handling**: External calls that return data — is the return value checked? Especially for ERC20 approve/transfer which may return false instead of reverting.

#### Module X: Version & Standard Compliance Audit (MANDATORY)

The #1 missed bug category across 35 shadow audits. Mechanically verifiable.

1. **EIP-712 Typehash Verification**: Find every `keccak256("TypeName(...")` typehash. Find the corresponding struct. Compare CHARACTER BY CHARACTER: field names, types, order. Check nested struct encoding (appended alphabetically). Check domain separator (chainId, verifyingContract, name, version).
2. **External Dependency Versions**: What Safe version? (1.3.0 guard interface has 2 params, 1.5.0 differs; `execTransactionFromModule` return data changes). What OZ version? (`_beforeTokenTransfer` vs `_update` in v4 vs v5). What Solidity version? (0.8.20+ PUSH0 breaks on older chains).
3. **Token Interface**: Does code assume `transfer` returns `bool`? (USDT doesn't). Assumes 18 decimals? (USDC=6, WBTC=8). Handles rebasing tokens? Transfer hooks?
4. **Proxy Initialization**: Can implementation be initialized directly? Does constructor call `_disableInitializers()`? Can initialized implementation be `selfdestruct`ed (pre-Cancun)? For UUPS: does implementation have `upgradeTo`?
5. **ERC Standard Compliance Checklists** — For each standard the contract implements, check mechanically:
   - *ERC-20*: transfer returns true? transferFrom decrements allowance? Self-transfer safe? Zero-amount transfer safe? Rebasing: totalSupply == sum(balanceOf)?
   - *ERC-721*: `ownerOf` reverts for nonexistent tokens? `tokenURI` reverts for nonexistent tokens? `safeTransferFrom` calls `onERC721Received`? `transferFrom` clears approvals? `balanceOf(address(0))` reverts?
   - *ERC-4626*: Rounding directions correct? (deposit rounds shares DOWN, mint rounds assets UP, withdraw rounds shares UP, redeem rounds assets DOWN). `maxDeposit`/`maxMint` return 0 when paused (not revert)? First depositor protection exists? `totalAssets` includes yield but is donation-safe?
   - *ERC-2981*: `royaltyInfo` receiver is untrusted — can it revert on ETH receive (DoS)?
   - *ERC-3156*: `onFlashLoan` return value checked? Fee charged on top of principal? Receiver approved lender for principal+fee?

### Step 5b: Cross-Function Analysis

After individual function interrogation:

1. **Guard Consistency**: Group functions by shared state writes. If function A has `onlyOwner` but function B writes to the same mapping without it → finding.
2. **Inverse Operation Parity**: Compare deposit↔withdraw, mint↔burn, stake↔unstake. Verify they're symmetric. If deposit validates X, withdraw must validate the inverse.
3. **State Transition Integrity**: Can states be skipped, triggered out-of-order, or triggered by wrong actors?
4. **Value Flow Conservation**: Does value in == value out? Can value be created or destroyed unexpectedly?
5. **Look for what's NOT there**: For each state-changing function, ask: "What SHOULD this function also do that it doesn't?"

### Step 6: Record Candidates

For EVERY suspected vulnerability, create a candidate entry:

```markdown
### [CANDIDATE-XXX] Title

**Severity**: CRITICAL / HIGH / MEDIUM / LOW
**File**: path/to/file.sol
**Lines**: XX-YY
**Category**: [category]

**Discovery Method**: [Which question/heuristic exposed this]

**Description**: [What's wrong, in concrete terms]

**Scenario**:
1. Attacker does X
2. This causes Y
3. Because the code at line Z does/doesn't do W
4. Result: [impact]

**Vulnerable Code**:
```solidity
// paste the actual vulnerable lines
```

**Why This Is a Bug**: [Not "might be" — state your case]

**Status**: UNVERIFIED — needs Critic validation
```

Save ALL candidates to `.audit/findings/detector-candidates.md`.

## Rules

- **MAXIMIZE RECALL, but not garbage.** Report anything suspicious that has a CONCRETE attack path. The Critic will filter further.
- **Every candidate MUST have file:line.** No generic warnings.
- **Read the actual code.** Never assume what a function does from its name.
- **Check inheritance.** A "missing" check may exist in a parent contract.
- **Track OpenZeppelin/Solmate usage.** Don't flag standard implementations as custom bugs.
- **Be concrete.** "This could be a problem" is worthless. "An attacker can call X with Y=0 to extract Z" is a finding.
- **Do NOT verify yet.** That's the Critic's job. Just find candidates.

## PRE-FILTER: Do NOT Generate Candidates For These (Automatic Kills)

These 8 categories have produced ZERO true positives across 35 shadow audits. Do NOT waste time generating candidates in these categories. They WILL be killed by the Critic.

**A. Generic Best Practice** — Do NOT report: SafeERC20 usage, safeApprove, two-step ownership, missing events, .transfer() gas limit, weak on-chain randomness (blockhash/prevrandao), generic deadline concerns, centralization risks. These are informational at best.

**B. Theoretical/Unrealistic** — Do NOT report findings requiring: exotic token behaviors not in the protocol's actual token list, oracle values outside documented range, integer overflow of practically bounded values, conditions prevented by deployment/initialization, fee-on-transfer behavior when protocol uses WETH/USDC/DAI. **For ANY token-behavior finding (FoT, rebasing, missing return, hooks), you MUST name the SPECIFIC token from THIS protocol's actual deployment that exhibits the behavior. "If a FoT token is used" = kill.**

**C. Intentional Design** — Do NOT report: behavior matching documentation/comments, patterns from reference implementations (UniV3, Curve, OZ, DODO), intentionally permissionless functions, features working as spec'd. **If this is a FORK, behavior inherited from the original protocol is intentional design — only report bugs in code that DIFFERS from the fork origin.**

**D. Speculative** — Do NOT report anything where you cannot immediately state: WHO is the attacker, WHAT function they call with WHAT params, and HOW MUCH they profit. "Could be an issue" = not a candidate.

**E. Admin Trust** — Do NOT report: "owner can set bad value", "admin can drain", "governance can rug". Unless: missing timelock on irreversible destructive action.

**F. Dust** — Do NOT report: rounding where max loss < $1 per tx, truncation dust, precision loss below gas cost.

**G. Out of Context** — Do NOT report: token behaviors for tokens not whitelisted, chain issues for unchosen chains, standard edge cases for unimplemented standards.

**H. Publicly Known Issues** — Do NOT report: any bug mechanism already described in the README's "Known Issues", "Acknowledged", or "Publicly Known Issues" sections, or in linked previous audit acknowledgments, or in the automated/bot report section. Read the README BEFORE generating candidates.
