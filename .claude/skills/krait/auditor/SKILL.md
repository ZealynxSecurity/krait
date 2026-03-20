# Krait Auditor — Master Orchestrator

> Full security audit pipeline. Coordinates all Krait sub-skills in an iterative feedback loop.

## Trigger

Invoked by `/krait` on a target codebase.

## Usage

```
/krait                              # Full audit of current directory
/krait --scope src/contracts/       # Audit specific directory
/krait --quick                      # Skip state analysis, no iteration (faster)
/krait --continue                   # Resume from last saved state
```

## Architecture

Krait runs a **4-phase iterative pipeline** where findings from each phase feed into the next, and cross-phase iteration catches bugs that no single methodology finds alone.

```
Phase 0: RECON ──────────────────────────────────────────────┐
  Architecture map, fund flows, trust boundaries, attack     │
  surface prioritization                                      │
                                                              ▼
Phase 1: DETECTION ──────────────────────────────────────────┐
  Feynman first-principles interrogation (7 categories,      │
  28+ questions) + 40 exploit-derived heuristics              │
                                                    ┌────────┤
Phase 2: STATE ANALYSIS ◄───── cross-feed ─────────►│        │
  Coupled state mapping, mutation matrix, parallel   │        │
  path comparison, masking code detection            │        │
                                            ┌───────┘        │
  ITERATE: If new findings emerge from      │                 │
  cross-feed, loop Phase 1↔2 (max 2 cycles)│                 │
                                            ▼                 │
Phase 3: VERIFICATION ◄─────────────────────┘                │
  Devil's advocate falsification, mandatory proof traces,     │
  systematic FP elimination                                   │
                                                              │
Phase 4: REPORT ◄─────────────────────────────────────────────┘
  Deduplication, severity ranking, professional output
```

## Execution Flow

### 1. Initialize

```bash
mkdir -p .audit/findings
```

Check for `.audit/recon.md` — if it exists and `--continue` is set, skip to the phase that hasn't been completed yet.

### 2. Phase 0: Recon

Run the krait-recon methodology:
- Read all source files, README, configuration
- Build architecture map, fund flows, trust boundaries
- Identify attack surfaces and prioritize files
- Select protocol-specific vulnerability checklists
- Save to `.audit/recon.md`

**Gate**: Recon must be complete before proceeding. You must understand the protocol.

### 3. Phase 1: Detection

Run the krait-detector methodology on ALL core source files:
- Build Function-State Matrix per contract
- Apply 7-category Feynman interrogation to every entry point
- Check 40 audit heuristics against code patterns
- Cross-function consistency analysis
- Record ALL candidates (maximize recall)
- Save to `.audit/findings/detector-candidates.md`

**If `--quick`**: Skip to Phase 3 (verification) after this. No state analysis, no iteration.

### 4. Phase 2: State Analysis

Run the krait-state-auditor methodology:
- Build Coupled State Dependency Map
- Build Mutation Matrix for all state variables
- Cross-check every mutation path for coupled state updates
- Analyze operation ordering within functions
- Compare parallel paths (withdraw vs liquidate, etc.)
- Simulate multi-step user journeys
- Detect masking code hiding broken invariants
- Cross-feed: consume Detector candidates as targeted input
- Save to `.audit/findings/state-candidates.md`

### 5. Cross-Feed Iteration Loop

**This is the key innovation.** After both Detection and State Analysis complete their first pass:

**Step A**: Take State Auditor's gaps → feed to Detector for targeted re-interrogation:
- "The State Auditor found that `liquidate()` doesn't update `rewardDebt`. WHY doesn't it? What assumption did the developers make? Can an attacker exploit the window between liquidation and the next reward update?"

**Step B**: Take Detector's suspects → feed to State Auditor for structural analysis:
- "The Detector flagged the callback in `flashLoan()`. Does this callback happen during a state inconsistency window? What coupled pairs are out of sync when the callback fires?"

**Step C**: Masking code analysis — for any defensive code (ternary clamps, try/catch, min caps) found by either auditor:
- "This `Math.min(calculated, available)` cap exists. What invariant is broken underneath? Which coupled pair desync is being hidden?"

**Convergence check**: If Steps A-C produced new findings, loop once more (max 2 total iteration cycles, max 6 total passes). If no new findings → converge and proceed.

Track the discovery path for each finding:
- "Detector-only" — found by Feynman interrogation alone
- "State-only" — found by structural state analysis alone
- "Cross-feed P1→P2" — found through iterative cross-pollination

### 6. Phase 3: Verification

Run the krait-critic methodology on ALL candidates from Detection + State Analysis:
- Attempt to disprove every CRITICAL, HIGH, and MEDIUM candidate
- Deep code trace through inheritance chains
- Construct concrete exploitation traces with values
- Systematic FP elimination using 10 known FP patterns
- Cross-feed iteration check (verified findings → new state insights?)
- Assign verdicts: TRUE POSITIVE, LIKELY TRUE, DOWNGRADE, FALSE POSITIVE, INSUFFICIENT EVIDENCE
- Save to `.audit/findings/critic-verdicts.md`

**Gate**: No finding reaches the report without a verdict.

### 7. Phase 4: Report

Run the krait-reporter methodology:
- Load only verified findings (TP + LT)
- Deduplicate overlapping findings
- Final severity ranking
- Generate professional Markdown report
- Generate machine-readable JSON
- Save to `.audit/krait-report.md` and `.audit/krait-findings.json`

## Quality Standards

### What Makes a TRUE POSITIVE Finding

A finding MUST have ALL of:
1. **Exact location**: file path + line number(s)
2. **Concrete scenario**: Step-by-step attack or trigger sequence
3. **Real code**: The actual vulnerable lines, not paraphrased
4. **Verified impact**: Not "could cause" but "causes" with evidence
5. **Root cause**: One sentence explaining WHY the bug exists
6. **Fix**: Specific code change to resolve it

### What Gets REJECTED

- Generic warnings without file:line ("consider adding access control")
- Theoretical vulnerabilities without reachable attack paths
- Issues in test/script/mock/interface files
- Standard library behavior flagged as custom bugs
- Severity inflation (revert != critical, dust loss != high)
- Duplicate descriptions of the same underlying bug

## Anti-Hallucination Protocol

**NEVER:**
- Invent code that doesn't exist in the files
- Assume a guard exists without reading the implementation
- Claim a variable is uninitialized without checking constructors/initializers
- Report findings without showing exact code
- Use hedging language ("could potentially", "might be vulnerable")
- Assume Solidity patterns apply to Rust/Move or vice versa

**ALWAYS:**
- Read actual code before questioning it
- Verify assumptions by inspecting called functions
- Check constructors, initializers, default values
- Show exact file paths and line numbers
- Use language-correct terminology
- Trace inheritance chains completely

## File Structure

After a complete audit:

```
.audit/
├── recon.md                              # Phase 0: Architecture map
├── findings/
│   ├── detector-candidates.md            # Phase 1: All candidates
│   ├── state-candidates.md               # Phase 2: State desync candidates
│   ├── critic-verdicts.md                # Phase 3: Verification results
│   └── review-second-opinion.md          # /krait-review: Re-examined killed findings
├── krait-report.md                       # Phase 4: Final report
└── krait-findings.json                   # Phase 4: Machine-readable
```

## Performance Notes

- **Full audit**: ~30-60 min for a small protocol (4-10 files), depending on complexity
- **Quick mode**: ~15-30 min (skips state analysis and iteration)
- **Resume**: Use `--continue` to pick up from the last completed phase

## Credits

Built by Zealynx Security. Methodology combines:
- Krait's 40+ exploit-derived audit heuristics and vulnerability pattern database
- Feynman first-principles interrogation (systematic reasoning over code)
- Structural state inconsistency analysis (coupled pair dependency mapping)
- Iterative cross-feed loop (findings from each methodology inform the other)
