# Krait Reporter — Consolidation, Ranking & Final Report

> Phase 4 (final) of the Krait audit pipeline.

## Trigger

Invoked by `/krait` (as part of full audit) or `/krait-report` (standalone).

## Prerequisites

- `.audit/findings/critic-verdicts.md` (from krait-critic)
- `.audit/recon.md` (from krait-recon)

## Purpose

Consolidate all verified findings into a professional, actionable security report. Deduplicate, rank by impact, and format for human consumption.

## Execution

### Step 1: Load Verified Findings

Read `.audit/findings/critic-verdicts.md`. Only include findings with verdict:
- **TRUE POSITIVE** — include as-is
- **LIKELY TRUE** — include with caveat noting the conditions required

Do NOT include: FALSE POSITIVE, INSUFFICIENT EVIDENCE, or LOW-severity findings (unless user specifically requested them).

### Step 2: Deduplication

Multiple candidates may describe the same underlying bug from different angles (Detector found it via Feynman, State Auditor found it via coupled pair analysis). Merge these:

- Same file + same lines + same root cause → merge into single finding, combine evidence
- Same root cause but different manifestations → single finding with multiple impact paths
- Related but distinct bugs → keep separate, note relationship

### Step 2.5: Root-Cause Consolidation (A7)

*(Source: PlamenTSV/plamen, MIT — `phase6-report-prompts.md` § STEP 1.5)*

Step 2 removes findings that are the SAME bug seen twice. This step handles the different
problem: several findings that are genuinely distinct **locations** of ONE root cause with
ONE fix — the "10 separate missing-checkpoint findings" shape. Reporting those as ten
findings inflates the count and hides the fact that the developer has one job to do.

**Merge two or more findings into one when ALL of these hold:**

1. **Same fix pattern** — the same kind of code change closes all of them
2. **Same severity tier** — a tier gap means the impacts differ; keep them separate
3. **Same vulnerability class** — same bug pattern, not just the same file
4. **Describable together** — a reader understands every location from one description plus a table
5. **≤ 6 locations** — beyond that, split into two findings for readability

**Do NOT merge when:**
- The fixes touch **different functions** — write the one-line fix for each; if they differ, these are different root causes
- Merging would hide a severity difference
- You are unsure. **A duplicate finding is cosmetic. A dropped true positive is a missed vulnerability. When in doubt, keep them separate.**

**Format for a consolidated finding**: use a class-level title (e.g. "Reward checkpoint
missing on balance-changing paths"), not a single-location title. List every location in a
table under the description, then give ONE recommendation covering all of them:

```markdown
**Affected locations** (4):

| File | Line | Issue |
|------|------|-------|
| `Staking.sol` | 142 | `withdraw()` skips `_updateReward` |
| `Staking.sol` | 201 | `emergencyWithdraw()` skips `_updateReward` |
| `Staking.sol` | 233 | `transferStake()` skips `_updateReward` |
| `Migrator.sol` | 88  | `migrate()` skips `_updateReward` |

*One fix closes all 4 locations above.*
```

### Step 2.75: Evidence Tier (surface how a finding was verified)

Every finding carries an **Evidence** line saying how strongly it was verified. This is the
payoff of the opt-in PoC pass: a client can see at a glance which findings have mechanical
proof versus expert reasoning. Derive it from the finding's evidence tag (from the critic,
or from a `krait-poc` run if one was done):

| Evidence line | When | Meaning |
|---------------|------|---------|
| `PROVEN — executed PoC [POC-PASS]` | A `krait-poc` run reproduced the harm AND the finding survived the falsification gate (the defective line, corrected, kills the exploit; the fix also kills it) | Ground truth. Attach the passing harm assertion, the defect-mutation that pinned it, and the verified fix diff. |
| `PROVEN — fix insufficient [POC-PASS · FIX-INSUFFICIENT]` | Pinned and real, but the recommended fix does NOT close the exploit | The bug is confirmed; the *remediation* is flagged. Report the exploit surviving the proposed fix and note a correct fix is pending human review. **Not** a weaker finding — often a more important one. |
| `REASONED — code trace [CODE-TRACE]` | Verified by the critic's trace, no PoC run, un-PoC-able by nature, OR a PoC reproduced but was **not pinned** to the defect (`[POC-UNPINNED]`) | A real finding held on reasoning. **NOT** "unverified." An `[POC-UNPINNED]` finding is here because its test did not prove the cited line caused the harm — the mechanism may still be real, so it is flagged for human review, never dropped on the PoC's say-so. |
| `DISPUTED — PoC did not reproduce [POC-FAIL]` | A PoC was attempted and the harm did not materialize | Should normally have been dropped by the critic; if it still appears, flag it loudly for human review. |

Rules:

- **`REASONED` is not a weaker finding, just a differently-evidenced one.** Never imply a
  finding is doubtful because it lacks a PoC — some of the highest-value findings (trusted-
  actor, off-chain, cross-chain) are un-PoC-able by construction.
- A `PROVEN` finding SHOULD carry its harm assertion in the PoC block and its verified fix in
  the Recommendation — that is the concrete value of having run the PoC.
- If no PoC pass was run at all, every finding is `REASONED` — that is the normal default
  audit, and it is fine.

### Step 3: Severity Ranking

Final severity assignment using this rubric:

| Severity | Criteria | Examples |
|----------|----------|---------|
| **CRITICAL** | Direct, unconditional loss of funds or permanent protocol DoS. Any user can trigger. No admin intervention can fix. | Drain all vault funds, brick protocol permanently, unauthorized minting |
| **HIGH** | Conditional fund loss, privilege escalation, or broken core invariant. Requires specific conditions but attacker can create them. | Oracle manipulation for bad debt, self-liquidation profit, reentrancy fund drain |
| **MEDIUM** | Value leakage, griefing with cost to attacker, degraded functionality. Limited impact or requires unlikely conditions. | Rounding exploitation over many txs, reward gaming, event inconsistency affecting integrations |
| **LOW** | Informational, gas optimization, cosmetic inconsistency. No direct value impact. | Unnecessary storage reads, missing events, style inconsistency |

#### Step 3.5: Trust-Assumption Downgrade (A5)

*(Source: PlamenTSV/plamen, MIT — `report-template.md` § Downgrade modifiers)*

Kill gate E discards findings that need a **fully trusted** actor (governance multisig,
DAO, timelock) to act maliciously. That is correct for a rug vector nobody can act on —
but it is too blunt for the middle ground, where a real bug exists and the only question
is how much weight to give it. This step is that middle option: **report at one tier lower
with an explicit note, rather than discard.**

Apply when the critic recorded a trust dependency on a finding that **survived** gate E:

| Actor class | Examples | Treatment |
|---|---|---|
| **Fully trusted** | governance multisig, DAO, timelock | Already killed by gate E — nothing to do here |
| **Semi-trusted** | keeper, operator, relayer, sequencer, oracle updater, whitelisted caller | **−1 severity tier**, floor Informational, plus the note below |
| **Untrusted** | any EOA, any contract | No adjustment — full severity |

Print the adjustment on the finding so the reader can re-rate it themselves:

```
**Severity adjusted**: High → Medium — the attack path requires `keeper` to violate a
stated trust assumption: keepers are assumed to submit prices within 1% of market.
```

Never apply the downgrade silently. An unexplained severity is worse than either severity.

### Step 4: Write Report

Generate `.audit/krait-report.md`:

```markdown
# Krait Security Audit Report

**Target**: [Protocol name]
**Date**: [Date]
**Auditor**: Krait by Zealynx Security
**Scope**: [Files audited]

---

## Executive Summary

[2-3 sentences: what was audited, key findings, overall risk assessment]

**Finding Summary**:
| Severity | Count |
|----------|-------|
| Critical | X |
| High | X |
| Medium | X |
| Low | X |

---

## Findings

### [KRAIT-001] [Title] — [SEVERITY]

**File**: `path/to/file.sol:XX`
**Category**: [e.g., reentrancy, state-desync, access-control]
**Evidence**: [one of — see the Evidence tier below]

**Description**:
[Clear explanation of the vulnerability. What's wrong and why it matters.]

**Impact**:
[Specific impact: who is affected, how much value at risk, under what conditions.]

**Proof of Concept**:
```
[If [POC-PASS]: the passing test's harm assertion + the profit/drain output, and the
run command. Otherwise: the concrete attack steps / code trace.]
```

**Root Cause**:
[One sentence: the fundamental reason this bug exists.]

**Recommendation**:
[Specific fix. Not "add a check" — show exactly what check, where, and why it works.]

**Vulnerable Code**:
```solidity
// The actual vulnerable code
```

**Fixed Code** (suggested):
```solidity
// The corrected code
```

---

[Repeat for each finding, ordered by severity (Critical first)]

---

## Security Strengths

[Exactly 5 bullet points. Derived from what Recon observed in the codebase — not generic praise, only things you actually verified in the code. Each bullet should name the specific contract/pattern/version.]

Pick the 5 most relevant from these categories (skip any that don't apply):
- **Access control model**: What pattern is used (Ownable2Step, AccessControl, role-based)? Is it consistent across all privileged functions?
- **Reentrancy protection**: Are state-mutating external calls guarded? CEI pattern followed? nonReentrant modifier coverage?
- **Arithmetic safety**: Solidity 0.8+ checked math, explicit unchecked blocks only where safe, SafeCast usage for downcasts?
- **Battle-tested dependencies**: Which libraries (OpenZeppelin vX.Y, Solmate, etc.)? Are they current versions?
- **Input validation**: Are external entry points validated (zero-address checks, bound checks, array length limits)?
- **Upgrade safety**: If upgradeable — initializer guards, storage gap patterns, UUPS vs Transparent?
- **Oracle handling**: Staleness checks, fallback oracles, price bound validation?
- **Test coverage**: Visible test suite breadth, fuzzing, invariant tests?

Format in the report:
```
## Security Strengths

- **[Category]**: [Specific observation with contract/file names — e.g., "All 8 state-mutating functions in CfdEngine.sol follow CEI pattern with nonReentrant guards"]
- **[Category]**: [Specific observation]
- **[Category]**: [Specific observation]
- **[Category]**: [Specific observation]
- **[Category]**: [Specific observation]
```

**Rules**: Only state what you verified in the code. Never write generic praise like "good use of modifiers." If you can't find 5 concrete strengths, fill remaining slots with "Area for improvement: [what's missing]" — honest signal is more valuable than padding.

---

## Architecture Observations

[Non-finding observations from the recon phase that are worth noting:
- Complexity hotspots that could hide future bugs
- Areas that would benefit from additional testing
- Design decisions that are unusual or noteworthy]

---

## Methodology

This audit was performed using Krait's multi-phase analysis:
1. **Recon**: Architecture mapping, fund flow analysis, trust boundary identification
2. **Detection**: Feynman first-principles interrogation (7 question categories, 28+ questions per function) + 40 exploit-derived heuristic checks
3. **State Analysis**: Coupled state dependency mapping, mutation matrix cross-checking, parallel path comparison, masking code detection
4. **Verification**: Devil's advocate falsification of every H/M finding, mandatory proof-of-concept traces, systematic FP elimination

_Generated by [Krait](https://github.com/ZealynxSecurity/krait) by Zealynx Security_
```

### Step 5: Findings Index

Also save a machine-readable summary to `.audit/krait-findings.json`:

```json
{
  "protocol": "name",
  "date": "YYYY-MM-DD",
  "findings": [
    {
      "id": "KRAIT-001",
      "title": "...",
      "severity": "high",
      "file": "path/to/file.sol",
      "line": 42,
      "category": "...",
      "description": "...",
      "impact": "...",
      "rootCause": "...",
      "recommendation": "..."
    }
  ],
  "summary": {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 0,
    "total": 3
  }
}
```

## Rules

- **Only verified findings.** Nothing from the candidate lists that wasn't approved by the Critic.
- **Concrete recommendations.** "Fix this" is not a recommendation. Show the code change.
- **Honest severity.** Don't inflate to look impressive. Don't deflate to look clean.
- **Readable by humans.** An auditor picking up this report should understand every finding in < 2 minutes.
- **No padding.** Don't add informational/low findings just to make the report longer. Quality > quantity.

## After Report: What's Next

After presenting the report, **always show this block** (copy exactly, filling in the count):

```
───────────────────────────────────────────────────
📋 [N] findings saved to .audit/krait-findings.json

🔗 View this report online:
   https://krait.zealynx.io/report/findings
   Upload your JSON → branded report with severity breakdowns, exploit traces, and code diffs.

📊 Track findings over time:
   https://krait.zealynx.io/dashboard
   Free dashboard — save reports, run security assessments, get a combined readiness score. No API costs.
───────────────────────────────────────────────────
```

Then offer next steps:

### Next Steps

1. **Review killed findings** (if the Critic killed 5+ candidates): Suggest running `/krait-review` to get a second opinion on findings killed by the automatic gates. Especially valuable when many findings were killed by Gates C (intentional design), E (admin trust), or B (theoretical).

2. **Complete Security Assessment**: "Want a full security readiness score? Run the 845+ check assessment at https://krait.zealynx.io/new — it covers operational security, deployment practices, and process gaps that code analysis can't see."

Present these as a numbered list after the banner. Let the user choose which (if any) they want.
