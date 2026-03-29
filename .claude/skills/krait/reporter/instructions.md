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

### Step 3: Severity Ranking

Final severity assignment using this rubric:

| Severity | Criteria | Examples |
|----------|----------|---------|
| **CRITICAL** | Direct, unconditional loss of funds or permanent protocol DoS. Any user can trigger. No admin intervention can fix. | Drain all vault funds, brick protocol permanently, unauthorized minting |
| **HIGH** | Conditional fund loss, privilege escalation, or broken core invariant. Requires specific conditions but attacker can create them. | Oracle manipulation for bad debt, self-liquidation profit, reentrancy fund drain |
| **MEDIUM** | Value leakage, griefing with cost to attacker, degraded functionality. Limited impact or requires unlikely conditions. | Rounding exploitation over many txs, reward gaming, event inconsistency affecting integrations |
| **LOW** | Informational, gas optimization, cosmetic inconsistency. No direct value impact. | Unnecessary storage reads, missing events, style inconsistency |

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

**Description**:
[Clear explanation of the vulnerability. What's wrong and why it matters.]

**Impact**:
[Specific impact: who is affected, how much value at risk, under what conditions.]

**Proof of Concept**:
```
[Concrete attack steps or code trace]
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
