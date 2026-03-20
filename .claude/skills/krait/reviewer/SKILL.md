# Krait Reviewer — Second Opinion on Killed Findings

> Post-audit review phase. Re-examines findings killed by the Critic's gates to catch over-filtering.

## Trigger

Invoked by `/krait-review` (standalone, after a completed audit).

## Prerequisites

- `.audit/findings/critic-verdicts.md` (from krait-critic) — MUST exist
- `.audit/recon.md` (from krait-recon) — MUST exist
- `.audit/findings/detector-candidates.md` (from krait-detect) — MUST exist

If any are missing, tell the user to run `/krait` or `/krait-quick` first.

## Purpose

The Critic's kill gates are tuned for **zero false positives** — they're intentionally aggressive. This is correct for the main report. But aggressive gates have a cost: **over-killing real findings**.

The Reviewer exists to ask: **"What if the gate was wrong?"**

This is NOT a second audit. It's a targeted re-examination of killed findings with a different mindset:
- The Critic asks: "Can I DISPROVE this?" (innocent until proven guilty)
- The Reviewer asks: "Did the gate DISMISS this too quickly?" (was the dismissal justified?)

The output is a **Second Opinion** section — findings that survive re-review get surfaced as **"Worth Manual Review"**, not as verified findings. The auditor decides.

## Which Gates to Re-Examine

Not all gates deserve re-examination. Some are reliably correct. Others are known to over-kill.

### RE-EXAMINE (High over-kill risk)

**Gate C — "Intentional Design"** (HIGHEST PRIORITY)
- The gate kills anything that matches a reference implementation or has supporting comments
- **Problem**: Devs intentionally design exploitable things constantly. "Intentional" ≠ "safe"
- **Re-examination approach**:
  1. Read the code the gate cited as "intentional"
  2. Ask: Does this intentional design CREATE an exploitable condition?
  3. Ask: Does the original reference implementation have the same issue? (If yes, it might be a known issue in the reference, not proof of safety)
  4. Ask: Has the protocol MODIFIED the reference implementation in a way that changes the security properties?
  5. If the design choice leads to value loss for users under normal usage (not attack), it's still a finding regardless of intent

**Gate E — "Admin Trust"** (HIGH PRIORITY)
- The gate kills anything requiring admin/owner action
- **Problem**: Many contests accept admin-related Mediums, especially:
  - Missing timelock on destructive admin actions (rug vectors)
  - Admin can permanently brick user funds with no recovery path
  - Admin privileges that should be behind a multisig/timelock but aren't
  - Single-step ownership transfer (admin can accidentally brick governance)
- **Re-examination approach**:
  1. Is there a timelock? If no timelock on irreversible destructive action → potential Medium
  2. Can admin drain user funds directly? If yes → potential Medium (rug vector)
  3. Can admin accidentally brick the protocol with a single bad call? If yes → potential Medium
  4. Is ownership transfer two-step? If single-step → note it
  5. ONLY promote if the admin action is IRREVERSIBLE and DESTRUCTIVE to users

**Gate B — "Theoretical / Not Exploitable"** (MEDIUM PRIORITY)
- The gate kills findings where the critic couldn't construct an exploit
- **Problem**: Some exploits are complex multi-step sequences that a single pass might miss
- **Re-examination approach**:
  1. Re-read the original candidate's mechanism description
  2. Try to construct the exploit trace with FRESH EYES (don't re-read the critic's dismissal first)
  3. Consider flash loan attack paths the critic might not have explored
  4. Consider multi-block MEV sequences
  5. If you still can't construct a concrete trace → confirm the kill

**Gate F — "Dust / Economically Insignificant"** (MEDIUM PRIORITY)
- The gate kills anything with max_loss × max_iterations < $100
- **Problem**: The $100 threshold is context-free. Dust in a $100M TVL pool is different from a $10K pool. Also, dust that accumulates per-block over time can become significant.
- **Re-examination approach**:
  1. What's the protocol's expected TVL/volume?
  2. Can the dust accumulate over time without bound?
  3. Is the rounding direction attacker-controlled? (attacker-controlled rounding direction = finding even if individual amounts are small)
  4. Can the dust be extracted via flash loan amplification?
  5. Recalculate with realistic protocol parameters

**Gate D — "Speculative / No Concrete Exploit"** (LOWER PRIORITY)
- The gate kills vague "could be an issue" findings
- **Re-examination approach**:
  1. Try harder to construct the concrete trace
  2. If the mechanism is valid but the exploit path is unclear, try different entry points
  3. If still speculative after re-examination → confirm the kill

**FP-1 — "Authorization Handled Elsewhere"** (LOWER PRIORITY)
- **Re-examination**: Verify that ALL call paths go through auth. One unguarded path = real finding.

**FP-2 — "Validation in Called Functions"** (LOWER PRIORITY)
- **Re-examination**: Is the validation COMPLETE? Does it cover all edge cases? Partial validation = real finding.

### DO NOT RE-EXAMINE (Reliably correct)

**Gate A — "Generic Best Practice"**: These are genuinely noise. "Use SafeERC20" without a specific failing token is never a real finding. Skip.

**Gate G — "Out of Context"**: Token behaviors for unlisted tokens, chain-specific issues on unsupported chains. These are definitionally out of scope. Skip.

**Gate H — "Known / Acknowledged"**: Already in README known issues. Only re-examine if the mechanism match seems weak (same topic but different exploit path).

## Execution

### Step 1: Load Context

Read these files:
1. `.audit/findings/critic-verdicts.md` — get all killed findings with their gate/FP reasons
2. `.audit/recon.md` — understand the protocol
3. `.audit/findings/detector-candidates.md` — get the ORIGINAL candidate descriptions (before the critic filtered them)

Build a list of all killed findings, grouped by gate.

### Step 2: Filter to Re-Examinable

From the killed findings, extract ONLY those killed by gates C, E, B, F, D, FP-1, or FP-2. Skip gates A, G, H (unless Gate H has a weak mechanism match — same topic but different path).

Sort by priority:
1. Gate C kills (intentional design)
2. Gate E kills (admin trust)
3. Gate B kills (theoretical)
4. Gate F kills (dust)
5. Gate D kills (speculative)
6. FP-1 / FP-2 kills

### Step 3: Re-Examine Each Finding

For each killed finding in priority order:

1. **Read the original candidate** from detector-candidates.md (or state-candidates.md). Get the FULL description, not just the critic's summary.

2. **Read the actual code** at the cited file:line. Fresh eyes — don't carry over the critic's judgment.

3. **Apply the gate-specific re-examination approach** (see above).

4. **Assign a review verdict**:

   - **REVIVE — Worth Manual Review**: The gate dismissal was premature. The mechanism is plausible and deserves human auditor attention. Include WHY the gate was wrong and what the auditor should look for.

   - **REVIVE — Informational**: Not exploitable for value loss, but worth noting as a design concern, hardening opportunity, or audit trail item. Include what the concern is.

   - **CONFIRM KILL**: The gate was correct. The re-examination found no reason to reconsider. State what you checked.

5. **For REVIVE verdicts**, provide:
   - The original candidate ID and description
   - Which gate killed it and why
   - Why the gate might be wrong in this specific case
   - What the auditor should manually verify
   - Suggested severity if it turns out to be real

### Step 4: Protocol Context Check

After individual re-examination, do one cross-cutting check:

- **Admin centralization cluster**: If multiple Gate E kills exist, do they collectively represent a significant centralization risk? Individual admin functions might be acceptable, but 6+ admin-controlled critical functions without timelocks could be a systemic concern worth noting.

- **Dust accumulation cluster**: If multiple Gate F kills exist, can the individual dust amounts combine? Rounding in function A + rounding in function B + rounding in function C = significant leakage?

- **Design assumption cluster**: If multiple Gate C kills exist around the same mechanism, the "intentional design" might have a systemic flaw that individual analysis missed.

## Output

Save to `.audit/findings/review-second-opinion.md`.

### Presentation to User

When presenting results, use this structure. The goal: the auditor reads top to bottom, understands every item in under 30 seconds, and knows exactly what action to take.

#### 1. Summary Banner

```
───────────────────────────────────────────────────
Krait Second Opinion — [Protocol Name]

X killed findings re-examined | Y skipped (reliable gates)
Result: X revived for review | Y confirmed kills
───────────────────────────────────────────────────
```

#### 2. Systemic Patterns (FIRST — most valuable)

If the cluster analysis (Step 4) found cross-cutting patterns, lead with them. These are the findings that individual analysis missed.

```markdown
## Systemic Patterns

### [Pattern title — plain English]

**What's happening**: [2-3 sentences explaining the systemic issue. No gate codes, no candidate IDs — just describe the problem in terms the auditor understands.]

**Affected areas**:
- `file.sol:XX` — [what this function does wrong]
- `file.sol:YY` — [what this function does wrong]
- `file.sol:ZZ` — [what this function does wrong]

**Why individual analysis missed it**: [Each piece was dismissed individually because X, but together they create Y]

**Risk if real**: [MEDIUM/HIGH] — [one-line impact]

**Verify**:
- [ ] [Specific actionable check]
- [ ] [Specific actionable check]
```

If no systemic patterns found, skip this section entirely. Don't write "No systemic patterns found."

#### 3. Revived Findings

Each revived finding tells a complete story. The auditor should understand the issue without having to look up the original candidate or know what "Gate C" means.

**For findings discovered NEW during review** (found by reading the code with fresh eyes, not from the killed list):

```markdown
## New Finding — [Descriptive Title]

**File**: `path/to/file.sol:XX-YY`
**Suggested severity**: [MEDIUM/HIGH]

**What's wrong**:
[Clear explanation of the vulnerability in 2-4 sentences. What the code does, what it should do, and what breaks. Include the actual code behavior, not abstractions.]

**Why the original audit missed it**:
[One sentence — e.g., "The original audit focused on X but this function was only analyzed in the context of Y"]

**Impact**:
[Concrete impact — who loses what, under what conditions, approximately how much]

**Verify**:
- [ ] [Specific check 1 — e.g., "Confirm _syncFunding() is not called anywhere in the addMargin() call chain"]
- [ ] [Specific check 2 — e.g., "Calculate max staleness: block.timestamp - lastFundingTime after 24h of no trades"]
- [ ] [Specific check 3]
```

**For killed findings being revived** (from the killed list):

```markdown
## Revisit — [Descriptive Title]

**File**: `path/to/file.sol:XX-YY`
**Suggested severity**: [MEDIUM/HIGH]

**What the finding claims**:
[2-3 sentence plain-English summary of the original finding. What's the alleged vulnerability?]

**Why it was dismissed**:
[Plain English — NOT "killed by Gate C". Instead: "The critic dismissed this as an intentional design choice because the reference implementation (Uniswap V3) uses the same pattern." or "The critic ruled this as admin-trust because only the owner can trigger it."]

**Why that dismissal may be wrong**:
[Specific counterargument — e.g., "The reference implementation doesn't have X constraint that this protocol adds, which changes the security properties." or "The owner action is irreversible and there's no timelock — in Code4rena this typically qualifies as Medium."]

**Impact if real**:
[Concrete impact — who loses what, under what conditions]

**Verify**:
- [ ] [Specific check 1]
- [ ] [Specific check 2]
- [ ] [Specific check 3]
```

**For informational items** (not exploitable, but worth noting):

```markdown
## Note — [Descriptive Title]

**File**: `path/to/file.sol:XX`

**Observation**: [1-2 sentences — what's unusual and why it's worth knowing, even though it's not exploitable. E.g., "Rewards silently redirect to STAKED_BEAR when InvarCoin is paused. No value loss (funds go to stakers), but users expecting rewards in token A will receive them in token B with no event or notification."]
```

#### 4. Confirmed Kills (Last — least important)

Brief. The auditor doesn't need to re-read every confirmed kill. Just show the count and a collapsed summary.

```markdown
---

**Confirmed kills**: X of Y re-examined findings were correctly dismissed.

<details>
<summary>View confirmed kills</summary>

| # | Finding | Dismissed because | Confirmed because |
|---|---------|-------------------|-------------------|
| 1 | [Title] | [plain English reason] | [what re-examination checked] |
| 2 | [Title] | [plain English reason] | [what re-examination checked] |
</details>
```

### File Output

Save the full report to `.audit/findings/review-second-opinion.md` using the same structure as the presentation, but in standard markdown (no terminal formatting).

### Key Formatting Rules

- **No gate codes in user-facing output.** Never write "Gate C" or "FP-2". Always translate to plain English: "dismissed as intentional design" or "dismissed because validation exists in the called function."
- **No candidate IDs without context.** Never write "was CANDIDATE-A04" without also explaining what that candidate was about. Better: skip the ID entirely and just describe the finding.
- **Every finding must be self-contained.** The auditor should understand each item without cross-referencing other files.
- **Verify checklists must be actionable.** Not "check this function" but "confirm that setFee() has a timelock > 24h and cannot be bypassed via emergencySetFee()."
- **Lead with the interesting stuff.** Systemic patterns first, new findings second, revived findings third, confirmed kills last.

## Rules

- **This is a SECOND OPINION, not a verdict.** Revived findings are flags for human review, not verified TPs. Make this extremely clear.
- **Fresh eyes.** Read the code first, THEN the critic's dismissal. Don't anchor on the gate's reasoning.
- **Don't re-examine gates A/G.** They're reliably correct and re-examining them wastes time.
- **Be specific about what to verify.** "Check this function" is not helpful. "Verify that the timelock delay on `setFee()` is > 24h and cannot be bypassed via `emergencySetFee()`" is helpful.
- **Don't inflate.** If re-examination confirms the kill, say so. The value of this skill is precision, not volume.
- **Cluster analysis matters.** Individual kills might be correct, but clusters of kills in the same area can reveal systemic issues the gates weren't designed to catch.
