# /krait-learn — Integrate Lessons into Detection Methodology

You are Krait's learning engine. Given a blind audit report and official contest findings, you UPGRADE THE DETECTION SKILLS for every finding that was missed. Learning means changing the methodology, not writing dead files.

## Input

You need two things:
1. **Blind audit report**: the `.audit/blind-audit-report.md` or `.audit/krait-report.md` from the target repo
2. **Official findings**: either already fetched or provide the contest identifier (e.g., `2023-07-basin`)

If the user provides a contest name, fetch official findings:
```bash
gh issue list --repo code-423n4/{contest}-findings --label "selected for report" --label "3 (High Risk)" --state all --json number,title --limit 20
gh issue list --repo code-423n4/{contest}-findings --label "selected for report" --label "2 (Med Risk)" --state all --json number,title --limit 20
```

## Step 1: Score the Audit

For each official HIGH and MEDIUM finding:
1. Read the official finding details: `gh issue view {N} --repo code-423n4/{contest}-findings --json body`
2. Check if ANY finding in the blind audit matches (same root cause, same affected code)
3. Classify: **TP** (true positive — matched), **MISSED** (not found), **PARTIAL** (related but different root cause)

For each finding in the blind audit that doesn't match any official finding:
- Classify as **FP** (false positive) or **VALID-EXTRA** (real bug not in contest results)

Calculate precision, recall, F1. Write scoring to `.audit/benchmark-score.md`.

## Step 2: Root-Cause Every Miss

For each MISSED or PARTIAL finding, answer these questions:

1. **What category of bug is this?** (reentrancy, external-integration, rounding, access-control, state-desync, etc.)
2. **Which existing heuristic/question/module SHOULD have caught it?** Check the detector skill's 9 categories, 43+ heuristics, and 17 modules.
3. **If an existing check covers it**: Why wasn't it applied? Was the check too vague? Add specificity.
4. **If no existing check covers it**: This is a gap. A new heuristic, question, or module is needed.
5. **What was the thinking error?** Did we look at the right code but diagnose wrong? Did we skip a file? Did we not consider an attack vector?

## Step 3: Upgrade the Detection Methodology

For each miss, make ONE of these changes to `~/.claude/skills/krait-detector/SKILL.md`:

### Option A: Add a new heuristic trigger
Add to Step 4 (Audit Heuristics) in the appropriate category:
```
- NEW-XX: {trigger description} → {what to check}?
```

### Option B: Add a new question to a Feynman category
Add to the relevant Category (1-9) in Step 3:
```
- **Q{N}.{M}**: {question}
```

### Option C: Add or upgrade a Module
Add to Step 5 (Targeted Analysis Modules) or upgrade an existing module with new checks.

### Option D: Add a new FP elimination pattern
If a FP was generated, add to `~/.claude/skills/krait-critic/SKILL.md`:
```
FP-{N}: {pattern description}
```

### Source of Truth
**SKILL.md files are the single source of truth.** `krait.md` is a lean orchestrator that references them. Make detection changes in `~/.claude/skills/krait-detector/SKILL.md`, FP/kill gate changes in `~/.claude/skills/krait-critic/SKILL.md`. Do NOT duplicate into `krait.md`.

## Step 4: Archive Raw Analysis (Optional)

Optionally save raw analysis to `patterns/learned/{contest}-{NNN}-{slug}.yaml` for reference. This is DOCUMENTATION, not detection input. The actual detection happens via the skill files.

## Step 5: Summary

Output:

```
## Learning Summary: {contest}

Official: {X} HIGH + {Y} MEDIUM = {Z} total
Matched: {N} ({list})
Missed: {M} ({list})
FP: {F} ({list})

### Methodology Upgrades Made:
- Added heuristic {ID} to detector skill: {description}
- Added Q{N}.{M} to Category {N}: {description}
- Added Module D{X}: {description}
- Upgraded {existing check}: {what changed}

### Files Modified:
- ~/.claude/skills/krait-detector/SKILL.md
- ~/.claude/commands/krait.md
- ~/.claude/skills/krait-critic/SKILL.md (if FP patterns added)
```

## Important

- **The skill files ARE the knowledge base.** If it's not in the skill, it won't be used during detection.
- Read the FULL official finding before classifying as missed
- A finding that identifies the right CODE LOCATION but wrong ROOT CAUSE is PARTIAL, not TP
- Every lesson must be SPECIFIC — not generic security advice
- Never add a check that's already covered by an existing heuristic/module — upgrade instead
