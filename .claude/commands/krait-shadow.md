# /krait-shadow — Shadow Audit Pipeline (Blind Benchmark + Learn)

You are the Krait shadow audit orchestrator. You run a BLIND audit on a past public contest, score against official findings, and generate lessons from every miss. This is the self-improvement loop.

## Usage

```
/krait-shadow {contest-identifier}
```

Example: `/krait-shadow 2023-07-basin`

If no contest specified, pick the next unaudited contest from `shadow-audits/registry.yaml`.

## Pipeline

### Phase A: Setup

1. Read `shadow-audits/registry.yaml` to get contest details
2. Clone the contest repo if not already in `test-repos/`:
   ```bash
   git clone --recursive https://github.com/code-423n4/{contest} test-repos/{short-name}
   ```
3. Create `.audit/` directory in the test repo
4. **DO NOT fetch official findings yet** — this must be blind

### Phase B: Blind Audit

Run the full `/krait` audit on the contest codebase:

1. Execute the full 4-phase audit (Recon → Detect → State Analysis → Verify → Report). All learned lessons are already integrated into the detector skill's heuristics, modules, and questions.
2. Save the complete report to `.audit/blind-audit-report.md`
3. Save structured findings to `.audit/krait-findings.json`

**CRITICAL**: Do not look at, fetch, or reference official findings during this phase.
The entire value of shadow auditing is the blind test. Any data contamination
invalidates the results.

### Phase C: Score

NOW fetch official findings and score:

1. Fetch HIGH findings:
   ```bash
   gh issue list --repo code-423n4/{contest}-findings --label "selected for report" --label "3 (High Risk)" --state all --json number,title --limit 20
   ```

2. Fetch MEDIUM findings:
   ```bash
   gh issue list --repo code-423n4/{contest}-findings --label "selected for report" --label "2 (Med Risk)" --state all --json number,title --limit 20
   ```

3. For each official finding, read its details:
   ```bash
   gh issue view {N} --repo code-423n4/{contest}-findings --json title,body,labels
   ```

4. Map each official finding against the blind audit's findings:
   - **TP**: Same root cause AND same affected code
   - **PARTIAL**: Same code area but different root cause, or same bug class but wrong location
   - **MISSED**: Not found at all
   - **FP**: Blind audit finding with no official match

5. Calculate precision, recall, F1
6. Write `.audit/benchmark-score.md`

### Phase D: Learn (INTEGRATE INTO SKILLS — NOT YAML FILES)

**CRITICAL**: Learning means MODIFYING THE DETECTION METHODOLOGY, not writing dead YAML files. The patterns/learned/ directory is an archive, not a detection engine.

For each MISSED finding:

1. **Root-cause the miss**: Was it a missing heuristic? Missing question category? Missing module? Wrong reasoning?
2. **Integrate directly into the skills**:
   - If it's a new bug class → add a new heuristic trigger (e.g., EXT-01) to `.claude/skills/krait-detector/SKILL.md`
   - If it's a new check methodology → add a new Module (e.g., Module D15) to the detector skill
   - If it's a new question angle → add to the relevant Feynman category (1-9) in the detector skill
   - If it's a FP pattern → add to the FP elimination list in `.claude/skills/krait-critic/SKILL.md`
3. **Mirror changes** in `.claude/commands/krait.md` (the command must match the skill)
4. **Optionally archive** raw analysis to `patterns/learned/` for reference — but this is documentation, not detection

For each FP:
1. Identify which FP elimination pattern (#1-13+) should have caught it
2. If no existing pattern fits → add a new FP pattern to the critic skill
3. If an existing pattern was too vague → make it more specific

For each PARTIAL:
1. The detection was close but reasoning was wrong → upgrade the relevant question/heuristic to cover the actual attack vector

### Phase E: Verify (optional)

If time permits, re-run the audit on the SAME contest WITH the new lessons loaded.
The new lessons should catch at least the findings from THIS contest.
This verifies the lessons are actionable, not just documentation.

### Phase F: Update Registry

Update `shadow-audits/registry.yaml` with results:
```yaml
  status: completed
  date: {today}
  results:
    high_recall: {X/Y}
    medium_recall: {X/Y}
    precision: {X%}
    recall: {X%}
    f1: {X.XX}
    lessons_generated: {N}
```

Update `shadow-audits/progress.md` with cumulative tracking.

## Sequencing for Multiple Contests

When running multiple contests in sequence:
1. Complete ALL phases (A through F) for contest N before starting contest N+1
2. Lessons from contest N are loaded during contest N+1's audit (Phase B)
3. Track improvement across contests in `shadow-audits/progress.md`

Expected improvement pattern:
- Contest 1-3: Low recall, many misses, lots of new lessons
- Contest 4-6: Improving recall as lessons accumulate
- Contest 7-10: Stabilizing — new misses are increasingly novel/creative

## Output

After each shadow audit, output:

```
## Shadow Audit Complete: {contest}

Score: {precision}% precision / {recall}% recall / F1={f1}
HIGHs: {found}/{total}
MEDIUMs: {found}/{total}

New lessons: {count} (total in DB: {total_lessons})
Key gaps: {list of gap categories}

Cumulative improvement: {recall_contest_1}% → {recall_this_contest}%
```

## Important Rules

1. **NEVER fetch findings before the audit is complete** — this is the #1 rule
2. **Learning = modifying the skill files** — NOT writing YAML to patterns/learned/. The detector skill IS the knowledge base.
3. **For EVERY miss, upgrade the methodology** — add a heuristic, question, or module to the detector skill
4. **Be honest about FPs** — don't rationalize false positives as "valid but not reported"
5. **Track cumulative metrics** — the whole point is measuring improvement over time
6. **SKILL.md files are the single source of truth.** `krait.md` is a lean orchestrator that references them — do NOT duplicate methodology content into `krait.md`. Make all detection changes in `.claude/skills/krait-detector/SKILL.md`, all FP/kill gate changes in `.claude/skills/krait-critic/SKILL.md`, all recon changes in `.claude/skills/krait-recon/SKILL.md`.
