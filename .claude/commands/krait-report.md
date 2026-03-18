# Krait Report — Final Report Generation

Run Phase 4 of the Krait audit pipeline standalone. Requires `.audit/findings/critic-verdicts.md`.

## Instructions

Follow ONLY the "Phase 4: REPORT" section from the full `/krait` command methodology. Read `~/.claude/skills/krait-reporter/SKILL.md` for detailed formatting rules.

Save output to `.audit/krait-report.md` and `.audit/krait-findings.json`.

**Key rules:**
- Only include TRUE POSITIVE and LIKELY TRUE findings
- Deduplicate: same file + lines + root cause = one finding
- Honest severity — don't inflate or deflate
- Every finding needs: file:line, proof trace, root cause, specific fix recommendation
- Present the final report to the user
