# Krait Critic — Verification Gate

Run Phase 3 of the Krait audit pipeline standalone. Requires candidate files in `.audit/findings/`.

## Instructions

Follow ONLY the "Phase 3: VERIFICATION" section from the full `/krait` command methodology. Read `~/.claude/skills/krait-critic/SKILL.md` for the full verification methodology and 10 FP patterns.

Read ALL candidate files:
- `.audit/findings/detector-candidates.md` (if exists)
- `.audit/findings/state-candidates.md` (if exists)

Save output to `.audit/findings/critic-verdicts.md`.

**Key rules:**
- INNOCENT UNTIL PROVEN GUILTY — attempt to disprove every finding
- Re-read every cited file to verify code exists at stated lines
- Trace inheritance chains completely
- Be ruthless — "might be exploitable" is NOT verified
- Zero false positives on H/M is the goal
