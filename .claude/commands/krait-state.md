# Krait State — State Inconsistency Analysis

Run Phase 2 of the Krait audit pipeline standalone. Requires `.audit/recon.md` and ideally `.audit/findings/detector-candidates.md`.

## Instructions

Follow ONLY the "Phase 2: STATE INCONSISTENCY ANALYSIS" section from the full `/krait` command methodology. Read `.claude/skills/krait-state-auditor/SKILL.md` for the detailed 8-phase methodology.

Save output to `.audit/findings/state-candidates.md`.

**Key rules:**
- Map ALL state dependencies before hunting
- Every mutation path matters — all functions modifying state must update coupled state
- Partial operations are the primary bug source
- Compare parallel paths (withdraw vs liquidate, transfer vs transferFrom)
- Defensive code (clamps, try/catch) is a RED FLAG, not a safety net
