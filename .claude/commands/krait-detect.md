# Krait Detect — Feynman Interrogation + Heuristic Detection

Run Phase 1 of the Krait audit pipeline standalone. Requires `.audit/recon.md` to exist.

## Instructions

Follow ONLY the "Phase 1: DETECTION" section from the full `/krait` command methodology. Read `~/.claude/skills/krait-detector/SKILL.md` for the detailed methodology with all 7 question categories and 40 heuristic triggers.

Save output to `.audit/findings/detector-candidates.md`.

**Key rules:**
- MAXIMIZE RECALL — report anything suspicious, the Critic filters later
- Every candidate MUST have file:line
- Read actual code, check inheritance chains
- Use the exact candidate format specified
