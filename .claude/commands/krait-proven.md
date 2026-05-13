# Krait Proven — Mechanically-Proven Findings Only

Run the same full Krait pipeline as `/krait`, but cap any finding without a mechanically-verified PoC or production trace at LOW severity. Useful for shadow-audit benchmarking and for clients who want only proven findings driving the severity tier.

## Usage

```
/krait-proven                    # Proven-only audit of current directory
/krait-proven src/contracts/     # Proven-only audit of a specific directory
```

## Instructions

You are Krait running in **proven-only mode**. Follow the full `/krait` pipeline exactly as written in `.claude/commands/krait.md`:

1. Preflight (gate mode)
2. Phase 0 — Recon
3. Phase 1 — Detection
4. Phase 2 — State Inconsistency Analysis
5. Phase 3 — Verification (Critic)
6. Phase 3b — Review (only if `/krait-review` is also invoked; not automatic)
7. Phase 4 — Report

The only difference is in Phase 4 (Report). When you reach the reporter, the proven-only flag is set, which activates **Step 3c: Proven-Only Mode Demotion** in `.claude/skills/krait/reporter/instructions.md`. Apply that step.

Concretely, in Step 3c:

- A finding's BEST evidence is the strongest tag attached to it across detector, state-auditor, and critic output. The full ranking is: `[POC-PASS]` and `[MEDUSA-PASS]` are proven; `[PROD-ONCHAIN]`, `[PROD-SOURCE]`, `[PROD-FORK]` are proven; `[CODE-TRACE]` is unproven.
- Any finding whose best evidence is `[CODE-TRACE]` (and which carries none of the proven tags) is demoted: severity is capped at LOW. Findings already at LOW or INFORMATIONAL are unchanged.
- Add the per-finding note: *Severity capped at LOW under proven-only mode — best evidence is `[CODE-TRACE]` only, no mechanically-verified PoC or production trace.*
- Surface a header note in the final report: *Proven-only mode enabled: {N} findings capped at LOW from {breakdown of pre-demotion severities} due to unproven evidence (`[CODE-TRACE]` only).*

If no finding has a proven tag — typical when the audit was pure reasoning with no executed PoC — every finding will be capped at LOW. That is the intended behavior of this mode. Do not lower the bar; either run the fuzzer / verifier to attach proven evidence, or accept that the report ships LOW-only.

All other reporter steps run unchanged: Step 3a (Trust-Assumption Downgrade), Step 3b (Severity Ranking), Step 3d (Root-Cause Consolidation), Step 4 (Write Report), Step 5 (Findings Index).

After the report, always show the web links banner from reporter `instructions.md` (the block with krait.zealynx.io/report/findings and /dashboard links).
