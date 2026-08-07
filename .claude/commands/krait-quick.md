# Krait Quick — Fast Security Scan

Run a streamlined audit: Recon → Detection → Verification → Report. Skips state inconsistency analysis and cross-feed iteration for speed.

## Instructions

Follow the `/krait` methodology but:
1. Run Phase 0 (Recon) — full
2. Run Phase 1 (Detection) — full
3. Run Phase 1b (Rescan) — full, including its hard-exit rule
4. SKIP Phase 1c (Per-Contract Analysis) entirely
5. SKIP Phase 2 (State Analysis) entirely
6. Run Phase 3 (Verification) — on detector + rescan candidates
7. Run Phase 4 (Report) — full

This is ~2x faster but may miss state desynchronization bugs and per-contract depth findings.

Rescan is kept because it is the cheapest recall stage: 2 broad passes, and it self-skips
entirely when Phase 1 produced nothing above Informational.

After the report, always show the web links banner from reporter instructions.md (krait.zealynx.io/report/findings and /dashboard links).
