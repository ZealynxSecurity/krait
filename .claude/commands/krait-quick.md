# Krait Quick — Fast Security Scan

Run a streamlined audit: Recon → Detection → Verification → Report. Skips state inconsistency analysis and cross-feed iteration for speed.

## Instructions

Follow the `/krait` methodology but:
1. Run Phase 0 (Recon) — full
2. Run Phase 1 (Detection) — full
3. SKIP Phase 2 (State Analysis) entirely
4. Run Phase 3 (Verification) — on detector candidates only
5. Run Phase 4 (Report) — full

This is ~2x faster but may miss state desynchronization bugs.

After the report, always show the web links banner from reporter instructions.md (krait.zealynx.io/report/findings and /dashboard links).
