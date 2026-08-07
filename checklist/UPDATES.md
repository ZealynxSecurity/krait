# Krait — Updates

A running log of **bigger improvements** to the Krait plugin (skills, frameworks, references, scripts) and the CLI ↔ web bridge contract. Small CTA/copy tweaks on the marketing site are intentionally out of scope here.

Format: most recent first. Each entry notes the date, the commit, and what materially changed.

---

## 2026-06-04 — Maintainer skill works in Claude + Grok
**Commit:** `5c3aa3b`

- Made the `krait-checklist` maintainer workflow portable across Claude Code and Grok, so the checklist review / mapping-bridge upkeep can be driven from either harness.

## 2026-06-02 — Full skill review & overhaul (harness pass)
**Commit:** `e72ec3e`

A substantial review-and-improve pass over all three skills plus the web bridge. Highlights:

- **`/krait:check` unbroken** — now resolves checks against the shipped `frameworks/scan/` tier via the index instead of failing on installed artifacts.
- **Vertical naming aligned** — consistent vertical names/prefixes (e.g. `dasf` for DEX/AMM) across `scan`, `assess`, `check`, the README, and `build-index.py`.
- **`/krait:assess` filters completed** — filter logic brought in line with its own docs, added `ci`/`pi` guidance, post-write validation of `.zealynx-run.json`, and output-template/progress fixes.
- **Web bridge correctness** — fixed `bridges` / `proxy` / `gamefi` mapping slugs so published checklist pages render Krait banners/badges/coverage; primer names surfaced in titles.
- **Truthful import coverage** — `KraitImport` coverage is vertical-scoped and uses shared helpers (no more false "global matched").
- **`krait_analysis` branding** — surfaced and preserved through `EvidenceInline` and `CheckCard`.
- **Drift guard** — added a pure `validateKraitMapping` validator + dev-time guard so CLI ↔ web slug drift is caught early.

See `docs/krait-checklist-improvements-retrospective.md` (website repo) for the full retrospective.

## 2026-04-08 — Initial plugin (v0.1.0)
**Commit:** `b3eff5c`

- First release of the Krait Claude Code plugin: `scan`, `assess`, and `check` skills; the three framework tiers (`condensed` / `scan` / full); `references/` (check index + severity guide); and `scripts/` (`build-index.py`, `sync-frameworks.sh`).
- 845 security checks across 39 DeFi verticals, derived from 4,500+ real audit findings sourced from Solodit.
- Standalone mode (`/krait:scan`, `/krait:check`) plus integrated mode (`/krait:assess` → `.zealynx-run.json` for import into audit-readiness.zealynx.io).
