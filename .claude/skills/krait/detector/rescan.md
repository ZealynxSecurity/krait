# Krait Rescan — Second Pass with Exclusion List (B4)

> Phase 1b of the Krait audit pipeline. Runs after Detection (Phase 1), before State Analysis (Phase 2).
> *(Methodology adapted from PlamenTSV/plamen, MIT — `phase3b-rescan-prompt.md`.)*

## Purpose

Counter **attention saturation**. A first pass fixates on the most prominent bug in each file and under-reads everything around it. This phase re-runs broad analysis while explicitly told what pass 1 already found, so attention lands in the gaps instead of on the same bug a second time.

This is a **recall** phase. Everything it surfaces still goes through the Critic's kill gates — the zero-FP bar is unchanged.

## Prerequisites

- `.audit/findings/detector-candidates.md` — pass 1 output
- `.audit/recon.md` — file risk table and protocol context

## Hard exit rule (check FIRST)

Count pass 1 candidates above Informational severity.

- **0 above Info** → **SKIP this phase entirely.** With no exclusion list there is nothing to diverge from; re-running the same broad analysis pays twice for one answer. Write `.audit/findings/rescan-candidates.md` with a one-line "skipped: pass 1 produced no candidates above Info" and move on.
- **≥ 1 above Info** → proceed.

## Step 1: Build the Exclusion List

From `detector-candidates.md`, extract ONE LINE per candidate:

```
- [HIGH] Vault.sol:142 — withdraw() skips reward checkpoint
- [MEDIUM] Pool.sol:88 — fee applied on gross instead of net
```

Keep it terse. The agent needs to *recognise* a duplicate, not re-read the original analysis. Full descriptions both blow the budget and anchor the second pass on the first pass's conclusions.

## Step 2: Identify Blind Spots

List every scope file that produced **zero** candidates in pass 1.

**These are the priority targets.** A file with no findings is UNDER-ANALYZED, not clean — 13% of all historically missed findings were in areas an earlier pass explicitly marked safe.

## Step 3: Run the Rescan

Run **2 passes** over the codebase, each covering roughly half the scope files with deliberate overlap. Broader scope than pass 1 — you are looking for what falls *between* the areas pass 1 examined closely.

For each pass, hold this framing:

> A first pass already analyzed this code and found the listed issues. Your job is to find what it MISSED. You are not re-checking its work.

### What attention saturation hides

Focus on the classes that a fixated first pass systematically misses:

1. **Cross-function state inconsistencies** — function A assumes an invariant that function B breaks
2. **Asymmetric operations** — the deposit path handles X but the withdraw path does not
3. **Parameter encoding mismatches between paired functions** — create/consume, lock/unlock, deposit/refund, encode/decode. Do both sides use the same inputs in the same order?
4. **Economic assumptions violated at the edges** — first user, last user, zero state, max state
5. **Time-dependent state going stale** under a specific operation sequence
6. **The quiet file next to the interesting one** — the helper, the library, the base contract nobody opened

Do NOT re-analyze the patterns pass 1 already covered. Look in the gaps BETWEEN what was analyzed.

## Quality gates

- Every finding needs a specific `file:line`. No location → discard it yourself; the pipeline will drop it anyway.
- If a candidate matches an exclusion-list entry on **location AND root cause**, skip it silently.
- Same area, different exploit path = **not** a duplicate. Report it.
- Do not report generic best practice ("use SafeERC20", "add events", "missing zero-address check"). Kill gate A removes those unconditionally, so they only cost budget.
- Record concrete values you tested as depth-evidence tags: `[BOUNDARY:reserve=0]`, `[TRACE:redeem(MAX)→revert L88]`.

## Output

Write `.audit/findings/rescan-candidates.md` using the standard candidate format, with IDs `RS-1`, `RS-2`, …

Then state: `Rescan complete: N new candidates ({H} high, {M} medium, {L} low)`.

## Non-goals

- Do NOT re-verify or overturn pass 1's findings. That's the Critic's job, then the Reviewer's.
- Do NOT deepen an existing candidate. If you find more evidence for a known finding, note it as a one-liner under `## Reinforced` — it strengthens the existing candidate, it is not a new one.
