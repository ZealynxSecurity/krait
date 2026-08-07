# Krait Per-Contract Analysis — Narrow Scope, Maximum Depth (B3)

> Phase 1c of the Krait audit pipeline. Runs after Rescan (Phase 1b), before State Analysis (Phase 2).
> *(Methodology adapted from PlamenTSV/plamen, MIT — `phase3b-rescan-prompt.md` § Phase 3c.)*

## Purpose

Counter **attention dilution**. A whole-codebase agent spends its budget on the two or three most interesting files; everything else gets a skim. This phase assigns one agent per contract cluster with a scope narrow enough that depth is affordable.

Rescan (B4) covers cross-contract bugs by looking broadly. This phase covers the opposite failure: bugs that need line-by-line attention on one file. The two are complementary — run both.

## Prerequisites

- `.audit/findings/detector-candidates.md` — pass 1 output
- `.audit/findings/rescan-candidates.md` — rescan output (if it ran)
- `.audit/recon.md` — file risk table, and `.audit/ast-facts.md` if present (authoritative inheritance)

## Step 1: Build Contract Clusters

Group scope files into clusters:

- **Same inheritance chain → same cluster.** A base and its derived contracts belong together: a "missing" check often lives in the parent, and an agent that only sees the child reports a false positive. Use `ast-facts.md`'s inheritance tree when it exists; otherwise read the `contract X is Y, Z` declarations directly.
- **Standalone contracts** → their own cluster.
- **Cluster size cap: ~1500 LOC.** Split larger clusters at a logical boundary.
- **Maximum 8 clusters.** If more exist, prioritise by RISK_SCORE from the recon table and note in the output which files got no dedicated pass — silently dropping coverage reads as "we covered everything" when you didn't.

Record the cluster plan before starting:

| Cluster | Files | LOC | Reason for grouping |
|---------|-------|-----|---------------------|

## Step 2: Build the Exclusion List

Same format as Rescan — one line per already-known candidate, from **both** `detector-candidates.md` and `rescan-candidates.md`:

```
- [HIGH] Vault.sol:142 — withdraw() skips reward checkpoint
```

### Exclusion source rule (recall-safe)

You may exclude a candidate as a duplicate ONLY if you can point at a **concrete entry in the list above** — a real ID or a real `file:line`. A bug you *believe* is already known but cannot find in the list MUST be reported as new. **When in doubt, emit.**

Every exclusion you record must name its referent and carry its own content:

```
EXCLUDED — byte-width mismatch at Encoder.sol:412 truncates the high byte so a crafted
account passes validation → asset mis-routing. Duplicate of [HIGH] Encoder.sol:412.
```

A bare "already known" with no location and no referent is a suppressed bug, not an exclusion.

## Step 3: Analyze Each Cluster

For EACH function in the cluster, in order:

1. **State completeness** — does every state-modifying path update ALL related state? (timestamps, accumulators, snapshots, mirrored balances)
2. **Conditional branch audit** — for each if/else, what state is written in each branch? Is anything left stale on the skip path?
3. **Boundary values** — what happens at 0, 1, MAX, and the type boundary for every parameter?
4. **Pairing audit** — for each encode / normalize / hash / lock operation, trace its inverse (decode / denormalize / verify / unlock). Same inputs, same order?
5. **Fee and reward trace** — follow accrual → accumulation → claim → transfer. Do assets and shares stay consistent at every step?
6. **Parent standalone pass** — when a base contract is in your cluster, also examine its unconditional paths *on their own terms*, as if no child existed. Timestamp updates, fee math and state transitions that run regardless of which override is active are invisible when you only read the parent through the child's lens.

### Cross-cluster boundaries

When an issue sits on a boundary with a contract outside your cluster, describe it from **your** files' perspective and name the external contract. Do not trace into it — another cluster's agent owns that code.

## Step 4: File Coverage Checkpoint (MANDATORY)

Before writing findings, list every file in your cluster and confirm you opened it:

| File | LOC | Opened? | Functions analyzed |
|------|-----|---------|--------------------|

Any `Opened: NO` → open and analyze it before returning. 28% of historically missed findings were in files the agent never opened.

## Quality gates

- Every finding needs a specific `file:line`.
- **Maximum 5 findings per cluster** — prioritise by severity. This is a depth pass, not a volume pass.
- Do not re-report anything on the exclusion list (subject to the exclusion source rule above).
- Do not report generic best practice; kill gate A removes those unconditionally.
- Record concrete values you tested as depth-evidence tags.

## Output

Write `.audit/findings/percontract-candidates.md` using the standard candidate format, with IDs `PC{cluster}-1`, `PC{cluster}-2`, …

Include the cluster plan table and the coverage checkpoint. If any scope file received no dedicated cluster, say so explicitly with its RISK_SCORE.

Then state: `Per-contract complete: N clusters, M new candidates`.

## No iteration

This phase does NOT iterate. The narrow scope *is* the depth mechanism — there is no attention saturation to counter by re-scanning. One pass per cluster is sufficient.
