# Preflight — Readiness Check

Shared readiness check used by both `/krait` (gate mode) and `/krait-init` (report mode).

## Modes

The caller specifies one of two modes:

- **gate** (used by `/krait` before Phase 0): run the hard checks only. If anything hard fails, abort with a one-line message pointing the user at `/krait-init` for details. Stay silent on success — the audit continues.
- **report** (used by `/krait-init`): run every check, print the full summary table, never abort. Output is the verdict.

## Hard vs soft checks

| Check | Hard (gate-fails the audit) | Why |
|-------|------------------------------|-----|
| `bash` available | yes | all recon scripts shell out via bash |
| `forge` available | yes | recon AST extraction + `/krait-fuzz` require it |
| `jq` available | yes | `ast-extract.sh` parses forge AST artifacts with `jq` |
| `*.sol` files in scope | yes | nothing to audit otherwise |
| `slither` available | no | optional pre-scan, skipped silently if absent |
| `node` ≥ 20 | no | only needed for the standalone CLI / MCP servers |
| `foundry.toml` / `hardhat.config.*` at target or parent | no | warn only; ast-extract has a regex fallback |
| `.audit/` in `.gitignore` | no | cosmetic; warn |
| `.krait-cache/` in `.gitignore` | no | cosmetic; warn |
| MCP servers registered (user scope) or built (project scope) | no | optional enrichment; skills work without them |
| `~/.claude/skills/krait/` and `~/.claude/commands/krait.md` exist | no | user may be running from a clone; warn |

## Step 1 — Required tooling

Run each check in parallel via Bash:

| Tool | Command | Hard? |
|------|---------|-------|
| `bash` | `bash --version` | yes |
| `forge` | `forge --version` | yes |
| `jq` | `jq --version` | yes |
| `slither` | `slither --version` | no |
| `node` | `node --version` (≥ 20) | no |

For each, capture `OK <version>` or `MISSING`. Do not speculate on install commands for platforms you can't detect — if unknown, say "consult the project's docs."

Suggested install hints (only mention when relevant):
- `forge`: `curl -L https://foundry.paradigm.xyz | bash && foundryup`
- `slither`: `pip install slither-analyzer`
- `jq`: `brew install jq` (macOS) / `apt-get install jq` (Debian/Ubuntu)

## Step 2 — Project shape

Verify the target looks like a Solidity project:

- A `*.sol` file exists somewhere under the target. Use:
  ```
  find <target> -name '*.sol' -not -path '*/node_modules/*' -not -path '*/lib/*' | head -20
  ```
- One of `foundry.toml` / `hardhat.config.*` / `truffle-config.js` exists at the target or a parent (look up to 2 levels).
- Detect the in-scope source dir matching `ast-extract.sh`'s logic: prefer `<target>/contracts`, then `<target>/src`, then `<target>/src/contracts`, then `<target>` itself.

Report the detected scope dir and approximate `.sol` file count. Zero `.sol` files → hard fail.

## Step 3 — Output and cache hygiene (soft)

Read `<target>/.gitignore` (read-only). Krait writes to `.audit/` and `.krait-cache/`; both should be gitignored.

If either is missing, **tell** the user what to add but **do not edit** the file:

```
.audit/
.krait-cache/
```

If there is no `.gitignore` at all, say so and suggest creating one — don't create it.

## Step 4 — MCP wiring (soft)

Krait ships two optional MCP servers (`krait-solodit`, `krait-forge`). They can be
registered two ways, and either is fine:

- **User scope** (what `scripts/install.sh` does) — registered once with absolute
  paths, available in every project. Check with `claude mcp list 2>/dev/null`.
- **Project scope** — a `.mcp.json` in the target declaring them with paths
  relative to the target. Only works when the target *is* the Krait clone.

Check in that order:

1. Run `claude mcp list 2>/dev/null | grep -i krait` (tolerate a missing `claude`
   CLI — that is not an error). If both servers appear, report OK and stop here.
2. Otherwise, if `<target>/.mcp.json` exists, read it, list the declared servers,
   and for each `"command": "node"` entry check that `args[0]` resolves to an
   existing file relative to `<target>`. A missing file means the build step
   hasn't run.
3. If neither is wired, surface the one-line fix and move on — the skills work
   without these servers:

   ```
   bash scripts/install.sh          # from a Krait clone: builds + registers both
   ```

   If the user is inside a Krait clone but only wants the build step:
   `npm run mcp:build`.

This check is always soft. Never modify `.mcp.json`, and never run `claude mcp add`
yourself — report the command, let the user run it.

## Step 5 — `~/.claude` skills sync (soft, report mode only)

Check that the `/krait` skill is installed in the user's Claude home:

```
ls ~/.claude/skills/krait/SKILL.md 2>/dev/null
ls ~/.claude/commands/krait.md 2>/dev/null
```

If missing, point them at the installer — don't copy files yourself:

```bash
bash scripts/install.sh    # from a Krait clone
```

(In `gate` mode, skip this check entirely — if the user just typed `/krait`, the skill obviously resolved.)

---

## Output

### gate mode (for `/krait`)

If ALL hard checks pass: emit one short line such as `Preflight OK.` and continue with Phase 0. Do not print the full table.

If ANY hard check fails: emit a single block, then STOP:

```
Preflight failed — cannot start audit:
  - forge: MISSING (install: curl -L https://foundry.paradigm.xyz | bash && foundryup)
  - jq: MISSING (brew install jq)

Run /krait-init for the full readiness report.
```

Do not proceed to Phase 0 in gate mode if any hard check fails.

### report mode (for `/krait-init`)

Emit the full summary table:

```
| Check                 | Status              | Action                                          |
|-----------------------|---------------------|-------------------------------------------------|
| bash                  | OK 5.2.15           | —                                               |
| forge                 | OK 0.2.0            | —                                               |
| slither               | MISSING             | optional; install: pip install slither-analyzer |
| jq                    | OK jq-1.7           | —                                               |
| .sol files in scope   | OK 47 files         | —                                               |
| foundry.toml          | OK at ./foundry.toml| —                                               |
| .audit/ in .gitignore | MISSING             | add line: .audit/                               |
| .krait-cache/ in .gi  | MISSING             | add line: .krait-cache/                         |
| MCP krait-solodit     | OK (user scope)     | —                                               |
| MCP krait-forge       | MISSING             | bash scripts/install.sh (from a Krait clone)    |
| ~/.claude/skills/krait| OK                  | —                                               |
```

Then a one-line verdict:

- `READY` — all checks OK.
- `READY (warnings)` — only soft checks failed; `/krait` will run.
- `NOT READY — fix the MISSING hard items above` — at least one hard check failed; `/krait` will refuse to start.

## Non-goals

- This skill does NOT install anything.
- This skill does NOT modify `.gitignore`, `.mcp.json`, or any source file.
- This skill does NOT validate Solidity source — that's `/krait`'s job.
