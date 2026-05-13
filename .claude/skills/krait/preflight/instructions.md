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
| `.mcp.json` declared servers have built artifacts | no | only matters if the user actually wants those servers |
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

If `<target>/.mcp.json` exists, read it and:

- List the declared servers.
- For each `"command": "node"` entry, check that `args[0]` resolves to an existing file relative to `<target>`. If not, the server's build step hasn't run.
- If `mcp-servers/solodit/` exists in the target but `mcp-servers/solodit/build/index.js` does not, surface: `cd mcp-servers/solodit && npm install && npm run build`. Same for `mcp-servers/forge/`.

Never modify `.mcp.json`.

## Step 5 — `~/.claude` skills sync (soft, report mode only)

Check that the `/krait` skill is installed in the user's Claude home:

```
ls ~/.claude/skills/krait/SKILL.md 2>/dev/null
ls ~/.claude/commands/krait.md 2>/dev/null
```

If missing, point them at the install snippet — don't copy files:

```bash
mkdir -p ~/.claude/commands ~/.claude/skills
cp -r .claude/commands/* ~/.claude/commands/
cp -r .claude/skills/* ~/.claude/skills/
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
| .mcp.json             | OK 2 servers        | —                                               |
| krait-solodit build   | MISSING             | cd mcp-servers/solodit && npm i && npm run build|
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
