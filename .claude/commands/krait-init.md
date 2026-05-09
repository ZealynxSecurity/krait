# Krait Init — Project Readiness Check

One-shot setup check before running `/krait` on a Solidity project. Verifies tools, gitignore, and MCP wiring. Reports what's missing and how to fix it. Does NOT install anything without explicit confirmation.

## Usage

```
/krait-init
/krait-init src/contracts/   # check a specific subdir
```

## Instructions

You are running a pre-audit readiness check. Do all checks in parallel where possible. Be terse — a tight pass/fail table beats narration.

**CRITICAL**:
- Read-only by default. Do NOT install dependencies, modify `.gitignore`, edit `.mcp.json`, or write `.audit/*` files unless the user explicitly says "go ahead" / "fix it" / "yes".
- If any check is environmental (e.g. `forge` not on PATH), say so and propose the install command — don't run it yourself.

---

## Step 1 — Required tooling

Use Bash for each, in parallel:

| Tool | Check | Why Krait needs it |
|------|-------|--------------------|
| `bash` | `bash --version` | All recon scripts shell out via bash. |
| `forge` | `forge --version` | Recon AST extraction prefers forge over regex; `/krait-fuzz` requires it. |
| `slither` | `slither --version` | Optional pre-scan in recon (skipped silently if absent). |
| `jq` | `jq --version` | Required to parse forge AST artifacts in `ast-extract.sh`. |
| `node` | `node --version` (≥ 20) | Needed only if user is running the CLI (`npm run dev`) or the MCP servers. |

For each, report `OK <version>` or `MISSING — install with: <command>`. Don't speculate on install commands you don't know — if you don't know the install command for the user's platform, say "consult the project's docs."

## Step 2 — Project shape

Verify the target directory looks like a Solidity project worth auditing:

- A `*.sol` file exists somewhere under the target (use `find <target> -name '*.sol' -not -path '*/node_modules/*' -not -path '*/lib/*' | head -20`).
- One of `foundry.toml` / `hardhat.config.*` / `truffle-config.js` exists at the target root or a parent.
- Find the in-scope source dir using the same logic as `ast-extract.sh`: prefer `<target>/contracts`, then `<target>/src`, then `<target>/src/contracts`, then `<target>` itself.

Report the detected scope directory and approximate `.sol` file count. If zero `.sol` files found, stop and tell the user the path is wrong.

## Step 3 — Output and cache hygiene

Check `<target>/.gitignore` (read-only). Krait writes to `.audit/` and `.krait-cache/`; both should be gitignored:

- `.audit/` — audit artifacts; not committed.
- `.krait-cache/` — AI response cache (auto-added by Krait at first run, but better preempted).

If either is missing from `.gitignore`, **tell** the user what to add but **do not edit** the file. Suggested patch:

```
.audit/
.krait-cache/
```

If there is no `.gitignore` at all, say so and suggest creating one — don't create it yourself.

## Step 4 — MCP wiring

Read `<target>/.mcp.json` if it exists. Report:

- Which MCP servers are declared.
- For each declared server with `"command": "node"`, check the referenced `args[0]` path exists relative to `<target>`. If not, the server's build step probably hasn't run.
- If `mcp-servers/solodit/` exists in the target but `mcp-servers/solodit/build/index.js` does not, tell the user to run `cd mcp-servers/solodit && npm install && npm run build`.
- If `mcp-servers/forge/` exists, do the same check for it.

Do NOT modify `.mcp.json`. If the user wants Krait's local MCP servers wired into a fresh project, point them at the `.mcp.json` in the Krait repo as a template.

## Step 5 — `~/.claude` skills sync

Check whether the `/krait` skill is installed in the user's Claude home:

```
ls ~/.claude/skills/krait/SKILL.md 2>/dev/null && echo OK || echo MISSING
ls ~/.claude/commands/krait.md 2>/dev/null && echo OK || echo MISSING
```

If either is missing, the user is running Krait from somewhere other than `~/.claude`. Tell them — don't try to copy files automatically. The README's install snippet is the canonical fix:

```bash
mkdir -p ~/.claude/commands ~/.claude/skills
cp -r .claude/commands/* ~/.claude/commands/
cp -r .claude/skills/* ~/.claude/skills/
```

## Step 6 — Summary table

Output one final table. Example shape:

```
| Check                 | Status              | Action                                  |
|-----------------------|---------------------|-----------------------------------------|
| bash                  | OK 5.2.15           | —                                       |
| forge                 | OK 0.2.0            | —                                       |
| slither               | MISSING             | optional; install: pip install slither-analyzer |
| jq                    | OK jq-1.7           | —                                       |
| .sol files in scope   | OK 47 files         | —                                       |
| foundry.toml          | OK at ./foundry.toml| —                                       |
| .audit/ in .gitignore | MISSING             | add line: .audit/                       |
| .krait-cache/ in .gi  | MISSING             | add line: .krait-cache/                 |
| .mcp.json             | OK 2 servers        | —                                       |
| krait-solodit build   | MISSING             | cd mcp-servers/solodit && npm i && npm run build |
| ~/.claude/skills/krait| OK                  | —                                       |
```

Then a one-line verdict: `READY`, `READY (warnings)`, or `NOT READY — fix the MISSING items above`.

If the user has only warnings, suggest `/krait` next. If `forge` or `bash` is missing, do not suggest `/krait` — fix env first.

## Non-goals

- This skill does NOT run an audit. It only checks readiness.
- This skill does NOT install or write anything by default.
- This skill does NOT validate Solidity source code itself — that's `/krait`'s job.
