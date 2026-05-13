# Krait Init — Project Readiness Check

Standalone readiness check before running `/krait`. Verifies tools, project shape, gitignore, MCP wiring, and ~/.claude install. Reports what's missing — does NOT install or modify anything.

Use this when you want to validate your environment without committing to a full audit run (CI setup, debugging, "is my env ready?"). `/krait` runs the hard checks automatically on every invocation, so most users will never need to call this directly.

## Usage

```
/krait-init
/krait-init src/contracts/   # check a specific subdir
```

## Instructions

Read and follow `~/.claude/skills/krait/preflight/instructions.md` in **report mode**.

That skill defines every check, the hard-vs-soft distinction, and the output table format. Your job is to run all of its checks (hard + soft, including `~/.claude` skills sync) and emit the full summary table with a single-line verdict at the end.

**CRITICAL:**
- Read-only. Do NOT install dependencies, modify `.gitignore`, edit `.mcp.json`, or write `.audit/*` files unless the user explicitly says "go ahead" / "fix it" / "yes".
- For environmental misses (e.g. `forge` not on PATH), propose the install command but don't run it yourself.
- Do all checks in parallel where possible. A tight pass/fail table beats narration.

If the verdict is `READY` or `READY (warnings)`, suggest `/krait` next. If it is `NOT READY`, do not suggest `/krait` — fix the env first.
