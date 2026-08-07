#!/usr/bin/env bash
# Install Krait into the user's Claude Code home and register its MCP servers.
#
#   ./scripts/install.sh            # install skills + commands, build + register MCP
#   ./scripts/install.sh --no-mcp   # skills + commands only
#   ./scripts/install.sh --dry-run  # print what would happen, change nothing
#
# Idempotent: safe to re-run after `git pull` to update an existing install.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CLAUDE_HOME="${CLAUDE_CONFIG_DIR:-$HOME/.claude}"

WITH_MCP=1
DRY_RUN=0
for arg in "$@"; do
  case "$arg" in
    --no-mcp)  WITH_MCP=0 ;;
    --dry-run) DRY_RUN=1 ;;
    -h|--help)
      sed -n '2,10p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    *)
      echo "install.sh: unknown argument '$arg' (try --help)" >&2
      exit 2
      ;;
  esac
done

run() {
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  [dry-run] $*"
  else
    "$@"
  fi
}

say() { printf '%s\n' "$*"; }

say "Krait installer"
say "  repo:        $REPO_ROOT"
say "  claude home: $CLAUDE_HOME"
[ "$DRY_RUN" -eq 1 ] && say "  mode:        DRY RUN (no changes)"
say ""

# ── 1. Skills + commands ─────────────────────────────────────────────────────
say "1/3  Installing skills and commands..."

run mkdir -p "$CLAUDE_HOME/commands" "$CLAUDE_HOME/skills"

if [ "$DRY_RUN" -eq 1 ]; then
  echo "  [dry-run] cp -R $REPO_ROOT/.claude/commands/. $CLAUDE_HOME/commands/"
  echo "  [dry-run] cp -R $REPO_ROOT/.claude/skills/.   $CLAUDE_HOME/skills/"
else
  cp -R "$REPO_ROOT/.claude/commands/." "$CLAUDE_HOME/commands/"
  cp -R "$REPO_ROOT/.claude/skills/."   "$CLAUDE_HOME/skills/"
fi

say "     commands: $(find "$REPO_ROOT/.claude/commands" -name '*.md' | wc -l | tr -d ' ') files"
say "     skills:   $REPO_ROOT/.claude/skills/krait -> $CLAUDE_HOME/skills/krait"
say ""

# ── 2. MCP servers ───────────────────────────────────────────────────────────
if [ "$WITH_MCP" -eq 0 ]; then
  say "2/3  Skipping MCP servers (--no-mcp)."
  say ""
else
  say "2/3  Building MCP servers..."
  if [ "$DRY_RUN" -eq 1 ]; then
    echo "  [dry-run] bash $REPO_ROOT/scripts/build-mcp.sh"
  else
    bash "$REPO_ROOT/scripts/build-mcp.sh"
  fi
  say ""

  say "3/3  Registering MCP servers with Claude Code (user scope)..."
  if ! command -v claude >/dev/null 2>&1; then
    say "     'claude' CLI not on PATH — skipping automatic registration."
    say "     Register manually once Claude Code is installed:"
    say ""
    say "       claude mcp add krait-solodit --scope user -- node $REPO_ROOT/mcp-servers/solodit/build/index.js"
    say "       claude mcp add krait-forge   --scope user -- node $REPO_ROOT/mcp-servers/forge/build/index.js"
    say ""
  else
    register_server() {
      local name="$1" entry="$2"

      if [ ! -f "$entry" ]; then
        say "     $name: build artifact missing — not registered."
        return 0
      fi

      # Re-register so the absolute path always matches this clone's location.
      if [ "$DRY_RUN" -eq 1 ]; then
        echo "  [dry-run] claude mcp remove $name --scope user"
        echo "  [dry-run] claude mcp add $name --scope user -- node $entry"
        return 0
      fi

      claude mcp remove "$name" --scope user >/dev/null 2>&1 || true
      if claude mcp add "$name" --scope user -- node "$entry" >/dev/null 2>&1; then
        say "     $name: registered (user scope)"
      else
        say "     $name: registration failed — add it manually:"
        say "       claude mcp add $name --scope user -- node $entry"
      fi
    }

    register_server krait-solodit "$REPO_ROOT/mcp-servers/solodit/build/index.js"
    register_server krait-forge   "$REPO_ROOT/mcp-servers/forge/build/index.js"
    say ""
  fi
fi

say "Done. Open Claude Code in any Solidity project and run /krait."
say "Verify readiness at any time with /krait-init."
