#!/usr/bin/env bash
# Build Krait's bundled MCP servers.
#
# Safe to run repeatedly. Never fails the caller: a missing toolchain or a
# broken optional server must not block `npm install` or the install script.
# Exit code is always 0; failures are reported on stderr and summarised at the
# end so the caller can tell the user what is degraded.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SERVERS=(solodit forge)

FORCE=0
for arg in "$@"; do
  case "$arg" in
    --force) FORCE=1 ;;
    *) ;;
  esac
done

if [ "${KRAIT_SKIP_MCP_BUILD:-0}" = "1" ]; then
  echo "krait: KRAIT_SKIP_MCP_BUILD=1 — skipping MCP server build." >&2
  exit 0
fi

if ! command -v npm >/dev/null 2>&1; then
  echo "krait: npm not found — skipping MCP server build." >&2
  echo "krait: install Node >= 20, then run: npm run mcp:build" >&2
  exit 0
fi

built=()
failed=()
skipped=()

for name in "${SERVERS[@]}"; do
  dir="$REPO_ROOT/mcp-servers/$name"

  if [ ! -f "$dir/package.json" ]; then
    skipped+=("$name (not present)")
    continue
  fi

  # Already built and not forced -> nothing to do.
  if [ "$FORCE" -eq 0 ] && [ -f "$dir/build/index.js" ]; then
    built+=("$name (cached)")
    continue
  fi

  echo "krait: building MCP server '$name'..." >&2

  if [ ! -d "$dir/node_modules" ] || [ "$FORCE" -eq 1 ]; then
    if ! (cd "$dir" && npm install --silent --no-audit --no-fund >/dev/null 2>&1); then
      echo "krait: npm install failed for MCP server '$name'." >&2
      failed+=("$name (npm install)")
      continue
    fi
  fi

  if ! (cd "$dir" && npm run --silent build >/dev/null 2>&1); then
    echo "krait: build failed for MCP server '$name'." >&2
    echo "krait: reproduce with: cd mcp-servers/$name && npm install && npm run build" >&2
    failed+=("$name (build)")
    continue
  fi

  if [ -f "$dir/build/index.js" ]; then
    built+=("$name")
  else
    failed+=("$name (no build/index.js emitted)")
  fi
done

if [ ${#built[@]} -gt 0 ]; then
  echo "krait: MCP servers ready: ${built[*]}" >&2
fi
if [ ${#skipped[@]} -gt 0 ]; then
  echo "krait: MCP servers skipped: ${skipped[*]}" >&2
fi
if [ ${#failed[@]} -gt 0 ]; then
  echo "krait: MCP servers NOT built: ${failed[*]}" >&2
  echo "krait: the skills still work without them — they only enrich pattern search and forge flows." >&2
fi

exit 0
