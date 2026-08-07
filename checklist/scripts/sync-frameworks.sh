#!/bin/bash
# Sync framework JSONs from the Zealynx website repo into this plugin.
#
# The website (ZealynxSecurity/Zealynx-WebSite) is the SOURCE OF TRUTH for the framework
# data: `public/frameworks/` there is refreshed weekly from Solodit by that repo's
# `refresh-frameworks.yml` workflow. This plugin carries a synced copy so it can run
# offline, with no network and no API key.
#
# Usage:
#   ./scripts/sync-frameworks.sh <path-to-website>/public/frameworks
#   KRAIT_FRAMEWORKS_SRC=~/code/Zealynx-WebSite/public/frameworks ./scripts/sync-frameworks.sh
#
# Before this plugin moved into ZealynxSecurity/krait it defaulted to `../public/frameworks`,
# which resolved only while it lived inside the website checkout. There is no sane default
# from here, so the source must be given explicitly.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PLUGIN_DIR="$(dirname "$SCRIPT_DIR")"
SOURCE_DIR="${1:-${KRAIT_FRAMEWORKS_SRC:-}}"

if [ -z "$SOURCE_DIR" ]; then
  cat >&2 <<'USAGE'
Error: no framework source given.

The frameworks live in the website repo, which is a separate checkout:

  ./scripts/sync-frameworks.sh /path/to/Zealynx-WebSite/public/frameworks

or set KRAIT_FRAMEWORKS_SRC to that path once and re-run.
USAGE
  exit 1
fi

if [ ! -d "$SOURCE_DIR" ]; then
  echo "Error: source directory not found: $SOURCE_DIR" >&2
  exit 1
fi

shopt -s nullglob
full=("$SOURCE_DIR"/*.json)
if [ ${#full[@]} -eq 0 ]; then
  echo "Error: no *.json files in $SOURCE_DIR — is that the frameworks directory?" >&2
  exit 1
fi

echo "Copying ${#full[@]} full framework JSONs from $SOURCE_DIR ..."
cp "${full[@]}" "$PLUGIN_DIR/frameworks/"

echo "Building condensed indexes..."
python3 "$SCRIPT_DIR/build-index.py" "$SOURCE_DIR"

echo "Done. Frameworks synced."
echo
echo "Note: frameworks/*.json (the full tier) is gitignored — only frameworks/index.json,"
echo "frameworks/condensed/ and frameworks/scan/ are committed."
