#!/bin/bash
# slither-summary.sh — Extract HIGH/MEDIUM Slither findings into markdown summary
# Usage: bash slither-summary.sh <slither-results.json> <output-file>
# Reads Slither JSON output, filters to High/Medium, writes markdown summary.

INPUT_FILE="${1:-.audit/slither-results.json}"
OUTPUT_FILE="${2:-.audit/slither-summary.md}"

if [ ! -f "$INPUT_FILE" ]; then
    echo "No Slither results found at $INPUT_FILE" >&2
    exit 1
fi

command -v jq &>/dev/null || {
    echo "jq required but not found" >&2
    exit 1
}

# Check if the file has valid JSON with results
if ! jq -e '.results.detectors' "$INPUT_FILE" &>/dev/null; then
    echo "Invalid Slither JSON or no detectors found" >&2
    exit 1
fi

{
    echo "# Slither Pre-Scan Summary"
    echo "> Source: $INPUT_FILE"
    echo "> Filtered to: High and Medium severity only"
    echo ""
    echo "| # | Detector | Severity | File:Line | Description |"
    echo "|---|----------|----------|-----------|-------------|"

    jq -r '
        .results.detectors[]
        | select(.impact == "High" or .impact == "Medium")
        | .check as $check
        | .impact as $severity
        | .description as $desc
        | (.elements[0] // {}) as $elem
        | ($elem.source_mapping.filename_relative // "unknown") as $file
        | ($elem.source_mapping.lines[0] // "?") as $line
        | ($desc | split("\n")[0] | .[0:120]) as $short_desc
        | "| - | \($check) | \($severity) | \($file):\($line) | \($short_desc) |"
    ' "$INPUT_FILE" 2>/dev/null | nl -ba -s' ' | sed 's/^ *\([0-9]*\) | - /| \1 /'

    echo ""

    total=$(jq '[.results.detectors[] | select(.impact == "High" or .impact == "Medium")] | length' "$INPUT_FILE" 2>/dev/null)
    high=$(jq '[.results.detectors[] | select(.impact == "High")] | length' "$INPUT_FILE" 2>/dev/null)
    med=$(jq '[.results.detectors[] | select(.impact == "Medium")] | length' "$INPUT_FILE" 2>/dev/null)

    echo "**Total**: ${total:-0} findings (${high:-0} High, ${med:-0} Medium)"
    echo ""
    echo "These findings are ADDITIONAL SIGNAL for Krait's detection phase — they are NOT auto-reported."
} > "$OUTPUT_FILE"

echo "Slither summary written to $OUTPUT_FILE" >&2
