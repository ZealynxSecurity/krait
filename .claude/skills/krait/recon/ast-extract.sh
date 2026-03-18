#!/bin/bash
# ast-extract.sh — Extract compiler-verified code facts from Solidity projects
# Usage: bash ast-extract.sh <project-root> <output-file>
# Outputs structured markdown for Krait's detection pipeline.
#
# Modes (tried in order):
#   1. forge-ast: Compile with Foundry, parse AST JSON via jq
#   2. regex-fallback: Grep-based extraction from raw .sol files (always works)

PROJECT_ROOT="${1:-.}"
OUTPUT_FILE="${2:-.audit/ast-facts.md}"
SCOPE_DIR=""
TMPFILE=""

# Resolve absolute paths
PROJECT_ROOT="$(cd "$PROJECT_ROOT" && pwd)"
mkdir -p "$(dirname "$OUTPUT_FILE")"
TMPFILE=$(mktemp)
trap "rm -f '$TMPFILE'" EXIT

# --- Find scope directory ---
find_scope_dir() {
    for dir in "$PROJECT_ROOT/contracts" "$PROJECT_ROOT/src" "$PROJECT_ROOT/src/contracts"; do
        if [ -d "$dir" ]; then
            SCOPE_DIR="$dir"
            return
        fi
    done
    SCOPE_DIR="$PROJECT_ROOT"
}

# --- Find all in-scope .sol files ---
find_scope_files() {
    find "$SCOPE_DIR" -name "*.sol" -type f \
        ! -path "*/test/*" ! -path "*/tests/*" \
        ! -path "*/mock/*" ! -path "*/mocks/*" \
        ! -path "*/script/*" ! -path "*/scripts/*" \
        ! -path "*/node_modules/*" ! -path "*/lib/*" \
        ! -path "*/forge-std/*" \
        ! -path "*/build/*" ! -path "*/out/*" ! -path "*/artifacts/*" \
        2>/dev/null | sort
}

# =============================================================================
# Regex fallback (always works)
# =============================================================================
generate_regex_output() {
    local files
    files=$(find_scope_files)
    if [ -z "$files" ]; then
        echo "No .sol files found in scope" >&2
        echo "(no files found)"
        return
    fi

    # --- Inheritance ---
    echo "## Inheritance Tree"
    echo "| Contract | File | Inherits From |"
    echo "|----------|------|---------------|"
    echo "$files" | while IFS= read -r file; do
        local relpath="${file#$PROJECT_ROOT/}"
        grep -E "^[[:space:]]*(abstract )?contract [A-Za-z0-9_]+ is " "$file" 2>/dev/null | while IFS= read -r line; do
            local contract=$(echo "$line" | sed -E 's/.*(abstract )?contract ([A-Za-z0-9_]+) is .*/\2/')
            local parents=$(echo "$line" | sed -E 's/.*(abstract )?contract [A-Za-z0-9_]+ is ([^{]+).*/\2/' | sed 's/ //g')
            echo "| $contract | $relpath | $parents |"
        done
    done
    echo ""

    # --- Function Registry ---
    echo "## Function Registry"
    echo "$files" | while IFS= read -r file; do
        local relpath="${file#$PROJECT_ROOT/}"
        local contract_name
        contract_name=$(grep -oE "^[[:space:]]*contract [A-Za-z0-9_]+" "$file" 2>/dev/null | head -1 | awk '{print $NF}')
        [ -z "$contract_name" ] && continue

        local funcs
        funcs=$(grep -nE "^\s*function [A-Za-z0-9_]+\(" "$file" 2>/dev/null || true)
        [ -z "$funcs" ] && continue

        echo "### $contract_name ($relpath)"
        echo "| Function | Visibility | Mutability | Modifiers |"
        echo "|----------|-----------|------------|-----------|"

        echo "$funcs" | while IFS= read -r funcline; do
            local fname=$(echo "$funcline" | sed -E 's/.*function ([A-Za-z0-9_]+)\(.*/\1/')

            local vis="internal"
            echo "$funcline" | grep -q "external" && vis="external"
            echo "$funcline" | grep -q "public" && vis="public"
            echo "$funcline" | grep -q "private" && vis="private"

            local mut="nonpayable"
            echo "$funcline" | grep -q "\bview\b" && mut="view"
            echo "$funcline" | grep -q "\bpure\b" && mut="pure"
            echo "$funcline" | grep -q "\bpayable\b" && mut="payable"

            # Extract modifiers: words between ) and { that aren't keywords
            local mods
            mods=$(echo "$funcline" | sed -E 's/.*\)//' | tr ' ' '\n' | grep -vE '^(external|public|internal|private|view|pure|payable|virtual|override|returns|{|$|//|/\*)' | grep -E '^[a-zA-Z]' | tr '\n' ', ' | sed 's/,$//' | sed 's/^,//')

            echo "| $fname | $vis | $mut | $mods |"
        done
        echo ""
    done

    # --- Call Graph ---
    echo "## Call Graph (External Calls)"
    echo "| Source File | Line | Call Pattern |"
    echo "|-----------|------|-------------|"
    echo "$files" | while IFS= read -r file; do
        local relpath="${file#$PROJECT_ROOT/}"
        grep -nE "\.(call|delegatecall|transfer|safeTransfer|safeTransferFrom)\(" "$file" 2>/dev/null | while IFS= read -r line; do
            local linenum=$(echo "$line" | cut -d: -f1)
            local content=$(echo "$line" | cut -d: -f2- | sed 's/^[[:space:]]*//' | cut -c1-120)
            echo "| $relpath | $linenum | \`$content\` |"
        done
    done
    echo ""

    # --- Modifier Definitions ---
    echo "## Modifier Definitions"
    echo "| Contract | Modifier |"
    echo "|----------|----------|"
    echo "$files" | while IFS= read -r file; do
        local contract_name
        contract_name=$(grep -oE "^[[:space:]]*contract [A-Za-z0-9_]+" "$file" 2>/dev/null | head -1 | awk '{print $NF}')
        [ -z "$contract_name" ] && continue
        grep -oE "modifier [A-Za-z0-9_]+" "$file" 2>/dev/null | while IFS= read -r mod; do
            local modname=$(echo "$mod" | awk '{print $2}')
            echo "| $contract_name | $modname |"
        done
    done
    echo ""

    # --- Risk Score Inputs ---
    echo "## Risk Score Inputs (Exact Counts)"
    echo "| File | LOC | External Calls | State Writers | Payable Fns | Assembly Blocks | Unchecked Blocks |"
    echo "|------|-----|---------------|---------------|-------------|----------------|-----------------|"
    echo "$files" | while IFS= read -r file; do
        local relpath="${file#$PROJECT_ROOT/}"
        local loc
        loc=$(wc -l < "$file" | tr -d '[:space:]')
        local ext_calls
        ext_calls=$(grep -cE "\.(call|delegatecall|transfer|safeTransfer|safeTransferFrom)\(" "$file" 2>/dev/null) || ext_calls=0
        local state_writers
        state_writers=$(grep -cE "function .*(external|public)" "$file" 2>/dev/null) || state_writers=0
        local payable_fns
        payable_fns=$(grep -cE "function .*payable" "$file" 2>/dev/null) || payable_fns=0
        local assembly_blocks
        assembly_blocks=$(grep -cE "assembly[[:space:]]*\{" "$file" 2>/dev/null) || assembly_blocks=0
        local unchecked_blocks
        unchecked_blocks=$(grep -cE "unchecked[[:space:]]*\{" "$file" 2>/dev/null) || unchecked_blocks=0
        echo "| ${relpath} | ${loc} | ${ext_calls} | ${state_writers} | ${payable_fns} | ${assembly_blocks} | ${unchecked_blocks} |"
    done
}

# =============================================================================
# Forge AST extraction (requires jq)
# =============================================================================
try_forge_ast() {
    local foundry_toml=""

    # Find foundry.toml
    if [ -f "$PROJECT_ROOT/foundry.toml" ]; then
        foundry_toml="$PROJECT_ROOT/foundry.toml"
    else
        foundry_toml=$(find "$PROJECT_ROOT" -maxdepth 2 -name "foundry.toml" -type f 2>/dev/null | head -1)
    fi
    [ -z "$foundry_toml" ] && return 1

    local foundry_dir="$(dirname "$foundry_toml")"
    command -v forge &>/dev/null || return 1
    command -v jq &>/dev/null || return 1

    echo "Attempting forge build in $foundry_dir..." >&2
    if ! (cd "$foundry_dir" && timeout 120 forge build --force 2>/dev/null); then
        echo "forge build failed, falling back to regex" >&2
        return 1
    fi

    local out_dir="$foundry_dir/out"
    [ -d "$out_dir" ] || return 1

    # Verify AST exists in artifacts
    local sample=$(find "$out_dir" -name "*.json" -type f 2>/dev/null | head -1)
    [ -z "$sample" ] && return 1
    jq -e '.ast' "$sample" &>/dev/null || return 1

    echo "Parsing forge AST..." >&2
    generate_forge_output "$out_dir"
    return 0
}

generate_forge_output() {
    local out_dir="$1"
    local scope_files
    scope_files=$(find_scope_files)

    # Map scope files to artifacts
    local artifacts=""
    echo "$scope_files" | while IFS= read -r sol_file; do
        local bn=$(basename "$sol_file" .sol)
        local artifact="$out_dir/$bn.sol/$bn.json"
        [ -f "$artifact" ] && echo "$artifact"
    done > "$TMPFILE.artifacts"

    local artifact_list
    artifact_list=$(cat "$TMPFILE.artifacts" 2>/dev/null)
    if [ -z "$artifact_list" ]; then
        generate_regex_output
        return
    fi

    # --- Inheritance ---
    echo "## Inheritance Tree"
    echo "| Contract | File | Inherits From |"
    echo "|----------|------|---------------|"
    echo "$artifact_list" | while IFS= read -r artifact; do
        local filepath=$(jq -r '.ast.absolutePath // "unknown"' "$artifact" 2>/dev/null)
        jq -r '
            .ast.nodes[]? | select(.nodeType == "ContractDefinition") |
            .name as $name |
            ([.baseContracts[]? | .baseName.name // .baseName.namePath // empty] | join(", ")) as $parents |
            select($parents != "") |
            "| \($name) | '"$filepath"' | \($parents) |"
        ' "$artifact" 2>/dev/null || true
    done
    echo ""

    # --- Function Registry ---
    echo "## Function Registry"
    echo "$artifact_list" | while IFS= read -r artifact; do
        local contract_name=$(jq -r '.ast.nodes[]? | select(.nodeType == "ContractDefinition") | .name' "$artifact" 2>/dev/null | head -1)
        local filepath=$(jq -r '.ast.absolutePath // "unknown"' "$artifact" 2>/dev/null)
        [ -z "$contract_name" ] && continue

        echo "### $contract_name ($filepath)"
        echo "| Function | Visibility | Mutability | Modifiers |"
        echo "|----------|-----------|------------|-----------|"

        jq -r '
            .ast.nodes[]? | select(.nodeType == "ContractDefinition") |
            .nodes[]? | select(.nodeType == "FunctionDefinition") |
            .name as $name |
            .visibility as $vis |
            .stateMutability as $mut |
            ([.modifiers[]? | .modifierName.name // empty] | join(", ")) as $mods |
            "| \(if $name == "" then "constructor" else $name end) | \($vis) | \($mut) | \($mods) |"
        ' "$artifact" 2>/dev/null || true
        echo ""
    done

    # --- State Variables ---
    echo "## State Variables"
    echo "$artifact_list" | while IFS= read -r artifact; do
        local contract_name=$(jq -r '.ast.nodes[]? | select(.nodeType == "ContractDefinition") | .name' "$artifact" 2>/dev/null | head -1)
        [ -z "$contract_name" ] && continue

        local vars
        vars=$(jq -r '
            .ast.nodes[]? | select(.nodeType == "ContractDefinition") |
            .nodes[]? | select(.nodeType == "VariableDeclaration" and .stateVariable == true) |
            "| \(.name) | \(.typeDescriptions.typeString // "unknown") | \(.visibility) |"
        ' "$artifact" 2>/dev/null || true)
        [ -z "$vars" ] && continue

        echo "### $contract_name"
        echo "| Variable | Type | Visibility |"
        echo "|----------|------|-----------|"
        echo "$vars"
        echo ""
    done

    # --- Modifier Definitions ---
    echo "## Modifier Definitions"
    echo "| Contract | Modifier |"
    echo "|----------|----------|"
    echo "$artifact_list" | while IFS= read -r artifact; do
        jq -r '
            .ast.nodes[]? | select(.nodeType == "ContractDefinition") |
            .name as $contract |
            .nodes[]? | select(.nodeType == "ModifierDefinition") |
            "| \($contract) | \(.name) |"
        ' "$artifact" 2>/dev/null || true
    done
    echo ""

    # --- Risk Score Inputs ---
    echo "## Risk Score Inputs (Exact Counts)"
    echo "| File | LOC | External Calls | State Writers | Payable Fns | Assembly Blocks | Unchecked Blocks |"
    echo "|------|-----|---------------|---------------|-------------|----------------|-----------------|"

    echo "$scope_files" | while IFS= read -r sol_file; do
        local relpath="${sol_file#$PROJECT_ROOT/}"
        local bn=$(basename "$sol_file" .sol)
        local artifact="$out_dir/$bn.sol/$bn.json"
        local loc=$(wc -l < "$sol_file" | tr -d ' ')

        if [ -f "$artifact" ]; then
            local ext_calls=$(jq '[.. | select(.nodeType? == "FunctionCall") | select(.expression.nodeType? == "MemberAccess")] | length' "$artifact" 2>/dev/null || echo "0")
            local state_writers=$(jq '[.ast.nodes[]? | select(.nodeType == "ContractDefinition") | .nodes[]? | select(.nodeType == "FunctionDefinition") | select(.visibility == "external" or .visibility == "public") | select(.stateMutability != "view" and .stateMutability != "pure")] | length' "$artifact" 2>/dev/null || echo "0")
            local payable=$(jq '[.ast.nodes[]? | select(.nodeType == "ContractDefinition") | .nodes[]? | select(.nodeType == "FunctionDefinition") | select(.stateMutability == "payable")] | length' "$artifact" 2>/dev/null || echo "0")
            local assembly=$(jq '[.. | select(.nodeType? == "InlineAssembly")] | length' "$artifact" 2>/dev/null || echo "0")
            local unchecked=$(jq '[.. | select(.nodeType? == "UncheckedBlock")] | length' "$artifact" 2>/dev/null || echo "0")
        else
            local ext_calls=$(grep -cE "\.(call|delegatecall|transfer|safeTransfer|safeTransferFrom)\(" "$sol_file" 2>/dev/null || echo "0")
            local state_writers=$(grep -cE "function .*(external|public)" "$sol_file" 2>/dev/null || echo "0")
            local payable=$(grep -cE "function .*payable" "$sol_file" 2>/dev/null || echo "0")
            local assembly=$(grep -cE "assembly[[:space:]]*\{" "$sol_file" 2>/dev/null || echo "0")
            local unchecked=$(grep -cE "unchecked[[:space:]]*\{" "$sol_file" 2>/dev/null || echo "0")
        fi
        echo "| $relpath | $loc | $ext_calls | $state_writers | $payable | $assembly | $unchecked |"
    done
}

# =============================================================================
# Main
# =============================================================================
find_scope_dir

AST_MODE="regex-fallback"

# Try forge first, capture output to temp file
if try_forge_ast > "$TMPFILE" 2>/dev/null; then
    AST_MODE="forge-ast"
fi

# If forge didn't work, generate regex output
if [ "$AST_MODE" = "regex-fallback" ]; then
    generate_regex_output > "$TMPFILE"
fi

# Write final output
{
    echo "# AST Facts (Compiler-Verified)"
    echo "> Extraction mode: $AST_MODE"
    echo "> Project root: $PROJECT_ROOT"
    echo "> Scope directory: $SCOPE_DIR"
    echo "> Extraction timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo ""
    cat "$TMPFILE"
} > "$OUTPUT_FILE"

echo "AST facts extracted to $OUTPUT_FILE (mode: $AST_MODE)" >&2
