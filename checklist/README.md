# Krait

Smart contract security analysis by [Zealynx Security](https://www.zealynx.io).

Krait analyzes Solidity code against **845 security checks** derived from **4,500+ real audit findings** sourced from Solodit across **39 DeFi verticals**.

## Install

**Claude Code plugin:**
```bash
/plugin marketplace add ZealynxSecurity/krait
/plugin install krait@krait
```

This gives you `/krait:scan`, `/krait:assess` and `/krait:check`.

**Manual (Claude Code or Cursor):**
```bash
git clone https://github.com/ZealynxSecurity/krait.git
# Claude Code
cp -r krait/checklist ~/.claude/skills/krait-checklist
# Cursor
cp -r krait/checklist ~/.cursor/skills/krait-checklist
```

> **This is one of two Krait surfaces in this repo.** The checklist plugin (here) evaluates
> code against a fixed framework of 845 curated checks and produces an importable
> assessment. The audit pipeline (repo root, `/krait`) is a multi-phase adversarial
> auditor that reasons from first principles and produces exploit traces. Different jobs —
> see the [root README](../README.md).

## Skills

### `/krait:scan` — Quick Security Scan

Fast security analysis of your Solidity code. Detects the protocol type automatically and applies the relevant security checks.

```
/krait:scan                     # Scan entire project
/krait:scan src/Pool.sol        # Scan specific file
/krait:scan src/core/           # Scan specific directory
/krait:scan --vertical lending  # Override vertical detection
```

### `/krait:assess` — Full Framework Assessment

Complete check-by-check assessment against the Zealynx security framework. Produces structured output compatible with [audit-readiness.zealynx.io](https://audit-readiness.zealynx.io).

```
/krait:assess dasf
/krait:assess vaults --config oracle=chainlink,admin=multisig
```

Outputs `.zealynx-run.json` — import it into the browser platform to pre-fill all checks with AI verdicts.

### `/krait:check` — Single Check Analysis

Deep analysis of a single framework check against your code.

```
/krait:check LN-01              # Analyze check LN-01
/krait:check AC-05 src/Admin.sol  # Analyze against specific file
```

## Verticals

39 DeFi verticals supported including dasf (DEX/AMM), Lending, Staking, Vaults, Bridges, Perpetuals, Stablecoins, EigenLayer, LayerZero, Chainlink, and more.

## How It Works

Krait runs **locally** in your Claude Code session. It reads your actual source files, applies the security framework checks, and reports findings. No code leaves your machine. No API calls. No cost beyond your Claude Code subscription.

The security checks are derived from real audit findings by firms like Trail of Bits, Spearbit, OpenZeppelin, Code4rena, Sherlock, and Codehawks — all sourced from Solodit.

## Limitations

- Optimized for codebases under ~2,500 NSLOC. For larger codebases, scan per module.
- Strong at pattern matching (missing access controls, reentrancy, oracle issues).
- Weaker at multi-transaction attacks, game theory, and cross-protocol composability.
- **Not a substitute for a professional audit.** Krait is a pre-audit readiness tool.

## Checklists & Mapping

Krait primer keys are static (for the marketing checklists published on zealynx.io). `/krait:assess` (and scan) use full DASF frameworks + emit `.zealynx-run.json` with `krait_analysis` evidence for the product at krait.zealynx.io / audit-readiness.zealynx.io. The website mapping is the bridge. Run validator after edits; import the JSON to see coverage.

The bridge itself (`src/data/krait-checklist-mapping.ts`) and its maintainer skill live in
the **website** repo, because they validate against that repo's published checklist data.
Only the plugin moved here.

## Updating the frameworks

The website repo is the source of truth: its `public/frameworks/` is refreshed weekly from
Solodit by a scheduled workflow. This plugin carries a synced copy so it runs offline with
no API key. To pull in an update:

```bash
./scripts/sync-frameworks.sh /path/to/Zealynx-WebSite/public/frameworks
# or: export KRAIT_FRAMEWORKS_SRC=~/code/Zealynx-WebSite/public/frameworks
```

Committed tiers are `frameworks/index.json`, `frameworks/condensed/` and `frameworks/scan/`
— the skills read only those. The full `frameworks/*.json` tier is gitignored (large, and
regenerable from the website).

## License

MIT — See [LICENSE](LICENSE).

Built by [Zealynx Security](https://www.zealynx.io).
