#!/usr/bin/env python3
"""
Build framework indexes from full framework JSONs.

Produces three tiers:
1. frameworks/condensed/*.json — slim (id, question, severity, tags) for quick reference
2. frameworks/scan/*.json — mid-weight (adds promptTemplate, mitigation) for /krait:scan
3. references/check-index.md — human-readable checklist

The full framework JSONs (source input) are used only to *generate* the tiers below; /krait:assess and /krait:scan use the generated scan tier (not the full JSONs).
"""

import json
import os
import sys
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent
PLUGIN_DIR = SCRIPT_DIR.parent
SOURCE_DIR = Path(sys.argv[1]) if len(sys.argv) > 1 else PLUGIN_DIR.parent / "public" / "frameworks"

VERTICAL_MAP = {
    "account-abstraction": "Account Abstraction",
    "airdrop": "Airdrop",
    "auction": "Auction",
    "balancer-v3": "Balancer V3",
    "bridges": "Bridges",
    "cctp": "CCTP",
    "cfa": "Cross-Function Analysis",
    "chainlink-functions": "Chainlink Functions",
    "chainlink": "Chainlink",
    "clm": "Concentrated Liquidity",
    "common": "Common (all protocols)",
    "crowdfunding": "Crowdfunding",
    "dao": "DAO Governance",
    "dasf": "DEX/AMM (full DASF)",
    "eigenlayer": "EigenLayer / Restaking",
    "etf": "ETF / Index Funds",
    "gaming": "Gaming",
    "ird": "Interest Rate Derivatives",
    "l2-zk": "L2 / ZK Rollups",
    "layerzero": "LayerZero",
    "lending": "Lending / Borrowing",
    "leverage": "Leverage Trading",
    "lottery": "Lottery",
    "migration": "Migration",
    "nft": "NFT",
    "perpetuals": "Perpetuals",
    "privacy": "Privacy",
    "risk-oracle": "Risk Oracle",
    "rwa": "Real World Assets",
    "social": "Social / SocialFi",
    "stablecoins": "Stablecoins",
    "staking": "Staking",
    "streaming": "Payment Streaming",
    "tfa": "Token Flow Analysis",
    "vaults": "Vaults / Yield",
    "vesting": "Vesting",
    "vrf": "VRF / Randomness",
    "wormhole": "Wormhole",
    "yield": "Yield Optimization",
}

def build():
    index = {}
    all_checks = []

    for fname in sorted(os.listdir(SOURCE_DIR)):
        if not fname.endswith(".json"):
            continue
        slug = fname.replace(".json", "")
        with open(SOURCE_DIR / fname) as f:
            fw = json.load(f)

        checks = []
        for c in fw["checks"]:
            entry = {
                "id": c["id"],
                "q": c["question"],
                "sev": c["severity"],
                "cat": c["category"],
                "tags": c["tags"],
            }
            checks.append(entry)
            all_checks.append({**entry, "vertical": slug})

        index[slug] = {
            "label": VERTICAL_MAP.get(slug, slug),
            "totalChecks": fw["totalChecks"],
            "version": fw["version"],
            "checks": checks,
        }

    # Write compact JSON index
    out_json = PLUGIN_DIR / "frameworks" / "index.json"
    with open(out_json, "w") as f:
        json.dump(index, f, separators=(",", ":"))
    print(f"Wrote {out_json} ({os.path.getsize(out_json):,} bytes)")

    # Write markdown checklist grouped by severity
    out_md = PLUGIN_DIR / "references" / "check-index.md"
    with open(out_md, "w") as f:
        f.write("# Krait Security Check Index\n\n")
        f.write(f"Total: {len(all_checks)} checks across {len(index)} verticals\n\n")

        for slug, data in sorted(index.items()):
            f.write(f"## {data['label']} ({slug}) — {data['totalChecks']} checks\n\n")

            by_sev = {"critical": [], "high": [], "medium": [], "low": [], None: []}
            for c in data["checks"]:
                by_sev.setdefault(c["sev"], []).append(c)

            for sev in ["critical", "high", "medium", "low"]:
                checks_at_sev = by_sev.get(sev, [])
                if not checks_at_sev:
                    continue
                f.write(f"### {sev.upper()} ({len(checks_at_sev)})\n")
                for c in checks_at_sev:
                    f.write(f"- **{c['id']}**: {c['q']}\n")
                f.write("\n")

            unclassified = by_sev.get(None, [])
            if unclassified:
                f.write(f"### UNCLASSIFIED ({len(unclassified)})\n")
                for c in unclassified:
                    f.write(f"- **{c['id']}**: {c['q']}\n")
                f.write("\n")

    print(f"Wrote {out_md} ({os.path.getsize(out_md):,} bytes)")

    # Write per-vertical condensed files (quick reference)
    condensed_dir = PLUGIN_DIR / "frameworks" / "condensed"
    condensed_dir.mkdir(exist_ok=True)
    for slug, data in index.items():
        out = condensed_dir / f"{slug}.json"
        with open(out, "w") as f:
            json.dump(data, f, separators=(",", ":"))
    print(f"Wrote {len(index)} condensed framework files to {condensed_dir}/")

    # Write per-vertical scan files (mid-weight: includes promptTemplate + mitigation)
    scan_dir = PLUGIN_DIR / "frameworks" / "scan"
    scan_dir.mkdir(exist_ok=True)
    for fname in sorted(os.listdir(SOURCE_DIR)):
        if not fname.endswith(".json"):
            continue
        slug = fname.replace(".json", "")
        with open(SOURCE_DIR / fname) as f:
            fw = json.load(f)

        scan_checks = []
        for c in fw["checks"]:
            entry = {
                "id": c["id"],
                "q": c["question"],
                "sev": c["severity"],
                "cat": c["category"],
                "tags": c["tags"],
                "desc": c.get("description"),
                "prompt": c.get("promptTemplate"),
                "fix": c.get("mitigation"),
            }
            if c.get("codeIndicators"):
                entry["ci"] = c["codeIndicators"]
            if c.get("passIndicators"):
                entry["pi"] = c["passIndicators"]
            scan_checks.append(entry)

        scan_data = {
            "label": VERTICAL_MAP.get(slug, slug),
            "version": fw["version"],
            "totalChecks": fw["totalChecks"],
            "checks": scan_checks,
        }
        out = scan_dir / f"{slug}.json"
        with open(out, "w") as f:
            json.dump(scan_data, f, separators=(",", ":"))

    total_size = sum(os.path.getsize(scan_dir / f) for f in os.listdir(scan_dir) if f.endswith(".json"))
    print(f"Wrote {len(os.listdir(scan_dir))} scan framework files to {scan_dir}/ ({total_size:,} bytes total)")

if __name__ == "__main__":
    build()
