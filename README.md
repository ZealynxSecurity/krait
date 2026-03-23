# Krait

**AI-assisted security verification for Solidity smart contracts.** Not a scanner — a structured methodology with 43 heuristics, 26 analysis modules, and 8 kill gates, tested blind against 45 Code4rena contests at **100% precision**. Runs inside [Claude Code](https://docs.anthropic.com/en/docs/claude-code). Free.

### At a Glance

| | |
|---|---|
| **Detection angles** | 16 per function (4 lenses × 4 mindsets) |
| **Heuristics** | 43 exploit-derived triggers |
| **Analysis modules** | 26 targeted deep dives (A-X) |
| **Domain primers** | 7 (DEX, Lending, Staking, GameFi, Bridges, Proxies, Wallets) |
| **Kill gates** | 8 automatic + 10 FP patterns |
| **Shadow audits** | 45 contests, 100% precision, 0 FPs/contest (v7) |
| **Full methodology** | [`METHODOLOGY.md`](METHODOLOGY.md) — every technique, publicly documented |

### Two Products, One Goal

**1. Audit skills** (this repo) — run `/krait` in Claude Code on any Solidity project. Free.

**2. Web platform** ([krait.zealynx.io](https://krait.zealynx.io)) — AI-assisted security verification with per-check prompt generation, auto-parsed verdicts, shareable reports, and PDF export. Also free.

```
┌─────────────────────────────────────────────────────────────────────────┐
│  /krait (local)                     krait.zealynx.io (web)             │
│  ─────────────                      ────────────────────               │
│  Run audit in Claude Code           845+ checks across 39 DeFi types  │
│  4-phase pipeline                   "Verify with AI" per check        │
│  Findings with exploit traces       ├─ Generates tailored prompt      │
│  .audit/krait-findings.json         ├─ Run in any IDE AI              │
│         │                           ├─ Paste response back            │
│         └──► Upload to dashboard    └─ Auto-detect verdict + files    │
│              Shareable reports       Shareable reports + PDF export    │
│              Track over time         Combined readiness score          │
└─────────────────────────────────────────────────────────────────────────┘
```

Built by [Zealynx Security](https://zealynx.io) — 30+ DeFi protocol audits.

## What Krait Does

Krait is a structured audit methodology encoded as Claude Code skills. When you run `/krait` on a Solidity project, it executes a 4-phase pipeline:

1. **Recon** — maps the architecture, extracts the AST, scores every file by risk, selects protocol-specific detection primers
2. **Detection** — analyzes each high-risk function from 16 angles (4 technical lenses x 4 independent mindsets), with consensus scoring across passes
3. **State Analysis** — finds coupled state pairs and mutation patterns that per-function scanning misses
4. **Verification** — 8 kill gates try to disprove every finding. Only those with a concrete exploit trace (WHO does WHAT to steal HOW MUCH) survive

The output is a structured report with findings at exact file:line locations, vulnerable code, suggested fixes, and exploit traces. Saved as both markdown and JSON.

![Krait report viewer showing findings with severity, file locations, and exploit traces](assets/report-viewer.png)

## What Krait Is Not

- Not a linter or regex scanner — Claude reads and reasons about code
- Not a SaaS product with API costs — runs locally in your Claude Code session
- Not a replacement for a professional audit — it's a tool that catches real bugs before your auditor does

---

## Quick Start

### Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (CLI, VS Code extension, or Cursor)
- A Claude subscription (Pro, Max, or Team)
- A Solidity project to audit

### Install

```bash
git clone https://github.com/ZealynxSecurity/krait.git
mkdir -p ~/.claude/commands ~/.claude/skills
cp -r krait/.claude/commands/* ~/.claude/commands/
cp -r krait/.claude/skills/* ~/.claude/skills/
```

Open Claude Code in any Solidity project and run `/krait`.

### Update

```bash
cd krait && git pull
cp -r .claude/commands/* ~/.claude/commands/
cp -r .claude/skills/* ~/.claude/skills/
```

### Optional: Pattern Search MCP Server

Krait includes an MCP server that lets you search 47 vulnerability patterns locally. No API key needed.

```bash
cd krait/mcp-servers/solodit
npm install && npm run build
```

The `.mcp.json` in the repo root auto-configures it for Claude Code. The skills work fine without the MCP server — it's an optional pattern search tool for development.

### Commands

| Command | What it does |
|---------|-------------|
| `/krait` | Full 4-phase audit: Recon → Detection → State Analysis → Verification → Report |
| `/krait-quick` | Same pipeline, skips state analysis — ~2x faster |
| `/krait-review` | Second opinion on killed findings — re-examines aggressive gate decisions |

All output to `.audit/` in your project directory.

### After the Audit

Every run saves findings to `.audit/krait-findings.json` and shows:

```
───────────────────────────────────────────────────
📋 N findings saved to .audit/krait-findings.json

🔗 View this report online:
   https://krait.zealynx.io/report/findings

📊 Track findings over time:
   https://krait.zealynx.io/dashboard
───────────────────────────────────────────────────
```

Findings are already verified — the critic phase requires a concrete exploit trace for every H/M before it reaches the report.

If the critic killed many candidates, run `/krait-review` to get a second opinion on the gate decisions.

---

## How Detection Works

### Multi-Mindset Analysis (v7.0)

Each of the 4 detection lenses analyzes code through 4 independent mindsets simultaneously:

| Mindset | Question |
|---------|----------|
| **Attacker** | "How would I exploit this to drain funds or escalate privilege?" |
| **Accountant** | "Trace every wei — do the numbers add up?" |
| **Spec Auditor** | "Does the code match what docs, comments, and EIPs say it should do?" |
| **Edge Case Hunter** | "What breaks at zero, max, empty, self-referential, or reentrant?" |

Every function in high-risk files gets examined from **16 angles** (4 lenses x 4 mindsets). Findings discovered by multiple mindsets get a consensus boost; single-source findings get extra scrutiny.

### Kill Gates (Verification)

Eight automatic gates try to **disprove every finding** before it reaches you:

- **A**: Generic best practice ("use SafeERC20") · **B**: Theoretical/unrealistic
- **C**: Intentional design · **D**: Speculative (no WHO/WHAT/HOW MUCH)
- **E**: Admin trust · **F**: Dust (<$100) · **G**: Out of context · **H**: Known issue

Result: FPs dropped from 4.2/contest → 0.0/contest in v7 (**100% reduction**). The last 10 contests (v6.4+v7) had only 1 total FP across 10 contests.

### Second Opinion (`/krait-review`)

The kill gates are aggressive by design — zero false positives is the priority. But aggressive gates can over-kill. Run `/krait-review` after an audit to re-examine killed findings with fresh eyes:

- **Gate C** (intentional design) — "intentional" doesn't always mean "safe"
- **Gate E** (admin trust) — missing timelocks and rug vectors are valid Mediums in many contests
- **Gate B** (theoretical) — retries exploit construction with flash loans, multi-block MEV
- **Gate F** (dust) — recalculates with protocol TVL context and accumulation analysis

Revived findings are surfaced as **"Worth Manual Review"** — flags for the auditor, not verified TPs. The main report's zero-FP standard is preserved.

---

## Benchmarks

Tested blind against 45 Code4rena contests. No other AI audit tool publishes precision/recall against real competitions.

| Version | Contests | Precision | FPs/Contest |
|---------|----------|-----------|-------------|
| v1 | 1-3 | 12% | 1.3 |
| v5 | 31-35 | 70% | 0.6 |
| v6.4 | 36-40 | 90% | 0.2 |
| **v7** | **41-45** | **100%** | **0.0** |

**Latest 5 contests (v7):**

| Contest | Type | Official H+M | TPs | FPs | Precision |
|---------|------|-------------|-----|-----|-----------|
| Neobase | ve(3,3) / Gauges | 8 | 1 | 0 | **100%** |
| Open Dollar | CDP + NFT Vaults | 17 | 3 | 0 | **100%** |
| BakerFi | Leverage Vault | 12 | 4 | 0 | **100%** |
| Loop | ETH Staking | 1 | 0 | 0 | N/A |
| Coinbase | Smart Wallet | 3 | 0 | 0 | N/A |

Every result is verifiable in [`shadow-audits/`](shadow-audits/).

### Self-Improving

After each blind test: score → root-cause every miss → update methodology → re-test. This loop produced 43 heuristics, 10 deep-dive module files, 26 inline modules, and 7 protocol-specific primers from real missed findings. v7 added CONST-01 (wrong constants), GAUGE-01 (removal safety), and REPLAY-01 (cross-chain replay) heuristics — all from v6.4 misses.

---

## Real Bugs Found (Blind)

- **ONE_HUNDRED_WAD constant bug** (Open Dollar H-01) — surplus auction math inflated 100x, bricking protocol economics *(v7, CONST-01 heuristic)*
- **Gauge removal locks voting power** (Neobase H-01) — contradictory guards permanently trap user governance power *(v7, GAUGE-01 heuristic)*
- **Zero slippage on all swaps** (BakerFi H-04) — amountOutMinimum=0 enables sandwich on every deposit/withdraw *(v7)*
- **Oracle staleness OR vs AND** (BakerFi M-06) — stale price accepted if either feed is fresh *(v7)*
- **AuraVault claim double-spend** (LoopFi H-401) — fees not deducted, draining vault
- **UniV3 fee drain via shared position** (Vultisig H-43) — first claimer steals all fees
- **ILO launch DoS** (Vultisig H-41) — slot0 manipulation blocks all launches
- **Public internals → permanent fund lock** (Phi H-51) — state corruption locks ETH
- **Both HIGHs** (Munchables) — lockOnBehalf griefing + early unlock, 100% precision
- **Assembly encoding bug** (DittoETH M-221) — `add` vs `and` corrupts data
- ERC4626 inflation (Basin), reentrancy (reNFT), EIP-712 mismatch (reNFT), oracle precision (Dopex), TVL error (Renzo)

---

## Detection Coverage

**Strong on**: Reentrancy/CEI, access control gaps, oracle issues, EIP/ERC compliance, first-depositor inflation, accounting errors, assembly bugs, pause bypasses

**Improving**: Complex math (CDP liquidation, options pricing), cross-chain edge cases, game mechanic exploits, protocol-specific integrations (Curve, UniV3 tick math), economic design flaws

---

## Web Platform — [krait.zealynx.io](https://krait.zealynx.io)

### Verify with AI (Unique Feature)

Every security check on the web platform generates a **tailored AI prompt** you can copy-paste into Claude Code, Cursor, Windsurf, or Codex. The prompt includes:

- The specific vulnerability to look for
- Real exploit examples from Solodit (protocols that were actually hacked)
- What secure code looks like (from mitigation data)
- Code patterns to grep for
- Structured output format (PASS/FAIL/NA with file:line references)

When you paste the AI's response back, Krait **auto-parses** it:
- Detects the verdict (PASS/FAIL/NOT APPLICABLE/NEEDS REVIEW)
- Extracts file:line references
- Scores confidence (high/medium/low)
- Auto-sets the check status

This turns every check from "do you think you're ok?" into "let's verify against your actual code with AI."

### Upload & View Reports

Upload `.audit/krait-findings.json` at [krait.zealynx.io/report/findings](https://krait.zealynx.io/report/findings) for a branded report with severity breakdowns, exploit traces, and code diffs. Share via persistent link or download as PDF.

### Security Verification (845+ Checks)

AI-assisted security verification covering **39 DeFi verticals** — each check backed by real Solodit exploit data, with "Verify with AI" prompts for every single one. Not a checklist you fill out manually — a verification pipeline that leverages your IDE's AI.

Start at [krait.zealynx.io/new](https://krait.zealynx.io/new).

### Dashboard

[krait.zealynx.io/dashboard](https://krait.zealynx.io/dashboard) — all projects in one place. Scan findings, verification scores, shareable reports, activity timeline.

---

## Author

**Carlos Vendrell Felici** — Founder, [Zealynx Security](https://zealynx.io)
[Twitter/X](https://x.com/TheBlockChainer) · [GitHub](https://github.com/vendrell46)

## License

[MIT](LICENSE) © Zealynx Security
