# Krait — Solidity Security Audit Skills for Claude Code

**Silent. Precise. Lethal.**

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills for **Solidity** smart contract security auditing. Type `/krait` in any Solidity project → structured audit with concrete exploit traces. **Free** — uses your Claude subscription, no API costs. Built by [Zealynx Security](https://zealynx.io).

| | |
|---|---|
| **Technology** | Solidity |
| **Platform** | Claude Code (skills + commands) |
| **Cost** | Free — uses your Claude subscription |
| **Precision** | 90% across 40 blind Code4rena contests |
| **Methodology** | v7.0 — Multi-mindset analysis + consensus scoring |
| **Install** | Copy to `~/.claude/` → `/krait` works everywhere |

> The methodology lives in `.claude/skills/` and `.claude/commands/` as structured prompts that Claude Code executes. No external API calls, no separate tool — just Claude, guided by 40 contests worth of battle-tested detection heuristics.

---

## Requirements

- [Claude Code](https://docs.anthropic.com/en/docs/claude-code) (CLI, VS Code extension, or Cursor)
- A Claude subscription (Pro, Max, or Team)
- A Solidity project to audit

## Installation

```bash
git clone https://github.com/ZealynxSecurity/krait.git
mkdir -p ~/.claude/commands ~/.claude/skills
cp -r krait/.claude/commands/* ~/.claude/commands/
cp -r krait/.claude/skills/* ~/.claude/skills/
```

That's it. Open Claude Code in **any** Solidity project and run `/krait`.

To update to the latest methodology:

```bash
cd krait && git pull
cp -r .claude/commands/* ~/.claude/commands/
cp -r .claude/skills/* ~/.claude/skills/
```

## Commands

| Command | What it does |
|---------|-------------|
| `/krait` | Full 4-phase audit: Recon → Detection → State Analysis → Verification → Report |
| `/krait-quick` | Same pipeline but skips state analysis — faster for quick checks |

Both commands output findings to `.audit/` in your project directory with a full markdown report.

### After the Audit

Every `/krait` run saves structured findings to `.audit/krait-findings.json` and shows:

```
───────────────────────────────────────────────────
📋 N findings saved to .audit/krait-findings.json

🔗 View this report online:
   https://krait.zealynx.io/report/findings

📊 Track findings over time:
   https://krait.zealynx.io/dashboard
───────────────────────────────────────────────────
```

Then offers three next steps:
1. **Verify findings** — trace the exploit path in code to confirm it's real
2. **Generate PoC** — write a Foundry proof-of-concept test for each finding
3. **Complete security assessment** — 845+ process-level checks at [krait.zealynx.io/new](https://krait.zealynx.io/new)

---

## How It Works

### Four-Phase Pipeline

| Phase | What It Does |
|-------|-------------|
| **Recon** | Architecture map, AST extraction, deterministic file risk scoring, protocol primer selection |
| **Detection** | Three passes × 4 parallel lenses with multi-mindset analysis + consensus scoring |
| **State Analysis** | Coupled state pairs, mutation matrix — catches sync bugs scanning misses |
| **Verification** | 8 kill gates + consensus-aware verification + concrete exploit trace for every H/M |

### Multi-Mindset Detection (v7.0)

Each of the 4 detection lenses analyzes code through **4 independent mindsets** simultaneously:

| Mindset | Question |
|---------|----------|
| **Attacker** | "How would I exploit this to drain funds or escalate privilege?" |
| **Accountant** | "Trace every wei — do the numbers add up?" |
| **Spec Auditor** | "Does the code match what docs, comments, and EIPs say it should do?" |
| **Edge Case Hunter** | "What breaks at zero, max, empty, self-referential, or reentrant?" |

This means every function in high-risk files gets examined from **16 angles** (4 lenses × 4 mindsets) — without increasing token cost, since the mindsets run within each lens's existing prompt.

### Consensus Scoring

After detection, findings are scored by how many independent sources discovered them:

| Consensus | Meaning | Critic behavior |
|-----------|---------|----------------|
| **Strong** (3+ sources) | Multiple passes independently found the same bug | Fast-track verification |
| **Moderate** (2 sources) | Two passes converged on the same issue | Normal scrutiny |
| **Single** (1 source) | Only one pass found this | Extra scrutiny — why did others miss it? |

### Kill Gates (Verification)

Eight automatic gates try to **disprove every finding** before it reaches you. They've never killed a true positive across 40 contests:

- **A**: Generic best practice ("use SafeERC20") · **B**: Theoretical/unrealistic
- **C**: Intentional design · **D**: Speculative (no WHO/WHAT/HOW MUCH)
- **E**: Admin trust · **F**: Dust (<$100) · **G**: Out of context · **H**: Known issue

Result: FPs dropped from 4.2/contest → 0.2/contest (**95% reduction**).

---

## Benchmarks

No other AI audit tool publishes precision/recall against real competitions. Krait has been **blind-tested against 40 Code4rena contests**:

```
v7.0 (latest):  Multi-mindset lenses + consensus scoring (built on v6.4 precision)
v6.4:           90% precision · 0.2 FPs/contest · 4/5 contests at 100% precision
```

| Version | Contests | Precision | FPs/Contest |
|---------|----------|-----------|-------------|
| v1 | 1–3 | 12% | 1.3 |
| v5 | 31–35 | 70% | 0.6 |
| **v6.4** | **36–40** | **90%** | **0.2** |

**Latest contest-by-contest (v6.4):**

| Contest | Type | Official H+M | TPs | FPs | Precision |
|---------|------|-------------|-----|-----|-----------|
| LoopFi | Lending/Looping | 45 | 2 | 0 | **100%** |
| DittoETH | Stablecoin/OrderBook | 16 | 1 | 1 | 50% |
| Phi | Social/NFT | 15 | 1 | 0 | **100%** |
| Vultisig | ILO/Token | 6 | 2 | 0 | **100%** |
| Predy | DeFi Derivatives | 12 | 1 | 0 | **100%** |

Every result is verifiable in [`shadow-audits/`](shadow-audits/).

### Self-Improving

After each blind test: score → root-cause every miss → update methodology → re-test. This loop produced 50+ heuristics, 30 modules, and 7 protocol-specific primers from real missed findings.

---

## Real Bugs Found (Blind)

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

Krait's web platform turns local audit results into a tracked, shareable security profile. Free, no API costs.

### Upload & View Reports

Upload your `.audit/krait-findings.json` at [krait.zealynx.io/report/findings](https://krait.zealynx.io/report/findings) → branded report with severity breakdowns, exploit traces, and code diffs. Save to your dashboard to track findings over time.

### Security Assessment (845+ Checks)

Interactive audit readiness checklist covering **39 DeFi verticals** — operational security, deployment practices, documentation, upgrade procedures, and process gaps that code analysis can't see. Backed by 4,500+ real findings from Solodit.

Start at [krait.zealynx.io/new](https://krait.zealynx.io/new). If you ran `/krait:assess` in Claude Code, import the `.zealynx-run.json` to pre-fill checks.

### Dashboard

[krait.zealynx.io/dashboard](https://krait.zealynx.io/dashboard) — all your projects in one place. Assessment scores, scan findings, combined readiness score (60% assessment + 40% scan), and activity timeline.

### The Full Pipeline

```
/krait (local)  →  Upload findings  →  Save to dashboard  →  Run assessment  →  Combined score
     │                   │                    │                      │                  │
  Claude Code    krait.zealynx.io     Track over time      845+ checks       60% assess + 40% scan
   (free)         /report/findings       /dashboard             /new              /dashboard/{id}
```

---

## Author

**Carlos Vendrell Felici** — Founder, [Zealynx Security](https://zealynx.io)
[Twitter/X](https://x.com/TheBlockChainer) · [GitHub](https://github.com/vendrell46)

## License

[MIT](LICENSE) © Zealynx Security
