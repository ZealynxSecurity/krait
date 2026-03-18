# Krait — Solidity Security Audit Skills for Claude Code

**Silent. Precise. Lethal.**

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills for **Solidity** smart contract security auditing. Type `/krait` in any Solidity project → structured audit with concrete exploit traces. **Free** — uses your Claude subscription, no API costs. Built by [Zealynx Security](https://zealynx.io).

| | |
|---|---|
| **Technology** | Solidity |
| **Platform** | Claude Code (skills + commands) |
| **Cost** | Free — uses your Claude subscription |
| **Precision** | 90% across 40 blind Code4rena contests |
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

---

## What Makes Krait Different

Most AI audit tools do: **scan code → report findings**. One pass, no verification, no benchmarks.

### Benchmarked Against 40 Real Contests

No other AI audit tool publishes precision/recall against real competitions. Krait has been **blind-tested against 40 Code4rena contests**:

```
v6.4 (latest):  90% precision · 0.2 FPs/contest · 4/5 contests at 100% precision
```

| Version | Contests | Precision | FPs/Contest |
|---------|----------|-----------|-------------|
| v1 | 1–3 | 12% | 1.3 |
| v5 | 31–35 | 70% | 0.6 |
| **v6.4** | **36–40** | **90%** | **0.2** |

**Latest (v6.4) contest-by-contest:**

| Contest | Type | Official H+M | TPs | FPs | Precision |
|---------|------|-------------|-----|-----|-----------|
| LoopFi | Lending/Looping | 45 | 2 | 0 | **100%** |
| DittoETH | Stablecoin/OrderBook | 16 | 1 | 1 | 50% |
| Phi | Social/NFT | 15 | 1 | 0 | **100%** |
| Vultisig | ILO/Token | 6 | 2 | 0 | **100%** |
| Predy | DeFi Derivatives | 12 | 1 | 0 | **100%** |

Every result is verifiable in [`shadow-audits/`](shadow-audits/).

### Four-Phase Pipeline

| Phase | What It Does |
|-------|-------------|
| **Recon** | Architecture map, deterministic file risk scoring, protocol primer selection |
| **Detection** | Three passes × 4 parallel lenses on highest-risk files |
| **State Analysis** | Coupled state pairs, mutation matrix — catches sync bugs scanning misses |
| **Verification** | Kill gates + concrete exploit trace required for every H/M |

### Verification Phase (Kill Gates)

Eight automatic gates try to **disprove every finding** before it reaches you. They've never killed a true positive across 40 contests:

- **A**: Generic best practice ("use SafeERC20") · **B**: Theoretical/unrealistic
- **C**: Intentional design · **D**: Speculative (no WHO/WHAT/HOW MUCH)
- **E**: Admin trust · **F**: Dust (<$100) · **G**: Out of context · **H**: Known issue

Result: FPs dropped from 4.2/contest → 0.2/contest (**95% reduction**).

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

## Web Assessment Platform

For process-level security (not code-level), see [krait.zealynx.io](https://krait.zealynx.io) — interactive audit readiness assessment covering 39 DeFi verticals with 845+ security checks.

---

## Author

**Carlos Vendrell Felici** — Founder, [Zealynx Security](https://zealynx.io)
[Twitter/X](https://x.com/TheBlockChainer) · [GitHub](https://github.com/vendrell46)

## License

[MIT](LICENSE) © Zealynx Security
