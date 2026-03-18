# Krait — Solidity Security Audit Skills for Claude Code

**Silent. Precise. Lethal.**

[Claude Code](https://docs.anthropic.com/en/docs/claude-code) skills for **Solidity** smart contract security auditing. Type `/krait` in any Solidity project → structured audit with concrete exploit traces, zero API cost. Built by [Zealynx Security](https://zealynx.io).

| | |
|---|---|
| **Technology** | Solidity |
| **Platform** | Claude Code (skills + commands) |
| **Cost** | Zero — uses your Claude subscription |
| **Precision** | 90% across 40 blind Code4rena contests |
| **Install** | Copy to `~/.claude/` → `/krait` works everywhere |

> The methodology lives in `.claude/skills/` and `.claude/commands/` as structured prompts that Claude Code executes. No external API calls, no separate tool — just Claude, guided by 40 contests worth of battle-tested detection heuristics.

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

### Verification Phase (Kill Gates)

Eight automatic gates try to **disprove every finding** before it reaches you. They've never killed a true positive across 40 contests:

- **A**: Generic best practice ("use SafeERC20") · **B**: Theoretical/unrealistic
- **C**: Intentional design · **D**: Speculative (no WHO/WHAT/HOW MUCH)
- **E**: Admin trust · **F**: Dust (<$100) · **G**: Out of context · **H**: Known issue

Result: FPs dropped from 4.2/contest → 0.2/contest (**95% reduction**).

### Self-Improving

After each blind test: score → root-cause every miss → update methodology → re-test. This loop produced 50+ heuristics, 30 modules, and 7 protocol-specific primers from real missed findings.

### Four-Phase Pipeline

| Phase | What It Does |
|-------|-------------|
| **Recon** | Architecture map, deterministic file risk scoring, protocol primer selection |
| **Detection** | Three passes × 4 parallel lenses on highest-risk files |
| **State Analysis** | Coupled state pairs, mutation matrix — catches sync bugs scanning misses |
| **Verification** | Kill gates + concrete exploit trace required for every H/M |

### Dual-Engine Architecture

Two complementary engines sharing the same knowledge base:

- **CLI Agent** (this repo): 4-phase adversarial pipeline for security researchers who want automated vulnerability analysis with concrete exploit traces.
- **Web Platform** ([krait.zealynx.io](https://krait.zealynx.io)): Protocol-specific security assessment — 39 DeFi verticals, 845+ checks, smart filtering, auto-generated architectural observations, branded exportable reports.

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

## Installation

### Claude Code Skills (Recommended — Zero Cost)

Install Krait's skills and commands into your global Claude Code directory:

```bash
git clone https://github.com/ZealynxSecurity/krait.git
mkdir -p ~/.claude/commands ~/.claude/skills
cp -r krait/.claude/commands/* ~/.claude/commands/
cp -r krait/.claude/skills/* ~/.claude/skills/
```

Then open Claude Code in **any** Solidity project and run:

```
/krait                  # Full 4-phase audit
/krait-quick            # Fast mode (skips state analysis)
```

Individual phases: `/krait-recon` · `/krait-detect` · `/krait-state` · `/krait-critic` · `/krait-report`

To update to the latest methodology:

```bash
cd krait && git pull
cp -r .claude/commands/* ~/.claude/commands/
cp -r .claude/skills/* ~/.claude/skills/
```

> Works with Claude Code CLI, VS Code extension, and Cursor. Once installed, `/krait` is available in every project — no per-project setup needed.

### CLI (API-Powered)

For automated batch processing via the Anthropic API:

```bash
npx krait audit /path/to/project                 # Full audit
npx krait audit /path/to/project --quick          # Fast mode
npx krait audit /path/to/project --dry-run        # Preview without API calls
npx krait patterns                                # List loaded patterns
```

Requires `ANTHROPIC_API_KEY` environment variable. Install globally with `npm install -g krait`.

---

## Project Status

| Component | Status |
|-----------|--------|
| Claude Code skills (4-phase audit) | Production |
| Kill gates + shadow benchmarking (40 contests) | Production |
| Detection primers (7 protocol types) | Production |
| Web assessment platform (39 verticals) | Live |
| CLI tool (`npx krait`) | Published |
| Multi-domain (Rust, TypeScript, AI) | Planned |

---

## Author

**Carlos Vendrell Felici** — Founder, [Zealynx Security](https://zealynx.io)
[Twitter/X](https://x.com/TheBlockChainer) · [GitHub](https://github.com/vendrell46)

## License

[MIT](LICENSE) © Zealynx Security
