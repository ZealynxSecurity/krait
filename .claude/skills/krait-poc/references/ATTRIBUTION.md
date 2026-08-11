# krait-poc — Sources & Attribution

The PoC-construction knowledge in this skill was distilled from public, permissively- or
educationally-licensed sources. **No third-party Solidity was copied into this skill** — the
patterns, cheatcode rankings, and provider tables are facts *derived* from analyzing the
corpora, expressed in original prose and an original harness.

## Corpora analyzed (facts derived, code not vendored)

| Source | License | What we derived | Link |
|--------|---------|-----------------|------|
| **SunWeb3Sec/DeFiHackLabs** | Apache-2.0 | Structural patterns across 844 real exploit PoCs: cheatcode usage frequency, flash-loan provider/callback frequency, chain distribution, the before/after balance-log harness shape. | [github.com/SunWeb3Sec/DeFiHackLabs](https://github.com/SunWeb3Sec/DeFiHackLabs) |
| **theredguild/damn-vulnerable-defi** | MIT | Local-harness patterns for PoCs against in-scope source with no live deployment. | [github.com/theredguild/damn-vulnerable-defi](https://github.com/theredguild/damn-vulnerable-defi) |
| **Foundry `forge-std`** | MIT / Apache-2.0 | Authoritative cheatcode signatures (`Vm.sol`) and fork-testing API. | [github.com/foundry-rs/foundry](https://github.com/foundry-rs/foundry) |

## Read for method only (NOT copied, license does not permit vendoring into MIT)

- **immunefi-team/forge-poc-templates** (LGPL-3.0) — reviewed for PoC-structure best
  practices (interface generation via `cast interface`, `cast etherscan-source`, the
  attack-contract-in-callback shape). No code reused.
- **SunWeb3Sec/DeFiVulnLabs** (no license stated) — reviewed for vulnerability-class PoC
  idioms. No code reused (unlicensed = all rights reserved).
- **crytic/building-secure-contracts** (AGPL-3.0) — reviewed for methodology. No code
  reused.

## Original to this skill

- The `BaseTestWithBalanceLog` harness in `harness.md` (an original, MIT-licensed
  reimplementation of the before/after-balance idea; not a copy of DeFiHackLabs' file).
- The workflow, the debug ladder, the assertion-retry protocol, and the evidence-tag
  integration with the Krait critic.
- The cheatcode and flash-loan-provider **rankings**, which are statistics computed over the
  DeFiHackLabs corpus — facts about the corpus, not its content.

## A note on the corpus's SPDX headers

DeFiHackLabs is Apache-2.0 at the repo level, but individual PoC `.sol` files carry
`SPDX-License-Identifier: UNLICENSED` because they embed third-party contract interfaces the
authors do not own. This is why we derive facts and write our own harness rather than
vendoring their test files — and why an incident PoC you generate should credit the original
researcher / post-mortem in its header (see `reproduce-incident.md`).
