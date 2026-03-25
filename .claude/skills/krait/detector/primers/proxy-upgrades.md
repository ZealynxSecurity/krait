# Krait Detection Primer: Proxy & Upgradeability

> Distilled from 33 verified checks (Zealynx proxy-security checklist). Attack-framed for Krait detection.

## CRITICAL — Must Check Every Proxy Audit

### 1. Unprotected Implementation Initialization
Can ANYONE call `initialize()` on the implementation contract directly (not through the proxy)? If implementation's constructor doesn't call `_disableInitializers()` → attacker initializes the implementation, becomes owner, calls `selfdestruct` (pre-Cancun) → ALL proxies bricked.
**Check**: Read the implementation constructor. Does it call `_disableInitializers()`? If not → Critical.

### 2. Storage Slot Collision
If proxy stores `_implementation` at a slot that overlaps with implementation's storage → upgrading corrupts data silently.
**Check**: Does proxy use ERC-1967 reserved slots? Or custom slots that could collide with implementation variables?

### 3. Unrestricted Upgrade Permissions
Can anyone call `upgradeTo()` or `upgradeToAndCall()`? Missing access control = complete takeover.
**Check**: Who can call upgrade functions? Is it multi-sig + timelock, or just `onlyOwner` with a single EOA?

### 4. Delegatecall Context Confusion
Code running via `delegatecall` writes to the PROXY's storage, not the implementation's. If implementation writes to `slot 0` thinking it's its own variable → overwrites proxy's `_implementation` or `_admin`.
**Check**: Does the implementation's storage layout start at the same slot as the proxy expects? Any `assembly { sstore(0, ...) }` in the implementation?

### 5. Function Selector Clash (Proxy vs Implementation)
If proxy has a function with the same 4-byte selector as an implementation function → proxy intercepts the call, implementation never gets it.
**Check**: List all proxy public functions. Check their selectors against implementation functions. Any collision?

## HIGH — Check If Relevant

### 6. Missing Storage Gap in Upgradeable Base Contracts
If base contract doesn't reserve `uint256[50] private __gap`, adding new variables in a future upgrade shifts ALL child contract storage.
**Check**: Does EVERY contract in the inheritance chain have `__gap`? Not just the top-level one.

### 7. Front-Running Initialization
If `deploy()` and `initialize()` are separate transactions → attacker front-runs `initialize()` with malicious params.
**Check**: Is deploy+init atomic? Or is there a window between deployment and initialization?

### 8. Reentrancy During Initialization
During `initialize()`, state is partially set. If an external call happens mid-initialization → re-enter to exploit inconsistent state.
**Check**: Does `initialize()` make any external calls? Is there a reentrancy guard?

### 9. UUPS Missing `upgradeTo` in New Implementation
If UUPS proxy upgrades to an implementation that doesn't have `upgradeTo()` → proxy permanently bricked, can never upgrade again.
**Check**: Does the new implementation inherit `UUPSUpgradeable`? Does it override `_authorizeUpgrade`?

### 10. Signature Replay Across Implementations
If signatures don't include `verifyingContract` in EIP-712 domain → old implementation signatures work on new implementation.
**Check**: Does EIP-712 domain separator include the contract address? Does it rebuild on upgrade?

### 11. Immutable Variables in Implementation
Immutables are stored in bytecode, not storage. Proxy uses its own bytecode → proxy cannot access implementation's immutables.
**Check**: Does the implementation use `immutable` variables? These won't work through the proxy.

### 12. Delegatecall to Non-Existent Contract
`delegatecall` to address with no code returns `true` with empty data. If implementation is destroyed or unset → proxy silently succeeds with no-op.
**Check**: Does proxy check `extcodesize(implementation) > 0` before delegatecall?

### 13. Proxy Admin Can't Call Implementation Functions (Transparent Proxy)
In Transparent Proxy pattern, admin calls go to proxy, user calls go to implementation. If admin accidentally calls an implementation function → proxy intercepts, wrong behavior.
**Check**: Is the admin a separate address from all users? Is ProxyAdmin contract used?

### 14. Missing Constructor in Implementation
Configuration set in constructor doesn't affect proxy (different storage). All config MUST be in `initialize()`.
**Check**: Does the implementation's constructor set any state variables? These are invisible to the proxy.

### 15. Clone (ERC-1167) with Predictable CREATE2 Salt
If salt is user-controlled or predictable → attacker pre-computes address, sends funds before deployment, or front-runs to deploy malicious version.
**Check**: Is CREATE2 salt derived from user input alone? Or includes `msg.sender` + nonce?

## STATISTICAL CONTEXT — Protocol-Type Enrichment

From analysis of proxy/upgrade audit findings:
- **#1 root cause**: Unprotected initialization (missing _disableInitializers, frontrunnable initialize) — most common proxy finding
- **#2 root cause**: Storage layout collision across upgrades (missing __gap, slot overlap) — 30%+
- **Deployment patterns**: CREATE2 predictable salt, gap between deploy and initialize, clone init races
- **Most missed**: UUPS implementation losing upgrade capability after upgrade (missing UUPSUpgradeable inheritance in new impl)

*(Source: forefy/.context, MIT)*

---
*Source: Zealynx proxy-security checklist (33 checks). Distilled to top 15 attack patterns.*
