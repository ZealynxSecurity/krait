# Krait Detection Primer: Wallet / Safe / Account Abstraction

> Built from Krait's shadow audit miss analysis (Brahma contest was a Safe integration). Addresses Safe version compatibility, EIP-712, and wallet integration patterns.

## CRITICAL — Must Check Every Wallet/Safe Audit

### 1. EIP-712 Typehash Mismatch
Find every `keccak256("TypeName(...")` typehash. Find the corresponding struct. Compare CHARACTER BY CHARACTER: field names, types (`uint256` not `uint`), order. If typehash string doesn't match struct → signatures validate against wrong data → bypass.
**Check**: For EVERY typehash, put the string and struct side by side. Compare each field name, type, and order. Check nested struct encoding (appended alphabetically).

### 2. Safe Version Incompatibility
Safe 1.3.0 vs 1.4.0 vs 1.5.0 have DIFFERENT interfaces:
- Guard interface: `checkTransaction`/`checkAfterExecution` params differ between versions
- `execTransactionFromModule` return data changes
- Module callback signatures change
If code targets Safe 1.3 but user deploys with Safe 1.5 → calls revert or behave unexpectedly.
**Check**: What Safe version does the code import/target? What version will users actually deploy? Are all interface assumptions correct?

### 3. Module Transaction Gas Refund Drain
If `execTransaction` includes a gas refund mechanism and the refund parameters (gasPrice, gasToken, refundReceiver) are NOT included in the policy/validation hash → operator sets high gasPrice → drains Safe's ETH as gas refund.
**Check**: Are gas parameters included in the signature/policy that validates the transaction? Can the executor choose their own gas price?

### 4. Uninitialized Proxy Implementation
If Safe module/guard uses proxy pattern and implementation can be initialized by anyone → attacker initializes → becomes owner → self-destructs implementation (pre-Cancun) → all proxies bricked.
**Check**: Can implementation be initialized directly? Does constructor call `_disableInitializers()`?

### 5. Missing Validation on Module Enable/Disable
If module can be enabled without proper authorization → attacker enables malicious module → executes transactions from the Safe.
**Check**: What's the flow to enable a new module? Does it require Safe owner signatures? Is there a timelock?

## HIGH — Check If Relevant

### 6. Guard Bypass via Module Execution
If guard protects `execTransaction` but modules can execute via `execTransactionFromModule` without going through the guard → guard is useless.
**Check**: Does the guard also apply to module-initiated transactions? Or only direct `execTransaction`?

### 7. Signature Replay Across Chains/Safes
If EIP-712 domain separator doesn't include `chainId` and `verifyingContract` → signature from one Safe/chain works on another.
**Check**: Does domain separator include both `chainId` AND `verifyingContract`? Is it rebuilt if either changes?

### 8. Delegate Call Restriction Bypass
If policy restricts `call` but not `delegatecall` → operator uses delegatecall to execute arbitrary code in Safe's context.
**Check**: Does the policy/guard check `operation` parameter (0=call, 1=delegatecall)? Are both restricted appropriately?

### 9. Validator Registration Without Ownership Proof
If validator/sub-account can be registered for a Safe without proving the registrant owns that Safe → attacker registers themselves as validator for victim's Safe.
**Check**: Does registration verify `msg.sender` is the Safe or an authorized Safe owner?

### 10. Nonce Management Gaps
If nonces are per-Safe but not per-operation-type → nonce used for one type of operation could collide with another.
**Check**: How are nonces managed? Per-Safe? Per-executor? Per-operation-type? Can nonce reuse occur?

### 11. Fallback Handler Manipulation
If fallback handler can be changed by module → attacker enables malicious module → changes fallback → intercepts all calls to the Safe.
**Check**: Can the fallback handler be changed by anyone other than Safe owners? Is there a timelock?

### 12. Recovery Mechanism Exploits
If social recovery or guardian system exists, can guardians collude to take over the Safe? Is there a delay period?
**Check**: What's the recovery threshold? Is there a timelock on recovery? Can the owner cancel a recovery?

---
*Source: Krait shadow audit analysis (Brahma Safe integration — 4 official findings, 3 related to Safe version compatibility and EIP-712). Addresses the #1 missed category in wallet/Safe audits.*
