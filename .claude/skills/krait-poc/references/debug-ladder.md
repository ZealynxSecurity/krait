# Debug ladder — error class → fix

When a PoC fails to compile or run, work top-to-bottom. Each rung is a real, recurring
failure class with its fix. **Cap: 5 compile attempts total**, then fall back to
`[CODE-TRACE]` — do not grind on a setup that will not build.

## Compile failures

### 1. Missing interface / undeclared identifier
`Error: Identifier not found` or `... is not a contract`.
→ You referenced a type you never defined. Generate the interface from the deployed ABI
(`cast interface <addr> -o IX.sol -n IX`) or add a minimal `interface IX { ... }` with just
the functions you call.

### 2. Wrong / stale function signature
Compiles against your interface but reverts at runtime with no revert reason, or
`function selector not recognized`.
→ Your interface disagrees with the deployed contract. Re-pull the real signature. This is
the #1 cause of a PoC that "should work" but silently no-ops. Never trust a signature you
did not read from source or ABI.

### 3. Constructor argument mismatch (local harness)
`Error: wrong argument count` when deploying an in-scope contract.
→ Read the project's own deploy script / `setUp` for the real constructor args and order.
Do not guess.

### 4. Type mismatch on an overloaded function
`mint(uint256)` vs `mint(MintParams)` — Solidity picks by argument types.
→ Match the exact overload the deployed contract uses; disambiguate by casting args.

### 5. Remapping / import path unresolved
`File not found` on an import.
→ Check `remappings.txt` / `foundry.toml`. Use the project's own import style. If a lib is
genuinely missing and cannot be installed, this is a `NO_BUILD_ENVIRONMENT` blocker.

## Runtime failures (compiled, but the test fails)

### 6. Fork RPC error
`Could not instantiate forked environment` / `error sending request`.
→ The chain alias has no RPC. Set it in `foundry.toml` `[rpc_endpoints]` with a valid
env-var URL. If no RPC is reachable in this environment, a fork PoC cannot run → record the
finding `[UNPROVEN-EXTERNAL]` with the blocker, keep it at proven-mechanism severity.

### 7. Unknown opcode / `EvmError: NotActivated`
→ The forked block uses opcodes newer than your EVM version. Add `--evm-version cancun`
(or the version matching the chain at that block).

### 8. Revert with no reason, mid-attack
→ Turn on the full trace: run with `-vvvv`. Read the trace from the bottom up to the frame
that reverted. Because you `vm.label`ed everything, the trace names the contracts. Common
causes: wrong `msg.sender` (`prank` vs `startPrank` confusion), flash-loan under-repayment,
an allowance you never set.

### 9. Flash-loan repayment revert
The whole tx reverts at the end of the callback.
→ You repaid the wrong amount. Fee-free providers want principal; Aave wants principal +
premium. See `flashloan.md`.

### 10. `deal` did not fund correctly
Balance looks set but transfers fail or accounting is wrong.
→ The token has a transfer hook / rebasing / non-standard `balanceOf` slot. Acquire the
token through the protocol (swap or flash loan) instead of `deal`.

## The harm assertion fails (compiled, ran, no harm)

This is a **result**, not a bug in your PoC — but confirm it is not a setup error first.
Apply the one-retry protocol in `assertion-protocol.md`. If the attack genuinely does not
reproduce the claimed harm after that retry → `[POC-FAIL]`.

## Reading a trace efficiently

- Run the failing test with `-vvvv` (full trace) via the forge MCP.
- Read bottom-up: the deepest frame is where it actually reverted.
- Labeled addresses make each frame legible — if you see raw hex, you skipped `vm.label`.
- The `[Revert]` line's reason string (if any) usually names the failed `require`.
