# Extended Heuristic Vectors — Advanced Detection Reference

> **Usage**: Read during Tier 1 deep analysis in Pass 2. NOT a module — always available for reference.
> **Source**: Curated from pashov/skills (MIT) — 58 general-advanced vectors organized by category.
> Each entry: `[P] VECTOR-NAME: one-line detection instruction`

---

## Assembly / Yul / Low-Level

- [P] DIRTY-BITS: Check if higher-order bits are cleaned after assembly operations — `calldataload`, `mload` return full 256 bits; if used as `address` or `uint96`, dirty bits corrupt values
- [P] SIGNED-INT-ASSEMBLY: Assembly arithmetic is unsigned by default — if `sdiv`, `smod`, `slt`, `sgt` not used for signed values → wrong results for negative numbers
- [P] RETURNDATA-ZERO: `returndatasize()` used as zero shorthand — breaks if ANY external call was made earlier in the call (returndatasize reflects LAST call)
- [P] FREE-MEMORY-PTR: If assembly writes past `mload(0x40)` without updating the free memory pointer → Solidity compiler may overwrite the data later
- [P] MEMORY-STRUCT-STORAGE: Modifying a memory copy of a storage struct does NOT write back to storage — changes lost silently
- [P] DELEGATECALL-PROPAGATION: Assembly `delegatecall` must propagate both `return` and `revert` data — missing either causes silent success on failure or lost return values
- [P] CREATE-ZERO-CHECK: `CREATE`/`CREATE2` returns `address(0)` on failure but doesn't revert — if return value unchecked → protocol operates with zero-address contract
- [P] CALLDATALOAD-OOB: `calldataload(offset)` beyond calldata length returns zero-padded — if protocol reads optional params this way, it silently uses 0
- [P] SCRATCH-SPACE: Writing to memory `0x00-0x3f` (scratch space) then calling a Solidity function → compiler may overwrite scratch space for hashing
- [P] MSTORE8-PARTIAL: `mstore8` only writes lowest byte — remaining 31 bytes unmodified. If later read with `mload`, stale data included

## Storage / Memory / State

- [P] STORAGE-COLLISION-PROXY: Implementation storage slot 0 overlaps with proxy's `_implementation` slot → upgrade corrupts implementation address
- [P] IMMUTABLE-PROXY: `immutable` variables are stored in bytecode — proxy `delegatecall` reads the PROXY's bytecode (which has no immutables) → always returns 0
- [P] STORAGE-WRITE-ARBITRARY: If user-controlled index reaches a `sstore(slot, value)` → arbitrary storage write → full contract takeover
- [P] PACKED-STORAGE-DIRTY: When writing to a packed storage slot, must preserve adjacent values — assembly `sstore` without masking corrupts packed variables
- [P] TRANSIENT-MULTICALL: `TSTORE` values persist across calls within a tx — in multicall/batch contexts, transient storage from interaction 1 leaks into interaction 2

## Accounting / Precision / Math

- [P] UNSAFE-DOWNCAST: `uint128(x)` does NOT revert in Solidity 0.8+ — silently truncates. Every explicit downcast is a potential state corruption
- [P] SMALL-TYPE-OVERFLOW: `uint32` timestamps overflow in year 2106, `uint48` in year 8.9M — but `uint32` for BLOCK NUMBERS overflows much sooner on L2s with fast blocks
- [P] DIVISION-BEFORE-MULTIPLY: `(a / b) * c` loses precision — rewrite as `(a * c) / b`. Common in fee calculations
- [P] ROUNDING-DIRECTION: Protocol-favorable rounding: `deposit` rounds DOWN (fewer shares), `withdraw` rounds UP (more assets per share). Reversed = drain
- [P] FEE-DOUBLE-APPLY: Sequential fees each on REMAINING amount — total must be < 100%. If each fee calculated on GROSS → total can exceed 100%
- [P] PRECISION-MISMATCH-LIBS: Two math libraries with similar names but different precision bases (1e6 vs 1e18 vs 1e27) — wrong library at any call site → orders-of-magnitude error
- [P] MULMOD-PHANTOM: `mulmod(a, b, 0)` returns 0, not revert. If modulus is a variable that can be 0 → silent precision loss
- [P] COMPOUND-OVERFLOW: `(1 + rate)^periods` overflows uint256 at high rate*periods combinations — especially dangerous in interest calculations

## Time-Dependent / Ordering

- [P] BLOCK-TIMESTAMP-L2: Block timestamps on L2s can have same timestamp across multiple blocks — time-based logic using `block.timestamp` may not advance as expected
- [P] EPOCH-BOUNDARY-RACE: Actions at exactly the epoch transition — user can act in last moment of old epoch AND first moment of new epoch, potentially double-counting
- [P] DEADLINE-BLOCKTIMESTAMP: `deadline = block.timestamp` is always satisfied — provides zero protection. Must be user-supplied from off-chain
- [P] NONCE-REVERT: If nonce is incremented inside a sub-call that reverts → nonce not incremented but main call succeeds → replay with same nonce
- [P] RETROACTIVE-PARAM: Admin changes rate/fee/duration → applies retroactively to in-flight operations (auctions, cooldowns, pending withdrawals)

## Array / Mapping / Data Structures

- [P] DELETE-ARRAY-GAP: `delete array[i]` sets element to 0 but doesn't shift — leaves gap. If later code assumes dense array → skips entries
- [P] MERKLE-LEAF-REUSE: If Merkle proof doesn't include a `claimed[leaf]` check → same proof reused for multiple claims
- [P] ENUMERABLE-GAS: `EnumerableSet.remove` swaps last element into removed slot — changes ordering. If any logic depends on order → broken
- [P] MAPPING-DELETE: `delete mappingOfStruct[key]` zeroes the struct but doesn't remove the key — `mapping[key].someField == 0` may be confused with "never set"
- [P] UNBOUNDED-PUSH: Array grows via `push()` without max length check → eventual gas limit DoS on iteration

## Emergency / Admin / Lifecycle

- [P] PAUSE-LIQUIDATION: If `whenNotPaused` is on `liquidate()` → pausing during crash prevents liquidation → bad debt accumulates
- [P] IRREVOCABLE-ROLE: Roles can be granted but never revoked — compromised role holder persists forever
- [P] INIT-REENTRANCY: During `initialize()`, contract state is partial — if an external call happens mid-init → reenter to exploit incomplete state
- [P] SELFDESTRUCT-FORCE-ETH: `selfdestruct(target)` (pre-Dencun) force-sends ETH — breaks `address(this).balance`-based accounting
- [P] FRONTRUN-INIT: Separate `deploy()` and `initialize()` txs → attacker front-runs init with malicious params

## Token / ERC Patterns

- [P] ERC777-REENTER: ERC777 `tokensReceived` hook gives recipient execution during transfer — reentrancy even with SafeERC20
- [P] PERMIT-WRONG-TOKEN: `permit(token, owner, spender, value, deadline, v, r, s)` — if `token` is not validated, permit from a different token may produce valid ecrecover
- [P] REBASE-CACHE: If protocol caches `balanceOf` for a rebasing token → cache becomes stale after rebase → accounting drift
- [P] FOT-ACCOUNTING: `transfer(amount)` delivers `amount - fee` — if protocol assumes `amount` was delivered → inflation, eventually drains
- [P] NFT-CALLBACK-REENTER: `safeTransferFrom` triggers `onERC721Received` — recipient gets execution during transfer. If state is partially updated → exploit
- [P] APPROVAL-RACE: ERC20 `approve(newValue)` without first setting to 0 → front-run: spender uses old + new allowance
- [P] MSGVALUE-LOOP: `msg.value` in a loop or multicall → same ETH counted multiple times. Each iteration uses the SAME `msg.value`

## Cross-Contract / Integration

- [P] RETURN-BOMB: External call returns huge data → calling contract OOGs copying return data. Use assembly `call` with bounded returndatasize
- [P] CROSS-REENTRANCY: Function A has `nonReentrant`, function B doesn't, both read/write same state → reenter B from A's external call
- [P] DIAMOND-STORAGE: Diamond proxy storage must be namespaced — if two facets use the same storage slot → silent corruption
- [P] FLASH-CALLBACK-TRUST: Flash loan callback — verify `msg.sender` is the expected pool. If callback doesn't validate caller → attacker triggers fake callback
- [P] EXTERNAL-SILENT-FAIL: External call silently returns without effect (mint returns without minting) → protocol continues with wrong assumptions
