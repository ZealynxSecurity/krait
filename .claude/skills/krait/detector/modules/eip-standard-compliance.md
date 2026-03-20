# EIP/Standard Compliance Module

> **Trigger**: Protocol implements ERC-20, ERC-721, ERC-4626, ERC-1155, ERC-2981, ERC-3156, EIP-712, or any EIP/ERC standard
> **Inject into**: Lens D (Edge/Math/Standards)
> **Priority**: CRITICAL — #1 missed bug category across 40 shadow audits

## 1. EIP-712 Typehash Verification (HIGHEST PRIORITY)

For EVERY `keccak256("TypeName(...")` typehash in the code:

1. Find the corresponding struct definition
2. Compare CHARACTER BY CHARACTER:
   - Field names match exactly? (case-sensitive)
   - Types are canonical Solidity types? (`uint256` not `uint`, `address` not `address payable`)
   - Order matches struct definition order?
3. Check nested struct encoding (alphabetical order per EIP-712 spec)
4. Check domain separator: chainId, verifyingContract, name, version — all present and correct?

**This is a mechanical check. Do it for every typehash. No shortcuts.**

## 2. ERC-4626 Vault Standard

| Check | Expected | Actual | Status |
|-------|----------|--------|--------|
| `deposit` rounds shares DOWN | | | |
| `mint` rounds assets UP | | | |
| `withdraw` rounds shares UP | | | |
| `redeem` rounds assets DOWN | | | |
| `maxDeposit` returns 0 when paused (not revert) | | | |
| `maxMint` returns 0 when paused | | | |
| First depositor protection exists | | | |
| `totalAssets` includes yield | | | |
| `totalAssets` is donation-safe | | | |

## 3. ERC-20 Compliance

| Check | Status |
|-------|--------|
| `transfer` returns `true`? | |
| `transferFrom` decrements allowance? | |
| Self-transfer safe? | |
| Zero-amount transfer safe? | |
| `totalSupply == sum(balanceOf)` after rebasing? | |

## 4. ERC-721 Compliance

| Check | Status |
|-------|--------|
| `ownerOf` reverts for nonexistent tokens? | |
| `tokenURI` reverts for nonexistent tokens? | |
| `safeTransferFrom` calls `onERC721Received`? | |
| `transferFrom` clears approvals? | |
| `balanceOf(address(0))` reverts? | |

## 5. Version Compatibility

| Dependency | Expected Version | Actual | Breaking Changes? |
|-----------|-----------------|--------|-------------------|
| OpenZeppelin | | | v4→v5: `_beforeTokenTransfer` → `_update` |
| Safe | | | 1.3.0→1.5.0: guard interface params differ |
| Solidity | | | 0.8.20+: PUSH0 breaks on older chains |
