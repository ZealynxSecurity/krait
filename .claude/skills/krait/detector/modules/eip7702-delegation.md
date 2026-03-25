# EIP-7702 Delegation Security Module

> **Trigger**: Protocol uses EIP-7702 or handles delegated EOAs
> **Inject into**: Lens A (Access/State) + Lens D (Edge/Math/Standards)
> **Priority**: MEDIUM-HIGH — EIP-7702 changes fundamental EOA assumptions
> <!-- Vectors from pashov/skills (MIT) -->

## 1. Code Inspection Opcode Invalidation

EIP-7702 allows EOAs to have code. Opcodes that distinguish EOA from contract become unreliable:
- `EXTCODESIZE(addr) == 0` no longer means "addr is an EOA" — delegated EOAs have code
- `EXTCODEHASH(addr) == keccak256("")` same issue
- Check: does the protocol use code size/hash to distinguish EOAs from contracts? If yes → broken under 7702

## 2. Whitelist Privilege Borrowing

- If a whitelisted/privileged address delegates to an attacker's code → attacker inherits the address's privileges while executing arbitrary logic
- Check: does the protocol whitelist specific addresses? Can whitelisted addresses delegate their code via 7702?

## 3. Dual Signature Confusion

- An EIP-7702 delegated EOA can validate signatures via BOTH the original ECDSA key AND the delegated contract's validation logic
- If protocol validates only one method → attacker uses the other to bypass
- Check: does signature validation handle both paths? Is there ambiguity about which signer is authoritative?

## 4. Delegation Initialization Front-Run

- When an EOA sets delegation for the first time, the initialization can be front-run
- Attacker sees delegation tx → front-runs with their own init params → victim's delegation points to attacker-controlled state
- Check: is delegation initialization protected against front-running? Is there a commit-reveal scheme?

## 5. tx.origin Bypass

- With EIP-7702, `tx.origin == msg.sender` no longer guarantees the caller is a plain EOA
- Delegated EOAs can have complex call chains where tx.origin check passes but the actual execution is contract code
- Check: does the protocol use `tx.origin` for authentication or EOA verification? If yes → broken under 7702

## 6. ERC-721/1155 Callback on Delegated EOA

- Sending NFTs to a delegated EOA triggers `onERC721Received` / `onERC1155Received` on the delegated code
- If the delegated code doesn't implement these callbacks → transfer reverts → NFTs can't be received
- Check: can delegated EOAs receive NFTs? Do all token transfer paths handle potential callback failures?

## 7. Cross-Chain Authorization Replay

- An EIP-7702 delegation authorization may be valid on multiple chains if `chainId == 0` (wildcard)
- Authorization signed for chain A replayed on chain B → unintended code delegation
- Check: do all authorization signatures include specific `chainId`? Is `chainId = 0` rejected?

## 8. Storage Collision on Redelegation

- If EOA delegates to contract A (which uses storage slots X, Y) then redelegates to contract B (which also uses slots X, Y but for different purposes) → corrupted state
- Check: is there a storage clearing mechanism on redelegation? Do delegated contracts use namespaced storage?
