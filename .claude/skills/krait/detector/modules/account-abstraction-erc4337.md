# Account Abstraction (ERC-4337) Security Module

> **Trigger**: Protocol implements ERC-4337 or handles UserOperations
> **Inject into**: Lens A (Access/State) + Lens D (Edge/Math/Standards)
> **Priority**: MEDIUM-HIGH — ERC-4337 introduces new trust boundaries and validation constraints
> <!-- Vectors from pashov/skills (MIT) -->

## 1. UserOp Validation Bypass

- `validateUserOp` MUST verify the signature is bound to: nonce, chainId, sender, callData
- If any field is missing from signature → attacker modifies unsigned fields:
  - Missing nonce → replay same operation
  - Missing chainId → replay on other chain
  - Missing callData → substitute different action with valid signature
- Check: what fields are included in the signature hash? Compare against UserOperation struct

## 2. Paymaster Drain Vectors

- **Gas penalty undercalculation**: If paymaster doesn't account for `PENALTY_PERCENT` (10%) on unused gas → bundler griefs paymaster by requesting high gas, using little
- **ERC-20 payment deferral**: If paymaster accepts ERC-20 in `postOp` but user's token balance can change between validation and execution → insufficient payment
- Check: does paymaster validate token balance/allowance in `validatePaymasterUserOp`? Is the gas penalty correctly calculated?

## 3. Banned Opcodes in Validation Phase

Per ERC-4337 spec, `validateUserOp` and `validatePaymasterUserOp` MUST NOT use:
- `BLOCKHASH`, `COINBASE`, `TIMESTAMP`, `NUMBER`, `PREVRANDAO`, `GASLIMIT`, `GASPRICE`
- `CREATE`, `CREATE2` (except for the account itself)
- `SELFDESTRUCT`
- External storage access (other than the account's own storage and associated storage)
- Check: does the validation function directly or indirectly use banned opcodes? Indirect usage through library calls counts

## 4. Missing EntryPoint Caller Restriction

- Account's `validateUserOp` MUST only be callable by the EntryPoint
- If any other address can call it → bypass bundler validation, fake signatures
- Check: is there `require(msg.sender == entryPoint)` at the start of `validateUserOp`?

## 5. Counterfactual Wallet Init Binding

- Wallet address is determined by `CREATE2(initCode, salt)`. If `initCode` doesn't bind initialization parameters to the address → attacker deploys wallet with different params at the expected address
- Check: does the factory's `createAccount` use ALL init params in the CREATE2 salt? Missing param → attacker substitutes
