# Access Control & State Integrity Module

> **Trigger**: Always active — every protocol has access control
> **Inject into**: Lens A (Access/State/Governance)
> **Priority**: HIGH — missing access control = instant critical

## 1. Permission Mapping

| Function | Modifier/Guard | Who Can Call | State Changes | Severity if Unprotected |
|----------|---------------|-------------|---------------|------------------------|
| {function} | {onlyOwner/etc} | {role} | {what changes} | {CRITICAL/HIGH/MED} |

For EVERY state-writing function: is there an access modifier? If not → candidate.

## 2. Role Hierarchy

- What roles exist? (owner, admin, operator, minter, pauser, guardian)
- Can a lower role escalate to a higher role?
- Is there a role renouncement function? What breaks if the role is renounced?
- Is ownership transfer two-step? (If single-step: typo in new address = permanent loss)

## 3. Initialization Safety

- Can `initialize()` be called more than once?
- Can the implementation contract be initialized directly (not through proxy)?
- Is `_disableInitializers()` called in constructor?
- Gap between deploy and initialize: can someone else initialize first?

## 4. Time-Lock Checks

For every admin function that changes critical parameters:
- Is there a timelock/delay?
- If NO: can admin rug users instantly?
- What parameters are "destructive" if changed? (fee to 100%, oracle to attacker-controlled, pause permanently)

## 5. State Transition Safety

For multi-state systems (proposals, orders, positions):
- Can states be skipped? (PENDING → EXECUTED, skipping APPROVED)
- Can states go backward? (EXECUTED → PENDING)
- Is the "completed" state truly terminal? Can it be re-entered?

## 6. Inherited Access Control

- Does the derived contract override a function but forget the modifier?
- Does the base contract's access check apply to all paths? (internal functions called by unprotected external functions)
