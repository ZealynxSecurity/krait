# Severity Classification Guide

Use this when determining whether a finding is critical, high, medium, or low.

## Critical

Direct loss of funds or permanent denial of service with no user action required.

Examples:
- Reentrancy allowing drain of pool funds
- Missing access control on withdraw/transfer functions
- Oracle manipulation leading to infinite minting
- Integer overflow causing incorrect token amounts (pre-Solidity 0.8)
- Proxy upgrade allowing arbitrary code execution

## High

Significant loss of funds requiring specific conditions, or temporary DoS of core functionality.

Examples:
- Flash loan attack vectors on price calculations
- Front-running sensitive operations (liquidations, swaps)
- Incorrect share/asset ratio calculation in vaults
- Missing slippage protection on swaps
- Governance takeover via flash loans

## Medium

Limited financial impact or requires unlikely conditions. Also includes issues that degrade protocol reliability.

Examples:
- Rounding errors causing small fund leakage over time
- Missing event emissions for critical state changes
- Centralization risks (single admin key)
- Stale oracle prices without staleness checks
- Missing zero-address validation on constructor params

## Low

Informational or best-practice violations. No direct financial impact.

Examples:
- Gas optimization opportunities
- Unused variables or imports
- Missing NatSpec documentation
- Non-standard naming conventions
- Redundant checks that don't affect correctness
