import { describe, it, expect } from 'vitest';
import { postProcessFindings } from '../post-processor.js';
import { Finding, FileInfo } from '../../core/types.js';

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'TEST-001',
    title: 'Test finding',
    severity: 'medium',
    confidence: 'medium',
    file: 'Contract.sol',
    line: 50,
    description: 'A detailed description of the vulnerability that is long enough to not trigger the vague penalty and describes the concrete exploit scenario.',
    impact: 'Medium impact',
    remediation: 'Fix it',
    category: 'business-logic',
    ...overrides,
  };
}

const emptyFiles: FileInfo[] = [];

// --- adjustConfidence tests ---

describe('postProcessFindings — confidence adjustments', () => {
  it('downgrades confidence for vague descriptions (< 50 chars)', () => {
    const f = makeFinding({ description: 'Short desc' });
    const contents = new Map([['Contract.sol', '']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result[0].confidence).toBe('low');
  });

  it('does NOT downgrade confidence for long descriptions', () => {
    const f = makeFinding({
      confidence: 'high',
      description: 'This vulnerability allows an attacker to drain the pool by calling withdraw() after a flash loan callback modifies state.',
    });
    const contents = new Map([['Contract.sol', '']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result[0].confidence).toBe('high');
  });

  it('downgrades generic titles only when description is also short', () => {
    const short = makeFinding({
      title: 'Missing input validation in deposit',
      severity: 'high',
      description: 'Inputs not validated.',
    });
    const long = makeFinding({
      title: 'Missing input validation in deposit',
      severity: 'high',
      description: 'The deposit function does not validate the amount parameter, allowing an attacker to deposit zero and manipulate share calculations.',
    });
    const contents = new Map([['Contract.sol', '']]);

    const resultShort = postProcessFindings([short], emptyFiles, contents);
    // Short desc + generic title → severity downgraded AND confidence low (vague)
    expect(resultShort[0].severity).not.toBe('high');

    const resultLong = postProcessFindings([long], emptyFiles, contents);
    // Long desc → generic title penalty does NOT apply
    expect(resultLong[0].severity).toBe('high');
  });

  it('does NOT penalize "potential reentrancy" or "unchecked return value" titles', () => {
    const f = makeFinding({
      title: 'Potential reentrancy in withdraw function',
      severity: 'high',
      description: 'Short.',
    });
    const contents = new Map([['Contract.sol', '']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    // "potential reentrancy" was removed from genericTitles — should not downgrade severity
    // But description is short so confidence goes low
    expect(result[0].severity).toBe('high');
  });

  it('penalizes fee-on-transfer findings when contract uses fixed tokens', () => {
    const f = makeFinding({
      title: 'Fee-on-transfer token handling',
      severity: 'high',
      confidence: 'high',
    });
    const contents = new Map([['Contract.sol', 'address public immutable baseToken;']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result[0].severity).toBe('medium');
    expect(result[0].confidence).toBe('medium');
  });

  it('does NOT penalize fee-on-transfer when contract accepts arbitrary tokens', () => {
    const f = makeFinding({
      title: 'Fee-on-transfer token handling',
      severity: 'high',
      confidence: 'high',
    });
    const contents = new Map([['Contract.sol', 'function deposit(address token, uint256 amount) external {']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result[0].severity).toBe('high');
  });

  it('penalizes reentrancy in initialization functions', () => {
    const f = makeFinding({
      title: 'Reentrancy in create function',
      severity: 'critical',
      confidence: 'high',
      category: 'reentrancy',
    });
    const contents = new Map([['Contract.sol', '']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result[0].severity).toBe('medium');
    expect(result[0].confidence).toBe('low');
  });

  it('filters out division by zero in Solidity 0.8+ (auto-reverts)', () => {
    const f = makeFinding({
      title: 'Division by zero vulnerability',
      severity: 'high',
    });
    const sol08Content = 'pragma solidity ^0.8.0;\ncontract Foo {}';
    const contents = new Map([['Contract.sol', sol08Content]]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result).toHaveLength(0);
  });

  it('does NOT downgrade division by zero in Solidity < 0.8', () => {
    const f = makeFinding({
      title: 'Division by zero vulnerability',
      severity: 'high',
    });
    const sol07Content = 'pragma solidity ^0.7.6;\ncontract Foo {}';
    const contents = new Map([['Contract.sol', sol07Content]]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result[0].severity).toBe('high');
  });

  it('boosts confirmed reentrancy with state-after-external-call', () => {
    const code = [
      'pragma solidity ^0.8.0;',
      'contract Vault {',
      '  mapping(address => uint256) public balances;',
      '  function withdraw(uint256 amount) external {',
      '    (bool success, ) = msg.sender.call{value: amount}("");',  // line 5
      '    require(success);',
      '    balances[msg.sender] -= amount;',  // state after external call
      '  }',
      '}',
    ].join('\n');
    const f = makeFinding({
      title: 'Reentrancy in withdraw',
      severity: 'medium',
      confidence: 'low',
      category: 'reentrancy',
      file: 'Vault.sol',
      line: 5,
    });
    const contents = new Map([['Vault.sol', code]]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result[0].confidence).toBe('high');
    expect(result[0].severity).toBe('high'); // boosted from medium
  });

  it('penalizes access-control findings near onlyOwner modifier', () => {
    const code = [
      'pragma solidity ^0.8.0;',
      'contract Pool {',
      '  address public owner;',
      '  modifier onlyOwner() { require(msg.sender == owner); _; }',
      '  function setFee(uint256 fee) external onlyOwner {',  // line 5
      '    protocolFee = fee;',
      '  }',
      '}',
    ].join('\n');
    // Use a title that triggers adjustConfidence (access-control + modifier detection)
    // but NOT isFalsePositive — "Bypassed access control" won't trigger "missing access control" FP filter
    const f = makeFinding({
      title: 'Insufficient access control on setFee',
      severity: 'critical',
      confidence: 'high',
      category: 'access-control',
      file: 'Pool.sol',
      line: 5,
    });
    const contents = new Map([['Pool.sol', code]]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result[0].confidence).toBe('low');
    expect(result[0].severity).toBe('medium'); // critical → medium via modifier detection
  });
});

// --- isFalsePositive tests ---

describe('postProcessFindings — false positive filtering', () => {
  it('filters "missing event emission"', () => {
    const f = makeFinding({ title: 'Missing event emission in transfer' });
    const contents = new Map([['Contract.sol', '']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result.length).toBe(0);
  });

  it('keeps "missing event" if severity is info', () => {
    const f = makeFinding({ title: 'Missing event emission', severity: 'info' });
    const contents = new Map([['Contract.sol', '']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result.length).toBe(1);
  });

  it('filters "centralization risk"', () => {
    const f = makeFinding({ title: 'Centralization risk in admin functions' });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('filters "centralization risk" in description too', () => {
    const f = makeFinding({ description: 'This poses a centralization risk because...' });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('filters "magic number"', () => {
    const f = makeFinding({ title: 'Magic number used instead of constant' });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('filters "floating pragma"', () => {
    const f = makeFinding({ title: 'Floating pragma version' });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('filters "zero address" validation findings', () => {
    for (const title of [
      'Missing zero address validation',
      'No zero-address check',
      'Address(0) validation missing',
      'Address zero not checked',
    ]) {
      const f = makeFinding({ title });
      const contents = new Map([['Contract.sol', '']]);
      expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
    }
  });

  it('filters "owner can manipulate" but NOT "owner can steal"', () => {
    const manipulate = makeFinding({ title: 'Owner can manipulate price oracle' });
    const steal = makeFinding({ title: 'Owner can steal user funds via execute' });
    const contents = new Map([['Contract.sol', '']]);

    expect(postProcessFindings([manipulate], emptyFiles, contents).length).toBe(0);
    expect(postProcessFindings([steal], emptyFiles, contents).length).toBe(1);
  });

  it('filters "missing balance validation"', () => {
    const f = makeFinding({ title: 'Missing balance validation in withdraw' });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('filters metadata contract DoS findings (medium and below)', () => {
    const f = makeFinding({
      title: 'DoS via malicious token contract',
      severity: 'medium',
      file: 'PrivatePoolMetadata.sol',
    });
    const contents = new Map([['PrivatePoolMetadata.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('keeps metadata contract HIGH findings', () => {
    const f = makeFinding({
      title: 'DoS via malicious token contract',
      severity: 'high',
      file: 'PrivatePoolMetadata.sol',
    });
    const contents = new Map([['PrivatePoolMetadata.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(1);
  });

  it('filters "price manipulation via setter"', () => {
    const f = makeFinding({ title: 'Price manipulation via virtual reserve setter functions' });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('keeps "price manipulation via flash loan"', () => {
    const f = makeFinding({ title: 'Price manipulation via flash loan attack' });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(1);
  });

  it('filters "fee-on-transfer" in Factory.sol', () => {
    const f = makeFinding({
      title: 'Fee-on-transfer token incompatibility',
      file: 'Factory.sol',
    });
    const contents = new Map([['Factory.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('filters "fee-on-transfer" in cross-contract findings', () => {
    const f = makeFinding({
      title: 'Fee-on-transfer token incompatibility causes protocol insolvency',
      file: 'cross-contract',
    });
    const contents = new Map<string, string>();
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('filters "no validation of pool response"', () => {
    const f = makeFinding({ title: 'No validation of pool response in router' });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('filters "precision loss" without exploit scenario', () => {
    const f = makeFinding({
      title: 'Precision loss in fee calculation',
      confidence: 'medium',
      description: 'Division before multiplication causes rounding errors.',
    });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('keeps "precision loss" with concrete exploit', () => {
    const f = makeFinding({
      title: 'Precision loss in fee calculation',
      confidence: 'high',
      description: 'An attacker can profit from rounding by depositing specific amounts.',
    });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(1);
  });

  it('filters "missing access control" when function is actually protected', () => {
    const code = [
      '', '', '', '', '',  // padding to line 5
      '', '', '', '', '',  // padding to line 10
      '', '', '', '', '',  // padding to line 15
      '', '', '', '', '',  // padding to line 20
      '', '', '', '', '',  // padding to line 25
      '', '', '', '', '',  // padding to line 30
      '', '', '', '', '',  // padding to line 35
      '  function setAllParameters(',                          // line 38
      '    uint128 newVirtualBaseTokenReserves,',
      '    uint128 newVirtualNftReserves,',
      '    bytes32 newMerkleRoot,',
      '    uint56 newFeeRate,',
      '    bool newUseStolenNftOracle,',
      '    bool newPayRoyalties',
      '  ) external onlyOwner {',                              // line 45
      '    virtualBaseTokenReserves = newVirtualBaseTokenReserves;',
      '  }',
    ].join('\n');
    const f = makeFinding({
      title: 'setAllParameters function missing access control allows unauthorized parameter changes',
      category: 'access-control',
      file: 'PrivatePool.sol',
      line: 45,
    });
    const contents = new Map([['PrivatePool.sol', code]]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result.length).toBe(0);
  });

  // --- Real-world false positive from shadow audit ---

  it('filters "unchecked return value" near safeTransfer', () => {
    const code = [
      '', '', '', '', '',
      '', '', '', '', '',
      '    token.safeTransferFrom(msg.sender, address(this), amount);',  // line 11
    ].join('\n');
    const f = makeFinding({
      title: 'Unchecked return value of token transfer',
      file: 'Pool.sol',
      line: 11,
      description: 'The return value is not checked.',
    });
    const contents = new Map([['Pool.sol', code]]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(0);
  });

  it('keeps "unchecked return value" when using .call{}', () => {
    const f = makeFinding({
      title: 'Unchecked return value of external call',
      description: 'The .call{value: amount}("") return value is not checked.',
    });
    const contents = new Map([['Contract.sol', '']]);
    expect(postProcessFindings([f], emptyFiles, contents).length).toBe(1);
  });
});

// --- Edge cases ---

describe('postProcessFindings — edge cases', () => {
  it('handles empty findings array', () => {
    const contents = new Map<string, string>();
    expect(postProcessFindings([], emptyFiles, contents).length).toBe(0);
  });

  it('handles finding with missing file in contents map', () => {
    const f = makeFinding({ file: 'NonExistent.sol' });
    const contents = new Map<string, string>();
    // Should not crash, returns the finding (possibly adjusted)
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result.length).toBeGreaterThanOrEqual(0);
  });

  it('preserves findings that pass all checks', () => {
    const f = makeFinding({
      title: 'Silent overflow in reserve update via uint128 casting',
      severity: 'high',
      confidence: 'high',
      category: 'integer-overflow',
    });
    const contents = new Map([['Contract.sol', 'pragma solidity ^0.8.0;']]);
    const result = postProcessFindings([f], emptyFiles, contents);
    expect(result.length).toBe(1);
    expect(result[0].severity).toBe('high');
    expect(result[0].confidence).toBe('high');
  });
});
