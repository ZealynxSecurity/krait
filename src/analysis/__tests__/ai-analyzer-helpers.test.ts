import { describe, it, expect } from 'vitest';
import { AIAnalyzer } from '../ai-analyzer.js';
import { Finding } from '../../core/types.js';

// Create analyzer with dummy config — we only test private helpers via prototype
const dummyConfig = {
  apiKey: 'test-key',
  model: 'claude-sonnet-4-20250514',
  deepModel: 'claude-sonnet-4-20250514',
  maxFiles: 50,
  maxFileSize: 100000,
  verbose: false,
  outputFormat: 'json' as const,
};

const analyzer = new AIAnalyzer(dummyConfig);

// Access private methods for testing
const detectFileAnalysisHints = (AIAnalyzer.prototype as any).detectFileAnalysisHints.bind(analyzer);
const extractFunctionInventory = (AIAnalyzer.prototype as any).extractFunctionInventory.bind(analyzer);
const identifyUncoveredFunctions = (AIAnalyzer.prototype as any).identifyUncoveredFunctions.bind(analyzer);
const extractFunctionsWithBodies = (AIAnalyzer.prototype as any).extractFunctionsWithBodies.bind(analyzer);
const extractStateContext = (AIAnalyzer.prototype as any).extractStateContext.bind(analyzer);
const normalizeSeverity = (AIAnalyzer.prototype as any).normalizeSeverity.bind(analyzer);
const normalizeConfidence = (AIAnalyzer.prototype as any).normalizeConfidence.bind(analyzer);

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'TEST-001',
    title: 'Test finding',
    severity: 'medium',
    confidence: 'medium',
    file: 'Contract.sol',
    line: 50,
    description: 'Test description',
    impact: 'Medium impact',
    remediation: 'Fix it',
    category: 'reentrancy',
    ...overrides,
  };
}

// --- detectFileAnalysisHints ---

describe('detectFileAnalysisHints', () => {
  it('returns empty string for code without recognized patterns', () => {
    expect(detectFileAnalysisHints('contract Foo { uint256 x; }')).toBe('');
  });

  it('detects fee/royalty logic', () => {
    const code = 'uint256 protocolFee = amount * feeBps / 10000;';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('FEE/ROYALTY');
    expect(result).toContain('denominator');
  });

  it('detects flash loan logic', () => {
    const code = 'function flashLoan(address token, uint256 amount) external {';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('FLASH LOAN');
  });

  it('detects token transfer patterns', () => {
    const code = 'token.safeTransferFrom(msg.sender, address(this), amount);';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('fee-on-transfer');
  });

  it('detects reserve/AMM math', () => {
    const code = 'uint256 virtualBaseTokenReserves; function getAmountOut() view {';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('RESERVE/AMM');
  });

  it('detects share/vault math', () => {
    const code = 'uint256 totalSupply; uint256 totalAssets; uint256 share;';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('SHARE/VAULT');
  });

  it('detects callback patterns', () => {
    const code = 'function onERC721Received(address, address, uint256, bytes) external returns (bytes4) {';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('CALLBACK');
  });

  it('detects explicit type casts', () => {
    const code = 'virtualBaseTokenReserves = uint128(newReserve);';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('TYPE CASTS');
    expect(result).toContain('silently truncate');
  });

  it('detects execute/delegatecall patterns', () => {
    const code = 'function execute(address target, bytes calldata data) external { target.delegatecall(data); }';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('ARBITRARY EXECUTION');
  });

  it('detects ERC2981 royalty', () => {
    const code = '(address recipient, uint256 royaltyAmount) = IERC2981(nft).royaltyInfo(tokenId, price);';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('royaltyInfo');
    expect(result).toContain('excessive royalty');
  });

  it('detects ETH transfer to external addresses', () => {
    const code = '(bool success, ) = recipient.call{value: amount}("");';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('sends ETH');
    expect(result).toContain('reverts');
  });

  it('detects CREATE2 / deterministic deployment', () => {
    const code = 'address pool = Clones.cloneDeterministic(implementation, salt);';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('deterministic deployment');
  });

  it('detects ownership transfer logic', () => {
    const code = 'function transferOwnership(address newOwner) external onlyOwner {';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('OWNERSHIP');
  });

  it('detects zero-amount fee edge case', () => {
    const code = 'function changeFee(uint56 newFee) external { feeRate = newFee; }';
    const result = detectFileAnalysisHints(code);
    expect(result).toContain('FEE TRANSFER EDGE CASE');
  });

  it('returns multiple hints for complex files', () => {
    const code = [
      'uint256 protocolFee;',
      'function flashLoan(uint256 amount) external {',
      '  token.safeTransferFrom(msg.sender, address(this), amount);',
      '  uint128(newReserve);',
      '}',
    ].join('\n');
    const result = detectFileAnalysisHints(code);
    // Should have fee, flash loan, transfer, and type cast hints
    const hintCount = (result.match(/^- /gm) || []).length;
    expect(hintCount).toBeGreaterThanOrEqual(3);
  });
});

// --- extractFunctionInventory ---

describe('extractFunctionInventory', () => {
  it('returns empty for files with fewer than 3 functions', () => {
    const code = [
      'contract Foo {',
      '  function a() external {}',
      '  function b() external {}',
      '}',
    ].join('\n');
    expect(extractFunctionInventory(code)).toBe('');
  });

  it('extracts inventory for files with 3+ functions', () => {
    const code = [
      'contract Vault {',
      '  function deposit(uint256 amount) external {',
      '    balances[msg.sender] += amount;',
      '  }',
      '  function withdraw(uint256 amount) external {',
      '    balances[msg.sender] -= amount;',
      '  }',
      '  function getBalance(address user) external view returns (uint256) {',
      '    return balances[user];',
      '  }',
      '}',
    ].join('\n');
    const result = extractFunctionInventory(code);
    expect(result).toContain('deposit()');
    expect(result).toContain('withdraw()');
    expect(result).toContain('STATE-CHANGING');
  });

  it('categorizes view functions separately', () => {
    const code = [
      'contract Pool {',
      '  function swap(uint256 a) external {',
      '    x = 1;',
      '  }',
      '  function addLiquidity(uint256 a) external {',
      '    y = 1;',
      '  }',
      '  function getPrice() public view returns (uint256) {',
      '    return price;',
      '  }',
      '  function version() external pure returns (string memory) {',
      '    return "1.0";',
      '  }',
      '}',
    ].join('\n');
    const result = extractFunctionInventory(code);
    expect(result).toContain('swap()');
    expect(result).toContain('STATE-CHANGING');
    // getPrice should be flagged as computing prices
    expect(result).toContain('getPrice()');
    expect(result).toContain('COMPUTES PRICES/FEES');
  });

  it('skips comment lines that look like function declarations', () => {
    const code = [
      'contract Foo {',
      '  // function fakeFunc() external {}',
      '  function realA() external {}',
      '  function realB() external {}',
      '  function realC() external {}',
      '}',
    ].join('\n');
    const result = extractFunctionInventory(code);
    expect(result).not.toContain('fakeFunc');
    expect(result).toContain('realA');
  });

  it('detects critical view functions by name', () => {
    const code = [
      'contract Pool {',
      '  function swap(uint256 a) external {}',
      '  function buy(uint256 a) external {}',
      '  function sellQuote(uint256 a) public view returns (uint256) {}',
      '  function buyQuote(uint256 a) public view returns (uint256) {}',
      '  function feeRate() public view returns (uint256) {}',
      '}',
    ].join('\n');
    const result = extractFunctionInventory(code);
    expect(result).toContain('sellQuote()');
    expect(result).toContain('buyQuote()');
    expect(result).toContain('feeRate()');
    expect(result).toContain('COMPUTES PRICES/FEES');
  });
});

// --- identifyUncoveredFunctions ---

describe('identifyUncoveredFunctions', () => {
  const code = [
    'contract Vault {',
    '  function deposit(uint256 amount) external {', // line 2
    '    balances[msg.sender] += amount;',
    '  }',                                           // line 4
    '  function withdraw(uint256 amount) external {', // line 5
    '    balances[msg.sender] -= amount;',
    '    msg.sender.call{value: amount}("");',
    '  }',                                           // line 8
    '  function flashLoan(uint256 amount) external {', // line 9
    '    token.transfer(msg.sender, amount);',
    '  }',                                           // line 11
    '}',
  ].join('\n');

  it('returns all functions when no findings exist', () => {
    const result = identifyUncoveredFunctions(code, []);
    expect(result).toContain('deposit()');
    expect(result).toContain('withdraw()');
    expect(result).toContain('flashLoan()');
    expect(result).toContain('UNCOVERED');
  });

  it('excludes functions that have findings in their line range', () => {
    const findings = [makeFinding({ line: 6 })]; // Inside withdraw (lines 5-8)
    const result = identifyUncoveredFunctions(code, findings);
    expect(result).not.toContain('withdraw()');
    expect(result).toContain('deposit()');
    expect(result).toContain('flashLoan()');
  });

  it('returns empty string when all functions are covered', () => {
    const findings = [
      makeFinding({ line: 3 }),  // in deposit
      makeFinding({ line: 6 }),  // in withdraw
      makeFinding({ line: 10 }), // in flashLoan
    ];
    const result = identifyUncoveredFunctions(code, findings);
    expect(result).toBe('');
  });

  it('handles code with no functions', () => {
    const result = identifyUncoveredFunctions('uint256 x = 1;', []);
    expect(result).toBe('');
  });
});

// --- extractFunctionsWithBodies ---

describe('extractFunctionsWithBodies', () => {
  it('extracts functions with correct line ranges', () => {
    const code = [
      'contract Vault {',                              // line 1
      '  function deposit(uint256 amount) external {',  // line 2
      '    balances[msg.sender] += amount;',
      '  }',                                            // line 4
      '  function withdraw(uint256 amount) external {', // line 5
      '    balances[msg.sender] -= amount;',
      '  }',                                            // line 7
      '}',
    ].join('\n');
    const result = extractFunctionsWithBodies(code);
    expect(result.length).toBe(2);
    expect(result[0].name).toBe('deposit');
    expect(result[0].startLine).toBe(2);
    expect(result[0].endLine).toBe(4);
    expect(result[0].bodyLines).toBe(3);
    expect(result[1].name).toBe('withdraw');
    expect(result[1].startLine).toBe(5);
    expect(result[1].endLine).toBe(7);
  });

  it('detects visibility and mutability even for closely-spaced functions', () => {
    // Functions close together — context window should stop at opening brace
    const code = [
      'contract Foo {',
      '  function doThing() external {',
      '    x = 1;',
      '  }',
      '  function getVal() public view returns (uint256) {',
      '    return x;',
      '  }',
      '  function helper() internal pure returns (uint256) {',
      '    return 42;',
      '  }',
      '}',
    ].join('\n');
    const result = extractFunctionsWithBodies(code);
    expect(result[0].visibility).toBe('external');
    expect(result[0].mutability).toBe('mutable');
    expect(result[1].visibility).toBe('public');
    expect(result[1].mutability).toBe('view');
    expect(result[2].visibility).toBe('internal');
    expect(result[2].mutability).toBe('pure');
  });

  it('skips commented-out functions', () => {
    const code = [
      'contract Foo {',
      '  // function oldFunc() external {}',
      '  * function docFunc() external {}',
      '  function realFunc() external {',
      '    x = 1;',
      '  }',
      '}',
    ].join('\n');
    const result = extractFunctionsWithBodies(code);
    expect(result.length).toBe(1);
    expect(result[0].name).toBe('realFunc');
  });

  it('handles nested braces correctly', () => {
    const code = [
      'contract Foo {',
      '  function complex() external {',  // line 2
      '    if (x > 0) {',
      '      if (y > 0) {',
      '        z = 1;',
      '      }',
      '    }',
      '  }',                              // line 8
      '}',
    ].join('\n');
    const result = extractFunctionsWithBodies(code);
    expect(result.length).toBe(1);
    expect(result[0].startLine).toBe(2);
    expect(result[0].endLine).toBe(8);
    expect(result[0].bodyLines).toBe(7);
  });
});

// --- extractStateContext ---

describe('extractStateContext', () => {
  it('extracts imports, contract declaration, and state variables', () => {
    const code = [
      'import "@openzeppelin/contracts/token/ERC20/IERC20.sol";',
      'import "./interfaces/IPool.sol";',
      '',
      'contract Pool is ERC20, Ownable {',
      '  mapping(address => uint256) public balances;',
      '  address public owner;',
      '  bool public paused;',
      '',
      '  function deposit() external {',
      '    balances[msg.sender] += msg.value;',
      '  }',
      '}',
    ].join('\n');
    const result = extractStateContext(code);
    expect(result).toContain('import');
    expect(result).toContain('contract Pool');
    expect(result).toContain('mapping');
    expect(result).toContain('address public owner');
    expect(result).toContain('bool public paused');
  });

  it('caps output at 50 lines', () => {
    const lines = Array.from({ length: 100 }, (_, i) => `uint256 public var${i};`);
    const code = ['contract Big {', ...lines, '}'].join('\n');
    const result = extractStateContext(code);
    const outputLines = result.split('\n');
    expect(outputLines.length).toBeLessThanOrEqual(50);
  });

  it('captures uint256/int256 state variables (not just uint/int)', () => {
    const code = [
      'contract Foo {',
      '  uint256 public totalReserve;',
      '  int256 public delta;',
      '  uint128 public cached;',
      '}',
    ].join('\n');
    const result = extractStateContext(code);
    expect(result).toContain('uint256 public totalReserve');
    expect(result).toContain('int256 public delta');
    expect(result).toContain('uint128 public cached');
  });

  it('includes events, errors, modifiers', () => {
    const code = [
      'contract Foo {',
      '  event Transfer(address from, address to, uint256 amount);',
      '  error InsufficientBalance();',
      '  modifier onlyOwner() { require(msg.sender == owner); _; }',
      '}',
    ].join('\n');
    const result = extractStateContext(code);
    expect(result).toContain('event Transfer');
    expect(result).toContain('error InsufficientBalance');
    expect(result).toContain('modifier onlyOwner');
  });
});

// --- normalizeSeverity ---

describe('normalizeSeverity', () => {
  it('accepts valid severities', () => {
    expect(normalizeSeverity('critical')).toBe('critical');
    expect(normalizeSeverity('high')).toBe('high');
    expect(normalizeSeverity('medium')).toBe('medium');
    expect(normalizeSeverity('low')).toBe('low');
    expect(normalizeSeverity('info')).toBe('info');
  });

  it('normalizes case', () => {
    expect(normalizeSeverity('HIGH')).toBe('high');
    expect(normalizeSeverity('Critical')).toBe('critical');
    expect(normalizeSeverity('MEDIUM')).toBe('medium');
  });

  it('defaults to info for invalid values', () => {
    expect(normalizeSeverity('severe')).toBe('info');
    expect(normalizeSeverity(undefined)).toBe('info');
    expect(normalizeSeverity(null)).toBe('info');
    expect(normalizeSeverity(42)).toBe('info');
  });
});

// --- normalizeConfidence ---

describe('normalizeConfidence', () => {
  it('accepts valid confidences', () => {
    expect(normalizeConfidence('high')).toBe('high');
    expect(normalizeConfidence('medium')).toBe('medium');
    expect(normalizeConfidence('low')).toBe('low');
  });

  it('normalizes case', () => {
    expect(normalizeConfidence('HIGH')).toBe('high');
    expect(normalizeConfidence('Low')).toBe('low');
  });

  it('defaults to medium for invalid values', () => {
    expect(normalizeConfidence('very high')).toBe('medium');
    expect(normalizeConfidence(undefined)).toBe('medium');
    expect(normalizeConfidence(null)).toBe('medium');
  });
});
