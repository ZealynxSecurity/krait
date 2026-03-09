import { describe, it, expect } from 'vitest';
import { scoreFileComplexity, batchSmallFiles } from '../file-scorer.js';
import { FileInfo } from '../types.js';

function makeFile(overrides: Partial<FileInfo> = {}): FileInfo {
  return {
    path: '/tmp/test.sol',
    relativePath: 'test.sol',
    language: 'solidity',
    lines: 100,
    size: 3000,
    ...overrides,
  };
}

describe('scoreFileComplexity', () => {
  describe('scoring', () => {
    it('scores based on complexity signals', () => {
      const content = `
pragma solidity ^0.8.0;
contract Vault {
  mapping(address => uint256) public balances;
  uint256 public totalDeposits;

  function deposit() external payable {
    balances[msg.sender] += msg.value;
    totalDeposits += msg.value;
  }

  function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount);
    balances[msg.sender] -= amount;
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
  }
}`;
      const file = makeFile({ lines: 100 }); // Set lines >= 80 so it's not batched
      const score = scoreFileComplexity(file, content);

      expect(score.score).toBeGreaterThan(0);
      expect(score.details.externalCalls).toBeGreaterThanOrEqual(1);
      expect(score.details.stateVars).toBeGreaterThanOrEqual(1);
      expect(score.decision).toBe('analyze');
    });

    it('detects assembly blocks', () => {
      const content = `
contract Foo {
  function bar() external {
    assembly {
      mstore(0, 1)
    }
  }
}`;
      const file = makeFile({ lines: 8 });
      const score = scoreFileComplexity(file, content);
      expect(score.details.assemblyBlocks).toBe(1);
    });

    it('detects unchecked blocks', () => {
      const content = `
contract Foo {
  function bar() external {
    unchecked {
      uint256 x = type(uint256).max + 1;
    }
  }
}`;
      const file = makeFile({ lines: 8 });
      const score = scoreFileComplexity(file, content);
      expect(score.details.uncheckedBlocks).toBe(1);
    });
  });

  describe('skip rules', () => {
    it('skips pure interfaces', () => {
      const content = `
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface IVault {
  function deposit(uint256 amount) external;
  function withdraw(uint256 amount) external returns (uint256);
  function balanceOf(address user) external view returns (uint256);
}`;
      const file = makeFile({ lines: content.split('\n').length });
      const score = scoreFileComplexity(file, content);
      expect(score.decision).toBe('skip');
      expect(score.skipReason).toContain('interface');
    });

    it('does not skip interface with function bodies', () => {
      const content = `
interface IVault {
  function deposit(uint256 amount) external;
}

contract Vault is IVault {
  function deposit(uint256 amount) external {
    // implementation
  }
}`;
      const file = makeFile({ lines: content.split('\n').length });
      const score = scoreFileComplexity(file, content);
      expect(score.decision).not.toBe('skip');
    });

    it('skips pure view/pure libraries', () => {
      const content = `
library MathLib {
  function add(uint256 a, uint256 b) internal pure returns (uint256) {
    return a + b;
  }

  function mul(uint256 a, uint256 b) internal pure returns (uint256) {
    return a * b;
  }
}`;
      const file = makeFile({ lines: content.split('\n').length });
      const score = scoreFileComplexity(file, content);
      expect(score.decision).toBe('skip');
      expect(score.skipReason).toContain('library');
    });

    it('does not skip libraries with external calls', () => {
      const content = `
library TransferLib {
  function safeTransfer(address token, address to, uint256 amount) internal {
    (bool ok,) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, amount));
    require(ok);
  }
}`;
      const file = makeFile({ lines: content.split('\n').length });
      const score = scoreFileComplexity(file, content);
      expect(score.decision).not.toBe('skip');
    });
  });

  describe('batch decision', () => {
    it('marks small files (<80 LOC) for batching', () => {
      const content = `
contract Small {
  uint256 public value;
  function set(uint256 v) external { value = v; }
}`;
      const file = makeFile({ lines: 5 });
      const score = scoreFileComplexity(file, content);
      expect(score.decision).toBe('batch');
    });

    it('does not batch files >= 80 LOC', () => {
      // Use actual code lines, not comments, to avoid >90% comments skip
      const lines = Array.from({ length: 80 }, (_, i) => `  uint256 public var${i};`);
      const content = `contract Big {\n${lines.join('\n')}\n}`;
      const file = makeFile({ lines: 82 });
      const score = scoreFileComplexity(file, content);
      expect(score.decision).toBe('analyze');
    });
  });
});

describe('batchSmallFiles', () => {
  it('groups small files into batches', () => {
    const files = [
      makeFile({ relativePath: 'a.sol', lines: 50 }),
      makeFile({ relativePath: 'b.sol', lines: 60 }),
      makeFile({ relativePath: 'c.sol', lines: 40 }),
    ];
    const contents = new Map<string, string>();
    files.forEach(f => contents.set(f.relativePath, `// ${f.relativePath}`));

    const batches = batchSmallFiles(files, contents);
    expect(batches.length).toBeGreaterThanOrEqual(1);
    // First batch should have 2 files (50+60=110 < 200) or be capped at 3
    expect(batches[0].files.length).toBeLessThanOrEqual(3);
  });

  it('respects max 200 combined LOC', () => {
    const files = [
      makeFile({ relativePath: 'a.sol', lines: 150 }),
      makeFile({ relativePath: 'b.sol', lines: 70 }),
    ];
    const contents = new Map<string, string>();
    files.forEach(f => contents.set(f.relativePath, `// ${f.relativePath}`));

    const batches = batchSmallFiles(files, contents);
    // 150 + 70 = 220 > 200, so should be 2 batches
    expect(batches.length).toBe(2);
  });

  it('respects max 3 files per batch', () => {
    const files = Array.from({ length: 6 }, (_, i) =>
      makeFile({ relativePath: `f${i}.sol`, lines: 30 })
    );
    const contents = new Map<string, string>();
    files.forEach(f => contents.set(f.relativePath, `// ${f.relativePath}`));

    const batches = batchSmallFiles(files, contents);
    for (const batch of batches) {
      expect(batch.files.length).toBeLessThanOrEqual(3);
    }
  });

  it('handles empty input', () => {
    const batches = batchSmallFiles([], new Map());
    expect(batches).toHaveLength(0);
  });

  it('single file becomes single batch', () => {
    const files = [makeFile({ relativePath: 'only.sol', lines: 50 })];
    const contents = new Map<string, string>();
    contents.set('only.sol', '// only');

    const batches = batchSmallFiles(files, contents);
    expect(batches).toHaveLength(1);
    expect(batches[0].files).toHaveLength(1);
  });
});
