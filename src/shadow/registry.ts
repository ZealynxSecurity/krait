/**
 * Contest registry — curated list of past C4/Sherlock/CodeHawks contests
 * with known findings for benchmarking Krait's detection quality.
 */

export interface ContestEntry {
  id: string;                    // Unique identifier, e.g. "amphora-2023"
  name: string;                  // Human-readable name
  platform: 'code4rena' | 'sherlock' | 'codehawks';
  date: string;                  // YYYY-MM-DD
  domain: 'solidity' | 'rust-solana' | 'web2-typescript';
  sourceRepo: string;            // GitHub repo URL for source code
  sourcePath: string;            // Path within repo to audit target
  findingsRepo: string;          // GitHub repo URL for official findings
  expectedHighs: number;         // Known high-severity findings
  expectedMediums: number;       // Known medium-severity findings
  estimatedLOC: number;          // Approximate lines of code
  difficulty: 'small' | 'medium' | 'large';
  notes?: string;
}

/**
 * Curated registry of contests suitable for shadow auditing.
 * Selection criteria:
 * - Well-documented official findings with report.md
 * - Reasonable size (not too large for cost efficiency)
 * - Mix of vulnerability types
 * - DeFi/Solidity focus (primary domain)
 */
export const CONTEST_REGISTRY: ContestEntry[] = [
  // === Already cloned and validated ===
  {
    id: 'amphora-2023-07',
    name: 'Amphora Protocol',
    platform: 'code4rena',
    date: '2023-07-21',
    domain: 'solidity',
    sourceRepo: 'https://github.com/code-423n4/2023-07-amphora',
    sourcePath: 'core/solidity/contracts',
    findingsRepo: 'https://github.com/code-423n4/2023-07-amphora-findings',
    expectedHighs: 3,
    expectedMediums: 3,
    estimatedLOC: 4600,
    difficulty: 'medium',
    notes: 'Lending protocol. Reentrancy, rounding errors, operator changes.',
  },
  {
    id: 'caviar-2023-04',
    name: 'Caviar Private Pools',
    platform: 'code4rena',
    date: '2023-04-07',
    domain: 'solidity',
    sourceRepo: 'https://github.com/code-423n4/2023-04-caviar',
    sourcePath: 'src',
    findingsRepo: 'https://github.com/code-423n4/2023-04-caviar-findings',
    expectedHighs: 3,
    expectedMediums: 17,
    estimatedLOC: 850,
    difficulty: 'small',
    notes: 'NFT AMM. Price manipulation, access control, flash loan vectors.',
  },
  {
    id: 'salty-2024-01',
    name: 'Salty.IO',
    platform: 'code4rena',
    date: '2024-01-16',
    domain: 'solidity',
    sourceRepo: 'https://github.com/code-423n4/2024-01-salty',
    sourcePath: 'src',
    findingsRepo: 'https://github.com/code-423n4/2024-01-salty-findings',
    expectedHighs: 6,
    expectedMediums: 31,
    estimatedLOC: 7200,
    difficulty: 'large',
    notes: 'DEX with staking. Numerous price manipulation and governance issues.',
  },

  // === New contests to add for broader benchmarking ===
  {
    id: 'basin-2023-07',
    name: 'Basin',
    platform: 'code4rena',
    date: '2023-07-03',
    domain: 'solidity',
    sourceRepo: 'https://github.com/code-423n4/2023-07-basin',
    sourcePath: 'src',
    findingsRepo: 'https://github.com/code-423n4/2023-07-basin-findings',
    expectedHighs: 3,
    expectedMediums: 9,
    estimatedLOC: 1500,
    difficulty: 'small',
    notes: 'DEX/AMM. Well scoped, good for testing oracle and AMM patterns.',
  },
  {
    id: 'ondo-2023-01',
    name: 'Ondo Finance',
    platform: 'code4rena',
    date: '2023-01-10',
    domain: 'solidity',
    sourceRepo: 'https://github.com/code-423n4/2023-01-ondo',
    sourcePath: 'contracts',
    findingsRepo: 'https://github.com/code-423n4/2023-01-ondo-findings',
    expectedHighs: 1,
    expectedMediums: 5,
    estimatedLOC: 2000,
    difficulty: 'medium',
    notes: 'RWA tokenization. Access control, flash loan, oracle patterns.',
  },
  {
    id: 'pooltogether-2023-07',
    name: 'PoolTogether',
    platform: 'code4rena',
    date: '2023-07-07',
    domain: 'solidity',
    sourceRepo: 'https://github.com/code-423n4/2023-07-pooltogether',
    sourcePath: 'src',
    findingsRepo: 'https://github.com/code-423n4/2023-07-pooltogether-findings',
    expectedHighs: 2,
    expectedMediums: 14,
    estimatedLOC: 2500,
    difficulty: 'medium',
    notes: 'Prize savings protocol. Vault, liquidation, TWAB patterns.',
  },
];

export function getContestById(id: string): ContestEntry | undefined {
  return CONTEST_REGISTRY.find(c => c.id === id);
}

export function getContestsByDifficulty(difficulty: ContestEntry['difficulty']): ContestEntry[] {
  return CONTEST_REGISTRY.filter(c => c.difficulty === difficulty);
}

export function listContests(): ContestEntry[] {
  return [...CONTEST_REGISTRY];
}
