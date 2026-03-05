/**
 * Protocol-specific vulnerability checklists.
 * These are injected into the AI system prompt to focus Claude's analysis
 * on the most relevant attack vectors for the protocol type.
 */

interface ChecklistEntry {
  area: string;
  checks: string[];
}

const DEX_AMM: ChecklistEntry[] = [
  {
    area: 'Price Manipulation',
    checks: [
      'Can spot price be manipulated via flash loans (e.g., using slot0/getReserves in the same tx)?',
      'Is TWAP used instead of spot price for critical calculations?',
      'Can sandwich attacks extract value from swaps?',
    ],
  },
  {
    area: 'Liquidity Accounting',
    checks: [
      'Are LP token minting/burning calculations correct (first depositor attack)?',
      'Can rounding errors in share calculations be exploited repeatedly?',
      'Fee-on-transfer tokens: does the pool account for actual received amounts?',
    ],
  },
  {
    area: 'Slippage & MEV',
    checks: [
      'Is there a deadline parameter on swaps? Can stale transactions be executed?',
      'Is minimum output enforced? Can it be set to 0?',
      'Can permissionless functions be front-run to extract value?',
    ],
  },
];

const LENDING: ChecklistEntry[] = [
  {
    area: 'Oracle & Pricing',
    checks: [
      'Can the oracle be manipulated to create bad debt (flash loan → inflate collateral → borrow → deflate)?',
      'Is there a stale price check? What happens if the oracle goes down?',
      'Are different decimals handled correctly between collateral and borrow tokens?',
    ],
  },
  {
    area: 'Liquidation Logic',
    checks: [
      'Can a liquidator liquidate more than they should (liquidation bonus calculation)?',
      'Can a user self-liquidate to avoid proper liquidation penalty?',
      'Can a user front-run liquidation to reduce their exposure?',
      'What happens when collateral value drops faster than liquidation can occur (bad debt)?',
    ],
  },
  {
    area: 'Interest Rate & Accounting',
    checks: [
      'Are interest calculations rounded in the protocol\'s favor?',
      'Can a user deposit/withdraw in the same block to avoid interest?',
      'Is the exchange rate (cToken model) manipulable via donation attacks?',
    ],
  },
];

const STABLECOIN: ChecklistEntry[] = [
  {
    area: 'Peg Mechanism',
    checks: [
      'Can the mint/redeem mechanism be exploited to extract value during depeg events?',
      'Is the collateral ratio correctly enforced? Can undercollateralized minting occur?',
      'Can flash loans be used to temporarily meet collateral requirements?',
    ],
  },
  {
    area: 'Liquidation & Bad Debt',
    checks: [
      'Can cascading liquidations cause a death spiral?',
      'Is there a mechanism to handle bad debt? Can it be gamed?',
      'Are liquidation incentives properly aligned?',
    ],
  },
];

const YIELD_VAULT: ChecklistEntry[] = [
  {
    area: 'Share Accounting',
    checks: [
      'First depositor attack: can the first depositor inflate share price to steal from subsequent depositors?',
      'Are deposit/withdraw conversions (assets ↔ shares) rounded correctly (down on deposit, up on withdraw)?',
      'Can donation attacks (sending tokens directly to vault) manipulate share price?',
    ],
  },
  {
    area: 'Strategy & Harvest',
    checks: [
      'Can harvest/compound be called in a way that benefits the caller at others\' expense?',
      'Are strategy returns validated? Can a compromised strategy drain the vault?',
      'Is there a withdrawal queue? Can it be front-run?',
    ],
  },
];

const GOVERNANCE_DAO: ChecklistEntry[] = [
  {
    area: 'Voting & Proposals',
    checks: [
      'Flash loan governance: can someone borrow tokens, vote, and return in one tx?',
      'Is the snapshot mechanism correct? Can voting power be double-counted?',
      'Can proposals be created and executed in a way that bypasses intended timelock?',
    ],
  },
  {
    area: 'Execution',
    checks: [
      'Can a proposal be executed multiple times?',
      'Can proposal execution be front-run or sandwiched?',
      'Are delegated votes properly tracked and can they be manipulated?',
    ],
  },
];

const NFT_MARKETPLACE: ChecklistEntry[] = [
  {
    area: 'Order & Auction Logic',
    checks: [
      'Can orders be replayed (missing nonce/expiry)?',
      'Can bids be front-run or canceled at the last moment?',
      'Are royalties correctly calculated and paid? Can they be bypassed?',
    ],
  },
  {
    area: 'Token Handling',
    checks: [
      'ERC721 vs ERC1155: are both handled correctly?',
      'Can ERC721 onReceived hooks cause reentrancy?',
      'Are token approvals properly scoped and revoked?',
    ],
  },
];

const ORACLE: ChecklistEntry[] = [
  {
    area: 'Data Freshness',
    checks: [
      'Is there a staleness check on oracle data (roundId, updatedAt)?',
      'What happens when the oracle returns a zero or negative price?',
      'Is the L2 sequencer uptime feed checked (for L2 deployments)?',
    ],
  },
  {
    area: 'Manipulation Resistance',
    checks: [
      'Can the oracle be manipulated within a single block/transaction?',
      'Is TWAP used with a sufficient window (>= 30 minutes)?',
      'Are multiple oracle sources used with a fallback mechanism?',
    ],
  },
];

const STAKING: ChecklistEntry[] = [
  {
    area: 'Reward Calculation',
    checks: [
      'Can rewards be gamed by staking/unstaking around distribution events?',
      'Are reward calculations correct with different decimal tokens?',
      'Can dust amounts cause precision loss in reward distribution?',
    ],
  },
  {
    area: 'Unstaking & Withdrawal',
    checks: [
      'Is the unbonding period enforced correctly? Can it be bypassed?',
      'Can a user claim rewards multiple times for the same period?',
      'What happens if the reward token is also the staking token?',
    ],
  },
];

// Dependency-specific checks
const CHAINLINK_CHECKS = [
  '**Chainlink-specific**: Check for stale price (updatedAt + heartbeat < block.timestamp)',
  '**Chainlink-specific**: Check for zero/negative price (answer <= 0)',
  '**Chainlink-specific**: Verify roundId completeness (answeredInRound >= roundId)',
  '**Chainlink-specific**: L2 sequencer uptime feed check if on Arbitrum/Optimism',
];

const UNISWAP_CHECKS = [
  '**Uniswap-specific**: slot0.sqrtPriceX96 is manipulable — NEVER use as oracle',
  '**Uniswap-specific**: Use TWAP (observe()) instead of spot price for any pricing',
  '**Uniswap-specific**: Check for price impact and slippage protection on swaps',
  '**Uniswap-specific**: Tick rounding can cause value extraction on concentrated liquidity positions',
];

const PROTOCOL_MAP: Record<string, ChecklistEntry[]> = {
  'dex': DEX_AMM,
  'amm': DEX_AMM,
  'swap': DEX_AMM,
  'decentralized exchange': DEX_AMM,
  'lending': LENDING,
  'borrowing': LENDING,
  'stablecoin': STABLECOIN,
  'yield': YIELD_VAULT,
  'vault': YIELD_VAULT,
  'erc4626': YIELD_VAULT,
  'governance': GOVERNANCE_DAO,
  'dao': GOVERNANCE_DAO,
  'nft': NFT_MARKETPLACE,
  'marketplace': NFT_MARKETPLACE,
  'oracle': ORACLE,
  'staking': STAKING,
  'stake': STAKING,
};

/**
 * Get a protocol-specific vulnerability checklist based on protocol type and dependencies.
 */
export function getProtocolChecklist(protocolType: string, dependencies: string[]): string {
  const sections: string[] = [];
  const typeLower = protocolType.toLowerCase();

  // Match protocol type to checklists
  const matched = new Set<ChecklistEntry[]>();
  for (const [keyword, checklist] of Object.entries(PROTOCOL_MAP)) {
    if (typeLower.includes(keyword)) {
      matched.add(checklist);
    }
  }

  if (matched.size === 0) return '';

  sections.push('## Protocol-Specific Vulnerability Checklist');
  sections.push('These checks are especially relevant for this type of protocol. Prioritize looking for these patterns:\n');

  for (const checklist of matched) {
    for (const entry of checklist) {
      sections.push(`### ${entry.area}`);
      for (const check of entry.checks) {
        sections.push(`- ${check}`);
      }
      sections.push('');
    }
  }

  // Dependency-specific checks
  const depsLower = dependencies.map(d => d.toLowerCase());
  if (depsLower.some(d => d.includes('chainlink'))) {
    sections.push('### Chainlink Integration Checks');
    for (const check of CHAINLINK_CHECKS) {
      sections.push(`- ${check}`);
    }
    sections.push('');
  }

  if (depsLower.some(d => d.includes('uniswap'))) {
    sections.push('### Uniswap Integration Checks');
    for (const check of UNISWAP_CHECKS) {
      sections.push(`- ${check}`);
    }
    sections.push('');
  }

  return sections.join('\n');
}
