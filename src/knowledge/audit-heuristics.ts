/**
 * Audit heuristics — compact trigger-response rules from real exploits.
 * These fill the GAP between generic YAML patterns and protocol-specific logic bugs.
 *
 * Sources: DeFiHackLabs (184 PoCs), Coinspect learn-evm-attacks (45 reproductions),
 * real audit reports from C4/Sherlock/CodeHawks.
 */

export interface AuditHeuristic {
  id: string;
  trigger: string;
  triggerKeywords: string[];
  check: string;
  category: string;
  severity: 'high' | 'medium';
  source?: string;
}

/**
 * 40 heuristics covering gap categories with 0 patterns today.
 */
export const AUDIT_HEURISTICS: AuditHeuristic[] = [
  // === Business Logic Flaws (multi-step process bugs) ===
  {
    id: 'BL-01',
    trigger: 'Multi-step process (deposit + stake, borrow + repay, create + finalize)',
    triggerKeywords: ['deposit', 'stake', 'finalize', 'commit', 'execute', 'settle', 'complete'],
    check: 'Can steps be called out of order? Can step 2 be called without step 1? Does partial execution leave inconsistent state?',
    category: 'business-logic',
    severity: 'high',
    source: 'DeFiHackLabs: Yearn V1, Harvest Finance',
  },
  {
    id: 'BL-02',
    trigger: 'State machine with multiple states/phases',
    triggerKeywords: ['state', 'phase', 'status', 'stage', 'enum', 'pending', 'active', 'closed'],
    check: 'Can state transitions be skipped or reversed? Can functions be called in wrong state? Is there a stuck state with no exit?',
    category: 'business-logic',
    severity: 'high',
  },
  {
    id: 'BL-03',
    trigger: 'Accounting with multiple balance sources (internal mapping + actual token balance)',
    triggerKeywords: ['balanceOf', 'totalSupply', 'mapping', 'balance', 'accounting', 'internal'],
    check: 'Can internal accounting diverge from actual token balance? Does a direct transfer (not through deposit function) break accounting? Donation attack?',
    category: 'business-logic',
    severity: 'high',
    source: 'DeFiHackLabs: multiple vault exploits',
  },
  {
    id: 'BL-04',
    trigger: 'Reward/yield distribution with staking or time-based accrual',
    triggerKeywords: ['reward', 'rewardPerToken', 'earned', 'accrue', 'yield', 'distribute', 'claim'],
    check: 'Can a user stake just before reward distribution and claim disproportionate rewards? Can rewards be double-claimed? Does unstake + restake reset or preserve rewards?',
    category: 'business-logic',
    severity: 'high',
    source: 'C4: multiple reward distribution bugs',
  },
  {
    id: 'BL-05',
    trigger: 'Auction or time-locked mechanism',
    triggerKeywords: ['auction', 'bid', 'deadline', 'expiry', 'timeout', 'timelock', 'cooldown'],
    check: 'Can the auction be griefed by last-second bids? Can expired items still be executed? Does block.timestamp manipulation affect outcomes?',
    category: 'business-logic',
    severity: 'medium',
  },
  {
    id: 'BL-06',
    trigger: 'Whitelist/blacklist with transfer restrictions',
    triggerKeywords: ['whitelist', 'blacklist', 'allowlist', 'denylist', 'blocked', 'restricted', 'frozen'],
    check: 'Can a blocked address transfer through an intermediary? Does restriction apply on both sender AND receiver? Can an attacker grief by getting a recipient blocked?',
    category: 'business-logic',
    severity: 'medium',
  },
  {
    id: 'BL-07',
    trigger: 'Liquidation mechanism',
    triggerKeywords: ['liquidat', 'underwater', 'collateral', 'health', 'insolvent', 'seize'],
    check: 'Can a liquidator extract more value than the underwater amount? Can self-liquidation be profitable? Can oracle manipulation trigger unwarranted liquidations?',
    category: 'business-logic',
    severity: 'high',
    source: 'DeFiHackLabs: Venus, Compound forks',
  },
  {
    id: 'BL-08',
    trigger: 'Withdrawal queue or delayed withdrawal',
    triggerKeywords: ['queue', 'pending', 'request', 'withdrawal', 'redeem', 'epoch', 'round'],
    check: 'Can a user front-run the queue? Can pending withdrawals be canceled by admin action? Is the exchange rate locked at request time or fulfillment time?',
    category: 'business-logic',
    severity: 'medium',
  },
  {
    id: 'BL-09',
    trigger: 'Fee-on-transfer or rebasing token interaction',
    triggerKeywords: ['transfer', 'transferFrom', 'amount', 'received', 'balance'],
    check: 'Does the contract assume amount sent == amount received? For rebasing tokens, does cached balance become stale? Is balanceOf checked before AND after transfer?',
    category: 'business-logic',
    severity: 'high',
    source: 'DeFiHackLabs: STA token, multiple',
  },
  {
    id: 'BL-10',
    trigger: 'First depositor or empty pool scenario (ERC4626 / share-based vaults)',
    triggerKeywords: ['convertToShares', 'convertToAssets', 'totalAssets', 'previewDeposit', 'previewMint', 'ERC4626'],
    check: 'Can the first depositor inflate share price by donating tokens? Is there a minimum deposit or virtual offset to prevent share inflation? What happens when pool is empty? NOTE: Only report if the code LACKS virtual offset protection (e.g., OpenZeppelin _decimalsOffset).',
    category: 'business-logic',
    severity: 'high',
    source: 'C4: ERC4626 vault inflation attacks',
  },
  {
    id: 'BL-11',
    trigger: 'Voting or governance with token-weighted power',
    triggerKeywords: ['vote', 'proposal', 'quorum', 'governance', 'delegate', 'snapshot'],
    check: 'Can flash-loaned tokens be used to vote? Is voting power snapshotted at proposal creation or vote time? Can a user vote, transfer tokens, vote again from another address?',
    category: 'business-logic',
    severity: 'high',
    source: 'DeFiHackLabs: Beanstalk governance attack',
  },
  {
    id: 'BL-12',
    trigger: 'Cross-chain or bridge message',
    triggerKeywords: ['bridge', 'cross-chain', 'layerzero', 'ccip', 'wormhole', 'message', 'relay'],
    check: 'Can the message be replayed on another chain? Is the source chain verified? Can a failed message leave tokens locked with no recovery?',
    category: 'business-logic',
    severity: 'high',
  },

  // === Arbitrary External Call ===
  {
    id: 'AEC-01',
    trigger: 'User-controlled call target or calldata',
    triggerKeywords: ['call(', '.call{', 'delegatecall', 'staticcall', 'target', 'data', 'payload'],
    check: 'Can the user set the call target to a token contract and drain approved tokens? Can they call selfdestruct? Is the target restricted to a whitelist?',
    category: 'arbitrary-call',
    severity: 'high',
    source: 'DeFiHackLabs: 7 incidents',
  },
  {
    id: 'AEC-02',
    trigger: 'Callback to user-supplied address after state change',
    triggerKeywords: ['callback', 'hook', 'notify', 'onReceived', 'onFlash', 'receiver'],
    check: 'Is state fully updated BEFORE the callback? Can the callback re-enter and exploit stale state? Can the callback revert to grief the transaction?',
    category: 'arbitrary-call',
    severity: 'high',
    source: 'DeFiHackLabs: multiple callback exploits',
  },
  {
    id: 'AEC-03',
    trigger: 'Multicall or batch execution pattern',
    triggerKeywords: ['multicall', 'batch', 'aggregate', 'execute', 'payable'],
    check: 'Can msg.value be reused across multiple calls in the batch? Can a user combine calls to bypass individual function restrictions?',
    category: 'arbitrary-call',
    severity: 'high',
    source: 'C4: Multicall msg.value reuse',
  },

  // === Read-Only Reentrancy ===
  {
    id: 'ROR-01',
    trigger: 'View function reading pool/vault state used by other protocols',
    triggerKeywords: ['getPrice', 'getRate', 'totalAssets', 'exchangeRate', 'getReserves', 'slot0'],
    check: 'During an external call in a state-changing function, can an attacker call this view function and get a stale/manipulated value? Are other protocols reading this during a callback window?',
    category: 'read-only-reentrancy',
    severity: 'high',
    source: 'DeFiHackLabs: Curve read-only reentrancy',
  },

  // === Proxy / Upgrade Bugs ===
  {
    id: 'PRX-01',
    trigger: 'Upgradeable proxy or initializer pattern',
    triggerKeywords: ['initializ', 'proxy', 'upgradeable', 'UUPS', 'transparent', 'beacon', '_disableInitializers'],
    check: 'Is `_disableInitializers()` called in the constructor? Can the implementation contract be initialized directly? Can a re-initialization overwrite state?',
    category: 'proxy',
    severity: 'high',
    source: 'Coinspect: proxy re-initialization',
  },
  {
    id: 'PRX-02',
    trigger: 'Delegatecall with storage layout',
    triggerKeywords: ['delegatecall', 'proxy', 'implementation', 'storage', 'slot'],
    check: 'Does the proxy and implementation have matching storage layouts? Can a storage collision corrupt critical state? Is there a gap array for future storage slots?',
    category: 'proxy',
    severity: 'high',
    source: 'Coinspect: storage collision',
  },

  // === Share Inflation / First Depositor ===
  {
    id: 'SI-01',
    trigger: 'ERC4626 vault or share-based accounting',
    triggerKeywords: ['ERC4626', 'convertToShares', 'convertToAssets', 'previewDeposit', 'previewMint', 'totalAssets'],
    check: 'Is there virtual offset (OpenZeppelin style) to prevent first-depositor inflation? Can an attacker donate to inflate share price and make small deposits round to 0 shares?',
    category: 'share-inflation',
    severity: 'high',
    source: 'C4/Sherlock: 20+ ERC4626 inflation findings',
  },

  // === Fee Double-Counting ===
  {
    id: 'FDC-01',
    trigger: 'Sequential fee deductions in same function',
    triggerKeywords: ['fee', 'protocolFee', 'platformFee', 'royalty', 'commission', 'deduct'],
    check: 'Is each fee calculated on the REMAINING amount after previous deductions? Or does each use the original amount (double-counting)? Are fees bounded to prevent >100% total?',
    category: 'fee-logic',
    severity: 'high',
  },
  {
    id: 'FDC-02',
    trigger: 'Fee calculation with different denomination/precision',
    triggerKeywords: ['bps', 'basis', 'percent', 'denominator', 'WAD', '1e18', '10000'],
    check: 'Is the fee denominator consistent (bps=10000, percent=100, WAD=1e18)? Does division before multiplication lose precision? Is rounding direction safe (round fee up, user amount down)?',
    category: 'fee-logic',
    severity: 'medium',
  },

  // === Transient Storage (EIP-1153) ===
  {
    id: 'TS-01',
    trigger: 'TSTORE/TLOAD or transient keyword usage',
    triggerKeywords: ['tstore', 'tload', 'transient', 'assembly'],
    check: 'Is transient storage cleared after the transaction ends as expected? Can a multicall within the same tx exploit stale transient values? Does it properly replace reentrancy guards?',
    category: 'transient-storage',
    severity: 'medium',
  },

  // === Missing Return Value Check ===
  {
    id: 'MRV-01',
    trigger: 'ERC20 transfer/approve without return value check',
    triggerKeywords: ['transfer(', 'approve(', 'transferFrom(', '.transfer(', '.approve('],
    check: 'Does the code use `safeTransfer`/`safeApprove` or check the return value? Some tokens (USDT) do not return bool. Unchecked calls silently fail.',
    category: 'missing-return-check',
    severity: 'medium',
    source: 'Coinspect: unsafe ERC20 interactions',
  },

  // === Oracle Manipulation ===
  {
    id: 'ORC-01',
    trigger: 'Spot price from AMM used for valuation or liquidation',
    triggerKeywords: ['getReserves', 'slot0', 'sqrtPrice', 'spot', 'price', 'balanceOf'],
    check: 'Is the price a spot price that can be manipulated in a single tx via flash loan? Should it use TWAP instead? Can the oracle be sandwiched?',
    category: 'oracle-manipulation',
    severity: 'high',
    source: 'DeFiHackLabs: 15+ oracle manipulation exploits',
  },
  {
    id: 'ORC-02',
    trigger: 'Chainlink oracle without staleness check',
    triggerKeywords: ['latestRoundData', 'chainlink', 'priceFeed', 'oracle', 'aggregator'],
    check: 'Is there a staleness check (updatedAt + heartbeat > block.timestamp)? Is the price checked for zero or negative? Is roundId validated? Is there a fallback oracle?',
    category: 'oracle-manipulation',
    severity: 'medium',
    source: 'C4/Sherlock: Chainlink staleness findings',
  },

  // === Signature / Permit Bugs ===
  {
    id: 'SIG-01',
    trigger: 'EIP-712 signature or permit pattern',
    triggerKeywords: ['permit', 'ecrecover', 'signature', 'v, r, s', 'nonce', 'deadline', 'DOMAIN_SEPARATOR'],
    check: 'Is there replay protection (nonce or deadline)? Is chainId included in the domain separator? Can signatures be used on other contracts with the same domain? Does ecrecover handle address(0)?',
    category: 'signature',
    severity: 'high',
  },
  {
    id: 'SIG-02',
    trigger: 'Permit2 or token approval with deadline',
    triggerKeywords: ['permit2', 'SignatureTransfer', 'AllowanceTransfer', 'PermitSingle'],
    check: 'Can a signature be front-run and used by a different caller? Is the permit nonce invalidated after use? Can an attacker grief by submitting the permit before the intended tx?',
    category: 'signature',
    severity: 'medium',
  },

  // === ETH Handling ===
  {
    id: 'ETH-01',
    trigger: 'Payable function that handles ETH',
    triggerKeywords: ['payable', 'msg.value', 'value:', '{value:', 'receive()', 'fallback()'],
    check: 'Is msg.value checked against the expected payment? Can excess ETH be locked? Is ETH refunded if the tx partially fails? Can forceSend via selfdestruct break accounting?',
    category: 'eth-handling',
    severity: 'medium',
  },
  {
    id: 'ETH-02',
    trigger: 'ETH sent to external address (not WETH wrap)',
    triggerKeywords: ['.call{value', '.transfer(', '.send(', 'recipient', 'receiver'],
    check: 'What if the recipient is a contract without receive()? Does the revert brick the entire function? Should it use WETH wrap-and-transfer instead of raw ETH?',
    category: 'eth-handling',
    severity: 'medium',
    source: 'C4: ETH transfer to contract without receive()',
  },

  // === Access Control Subtleties ===
  {
    id: 'AC-01',
    trigger: 'Role-based access with multiple privileged roles',
    triggerKeywords: ['role', 'ADMIN', 'MINTER', 'PAUSER', 'grantRole', 'hasRole', 'AccessControl'],
    check: 'Can one role escalate to another? Is there a role admin that can grant critical roles? Can a compromised non-critical role cause fund loss?',
    category: 'access-control',
    severity: 'medium',
  },
  {
    id: 'AC-02',
    trigger: 'Two-step ownership transfer',
    triggerKeywords: ['transferOwnership', 'acceptOwnership', 'pendingOwner', 'Ownable2Step'],
    check: 'If NOT using two-step transfer, can ownership be sent to wrong address permanently? If using two-step, can pending owner be griefed?',
    category: 'access-control',
    severity: 'medium',
  },

  // === Token Standard Edge Cases ===
  {
    id: 'TOK-01',
    trigger: 'ERC721/ERC1155 with hooks',
    triggerKeywords: ['safeTransferFrom', 'onERC721Received', 'onERC1155Received', '_safeMint', 'safeMint'],
    check: 'The safe* functions call onReceived hooks on the recipient. Can the recipient re-enter during the callback? Is state fully updated before the safe transfer?',
    category: 'token-hooks',
    severity: 'high',
    source: 'Coinspect: NFT callback reentrancy',
  },
  {
    id: 'TOK-02',
    trigger: 'Token with non-standard decimals',
    triggerKeywords: ['decimals', 'USDC', 'USDT', 'WBTC', '1e6', '1e8'],
    check: 'Does the code assume 18 decimals? With 6-decimal tokens (USDC), small amounts round to zero. With 8-decimal tokens (WBTC), precision loss accumulates differently.',
    category: 'token-edge-case',
    severity: 'medium',
  },

  // === Flash Loan Specific ===
  {
    id: 'FL-01',
    trigger: 'Function that reads balanceOf for accounting (not using internal tracking)',
    triggerKeywords: ['balanceOf', 'balance', 'reserve', 'sync'],
    check: 'Can an attacker flash-loan tokens into the contract to manipulate balanceOf-based calculations? Does a flash loan + deposit/swap exploit the pricing?',
    category: 'flash-loan',
    severity: 'high',
    source: 'DeFiHackLabs: multiple balance manipulation exploits',
  },

  // === CREATE2 / Deterministic Deployment ===
  {
    id: 'C2-01',
    trigger: 'CREATE2 or CloneDeterministic deployment',
    triggerKeywords: ['create2', 'cloneDeterministic', 'salt', 'predictDeterministicAddress'],
    check: 'Can an attacker deploy a contract at the predicted address before the intended deployment? After destruction + redeployment, is the storage reset correctly?',
    category: 'create2',
    severity: 'medium',
    source: 'DeFiHackLabs: Tornado Cash Governance',
  },

  // === Reentrancy (specific patterns not covered by generic guard) ===
  {
    id: 'RE-01',
    trigger: 'Cross-function reentrancy (lock protects one function but not another)',
    triggerKeywords: ['nonReentrant', 'ReentrancyGuard', 'locked', 'mutex', 'external'],
    check: 'If function A has nonReentrant but function B does not, can re-entering B during A\'s external call exploit shared state? Are ALL state-changing functions protected?',
    category: 'reentrancy',
    severity: 'high',
    source: 'Coinspect: cross-function reentrancy',
  },

  // === Precision and Rounding ===
  {
    id: 'PR-01',
    trigger: 'Division that could round to zero for small amounts',
    triggerKeywords: ['/', 'div', 'mulDiv', 'fullMul', 'muldiv'],
    check: 'For small input amounts, does division round to zero? Can an attacker make many small transactions where each rounds in their favor, accumulating profit?',
    category: 'precision',
    severity: 'medium',
  },
  {
    id: 'PR-02',
    trigger: 'Price or exchange rate stored as integer ratio',
    triggerKeywords: ['price', 'rate', 'ratio', 'exchange', 'convert'],
    check: 'Does the conversion round in the protocol\'s favor (up for debt, down for collateral)? Can manipulation of one side of the ratio cause disproportionate changes?',
    category: 'precision',
    severity: 'medium',
  },
  {
    id: 'PR-03',
    trigger: 'Dual conversion functions (assets→shares AND shares→assets, wrap↔unwrap)',
    triggerKeywords: ['mint', 'burn', 'wrap', 'unwrap', 'deposit', 'withdraw', 'totalSupply'],
    check: 'Do the two conversion directions round in OPPOSITE directions? deposit/wrap should round DOWN shares received (user gets less), mint/unwrap should round UP cost (user pays more). If BOTH use floor division, attacker can mint(1 wei) paying 0 and extract value via repeated small txs. This is DIFFERENT from first-depositor inflation.',
    category: 'precision',
    severity: 'high',
    source: 'C4: Amphora H-03 WUSDA rounding, multiple ERC4626 rounding bugs',
  },
];

/**
 * Get heuristics relevant to a file based on keyword matching.
 * Returns top 10 scored by keyword match count.
 */
export function getHeuristicsForFile(content: string): AuditHeuristic[] {
  const lower = content.toLowerCase();

  const scored = AUDIT_HEURISTICS.map(h => {
    const matchCount = h.triggerKeywords.reduce((count, kw) => {
      return count + (lower.includes(kw.toLowerCase()) ? 1 : 0);
    }, 0);
    return { heuristic: h, score: matchCount };
  });

  return scored
    .filter(s => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, 10)
    .map(s => s.heuristic);
}

/**
 * Format heuristics for inclusion in system prompt.
 * Compact format: ~3 lines per heuristic.
 */
export function formatHeuristicsForPrompt(heuristics: AuditHeuristic[]): string {
  if (heuristics.length === 0) return '';

  const lines = ['## Audit Heuristics (from real exploits — check these specifically):\n'];
  for (const h of heuristics) {
    const source = h.source ? ` (${h.source})` : '';
    lines.push(`- **[${h.id}] ${h.trigger}**: ${h.check}${source}`);
  }
  return lines.join('\n');
}
