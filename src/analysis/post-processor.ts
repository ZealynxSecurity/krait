import { Finding, FileInfo } from '../core/types.js';
import { ProjectContext } from './context-gatherer.js';
import { SoloditClient } from '../knowledge/solodit-client.js';

/**
 * Post-process findings with domain-specific heuristics to reduce false positives
 * and adjust confidence scores.
 */
export function postProcessFindings(
  findings: Finding[],
  files: FileInfo[],
  fileContents: Map<string, string>,
  projectContext?: ProjectContext
): Finding[] {
  let processed = findings
    .map(f => {
      try {
        return adjustConfidence(f, fileContents, projectContext);
      } catch {
        return f; // Return unmodified if adjustment fails
      }
    })
    .filter(f => {
      try {
        return !isFalsePositive(f, fileContents, projectContext);
      } catch {
        return true; // Keep if FP check fails
      }
    });

  // Per-file finding cap for large codebases
  // Keeps top findings by severity, drops low-confidence excess
  if (files.length > 15) {
    processed = capFindingsPerFile(processed, 2);
  } else if (files.length > 10) {
    processed = capFindingsPerFile(processed, 3);
  }

  return processed;
}

/**
 * Cap findings per file to limit noise on large codebases.
 * Keeps the highest-severity findings, drops low-confidence ones first.
 */
function capFindingsPerFile(findings: Finding[], maxPerFile: number): Finding[] {
  const byFile = new Map<string, Finding[]>();
  for (const f of findings) {
    const arr = byFile.get(f.file) || [];
    arr.push(f);
    byFile.set(f.file, arr);
  }

  const sevOrder: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  const confOrder: Record<string, number> = { high: 0, medium: 1, low: 2 };

  const result: Finding[] = [];
  for (const [, fileFindings] of byFile) {
    if (fileFindings.length <= maxPerFile) {
      result.push(...fileFindings);
      continue;
    }
    // Sort by severity (asc = most severe first), then confidence
    fileFindings.sort((a, b) => {
      const sevDiff = (sevOrder[a.severity] || 4) - (sevOrder[b.severity] || 4);
      if (sevDiff !== 0) return sevDiff;
      return (confOrder[a.confidence] || 2) - (confOrder[b.confidence] || 2);
    });
    result.push(...fileFindings.slice(0, maxPerFile));
  }
  return result;
}

function adjustConfidence(finding: Finding, fileContents: Map<string, string>, projectContext?: ProjectContext): Finding {
  const adjusted = { ...finding };
  const content = fileContents.get(finding.file) || '';
  const contentLower = content.toLowerCase();

  // Vague description penalty: if description < 50 chars, downgrade confidence
  if (finding.description.length < 50) {
    adjusted.confidence = 'low';
  }

  // Generic title downgrade: titles that indicate low-value findings
  // Only downgrade if BOTH generic title AND short description (< 100 chars)
  // "potential reentrancy", "unchecked return value", "missing access control" are real
  // vulnerability classes — only penalize when description lacks substance
  const genericTitles = [
    'missing input validation', 'gas optimization', 'lack of input validation',
    'missing validation', 'no input validation', 'missing error handling',
  ];
  const titleLower = finding.title.toLowerCase();
  if (genericTitles.some(t => titleLower.includes(t)) && finding.description.length < 100) {
    if (adjusted.severity === 'critical') adjusted.severity = 'high';
    if (adjusted.severity === 'high') adjusted.severity = 'medium';
  }

  // OZ inheritance cross-reference: access-control on Ownable/AccessControl contracts
  if (projectContext && finding.category === 'access-control') {
    const contractName = extractContractNameFromFile(content);
    if (contractName) {
      const parents = projectContext.inheritanceGraph.get(contractName) || [];
      const hasOzAccessControl = parents.some(p =>
        p.includes('Ownable') || p.includes('AccessControl') ||
        p.includes('Ownable2Step') || p.includes('OwnableUpgradeable')
      );
      if (hasOzAccessControl) {
        adjusted.confidence = 'low';
      }
    }
  }

  // ReentrancyGuard inheritance: hard drop reentrancy on guarded contracts
  if (projectContext && finding.category === 'reentrancy') {
    const contractName = extractContractNameFromFile(content);
    if (contractName) {
      const parents = projectContext.inheritanceGraph.get(contractName) || [];
      const hasReentrancyGuard = parents.some(p =>
        p.includes('ReentrancyGuard') || p.includes('ReentrancyGuardUpgradeable')
      );
      if (hasReentrancyGuard) {
        // Check if the specific function has nonReentrant
        const lines = content.split('\n');
        const contextStart = Math.max(0, finding.line - 5);
        const contextEnd = Math.min(lines.length, finding.line + 2);
        const funcContext = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();
        if (funcContext.includes('nonreentrant')) {
          // Hard drop: set to info so it gets filtered later
          adjusted.severity = 'info';
          adjusted.confidence = 'low';
        } else {
          // Contract has guard but not on this function — still suspicious
          adjusted.confidence = 'low';
        }
      }
    }
  }

  // Boost: finding matches a known high-impact pattern
  if (isHighImpactPattern(finding)) {
    if (adjusted.confidence === 'low') adjusted.confidence = 'medium';
  }

  // Penalize: finding is about a function protected by modifiers
  if (finding.category === 'access-control' && finding.line > 0) {
    const lines = content.split('\n');
    const contextStart = Math.max(0, finding.line - 5);
    const contextEnd = Math.min(lines.length, finding.line + 3);
    const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();

    if (context.includes('onlyowner') || context.includes('onlyadmin') ||
        context.includes('onlyminter') || context.includes('onlycontroller') ||
        context.includes('require(msg.sender ==') || context.includes('require(_msgSender() ==')) {
      adjusted.confidence = 'low';
      adjusted.severity = adjusted.severity === 'critical' ? 'medium' : adjusted.severity === 'high' ? 'low' : adjusted.severity;
    }
  }

  // Penalize: generic "fee-on-transfer token incompatibility" when the contract
  // doesn't accept arbitrary tokens (uses specific baseToken, ETH, or WETH)
  if (titleLower.includes('fee-on-transfer') || titleLower.includes('fee on transfer') ||
      (titleLower.includes('token incompatib') && !finding.description.toLowerCase().includes('specific token'))) {
    // Check if the contract uses a fixed/known token rather than arbitrary user input
    const hasFixedToken = contentLower.includes('basetoken') || contentLower.includes('weth') ||
      contentLower.includes('address(0)') || content.includes('immutable') && contentLower.includes('token');
    if (hasFixedToken) {
      // Still valid concern but lower confidence — protocol chooses which tokens to support
      if (adjusted.confidence === 'high') adjusted.confidence = 'medium';
      if (adjusted.severity === 'high') adjusted.severity = 'medium';
    }
  }

  // Penalize: "price manipulation via donation" — speculative without concrete profit path
  if ((titleLower.includes('donation') || titleLower.includes('direct transfer')) &&
      titleLower.includes('manipulation') && adjusted.confidence !== 'high') {
    adjusted.confidence = 'low';
  }

  // Penalize: reentrancy in initialization/creation functions — usually not exploitable
  if (finding.category === 'reentrancy' &&
      (titleLower.includes('create') || titleLower.includes('initialize') ||
       titleLower.includes('constructor') || titleLower.includes('deploy'))) {
    adjusted.confidence = 'low';
    if (adjusted.severity === 'critical') adjusted.severity = 'medium';
  }

  // Penalize: "division by zero" in Solidity 0.8+ (auto-reverts)
  if (finding.title.toLowerCase().includes('division by zero') ||
      finding.title.toLowerCase().includes('divide by zero')) {
    if (isSolidity08Plus(content)) {
      // In 0.8+, division by zero reverts. It's a DoS vector at most, not fund loss.
      adjusted.severity = 'low';
      adjusted.confidence = 'low';
    }
  }

  // Boost: reentrancy finding with state-after-external-call confirmed
  if (finding.category === 'reentrancy' && finding.line > 0) {
    const lines = content.split('\n');
    const funcBody = extractFunctionBody(lines, finding.line);
    if (funcBody && hasStateAfterExternalCall(funcBody)) {
      adjusted.confidence = 'high';
      if (hasValueTransfer(funcBody)) {
        // Confirmed CEI violation with value movement = at least high
        if (adjusted.severity === 'medium') adjusted.severity = 'high';
        if (adjusted.severity === 'low') adjusted.severity = 'medium';
      }
    }
  }

  return adjusted;
}

function isFalsePositive(finding: Finding, fileContents: Map<string, string>, projectContext?: ProjectContext): boolean {
  const titleLower = (finding.title || '').toLowerCase();
  const descLower = (finding.description || '').toLowerCase();

  // FP: "missing event emission" — not a security issue
  if (titleLower.includes('missing event') || titleLower.includes('no event')) {
    return finding.severity !== 'info';  // Keep if already info, drop if higher
  }

  // FP: "centralization risk" — design choice, not a vulnerability
  if (titleLower.includes('centralization') || descLower.includes('centralization risk')) {
    return true;
  }

  // FP: "magic number" or "hardcoded value" — code quality, not security
  if (titleLower.includes('magic number') || titleLower.includes('hardcoded')) {
    return true;
  }

  // FP: "floating pragma" — this is a best practice, not a vulnerability
  if (titleLower.includes('floating pragma') || titleLower.includes('pragma solidity')) {
    return true;
  }

  // FP: "missing zero address validation" — not a vulnerability, just a best practice
  if (titleLower.includes('zero address') || titleLower.includes('zero-address') ||
      titleLower.includes('address(0)') || titleLower.includes('address zero')) {
    return true;
  }

  // FP: "missing constructor validation" — code quality, not security
  if (titleLower.includes('constructor lacks') || titleLower.includes('constructor missing')) {
    return true;
  }

  // FP: "unsafe transfer" as standalone finding — usually just a style preference
  if (titleLower.includes('unsafe transfer') && !titleLower.includes('reentrancy') &&
      !titleLower.includes('before state') && !descLower.includes('reentrancy')) {
    return finding.severity === 'low';
  }

  // FP: "unchecked return value" on safeTransfer/safeTransferFrom — already checked by safe wrapper
  if ((titleLower.includes('unchecked return') || titleLower.includes('return value')) &&
      !descLower.includes('call(') && !descLower.includes('.call{')) {
    const content = fileContents.get(finding.file) || '';
    const lines = content.split('\n');
    const nearbyCode = lines.slice(Math.max(0, finding.line - 3), finding.line + 3).join('\n').toLowerCase();
    if (nearbyCode.includes('safetransfer') || nearbyCode.includes('safetransferfrom')) {
      return true;
    }
  }

  // FP: "owner can manipulate" / "admin can" — unless it's about execute() or delegatecall
  if ((titleLower.includes('owner can manipulate') || titleLower.includes('admin can manipulate') ||
       titleLower.includes('owner can change') || titleLower.includes('owner can set')) &&
      !titleLower.includes('execute') && !titleLower.includes('delegatecall') && !titleLower.includes('steal')) {
    return true;
  }

  // FP: "missing balance validation" / "missing validation in withdraw" — generic
  if ((titleLower.includes('missing balance') || titleLower.includes('missing validation')) &&
      !titleLower.includes('oracle') && !titleLower.includes('price')) {
    return true;
  }

  // FP: findings in metadata/view-only contracts about DoS — not security-critical
  if (finding.file.toLowerCase().includes('metadata') &&
      (titleLower.includes('dos') || titleLower.includes('revert') || titleLower.includes('malicious') ||
       titleLower.includes('manipulat') || titleLower.includes('spoof'))) {
    return finding.severity !== 'high' && finding.severity !== 'critical';
  }

  // FP: "price manipulation via setter" / "via virtual reserve" / "via reserve updates" — owner-controlled setters are by design
  if (titleLower.includes('price manipulation') &&
      (titleLower.includes('setter') || titleLower.includes('set ') || titleLower.includes('virtual reserve') || titleLower.includes('reserve update')) &&
      !titleLower.includes('flash') && !titleLower.includes('sandwich')) {
    return true;
  }

  // FP: "fee-on-transfer token incompatibility" — generic token compatibility warning without concrete exploit
  if ((titleLower.includes('fee-on-transfer') || titleLower.includes('fee on transfer')) &&
      (titleLower.includes('incompatib') || titleLower.includes('not supported') || titleLower.includes('accounting'))) {
    return true;
  }

  // FP: "no validation of pool response" / "missing return value check" for pool calls — pool is trusted
  if ((titleLower.includes('no validation of') || titleLower.includes('missing return value') ||
       titleLower.includes('unchecked external')) &&
      !descLower.includes('.call{') && !descLower.includes('low-level')) {
    return true;
  }

  // FP: "division before multiplication" as standalone finding without concrete value loss
  // BUT keep rounding-direction bugs (these are real even without "attacker" language)
  if (titleLower.includes('division before multiplication') || titleLower.includes('precision loss')) {
    const isRoundingDirection = titleLower.includes('rounding direction') || titleLower.includes('rounds down') ||
      titleLower.includes('rounds in') || descLower.includes('rounding direction') ||
      descLower.includes('mint(1') || descLower.includes('round down') || descLower.includes('rounds down');
    if (!isRoundingDirection) {
      if (!descLower.includes('attacker') && !descLower.includes('profit') && !descLower.includes('steal')) {
        if (finding.confidence !== 'high') return true;
      }
    }
  }

  // FP: "TWAP manipulation" / "oracle manipulation" on TWAP oracle contracts — the TWAP IS the manipulation resistance
  if ((titleLower.includes('twap') || titleLower.includes('time-weighted')) &&
      (titleLower.includes('manipulat') || titleLower.includes('can be influenced'))) {
    return true;
  }

  // FP: "Chainlink staleness" when the file delegates staleness to a separate check
  if ((titleLower.includes('stale') || titleLower.includes('staleness')) &&
      (titleLower.includes('chainlink') || titleLower.includes('oracle'))) {
    const content = fileContents.get(finding.file) || '';
    // If the contract or a related contract has isStale() / stalePriceDelay, staleness is handled
    if (content.includes('isStale') || content.includes('stalePriceDelay') ||
        content.includes('stalePrice')) {
      return true;
    }
  }

  // FP: "approve race condition" — known ERC20 pattern, not a real H/M
  if (titleLower.includes('approve') && (titleLower.includes('race') || titleLower.includes('front-run'))) {
    return true;
  }

  // FP: governance setter functions gated by onlyGov / address(this) — governance timelock
  if (finding.category === 'access-control' || titleLower.includes('can change') || titleLower.includes('can set')) {
    const content = fileContents.get(finding.file) || '';
    const contentLower = content.toLowerCase();
    // Governor contracts where msg.sender == address(this) means governance proposal
    if (contentLower.includes('onlygov') || contentLower.includes('msg.sender == address(this)') ||
        (contentLower.includes('governor') && contentLower.includes('timelock'))) {
      return true;
    }
  }

  // FP: "arbitrary execution" / "arbitrary call" in governance execute functions — that's the point
  if ((titleLower.includes('arbitrary') && (titleLower.includes('execution') || titleLower.includes('call'))) ||
      titleLower.includes('unvalidated external call')) {
    const content = fileContents.get(finding.file) || '';
    if (content.toLowerCase().includes('governor') || content.toLowerCase().includes('timelock') ||
        content.toLowerCase().includes('executeTransaction')) {
      return true;
    }
  }

  // FP: "hardcoded address" — configuration, not a vulnerability
  if (titleLower.includes('hardcoded address') || titleLower.includes('hard-coded address')) {
    return true;
  }

  // FP: findings about rebasing token internal math (gons/fragments) — well-audited pattern
  if (finding.file.toLowerCase().includes('fragment') || finding.file.toLowerCase().includes('rebase')) {
    if (titleLower.includes('precision') || titleLower.includes('rounding') ||
        titleLower.includes('truncat') || titleLower.includes('dust') ||
        titleLower.includes('supply') || titleLower.includes('max_supply')) {
      if (finding.confidence !== 'high') return true;
    }
  }

  // FP: "division by zero" in Solidity 0.8+ — auto-reverts, DoS at most, not fund loss
  if (titleLower.includes('division by zero') || titleLower.includes('divide by zero')) {
    const content = fileContents.get(finding.file) || '';
    if (isSolidity08Plus(content) && finding.severity !== 'critical') {
      return true;
    }
  }

  // FP: "flash loan governance" / "vote manipulation" — requires token holder to be a contract, extreme edge case
  if ((titleLower.includes('flash loan') && titleLower.includes('governance')) ||
      (titleLower.includes('flash loan') && titleLower.includes('vote')) ||
      (titleLower.includes('vote') && titleLower.includes('overflow'))) {
    const content = fileContents.get(finding.file) || '';
    if (content.toLowerCase().includes('governor') || content.toLowerCase().includes('governance')) {
      return true;
    }
  }

  // FP: "ETH value validation" in governance executeTransaction — timelock pattern
  if (titleLower.includes('eth value') && (titleLower.includes('governance') || titleLower.includes('proposal') || titleLower.includes('execution'))) {
    return true;
  }

  // FP: "unsafe type cast" from interface — Solidity interface casts are compile-time checked
  if ((titleLower.includes('unsafe') || titleLower.includes('without validation')) &&
      titleLower.includes('type cast') && titleLower.includes('interface')) {
    return true;
  }

  // FP: "missing access control" on functions — check if actually protected
  if (titleLower.includes('missing access control') || titleLower.includes('access control allows')) {
    const content = fileContents.get(finding.file) || '';
    if (content && finding.line > 0) {
      const lines = content.split('\n');
      // Search wider context (whole function) for access control modifiers
      const contextStart = Math.max(0, finding.line - 15);
      const contextEnd = Math.min(lines.length, finding.line + 10);
      const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();
      if (context.includes('onlyowner') || context.includes('require(msg.sender == owner') ||
          context.includes('_checkowner') || context.includes('onlyadmin') ||
          context.includes('require(msg.sender ==')) {
        return true;
      }
    }
    // Also match by function name — setAllParameters, setFeeRate, etc. are typically owner-only
    const funcName = titleLower.match(/\b(set\w+|update\w+)\b/);
    if (funcName && !titleLower.includes('user') && !titleLower.includes('anyone')) {
      // If it claims "allows unauthorized" but doesn't mention a specific bypass, likely FP
      if (finding.confidence === 'low') return true;
    }
  }

  return false;
}

function isHighImpactPattern(finding: Finding): boolean {
  const highImpactCategories = [
    'reentrancy', 'access-control', 'oracle-manipulation',
    'flash-loan', 'price-manipulation',
  ];
  return highImpactCategories.includes(finding.category) &&
    ['critical', 'high'].includes(finding.severity);
}

function isSolidity08Plus(content: string): boolean {
  const pragmaMatch = content.match(/pragma\s+solidity\s+[\^~>=]*\s*(0\.(\d+))/);
  if (pragmaMatch) {
    const minor = parseInt(pragmaMatch[2], 10);
    return minor >= 8;
  }
  return false;
}

function extractFunctionBody(lines: string[], lineNum: number): string | null {
  if (lines.length === 0 || lineNum <= 0 || lineNum > lines.length) return null;

  // Walk backwards to find function start
  let start = lineNum - 1;
  while (start > 0 && lines[start] && !lines[start].match(/function\s+\w+/)) {
    start--;
  }
  if (start < 0) return null;

  // Walk forward to find function end
  let braceCount = 0;
  let end = start;
  let started = false;
  for (let i = start; i < lines.length; i++) {
    for (const ch of lines[i]) {
      if (ch === '{') { braceCount++; started = true; }
      if (ch === '}') braceCount--;
    }
    if (started && braceCount === 0) {
      end = i;
      break;
    }
  }

  return lines.slice(start, end + 1).join('\n');
}

function hasStateAfterExternalCall(funcBody: string): boolean {
  const lines = funcBody.split('\n');
  let seenExternalCall = false;

  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('//')) continue;

    // External calls
    if (trimmed.includes('.call{') || trimmed.includes('.call(') ||
        trimmed.match(/\.\w+\(/) && (trimmed.includes('transfer(') || trimmed.includes('send('))) {
      seenExternalCall = true;
    }

    // State modifications after external call
    if (seenExternalCall) {
      if (trimmed.match(/\w+\[.*\]\s*[+\-*/]?=/) ||
          trimmed.match(/\w+\s*[+\-*/]?=\s*\w/) ||
          trimmed.includes('_burn(') || trimmed.includes('_mint(') ||
          trimmed.includes('delete ')) {
        return true;
      }
    }
  }

  return false;
}

function hasValueTransfer(funcBody: string): boolean {
  return funcBody.includes('.call{value') ||
    funcBody.includes('.transfer(') ||
    funcBody.includes('.send(') ||
    funcBody.includes('safeTransfer(') ||
    funcBody.includes('.transfer(');
}

function extractContractNameFromFile(content: string): string | null {
  const match = content.match(/\b(?:contract|library|abstract\s+contract)\s+(\w+)/);
  return match ? match[1] : null;
}

/**
 * Validate findings against Solodit's database.
 * Boosts confidence for findings with real-world corroboration,
 * penalizes generic-sounding findings with no matches.
 *
 * This is a separate async function to avoid touching the sync postProcessFindings.
 */
export async function validateWithSolodit(
  findings: Finding[],
  soloditClient: SoloditClient
): Promise<Finding[]> {
  const validated: Finding[] = [];

  for (const finding of findings) {
    const adjusted = { ...finding };

    // Only validate HIGH/CRITICAL — not worth API calls for lower severity
    if (!['critical', 'high'].includes(finding.severity)) {
      validated.push(adjusted);
      continue;
    }

    try {
      const result = await soloditClient.validateFinding(finding.title, finding.category);

      if (result.matchCount >= 2) {
        // Strong corroboration: boost confidence, attach refs
        if (adjusted.confidence === 'low') adjusted.confidence = 'medium';
        if (adjusted.confidence === 'medium') adjusted.confidence = 'high';
        adjusted.soloditRefs = result.slugs.slice(0, 3).map(
          slug => `https://solodit.cyfrin.io/issues/${slug}`
        );
      } else if (result.matchCount === 0) {
        // No matches + generic title → penalize
        const genericIndicators = [
          'missing', 'lack', 'potential', 'possible', 'no validation',
          'unchecked', 'without',
        ];
        const titleLower = finding.title.toLowerCase();
        if (genericIndicators.some(g => titleLower.includes(g))) {
          adjusted.confidence = 'low';
        }
      }
    } catch {
      // Validation failure is non-fatal — keep finding as-is
    }

    validated.push(adjusted);
  }

  return validated;
}
