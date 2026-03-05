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
  return findings
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
  const genericTitles = [
    'missing input validation', 'gas optimization', 'lack of input validation',
    'missing validation', 'unchecked return value', 'missing access control',
    'potential reentrancy', 'no input validation', 'missing error handling',
  ];
  const titleLower = finding.title.toLowerCase();
  if (genericTitles.some(t => titleLower.includes(t))) {
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

  // Penalize: "division by zero" in Solidity 0.8+ (auto-reverts)
  if (finding.title.toLowerCase().includes('division by zero') ||
      finding.title.toLowerCase().includes('divide by zero')) {
    if (isSolidity08Plus(content)) {
      // In 0.8+, division by zero reverts. It's a DoS vector at most, not fund loss.
      if (adjusted.severity === 'critical') adjusted.severity = 'medium';
      if (adjusted.severity === 'high') adjusted.severity = 'medium';
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

  // Penalize: contract has ReentrancyGuard / nonReentrant
  if (finding.category === 'reentrancy') {
    if (contentLower.includes('nonreentrant') || contentLower.includes('reentrancyguard')) {
      // Check if the specific function has the guard
      const lines = content.split('\n');
      const contextStart = Math.max(0, finding.line - 5);
      const contextEnd = Math.min(lines.length, finding.line + 2);
      const context = lines.slice(contextStart, contextEnd).join('\n').toLowerCase();

      if (context.includes('nonreentrant')) {
        adjusted.confidence = 'low';
        adjusted.severity = 'low';
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
