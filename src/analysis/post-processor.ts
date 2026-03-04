import { Finding, FileInfo } from '../core/types.js';

/**
 * Post-process findings with domain-specific heuristics to reduce false positives
 * and adjust confidence scores.
 */
export function postProcessFindings(
  findings: Finding[],
  files: FileInfo[],
  fileContents: Map<string, string>
): Finding[] {
  return findings
    .map(f => adjustConfidence(f, fileContents))
    .filter(f => !isFalsePositive(f, fileContents));
}

function adjustConfidence(finding: Finding, fileContents: Map<string, string>): Finding {
  const adjusted = { ...finding };
  const content = fileContents.get(finding.file) || '';
  const contentLower = content.toLowerCase();

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

function isFalsePositive(finding: Finding, fileContents: Map<string, string>): boolean {
  const titleLower = finding.title.toLowerCase();
  const descLower = finding.description.toLowerCase();

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
  // Walk backwards to find function start
  let start = lineNum - 1;
  while (start > 0 && !lines[start].match(/function\s+\w+/)) {
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
