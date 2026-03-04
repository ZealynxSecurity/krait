import { readFileSync, existsSync } from 'fs';
import { resolve, join } from 'path';
import { Finding, Severity } from './types.js';

export interface OfficialFinding {
  id: string;          // e.g. "H-01", "M-03"
  title: string;
  severity: 'high' | 'medium';
  url?: string;
  files?: string[];    // Referenced file paths (extracted from title/body)
  keywords: string[];  // Key terms for matching
}

export interface MatchResult {
  official: OfficialFinding;
  matched: Finding | null;
  matchScore: number;
  matchReason: string;
}

export interface CompareResult {
  contestName: string;
  officialFindings: OfficialFinding[];
  kraitFindings: Finding[];
  matches: MatchResult[];
  truePositives: number;   // Krait findings that match official
  falseNegatives: number;  // Official findings Krait missed
  falsePositives: number;  // Krait findings not in official
  precision: number;
  recall: number;
  f1: number;
  byRisk: {
    high: { tp: number; fn: number; total: number; recall: number };
    medium: { tp: number; fn: number; total: number; recall: number };
  };
}

/**
 * Parse official H/M findings from a C4 report.md file.
 */
export function parseOfficialFindings(reportPath: string): OfficialFinding[] {
  const content = readFileSync(reportPath, 'utf-8');
  const findings: OfficialFinding[] = [];

  // Match lines like: ## [[H-01] Title text](url)
  const findingRegex = /^##\s+\[\[([HM]-\d+)\]\s+(.+?)\]\((.+?)\)/gm;
  let match;

  while ((match = findingRegex.exec(content)) !== null) {
    const id = match[1];
    const title = match[2];
    const url = match[3];
    const severity = id.startsWith('H') ? 'high' as const : 'medium' as const;

    // Extract keywords from title
    const keywords = extractKeywords(title);

    // Try to extract referenced files from the section body
    const sectionEnd = content.indexOf('\n## [', match.index + 1);
    const sectionBody = sectionEnd > 0
      ? content.slice(match.index, sectionEnd)
      : content.slice(match.index, match.index + 3000);

    const files = extractFileReferences(sectionBody);

    findings.push({ id, title, severity, url, files, keywords });
  }

  return findings;
}

/**
 * Parse official findings from individual JSON files in a C4 data/ directory.
 * Uses the accepted findings (those appearing in report.md) rather than all submissions.
 */
export function parseFromDataDir(dataDir: string): OfficialFinding[] {
  // This is a fallback if report.md doesn't exist.
  // We look for risk=2 (medium) and risk=3 (high) findings.
  const { readdirSync } = require('fs');
  const files = readdirSync(dataDir).filter((f: string) => f.endsWith('.json'));
  const findings: OfficialFinding[] = [];
  const seen = new Set<string>();

  for (const file of files) {
    try {
      const data = JSON.parse(readFileSync(join(dataDir, file), 'utf-8'));
      const risk = String(data.risk);
      if (risk !== '2' && risk !== '3') continue;

      // Deduplicate by title similarity (many wardens report same issue)
      const normalizedTitle = data.title?.toLowerCase().replace(/[^a-z0-9]/g, '') || '';
      if (seen.has(normalizedTitle)) continue;
      seen.add(normalizedTitle);

      const severity = risk === '3' ? 'high' as const : 'medium' as const;
      findings.push({
        id: `${severity === 'high' ? 'H' : 'M'}-${findings.length + 1}`,
        title: data.title || file,
        severity,
        url: data.issueUrl,
        keywords: extractKeywords(data.title || ''),
      });
    } catch {
      // Skip unparseable files
    }
  }

  return findings;
}

/**
 * Load a Krait report JSON and extract findings.
 */
export function loadKraitReport(reportPath: string): Finding[] {
  const data = JSON.parse(readFileSync(reportPath, 'utf-8'));
  return data.findings || [];
}

/**
 * Compare Krait findings against official contest findings.
 */
export function compareFindings(
  contestName: string,
  officialFindings: OfficialFinding[],
  kraitFindings: Finding[]
): CompareResult {
  const matches: MatchResult[] = [];
  const matchedKraitIndices = new Set<number>();

  // For each official finding, find the best matching Krait finding
  for (const official of officialFindings) {
    let bestMatch: Finding | null = null;
    let bestScore = 0;
    let bestReason = '';
    let bestIdx = -1;

    for (let i = 0; i < kraitFindings.length; i++) {
      if (matchedKraitIndices.has(i)) continue;

      const { score, reason } = computeMatchScore(official, kraitFindings[i]);
      if (score > bestScore) {
        bestScore = score;
        bestMatch = kraitFindings[i];
        bestReason = reason;
        bestIdx = i;
      }
    }

    // Threshold: need at least 0.3 to count as a match
    if (bestScore >= 0.3 && bestIdx >= 0) {
      matchedKraitIndices.add(bestIdx);
      matches.push({ official, matched: bestMatch, matchScore: bestScore, matchReason: bestReason });
    } else {
      matches.push({ official, matched: null, matchScore: 0, matchReason: 'No match found' });
    }
  }

  const truePositives = matches.filter(m => m.matched !== null).length;
  const falseNegatives = matches.filter(m => m.matched === null).length;

  // False positives: Krait findings that are high/critical/medium severity but don't match any official
  const significantKrait = kraitFindings.filter((f, i) =>
    !matchedKraitIndices.has(i) && ['critical', 'high', 'medium'].includes(f.severity)
  );
  const falsePositives = significantKrait.length;

  const precision = truePositives + falsePositives > 0
    ? truePositives / (truePositives + falsePositives) : 0;
  const recall = officialFindings.length > 0
    ? truePositives / officialFindings.length : 0;
  const f1 = precision + recall > 0
    ? 2 * (precision * recall) / (precision + recall) : 0;

  // Breakdown by risk
  const highOfficial = officialFindings.filter(f => f.severity === 'high');
  const highMatched = matches.filter(m => m.official.severity === 'high' && m.matched !== null);
  const mediumOfficial = officialFindings.filter(f => f.severity === 'medium');
  const mediumMatched = matches.filter(m => m.official.severity === 'medium' && m.matched !== null);

  return {
    contestName,
    officialFindings,
    kraitFindings,
    matches,
    truePositives,
    falseNegatives,
    falsePositives,
    precision,
    recall,
    f1,
    byRisk: {
      high: {
        tp: highMatched.length,
        fn: highOfficial.length - highMatched.length,
        total: highOfficial.length,
        recall: highOfficial.length > 0 ? highMatched.length / highOfficial.length : 0,
      },
      medium: {
        tp: mediumMatched.length,
        fn: mediumOfficial.length - mediumMatched.length,
        total: mediumOfficial.length,
        recall: mediumOfficial.length > 0 ? mediumMatched.length / mediumOfficial.length : 0,
      },
    },
  };
}

/**
 * Compute a match score between an official finding and a Krait finding.
 * Returns 0-1 score and a reason string.
 */
function computeMatchScore(
  official: OfficialFinding,
  krait: Finding
): { score: number; reason: string } {
  let score = 0;
  const reasons: string[] = [];

  // 1. Keyword overlap (most important)
  const kraitKeywords = extractKeywords(krait.title + ' ' + krait.description);
  const overlap = official.keywords.filter(k => kraitKeywords.includes(k));
  const keywordScore = official.keywords.length > 0
    ? overlap.length / official.keywords.length : 0;

  if (keywordScore > 0) {
    score += keywordScore * 0.5;
    reasons.push(`keywords: ${overlap.join(', ')}`);
  }

  // 2. File reference match
  if (official.files && official.files.length > 0) {
    const kraitFile = krait.file.toLowerCase();
    const fileMatch = official.files.some(f =>
      kraitFile.includes(f.toLowerCase()) || f.toLowerCase().includes(extractFileName(kraitFile))
    );
    if (fileMatch) {
      score += 0.25;
      reasons.push('file match');
    }
  }

  // 3. Category/title similarity
  const titleSim = jaccardSimilarity(
    normalizeForComparison(official.title),
    normalizeForComparison(krait.title)
  );
  if (titleSim > 0.2) {
    score += titleSim * 0.25;
    reasons.push(`title sim: ${(titleSim * 100).toFixed(0)}%`);
  }

  // 4. Severity alignment bonus
  const severityMap: Record<string, string[]> = {
    high: ['critical', 'high'],
    medium: ['medium', 'high'],
  };
  if (severityMap[official.severity]?.includes(krait.severity)) {
    score += 0.05;
  }

  return { score: Math.min(score, 1), reason: reasons.join('; ') || 'weak match' };
}

function extractKeywords(text: string): string[] {
  // Domain-specific important terms
  const stopWords = new Set([
    'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by',
    'is', 'are', 'was', 'were', 'be', 'been', 'can', 'could', 'will', 'would',
    'should', 'may', 'might', 'all', 'any', 'some', 'this', 'that', 'from',
    'or', 'and', 'but', 'not', 'if', 'when', 'which', 'how', 'what', 'where',
    'has', 'have', 'had', 'does', 'do', 'did', 'than', 'then', 'also', 'into',
    'more', 'other', 'its', 'their', 'it', 'as', 'up', 'out', 'so', 'no',
    'function', 'method', 'contract', 'issue', 'vulnerability', 'bug', 'due',
    'result', 'results', 'cause', 'causes', 'lead', 'leads', 'during', 'while',
    'being', 'used', 'using', 'use', 'called', 'calling', 'call',
  ]);

  return text
    .toLowerCase()
    .replace(/[^a-z0-9_\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 2 && !stopWords.has(w))
    .filter((w, i, arr) => arr.indexOf(w) === i); // unique
}

function extractFileReferences(text: string): string[] {
  const files: string[] = [];
  // Match Solidity file references
  const fileRegex = /\b(\w+\.sol)\b/g;
  let match;
  while ((match = fileRegex.exec(text)) !== null) {
    if (!files.includes(match[1])) {
      files.push(match[1]);
    }
  }
  return files;
}

function extractFileName(path: string): string {
  return path.split('/').pop() || path;
}

function normalizeForComparison(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, '')
    .split(/\s+/)
    .filter(w => w.length > 2);
}

function jaccardSimilarity(a: string[], b: string[]): number {
  if (a.length === 0 || b.length === 0) return 0;
  const setA = new Set(a);
  const setB = new Set(b);
  const intersection = [...setA].filter(w => setB.has(w)).length;
  const union = new Set([...setA, ...setB]).size;
  return intersection / union;
}

/**
 * Format comparison results for console output.
 */
export function formatCompareResults(result: CompareResult): string {
  const lines: string[] = [];

  lines.push(`\n  Contest: ${result.contestName}`);
  lines.push(`  Official findings: ${result.officialFindings.length} (${result.byRisk.high.total}H / ${result.byRisk.medium.total}M)`);
  lines.push(`  Krait findings: ${result.kraitFindings.length}`);
  lines.push('');

  // Matches
  lines.push('  Matching Results:');
  for (const m of result.matches) {
    const status = m.matched ? '✓' : '✗';
    const matchInfo = m.matched
      ? `→ ${m.matched.id} "${m.matched.title.slice(0, 50)}" (${(m.matchScore * 100).toFixed(0)}%)`
      : '→ NOT FOUND';
    lines.push(`    ${status} [${m.official.id}] ${m.official.title.slice(0, 60)}`);
    lines.push(`      ${matchInfo}`);
    if (m.matchReason && m.matched) {
      lines.push(`      Reason: ${m.matchReason}`);
    }
  }

  lines.push('');
  lines.push('  Scores:');
  lines.push(`    Precision: ${(result.precision * 100).toFixed(1)}%`);
  lines.push(`    Recall:    ${(result.recall * 100).toFixed(1)}%`);
  lines.push(`    F1:        ${(result.f1 * 100).toFixed(1)}%`);
  lines.push('');
  lines.push('  By Severity:');
  lines.push(`    High:   ${result.byRisk.high.tp}/${result.byRisk.high.total} recalled (${(result.byRisk.high.recall * 100).toFixed(0)}%)`);
  lines.push(`    Medium: ${result.byRisk.medium.tp}/${result.byRisk.medium.total} recalled (${(result.byRisk.medium.recall * 100).toFixed(0)}%)`);
  lines.push('');
  lines.push(`  True Positives:  ${result.truePositives}`);
  lines.push(`  False Negatives: ${result.falseNegatives}`);
  lines.push(`  False Positives: ${result.falsePositives}`);

  return lines.join('\n');
}
