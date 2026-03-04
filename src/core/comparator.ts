import { readFileSync, existsSync } from 'fs';
import { resolve, join } from 'path';
import Anthropic from '@anthropic-ai/sdk';
import { Finding, Severity } from './types.js';

export interface OfficialFinding {
  id: string;          // e.g. "H-01", "M-03"
  title: string;
  severity: 'high' | 'medium';
  url?: string;
  description?: string; // First ~500 chars of the finding body
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

    // Extract description (first ~500 chars after the heading line)
    const bodyStart = sectionBody.indexOf('\n');
    const description = bodyStart > 0
      ? sectionBody.slice(bodyStart + 1, bodyStart + 501).trim()
      : '';

    findings.push({ id, title, severity, url, description, files, keywords });
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
 * Compare Krait findings against official contest findings (heuristic mode).
 */
export function compareFindings(
  contestName: string,
  officialFindings: OfficialFinding[],
  kraitFindings: Finding[]
): CompareResult {
  const matches: MatchResult[] = [];
  const matchedKraitIndices = new Set<number>();

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

    if (bestScore >= 0.35 && bestIdx >= 0) {
      matchedKraitIndices.add(bestIdx);
      matches.push({ official, matched: bestMatch, matchScore: bestScore, matchReason: bestReason });
    } else {
      matches.push({ official, matched: null, matchScore: 0, matchReason: 'No match found' });
    }
  }

  return buildCompareResult(contestName, officialFindings, kraitFindings, matches, matchedKraitIndices);
}

/**
 * Compare Krait findings against official findings using AI-assisted semantic matching.
 * Uses Claude Haiku to judge whether two findings describe the same vulnerability.
 */
export async function compareFindingsAI(
  contestName: string,
  officialFindings: OfficialFinding[],
  kraitFindings: Finding[],
  apiKey?: string,
  log: (msg: string) => void = () => {}
): Promise<CompareResult> {
  const client = new Anthropic({ apiKey: apiKey || process.env.ANTHROPIC_API_KEY });
  const matches: MatchResult[] = [];
  const matchedKraitIndices = new Set<number>();

  for (const official of officialFindings) {
    // Pre-filter: only send candidates with SOME heuristic signal to reduce API calls
    const candidates: Array<{ index: number; finding: Finding; heuristicScore: number }> = [];
    for (let i = 0; i < kraitFindings.length; i++) {
      if (matchedKraitIndices.has(i)) continue;
      const { score } = computeMatchScore(official, kraitFindings[i]);
      // Low bar for pre-filter — just need any signal at all
      if (score >= 0.05) {
        candidates.push({ index: i, finding: kraitFindings[i], heuristicScore: score });
      }
    }

    // Sort by heuristic score descending, take top 10 candidates
    candidates.sort((a, b) => b.heuristicScore - a.heuristicScore);
    const topCandidates = candidates.slice(0, 10);

    if (topCandidates.length === 0) {
      matches.push({ official, matched: null, matchScore: 0, matchReason: 'No candidates (AI)' });
      continue;
    }

    // Ask Claude to judge which (if any) candidate matches
    const aiResult = await aiJudgeMatch(client, official, topCandidates, log);

    if (aiResult) {
      matchedKraitIndices.add(aiResult.index);
      matches.push({
        official,
        matched: aiResult.finding,
        matchScore: aiResult.confidence,
        matchReason: `AI: ${aiResult.reason}`,
      });
    } else {
      matches.push({ official, matched: null, matchScore: 0, matchReason: 'No match (AI judged)' });
    }
  }

  return buildCompareResult(contestName, officialFindings, kraitFindings, matches, matchedKraitIndices);
}

/**
 * Use Claude Haiku to judge whether any candidate finding matches an official finding.
 */
async function aiJudgeMatch(
  client: Anthropic,
  official: OfficialFinding,
  candidates: Array<{ index: number; finding: Finding; heuristicScore: number }>,
  log: (msg: string) => void
): Promise<{ index: number; finding: Finding; confidence: number; reason: string } | null> {
  const candidateDescriptions = candidates.map((c, i) => {
    return `[${i}] Title: "${c.finding.title}"
   File: ${c.finding.file}:${c.finding.line}
   Severity: ${c.finding.severity}
   Description: ${c.finding.description.slice(0, 300)}`;
  }).join('\n\n');

  const officialDesc = official.description
    ? `\nDescription: ${official.description.slice(0, 400)}`
    : '';

  const prompt = `You are evaluating whether any of the CANDIDATE findings describe the same vulnerability as the OFFICIAL finding from a security audit contest.

OFFICIAL FINDING:
  ID: ${official.id}
  Title: "${official.title}"
  Severity: ${official.severity}${officialDesc}
  Files referenced: ${official.files?.join(', ') || 'none'}

CANDIDATE FINDINGS:
${candidateDescriptions}

RULES:
- Two findings match if they describe the SAME root cause vulnerability, even if worded differently.
- A match does NOT require identical severity or exact same file — the same bug can be described from different angles.
- However, two findings about DIFFERENT bugs in the same file are NOT a match.
- Be strict: only match if you are reasonably confident they describe the same underlying issue.

Respond with EXACTLY one line in this format:
MATCH <candidate_number> <confidence_0_to_100> <brief_reason>
or:
NO_MATCH <brief_reason>

Examples:
MATCH 2 85 Both describe reentrancy in the withdraw function allowing double-spending
NO_MATCH Official finding is about oracle manipulation but candidates are about access control`;

  try {
    const response = await client.messages.create({
      model: 'claude-haiku-4-5-20251001',
      max_tokens: 150,
      messages: [{ role: 'user', content: prompt }],
    });

    const text = response.content
      .filter((b): b is Anthropic.TextBlock => b.type === 'text')
      .map(b => b.text)
      .join('');

    // Parse response
    const matchLine = text.trim().split('\n')[0];
    const matchParse = matchLine.match(/^MATCH\s+(\d+)\s+(\d+)\s+(.+)/);
    if (matchParse) {
      const candidateIdx = parseInt(matchParse[1], 10);
      const confidence = parseInt(matchParse[2], 10) / 100;
      const reason = matchParse[3].trim();

      if (candidateIdx >= 0 && candidateIdx < candidates.length && confidence >= 0.5) {
        const selected = candidates[candidateIdx];
        log(`    AI match: [${official.id}] → ${selected.finding.id} (${(confidence * 100).toFixed(0)}%) — ${reason}`);
        return { index: selected.index, finding: selected.finding, confidence, reason };
      }
    }

    // NO_MATCH or low confidence
    return null;
  } catch (err) {
    log(`    AI match error for ${official.id}: ${err instanceof Error ? err.message : String(err)}`);
    // Fallback to heuristic best match
    const best = candidates[0];
    if (best.heuristicScore >= 0.35) {
      return { index: best.index, finding: best.finding, confidence: best.heuristicScore, reason: 'heuristic fallback' };
    }
    return null;
  }
}

function buildCompareResult(
  contestName: string,
  officialFindings: OfficialFinding[],
  kraitFindings: Finding[],
  matches: MatchResult[],
  matchedKraitIndices: Set<number>
): CompareResult {
  const truePositives = matches.filter(m => m.matched !== null).length;
  const falseNegatives = matches.filter(m => m.matched === null).length;

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

  // 1. Keyword overlap — domain-specific keywords from titles + descriptions
  const kraitKeywords = extractKeywords(krait.title + ' ' + krait.description);
  const overlap = official.keywords.filter(k => kraitKeywords.includes(k));
  const keywordScore = official.keywords.length > 0
    ? overlap.length / official.keywords.length : 0;

  if (overlap.length > 0) {
    score += keywordScore * 0.4;
    reasons.push(`keywords(${overlap.length}): ${overlap.join(', ')}`);
  }

  // 2. File reference match
  let fileMatch = false;
  if (official.files && official.files.length > 0) {
    const kraitFile = krait.file.toLowerCase();
    fileMatch = official.files.some(f =>
      kraitFile.includes(f.toLowerCase()) || f.toLowerCase().includes(extractFileName(kraitFile))
    );
    if (fileMatch) {
      // File match is worth more when combined with keyword overlap
      score += overlap.length > 0 ? 0.20 : 0.10;
      reasons.push('file match');
    }
  }

  // 3. Title similarity (Jaccard on normalized words)
  const titleSim = jaccardSimilarity(
    normalizeForComparison(official.title),
    normalizeForComparison(krait.title)
  );
  if (titleSim > 0.15) {
    score += titleSim * 0.25;
    reasons.push(`title sim: ${(titleSim * 100).toFixed(0)}%`);
  }

  // 4. Description-to-title cross-similarity (official title vs krait description)
  const descSim = jaccardSimilarity(
    normalizeForComparison(official.title),
    normalizeForComparison(krait.description)
  );
  if (descSim > 0.1) {
    score += descSim * 0.15;
    reasons.push(`desc sim: ${(descSim * 100).toFixed(0)}%`);
  }

  // 5. Severity alignment bonus
  const severityMap: Record<string, string[]> = {
    high: ['critical', 'high'],
    medium: ['medium', 'high'],
  };
  if (severityMap[official.severity]?.includes(krait.severity)) {
    score += 0.03;
  }

  return { score: Math.min(score, 1), reason: reasons.join('; ') || 'weak match' };
}

function extractKeywords(text: string): string[] {
  // Comprehensive stop words — must filter ALL generic words that cause false matches
  const stopWords = new Set([
    // English common
    'the', 'a', 'an', 'in', 'on', 'at', 'to', 'for', 'of', 'with', 'by',
    'is', 'are', 'was', 'were', 'be', 'been', 'can', 'could', 'will', 'would',
    'should', 'may', 'might', 'all', 'any', 'some', 'this', 'that', 'from',
    'or', 'and', 'but', 'not', 'if', 'when', 'which', 'how', 'what', 'where',
    'has', 'have', 'had', 'does', 'do', 'did', 'than', 'then', 'also', 'into',
    'more', 'other', 'its', 'their', 'it', 'as', 'up', 'out', 'so', 'no',
    'only', 'there', 'end', 'first', 'after', 'before', 'without', 'through',
    'between', 'each', 'every', 'such', 'those', 'these', 'once', 'already',
    'able', 'because', 'since', 'while', 'during', 'still', 'specific',
    'correctly', 'immediately', 'directly', 'properly', 'simply', 'currently',
    // Generic security/code terms (too common to be meaningful)
    'function', 'method', 'contract', 'issue', 'vulnerability', 'bug', 'due',
    'result', 'results', 'cause', 'causes', 'lead', 'leads', 'causing',
    'being', 'used', 'using', 'use', 'called', 'calling', 'call', 'calls',
    'allow', 'allows', 'allowed', 'allowing', 'enable', 'enables',
    'check', 'checks', 'checked', 'missing', 'lack', 'lacks',
    'incorrect', 'invalid', 'wrong', 'error', 'errors',
    'potential', 'possible', 'risk', 'risks',
    'value', 'values', 'data', 'state', 'address',
    'user', 'users', 'attacker', 'anyone', 'caller',
    'implementation', 'mechanism', 'logic', 'process',
    'token', 'tokens', 'amount', 'balance',
    'way', 'case', 'step', 'make', 'take', 'get', 'set',
    'new', 'old', 'one', 'two', 'same',
  ]);

  return text
    .toLowerCase()
    .replace(/[^a-z0-9_\s]/g, ' ')
    .split(/\s+/)
    .filter(w => w.length > 3 && !stopWords.has(w))  // min 4 chars
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
