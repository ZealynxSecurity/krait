/**
 * Feedback report generator — for each missed official finding,
 * generate a pattern suggestion to improve future detection.
 */

import { readFileSync, writeFileSync, existsSync } from 'fs';
import { join } from 'path';
import { CompareResult, OfficialFinding } from '../core/comparator.js';

export interface PatternSuggestion {
  sourceContest: string;
  officialId: string;
  officialTitle: string;
  severity: string;
  suggestedCategory: string;
  suggestedIndicators: string[];
  suggestedDetectionStrategy: string;
  referencedFiles: string[];
  notes: string;
}

/**
 * Generate pattern suggestions from missed findings (false negatives).
 */
export function generateFeedback(
  result: CompareResult,
  findingsDir: string
): PatternSuggestion[] {
  const missed = result.matches.filter(m => m.matched === null);
  if (missed.length === 0) return [];

  const suggestions: PatternSuggestion[] = [];

  for (const miss of missed) {
    const official = miss.official;

    // Try to get more details from the report.md section
    const details = extractFindingDetails(official, findingsDir);

    suggestions.push({
      sourceContest: result.contestName,
      officialId: official.id,
      officialTitle: official.title,
      severity: official.severity,
      suggestedCategory: inferCategory(official.title, details),
      suggestedIndicators: inferIndicators(official.title, details),
      suggestedDetectionStrategy: inferStrategy(official.title, details),
      referencedFiles: official.files || [],
      notes: details.summary,
    });
  }

  return suggestions;
}

/**
 * Format suggestions as YAML pattern drafts.
 */
export function formatSuggestionsAsYaml(suggestions: PatternSuggestion[]): string {
  if (suggestions.length === 0) return '# No missed findings — no pattern suggestions needed.\n';

  const lines: string[] = [
    '# Pattern suggestions from shadow audit feedback',
    '# Review and refine before adding to patterns/',
    '',
  ];

  for (const s of suggestions) {
    lines.push(`# From: ${s.sourceContest} — ${s.officialId}`);
    lines.push(`- id: "DRAFT-${s.officialId.replace('-', '')}"`);
    lines.push(`  name: "${escapeYaml(s.officialTitle)}"`);
    lines.push(`  category: "${s.suggestedCategory}"`);
    lines.push(`  severity: "${s.severity}"`);
    lines.push(`  description: "${escapeYaml(s.notes)}"`);
    lines.push(`  detection:`);
    lines.push(`    strategy: "${escapeYaml(s.suggestedDetectionStrategy)}"`);
    lines.push(`    indicators:`);
    for (const ind of s.suggestedIndicators) {
      lines.push(`      - "${escapeYaml(ind)}"`);
    }
    lines.push(`  tags: ["solidity", "defi", "${s.suggestedCategory}"]`);
    lines.push(`  confidence: "medium"`);
    lines.push(`  real_examples:`);
    lines.push(`    - source: "${s.sourceContest}"`);
    lines.push(`      finding_id: "${s.officialId}"`);
    lines.push(`      impact: "${escapeYaml(s.officialTitle)}"`);
    if (s.referencedFiles.length > 0) {
      lines.push(`      # Referenced files: ${s.referencedFiles.join(', ')}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

/**
 * Write feedback report to disk.
 */
export function writeFeedbackReport(
  suggestions: PatternSuggestion[],
  outputDir: string,
  contestId: string
): string {
  const yamlContent = formatSuggestionsAsYaml(suggestions);
  const outputPath = join(outputDir, `feedback-${contestId}.yaml`);
  writeFileSync(outputPath, yamlContent);
  return outputPath;
}

// --- Internal helpers ---

interface FindingDetails {
  summary: string;
  codeSnippets: string[];
  fileRefs: string[];
}

function extractFindingDetails(
  official: OfficialFinding,
  findingsDir: string
): FindingDetails {
  const reportMd = join(findingsDir, 'report.md');
  if (!existsSync(reportMd)) {
    return { summary: official.title, codeSnippets: [], fileRefs: official.files || [] };
  }

  try {
    const content = readFileSync(reportMd, 'utf-8');

    // Find the section for this finding
    const pattern = new RegExp(
      `## \\[\\[${escapeRegex(official.id)}\\].*?\\n([\\s\\S]*?)(?=\\n## \\[|$)`,
      'm'
    );
    const match = content.match(pattern);

    if (!match) {
      return { summary: official.title, codeSnippets: [], fileRefs: official.files || [] };
    }

    const section = match[1].slice(0, 3000); // Limit to first 3000 chars

    // Extract a brief summary from the first paragraph
    const paragraphs = section.split('\n\n').filter(p => p.trim().length > 20);
    const summary = paragraphs[0]?.replace(/\n/g, ' ').trim().slice(0, 300) || official.title;

    // Extract code snippets
    const codeBlocks = section.match(/```[\s\S]*?```/g) || [];
    const codeSnippets = codeBlocks.map(b => b.replace(/```\w*\n?/g, '').trim()).slice(0, 3);

    // Extract file references
    const fileRefs = [...(official.files || [])];
    const solFiles = section.match(/\b\w+\.sol\b/g) || [];
    for (const f of solFiles) {
      if (!fileRefs.includes(f)) fileRefs.push(f);
    }

    return { summary, codeSnippets, fileRefs };
  } catch {
    return { summary: official.title, codeSnippets: [], fileRefs: official.files || [] };
  }
}

function inferCategory(title: string, details: FindingDetails): string {
  const text = (title + ' ' + details.summary).toLowerCase();

  const categoryMap: Array<[string, string[]]> = [
    ['reentrancy', ['reentrancy', 'reentrant', 'callback', 'external call before state']],
    ['access-control', ['access', 'permission', 'unauthorized', 'privilege', 'admin', 'owner']],
    ['price-manipulation', ['price', 'oracle', 'manipulation', 'flash loan', 'sandwich']],
    ['arithmetic', ['overflow', 'underflow', 'rounding', 'precision', 'division']],
    ['front-running', ['frontrun', 'front-run', 'mev', 'sandwich', 'reorg']],
    ['denial-of-service', ['dos', 'denial', 'revert', 'block', 'gas limit', 'unbounded']],
    ['logic-error', ['logic', 'incorrect', 'wrong', 'broken', 'functionality']],
    ['data-validation', ['validation', 'check', 'missing', 'unchecked', 'invalid']],
    ['upgrade-safety', ['upgrade', 'proxy', 'implementation', 'delegatecall']],
    ['token-handling', ['token', 'transfer', 'approve', 'allowance', 'erc20']],
  ];

  for (const [category, keywords] of categoryMap) {
    if (keywords.some(k => text.includes(k))) {
      return category;
    }
  }

  return 'logic-error';
}

function inferIndicators(title: string, details: FindingDetails): string[] {
  const indicators: string[] = [];
  const text = (title + ' ' + details.summary).toLowerCase();

  // Extract function names
  const funcNames = text.match(/`(\w+)`/g);
  if (funcNames) {
    indicators.push(...funcNames.map(f => f.replace(/`/g, '')).slice(0, 3));
  }

  // Extract contract/file names
  for (const ref of details.fileRefs.slice(0, 3)) {
    indicators.push(ref);
  }

  // Add generic indicators based on category
  if (text.includes('reentrancy')) indicators.push('.call{', 'state change after external call');
  if (text.includes('rounding')) indicators.push('division', 'truncation', 'precision loss');
  if (text.includes('access')) indicators.push('msg.sender', 'onlyOwner', 'require');
  if (text.includes('oracle')) indicators.push('getPrice', 'latestAnswer', 'spot price');

  return [...new Set(indicators)].slice(0, 8);
}

function inferStrategy(title: string, details: FindingDetails): string {
  const summary = details.summary.slice(0, 200);
  return `Look for code patterns matching: ${title}. ${summary}`;
}

function escapeYaml(s: string): string {
  return s.replace(/"/g, '\\"').replace(/\n/g, ' ');
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
