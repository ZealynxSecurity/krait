import { writeFileSync } from 'fs';
import { Report, Finding, ReportSummary, Severity, FindingLocation } from './types.js';

const SEVERITY_RANK: Record<Severity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const STOPWORDS = new Set([
  'a', 'an', 'and', 'on', 'in', 'of', 'the', 'to', 'for', 'with', 'when',
  'into', 'via', 'over', 'after', 'before', 'between', 'or', 'is', 'are',
  'this', 'that', 'these', 'those',
]);

const LOCATION_TOKEN_RE = /^(L?\d+|line|lines|at|near|function|fn)$/i;

function consolidationSignature(title: string): string {
  const cleaned = title
    .toLowerCase()
    .replace(/`[^`]*`/g, ' ')
    .replace(/\b0x[0-9a-f]+\b/g, ' ')
    .replace(/[^\p{L}\p{N}\s]/gu, ' ');
  const words: string[] = [];
  for (const word of cleaned.split(/\s+/)) {
    if (!word || STOPWORDS.has(word)) continue;
    if (LOCATION_TOKEN_RE.test(word)) continue;
    if (/^\d+$/.test(word)) continue;
    words.push(word);
    if (words.length >= 8) break;
  }
  return words.join(' ');
}

function jaccard(a: string, b: string): number {
  if (a === b) return 1;
  const ta = new Set(a.split(/\s+/).filter(w => w.length > 0));
  const tb = new Set(b.split(/\s+/).filter(w => w.length > 0));
  if (ta.size === 0 && tb.size === 0) return 1;
  let inter = 0;
  for (const w of ta) if (tb.has(w)) inter++;
  const union = ta.size + tb.size - inter;
  return union === 0 ? 0 : inter / union;
}

function commonPrefixTitle(titles: string[]): string {
  if (titles.length === 0) return '';
  if (titles.length === 1) return titles[0];
  const tokenLists = titles.map(t => t.split(/\s+/));
  const minLen = Math.min(...tokenLists.map(tl => tl.length));
  const prefix: string[] = [];
  for (let i = 0; i < minLen; i++) {
    const token = tokenLists[0][i];
    if (tokenLists.every(tl => tl[i].toLowerCase() === token.toLowerCase())) {
      prefix.push(token);
    } else {
      break;
    }
  }
  if (prefix.length < 2) return `${titles[0]} (multiple locations)`;
  return `${prefix.join(' ')} (multiple locations)`;
}

function mergeFindings(group: Finding[]): Finding {
  // Pick the highest-severity finding as the base.
  const sorted = [...group].sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
  const base = sorted[0];
  const titles = group.map(f => f.title);
  const locations: FindingLocation[] = group.map(f => ({
    file: f.file,
    line: f.line,
    endLine: f.endLine,
    note: f.title,
  }));
  const locationList = locations
    .map(l => `${l.file}:${l.line}`)
    .join(', ');
  const description = `${base.description}\n\nThis issue occurs at ${group.length} locations: ${locationList}.`;
  return {
    ...base,
    title: commonPrefixTitle(titles),
    description,
    impact: base.impact,
    consolidatedFrom: group.map(f => f.id),
    locations,
  };
}

/**
 * Consolidate findings that share a root cause (same severity, same category,
 * and a similar title signature). Cap each merged finding at 6 locations.
 */
export function consolidateByRootCause(findings: Finding[]): Finding[] {
  if (findings.length <= 1) return findings;

  type Group = { sig: string; findings: Finding[] };
  const groupsByKey = new Map<string, Group[]>();

  for (const f of findings) {
    const sig = consolidationSignature(f.title);
    if (!sig) {
      const key = `${f.severity}::${f.category}::__empty__::${f.id}`;
      groupsByKey.set(key, [{ sig: '', findings: [f] }]);
      continue;
    }
    const bucketKey = `${f.severity}::${f.category}`;
    const buckets = groupsByKey.get(bucketKey) ?? [];
    let placed = false;
    for (const group of buckets) {
      if (jaccard(group.sig, sig) >= 0.7) {
        group.findings.push(f);
        placed = true;
        break;
      }
    }
    if (!placed) {
      buckets.push({ sig, findings: [f] });
    }
    groupsByKey.set(bucketKey, buckets);
  }

  const out: Finding[] = [];
  for (const buckets of groupsByKey.values()) {
    for (const group of buckets) {
      if (group.findings.length === 1) {
        out.push(group.findings[0]);
        continue;
      }
      // Cap merges at 6 locations per finding — split larger groups.
      for (let i = 0; i < group.findings.length; i += 6) {
        const chunk = group.findings.slice(i, i + 6);
        if (chunk.length === 1) {
          out.push(chunk[0]);
        } else {
          out.push(mergeFindings(chunk));
        }
      }
    }
  }

  // Preserve original order as much as possible by sorting by min original index.
  const indexById = new Map<string, number>();
  findings.forEach((f, i) => indexById.set(f.id, i));
  out.sort((a, b) => {
    const minA = a.consolidatedFrom
      ? Math.min(...a.consolidatedFrom.map(id => indexById.get(id) ?? Number.MAX_SAFE_INTEGER))
      : indexById.get(a.id) ?? 0;
    const minB = b.consolidatedFrom
      ? Math.min(...b.consolidatedFrom.map(id => indexById.get(id) ?? Number.MAX_SAFE_INTEGER))
      : indexById.get(b.id) ?? 0;
    return minA - minB;
  });

  return out;
}

export function buildSummary(findings: Finding[], filesAnalyzed: number, linesOfCode: number): ReportSummary {
  return {
    totalFindings: findings.length,
    critical: findings.filter(f => f.severity === 'critical').length,
    high: findings.filter(f => f.severity === 'high').length,
    medium: findings.filter(f => f.severity === 'medium').length,
    low: findings.filter(f => f.severity === 'low').length,
    info: findings.filter(f => f.severity === 'info').length,
    filesAnalyzed,
    linesOfCode,
  };
}

export function generateJsonReport(report: Report, outputPath: string): void {
  writeFileSync(outputPath, JSON.stringify(report, null, 2));
}

export function generateMarkdownReport(report: Report): string {
  const lines: string[] = [];

  lines.push(`# Krait Security Audit Report`);
  lines.push('');
  lines.push(`**Project**: ${report.projectName}`);
  lines.push(`**Path**: ${report.projectPath}`);
  lines.push(`**Date**: ${report.timestamp}`);
  lines.push(`**Duration**: ${(report.duration / 1000).toFixed(1)}s`);
  lines.push(`**Model**: ${report.model}`);
  lines.push(`**Patterns loaded**: ${report.patternsUsed}`);
  if (report.provenOnlyNote) {
    lines.push('');
    lines.push(`**${report.provenOnlyNote}**`);
  }
  lines.push('');

  // Summary
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Severity | Count |`);
  lines.push(`|----------|-------|`);
  lines.push(`| Critical | ${report.summary.critical} |`);
  lines.push(`| High | ${report.summary.high} |`);
  lines.push(`| Medium | ${report.summary.medium} |`);
  lines.push(`| Low | ${report.summary.low} |`);
  lines.push(`| Info | ${report.summary.info} |`);
  lines.push(`| **Total** | **${report.summary.totalFindings}** |`);
  lines.push('');
  lines.push(`Files analyzed: ${report.summary.filesAnalyzed}`);
  lines.push(`Lines of code: ${report.summary.linesOfCode}`);
  lines.push('');

  if (report.findings.length === 0) {
    lines.push('## Findings');
    lines.push('');
    lines.push('No vulnerabilities found.');
    return lines.join('\n');
  }

  // Findings grouped by severity
  const severityOrder = ['critical', 'high', 'medium', 'low', 'info'] as const;

  for (const severity of severityOrder) {
    const sevFindings = report.findings.filter(f => f.severity === severity);
    if (sevFindings.length === 0) continue;

    lines.push(`## ${severity.charAt(0).toUpperCase() + severity.slice(1)} Findings`);
    lines.push('');

    for (const finding of sevFindings) {
      lines.push(`### ${finding.id}: ${finding.title}`);
      lines.push('');
      if (finding.locations && finding.locations.length > 1) {
        lines.push('**Location**:');
        lines.push('');
        lines.push('| Contract | Function | Line |');
        lines.push('|----------|----------|------|');
        for (const loc of finding.locations) {
          const fn = loc.function ?? loc.note ?? '';
          lines.push(`| \`${loc.file}\` | ${fn} | ${loc.line} |`);
        }
        lines.push('');
      } else {
        lines.push(`**File**: \`${finding.file}:${finding.line}\``);
      }
      lines.push(`**Confidence**: ${finding.confidence}`);
      lines.push(`**Category**: ${finding.category}`);
      if (finding.patternId) {
        lines.push(`**Pattern**: ${finding.patternId}`);
      }
      lines.push(`**Evidence**: [${finding.evidenceTag ?? 'CODE-TRACE'}]`);
      if (finding.originalSeverity && finding.originalSeverity !== finding.severity) {
        lines.push(`**Original Severity**: ${finding.originalSeverity}`);
      }
      lines.push('');
      lines.push(`**Description**: ${finding.description}`);
      lines.push('');
      lines.push(`**Impact**: ${finding.impact}`);
      if (finding.impactPremise) {
        lines.push('');
        lines.push(`**Impact Premise**: ${finding.impactPremise}`);
      }
      lines.push('');
      lines.push(`**Remediation**: ${finding.remediation}`);
      if (finding.codeSnippet) {
        lines.push('');
        lines.push('**Code**:');
        lines.push('```');
        lines.push(finding.codeSnippet);
        lines.push('```');
      }
      lines.push('');
      lines.push('---');
      lines.push('');
    }
  }

  lines.push('');
  lines.push('*Generated by [Krait](https://github.com/ZealynxSecurity/krait) — AI Security Auditor by Zealynx Security*');

  return lines.join('\n');
}

export function writeMarkdownReport(report: Report, outputPath: string): void {
  const md = generateMarkdownReport(report);
  writeFileSync(outputPath, md);
}
