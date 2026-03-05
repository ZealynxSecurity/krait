import { Finding } from '../core/types.js';

/**
 * Deduplicate findings that describe the same issue pattern.
 * Two findings are considered duplicates if they have:
 * 1. Same category AND similar title (same pattern in different files), OR
 * 2. Same file AND overlapping line range AND same category
 *
 * When merging, keep the highest-severity instance and note affected locations.
 */
export function deduplicateFindings(findings: Finding[]): Finding[] {
  if (findings.length <= 1) return findings;

  // First suppress pattern flood, then deduplicate
  const capped = suppressPatternFlood(findings);

  const groups: Finding[][] = [];
  const assigned = new Set<number>();

  for (let i = 0; i < capped.length; i++) {
    if (assigned.has(i)) continue;

    const group = [capped[i]];
    assigned.add(i);

    for (let j = i + 1; j < capped.length; j++) {
      if (assigned.has(j)) continue;

      if (areDuplicates(capped[i], capped[j])) {
        group.push(capped[j]);
        assigned.add(j);
      }
    }

    groups.push(group);
  }

  return groups.map(mergeDuplicateGroup);
}

/**
 * Cap same-category medium/low findings at 3 instances.
 * Critical/high are always kept.
 */
function suppressPatternFlood(findings: Finding[]): Finding[] {
  const categoryCounts = new Map<string, number>();
  const result: Finding[] = [];

  for (const f of findings) {
    // Always keep critical/high
    if (f.severity === 'critical' || f.severity === 'high') {
      result.push(f);
      continue;
    }

    const key = f.category;
    const count = categoryCounts.get(key) || 0;
    if (count < 3) {
      result.push(f);
      categoryCounts.set(key, count + 1);
    }
    // else: silently drop — too many of same category at medium/low
  }

  return result;
}

function areDuplicates(a: Finding, b: Finding): boolean {
  // Same file, overlapping lines, same category
  if (a.file === b.file && a.category === b.category) {
    const overlap = Math.abs(a.line - b.line) <= 10;
    if (overlap) return true;
  }

  // Different files, same category, similar titles (same pattern repeated)
  if (a.category === b.category && a.file !== b.file) {
    const titleSimilarity = computeTitleSimilarity(a.title, b.title);
    if (titleSimilarity >= 0.5) return true;

    // For oracle contracts specifically, merge findings in the same directory
    // that have the same severity — these are typically repetitive "oracle can be manipulated"
    if (a.category === 'oracle-manipulation' && a.severity === b.severity) {
      const dirA = a.file.split('/').slice(0, -1).join('/');
      const dirB = b.file.split('/').slice(0, -1).join('/');
      if (dirA === dirB && dirA.length > 0) return true;
    }
  }

  return false;
}

function computeTitleSimilarity(a: string, b: string): number {
  const wordsA = normalizeTitle(a);
  const wordsB = normalizeTitle(b);

  if (wordsA.length === 0 || wordsB.length === 0) return 0;

  const setA = new Set(wordsA);
  const setB = new Set(wordsB);
  const intersection = [...setA].filter(w => setB.has(w)).length;
  const union = new Set([...setA, ...setB]).size;

  return intersection / union; // Jaccard similarity
}

function normalizeTitle(title: string): string[] {
  return title
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, '')
    .split(/\s+/)
    .filter(w => w.length > 2)
    .filter(w => !['the', 'and', 'for', 'with', 'from', 'that', 'this', 'function'].includes(w));
}

function mergeDuplicateGroup(group: Finding[]): Finding {
  if (group.length === 1) return group[0];

  // Sort by severity (critical > high > medium > low > info)
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
  group.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  const primary = { ...group[0] };

  // If findings span multiple files, note that in the description
  const uniqueFiles = [...new Set(group.map(f => f.file))];
  if (uniqueFiles.length > 1) {
    const locations = group.map(f => `${f.file}:${f.line}`).join(', ');
    primary.description = `${primary.description}\n\nAlso found in: ${locations}`;
  }

  // Boost confidence if found multiple times independently
  if (group.length >= 3) {
    primary.confidence = 'high';
  } else if (group.length >= 2 && primary.confidence === 'low') {
    primary.confidence = 'medium';
  }

  return primary;
}
