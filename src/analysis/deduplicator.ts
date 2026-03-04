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

  const groups: Finding[][] = [];
  const assigned = new Set<number>();

  for (let i = 0; i < findings.length; i++) {
    if (assigned.has(i)) continue;

    const group = [findings[i]];
    assigned.add(i);

    for (let j = i + 1; j < findings.length; j++) {
      if (assigned.has(j)) continue;

      if (areDuplicates(findings[i], findings[j])) {
        group.push(findings[j]);
        assigned.add(j);
      }
    }

    groups.push(group);
  }

  return groups.map(mergeDuplicateGroup);
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
    if (titleSimilarity >= 0.7) return true;
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
