/**
 * Pattern generator — clusters solodit findings by vulnerability type and
 * generates new YAML patterns with real code examples.
 *
 * Pipeline:
 * 1. Parse all report files → RawFinding[]
 * 2. Classify each finding into vulnerability taxonomy via Haiku
 * 3. Cluster by (category, clusterKey)
 * 4. Generate YAML patterns from clusters with 3+ findings
 * 5. Deduplicate against existing patterns
 */

import Anthropic from '@anthropic-ai/sdk';
import { readFileSync, writeFileSync, readdirSync, existsSync, statSync } from 'fs';
import { join, relative, extname } from 'path';
import * as yaml from 'js-yaml';
import { RawFinding, parseReportFile } from './solodit-parser.js';
import { VulnerabilityPattern } from '../core/types.js';

interface ClassifiedFinding extends RawFinding {
  category: string;
  clusterKey: string;
}

interface GeneratedPattern {
  id: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  detection: {
    strategy: string;
    indicators: string[];
  };
  real_examples: Array<{
    source: string;
    project: string;
    finding_id: string;
    impact: string;
    code_vulnerable?: string;
  }>;
  false_positive_notes: string;
  tags: string[];
  added_date: string;
  confidence: string;
  source_count: number;
}

export interface IngestOptions {
  maxReports?: number;
  minClusterSize?: number;
  dryRun?: boolean;
  verbose?: boolean;
}

/**
 * Main entry point — processes solodit repo and generates new patterns.
 */
export async function generatePatternsFromSolodit(
  repoPath: string,
  outputDir: string,
  existingPatterns: VulnerabilityPattern[],
  apiKey: string,
  options: IngestOptions = {},
  log: (msg: string) => void = console.log
): Promise<{ generated: number; skippedDuplicates: number; totalFindings: number }> {
  const maxReports = options.maxReports || 400;
  const minClusterSize = options.minClusterSize || 3;

  // Step 1: Find and parse report files
  log('  Scanning for report files...');
  const reportFiles = findReportFiles(repoPath, maxReports);
  log(`  Found ${reportFiles.length} report files`);

  // Step 2: Parse all reports
  log('  Parsing reports...');
  const allFindings: RawFinding[] = [];
  let parseErrors = 0;

  for (const filePath of reportFiles) {
    try {
      const content = readFileSync(filePath, 'utf-8');
      const findings = parseReportFile(relative(repoPath, filePath), content);
      allFindings.push(...findings);
    } catch {
      parseErrors++;
    }
  }

  log(`  Parsed ${allFindings.length} findings from ${reportFiles.length} reports (${parseErrors} errors)`);

  if (allFindings.length === 0) {
    log('  No findings parsed — nothing to do');
    return { generated: 0, skippedDuplicates: 0, totalFindings: 0 };
  }

  // Filter to high/medium only for pattern generation (most valuable)
  const significantFindings = allFindings.filter(f =>
    f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'
  );
  log(`  Significant findings (H/M/C): ${significantFindings.length}`);

  // Step 3: Classify findings via Haiku
  log('  Classifying findings...');
  const classified = await classifyFindings(significantFindings, apiKey, options.verbose ? log : undefined);
  log(`  Classified ${classified.length} findings`);

  // Step 4: Cluster
  const clusters = clusterFindings(classified, minClusterSize);
  log(`  Formed ${clusters.size} clusters (min size: ${minClusterSize})`);

  // Step 5: Generate patterns
  const generated: GeneratedPattern[] = [];
  let skippedDuplicates = 0;

  for (const [key, cluster] of clusters) {
    // Check against existing patterns
    if (isDuplicateOfExisting(cluster, existingPatterns)) {
      skippedDuplicates++;
      if (options.verbose) log(`    Skip (duplicate): ${key}`);
      continue;
    }

    const pattern = generatePatternFromCluster(key, cluster);
    generated.push(pattern);
  }

  log(`  Generated ${generated.length} new patterns (${skippedDuplicates} duplicates skipped)`);

  // Step 6: Write patterns
  if (!options.dryRun && generated.length > 0) {
    writePatterns(generated, outputDir);
    log(`  Written to: ${outputDir}`);
  } else if (options.dryRun) {
    log('  [DRY RUN] Would write:');
    for (const p of generated) {
      log(`    ${p.id}: ${p.name} (${p.source_count} sources, ${p.severity})`);
    }
  }

  return {
    generated: generated.length,
    skippedDuplicates,
    totalFindings: allFindings.length,
  };
}

/**
 * Find all .md report files in the solodit repo.
 */
function findReportFiles(repoPath: string, maxReports: number): string[] {
  const files: string[] = [];

  function walk(dir: string): void {
    if (files.length >= maxReports) return;

    let entries: string[];
    try {
      entries = readdirSync(dir);
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= maxReports) return;

      const fullPath = join(dir, entry);
      try {
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          // Skip hidden dirs, node_modules
          if (!entry.startsWith('.') && entry !== 'node_modules') {
            walk(fullPath);
          }
        } else if (extname(entry) === '.md' && stat.size > 500) {
          // Only include files that look like reports (not READMEs)
          if (!entry.toLowerCase().startsWith('readme') &&
              !entry.toLowerCase().startsWith('contributing')) {
            files.push(fullPath);
          }
        }
      } catch {
        // Skip inaccessible files
      }
    }
  }

  walk(repoPath);
  return files;
}

/**
 * Classify findings into vulnerability taxonomy using Haiku (batched).
 */
async function classifyFindings(
  findings: RawFinding[],
  apiKey: string,
  log?: (msg: string) => void
): Promise<ClassifiedFinding[]> {
  const client = new Anthropic({ apiKey });
  const classified: ClassifiedFinding[] = [];
  const batchSize = 10;

  for (let i = 0; i < findings.length; i += batchSize) {
    const batch = findings.slice(i, i + batchSize);
    if (log && i % 50 === 0) {
      log(`    Classifying batch ${Math.floor(i / batchSize) + 1}/${Math.ceil(findings.length / batchSize)}...`);
    }

    try {
      const batchText = batch.map((f, idx) => (
        `[${idx}] "${f.title}" (${f.severity}): ${f.description.slice(0, 200)}`
      )).join('\n');

      const response = await client.messages.create({
        model: 'claude-haiku-4-5-20251001',
        max_tokens: 1024,
        system: `You classify security audit findings into categories. For each finding, output a line with the format:
[index] category | cluster_key

Categories: reentrancy, access-control, oracle-manipulation, price-manipulation, flash-loan, rounding-error, fee-logic, token-compatibility, state-inconsistency, front-running, dos, signature, upgrade, governance, cross-contract, input-validation, storage-collision, unchecked-return, timestamp-dependence, other

The cluster_key should be a 2-4 word lowercase phrase describing the specific sub-type (e.g., "read-only reentrancy", "stale price feed", "first depositor attack").

Output ONLY the classifications, one per line.`,
        messages: [{ role: 'user', content: batchText }],
      });

      const responseText = response.content[0].type === 'text' ? response.content[0].text : '';
      const lines = responseText.trim().split('\n');

      for (const line of lines) {
        const match = line.match(/\[(\d+)\]\s*(\S+)\s*\|\s*(.+)/);
        if (match) {
          const idx = parseInt(match[1], 10);
          if (idx >= 0 && idx < batch.length) {
            classified.push({
              ...batch[idx],
              category: match[2].trim(),
              clusterKey: match[3].trim().toLowerCase(),
            });
          }
        }
      }
    } catch (err) {
      // On API error, skip this batch
      if (log) log(`    Classification batch error: ${err}`);
    }
  }

  return classified;
}

/**
 * Cluster classified findings by (category, clusterKey).
 */
function clusterFindings(
  findings: ClassifiedFinding[],
  minSize: number
): Map<string, ClassifiedFinding[]> {
  const raw = new Map<string, ClassifiedFinding[]>();

  for (const f of findings) {
    const key = `${f.category}::${f.clusterKey}`;
    const group = raw.get(key) || [];
    group.push(f);
    raw.set(key, group);
  }

  // Filter by minimum cluster size
  const filtered = new Map<string, ClassifiedFinding[]>();
  for (const [key, group] of raw) {
    if (group.length >= minSize) {
      filtered.set(key, group);
    }
  }

  return filtered;
}

/**
 * Check if a cluster duplicates an existing pattern.
 * Uses Jaccard similarity on description keywords.
 */
function isDuplicateOfExisting(
  cluster: ClassifiedFinding[],
  existingPatterns: VulnerabilityPattern[]
): boolean {
  // Build keyword set from cluster titles and descriptions
  const clusterWords = new Set<string>();
  for (const f of cluster) {
    for (const word of tokenize(f.title + ' ' + f.description.slice(0, 200))) {
      clusterWords.add(word);
    }
  }

  for (const pattern of existingPatterns) {
    const patternWords = new Set<string>();
    for (const word of tokenize(pattern.name + ' ' + pattern.description)) {
      patternWords.add(word);
    }
    for (const indicator of pattern.detection.indicators) {
      for (const word of tokenize(indicator)) {
        patternWords.add(word);
      }
    }

    const intersection = [...clusterWords].filter(w => patternWords.has(w)).length;
    const union = new Set([...clusterWords, ...patternWords]).size;
    const jaccard = union > 0 ? intersection / union : 0;

    if (jaccard >= 0.6) return true;
  }

  return false;
}

function tokenize(text: string): string[] {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9\s]/g, '')
    .split(/\s+/)
    .filter(w => w.length > 2)
    .filter(w => !['the', 'and', 'for', 'with', 'from', 'that', 'this', 'can', 'will', 'not'].includes(w));
}

/**
 * Generate a YAML pattern from a cluster of similar findings.
 */
function generatePatternFromCluster(
  key: string,
  cluster: ClassifiedFinding[]
): GeneratedPattern {
  const [category, clusterKey] = key.split('::');

  // Use the most common severity
  const severityCounts = new Map<string, number>();
  for (const f of cluster) {
    severityCounts.set(f.severity, (severityCounts.get(f.severity) || 0) + 1);
  }
  const severity = [...severityCounts.entries()].sort((a, b) => b[1] - a[1])[0][0];

  // Build detection indicators from descriptions
  const indicators = extractIndicators(cluster);

  // Pick best examples (with code snippets)
  const examples = cluster
    .filter(f => f.codeSnippets.length > 0)
    .slice(0, 3)
    .map(f => ({
      source: `solodit/${f.auditor}`,
      project: f.protocol,
      finding_id: f.title.slice(0, 60),
      impact: f.impact || f.description.slice(0, 200),
      code_vulnerable: f.codeSnippets[0]?.slice(0, 500),
    }));

  // Generate name from cluster key
  const name = clusterKey
    .split(/[-_ ]+/)
    .map(w => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');

  // ID: solodit-{category}-{clusterKey-slugified}
  const id = `solodit-${category}-${clusterKey.replace(/\s+/g, '-')}`;

  // Build description from common themes
  const description = buildDescription(cluster);

  // False positive notes from remediation patterns
  const fpNotes = buildFalsePositiveNotes(cluster);

  return {
    id,
    name,
    category,
    severity,
    description,
    detection: {
      strategy: `Look for ${clusterKey} patterns. Found in ${cluster.length} real audit reports.`,
      indicators,
    },
    real_examples: examples,
    false_positive_notes: fpNotes,
    tags: [category, 'solodit', 'auto-generated'],
    added_date: new Date().toISOString().split('T')[0],
    confidence: cluster.length >= 5 ? 'high' : 'medium',
    source_count: cluster.length,
  };
}

function extractIndicators(cluster: ClassifiedFinding[]): string[] {
  // Extract common phrases from titles
  const phraseCounts = new Map<string, number>();

  for (const f of cluster) {
    const words = tokenize(f.title);
    // Use 2-grams and 3-grams
    for (let i = 0; i < words.length - 1; i++) {
      const bigram = `${words[i]} ${words[i + 1]}`;
      phraseCounts.set(bigram, (phraseCounts.get(bigram) || 0) + 1);

      if (i < words.length - 2) {
        const trigram = `${words[i]} ${words[i + 1]} ${words[i + 2]}`;
        phraseCounts.set(trigram, (phraseCounts.get(trigram) || 0) + 1);
      }
    }
  }

  // Keep phrases that appear in 2+ findings
  const indicators = [...phraseCounts.entries()]
    .filter(([, count]) => count >= 2)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([phrase]) => phrase);

  // Add some from descriptions if needed
  if (indicators.length < 3) {
    for (const f of cluster.slice(0, 3)) {
      const desc = f.description.slice(0, 100);
      if (desc.length > 20) indicators.push(desc);
    }
  }

  return indicators.slice(0, 6);
}

function buildDescription(cluster: ClassifiedFinding[]): string {
  // Use the longest description from the cluster as the base
  const sorted = [...cluster].sort((a, b) => b.description.length - a.description.length);
  const best = sorted[0];

  let desc = best.description.slice(0, 500);
  if (cluster.length > 1) {
    desc += `\n\nThis pattern was found in ${cluster.length} independent audit reports.`;
  }

  return desc;
}

function buildFalsePositiveNotes(cluster: ClassifiedFinding[]): string {
  const remediations = cluster
    .filter(f => f.remediation.length > 20)
    .map(f => f.remediation)
    .slice(0, 3);

  if (remediations.length === 0) return '';

  return `Safe if: ${remediations[0].slice(0, 200)}`;
}

/**
 * Write generated patterns to YAML files.
 */
function writePatterns(patterns: GeneratedPattern[], outputDir: string): void {
  // Group by category for organization
  const byCategory = new Map<string, GeneratedPattern[]>();
  for (const p of patterns) {
    const group = byCategory.get(p.category) || [];
    group.push(p);
    byCategory.set(p.category, group);
  }

  for (const [category, categoryPatterns] of byCategory) {
    const filePath = join(outputDir, `solodit-${category}.yaml`);

    // Convert to YAML-friendly format (strip source_count)
    const yamlPatterns = categoryPatterns.map(p => {
      const { source_count, ...rest } = p;
      return rest;
    });

    const content = yaml.dump({ patterns: yamlPatterns }, {
      lineWidth: 120,
      noRefs: true,
    });

    writeFileSync(filePath, content, 'utf-8');
  }
}
