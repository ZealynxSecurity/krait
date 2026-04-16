/**
 * Fuzz reporter — generates JSON and Markdown reports for invariant fuzzing results.
 */

import { writeFileSync, mkdirSync } from 'fs';
import { dirname } from 'path';
import { FuzzReport, InvariantResult, FuzzPipelineStats, Invariant } from './types.js';

export function generateFuzzJsonReport(report: FuzzReport, outputPath: string): void {
  mkdirSync(dirname(outputPath), { recursive: true });
  writeFileSync(outputPath, JSON.stringify(report, null, 2));
}

export function generateFuzzMarkdownReport(report: FuzzReport): string {
  const lines: string[] = [];

  lines.push(`# Krait Invariant Fuzzing Report`);
  lines.push('');
  lines.push(`**Project**: ${report.projectName}`);
  lines.push(`**Path**: ${report.projectPath}`);
  lines.push(`**Date**: ${report.timestamp}`);
  lines.push(`**Duration**: ${(report.duration / 1000).toFixed(1)}s`);
  lines.push(`**Model**: ${report.model}`);
  lines.push(`**Fuzz runs**: ${report.fuzzRuns}`);
  lines.push(`**Max fix iterations**: ${report.maxIterations}`);
  lines.push('');

  // Summary table
  lines.push('## Summary');
  lines.push('');
  lines.push(`| Status | Count |`);
  lines.push(`|--------|-------|`);
  lines.push(`| HOLDS | ${report.summary.invariantsHold} |`);
  lines.push(`| VIOLATED | ${report.summary.invariantsViolated} |`);
  lines.push(`| INCONCLUSIVE | ${report.summary.invariantsInconclusive} |`);
  lines.push(`| **Total Invariants** | **${report.summary.invariantsExtracted}** |`);
  lines.push('');
  lines.push(`Files analyzed: ${report.filesAnalyzed.length}`);
  lines.push(`Test files generated: ${report.summary.testsGenerated}`);
  lines.push(`Total forge runs: ${report.summary.totalForgeRuns}`);
  lines.push(`Total fix iterations: ${report.summary.totalIterations}`);
  lines.push('');

  // ─── Violated Invariants (the main findings) ───
  const violated = report.results.filter(r => r.status === 'VIOLATED');
  if (violated.length > 0) {
    lines.push('---');
    lines.push('');
    lines.push('## Violated Invariants');
    lines.push('');
    lines.push('These invariants were broken by the fuzzer — potential vulnerabilities in the source contracts.');
    lines.push('');

    for (const result of violated) {
      lines.push(`### ${result.invariant.id}: ${result.invariant.description}`);
      lines.push('');
      lines.push(`**Status**: VIOLATED`);
      lines.push(`**Contract**: \`${result.invariant.contractName}\``);
      lines.push(`**File**: \`${result.invariant.file}\``);
      lines.push(`**Category**: ${result.invariant.category}`);
      lines.push(`**Priority**: ${result.invariant.priority}`);
      if (result.invariant.formalExpression) {
        lines.push(`**Formal**: \`${result.invariant.formalExpression}\``);
      }
      lines.push(`**State variables**: ${result.invariant.stateVariables.join(', ')}`);
      lines.push(`**Related functions**: ${result.invariant.relatedFunctions.join(', ')}`);
      lines.push('');

      if (result.counterexample) {
        lines.push('**Counterexample**:');
        lines.push('```');
        lines.push(result.counterexample);
        lines.push('```');
        lines.push('');
      }

      if (result.notes) {
        lines.push(`**Notes**: ${result.notes}`);
        lines.push('');
      }

      // Iteration history
      if (result.iterations.length > 1) {
        lines.push(`**Iterations**: ${result.iterations.length}`);
        for (const iter of result.iterations) {
          lines.push(`- Iteration ${iter.iteration} (${iter.action}): ${iter.description}`);
        }
        lines.push('');
      }

      lines.push('---');
      lines.push('');
    }
  }

  // ─── Invariants That Hold ───
  const holds = report.results.filter(r => r.status === 'HOLDS');
  if (holds.length > 0) {
    lines.push('## Invariants That Hold');
    lines.push('');
    lines.push('These invariants were verified by the fuzzer — no violations found.');
    lines.push('');

    // Group by category for readability
    const byCategory = new Map<string, InvariantResult[]>();
    for (const result of holds) {
      const cat = result.invariant.category;
      if (!byCategory.has(cat)) byCategory.set(cat, []);
      byCategory.get(cat)!.push(result);
    }

    for (const [category, results] of byCategory) {
      lines.push(`### ${category}`);
      lines.push('');
      for (const result of results) {
        const formal = result.invariant.formalExpression
          ? ` — \`${result.invariant.formalExpression}\``
          : '';
        lines.push(`- **${result.invariant.id}**: ${result.invariant.description}${formal} (\`${result.invariant.contractName}\`)`);
      }
      lines.push('');
    }
  }

  // ─── Inconclusive ───
  const inconclusive = report.results.filter(r => r.status === 'INCONCLUSIVE');
  if (inconclusive.length > 0) {
    lines.push('## Inconclusive');
    lines.push('');
    lines.push('These invariants could not be conclusively tested. The test may have persistent issues.');
    lines.push('');

    for (const result of inconclusive) {
      lines.push(`- **${result.invariant.id}**: ${result.invariant.description} (\`${result.invariant.contractName}\`) — ${result.notes || 'unknown reason'}`);
    }
    lines.push('');
  }

  // ─── All Invariants Reference ───
  lines.push('## All Extracted Invariants');
  lines.push('');
  lines.push('| ID | Contract | Category | Priority | Description | Status |');
  lines.push('|----|----------|----------|----------|-------------|--------|');
  for (const inv of report.invariants) {
    const result = report.results.find(r => r.invariantId === inv.id);
    const status = result?.status || 'N/A';
    const desc = inv.description.length > 60 ? inv.description.slice(0, 57) + '...' : inv.description;
    lines.push(`| ${inv.id} | ${inv.contractName} | ${inv.category} | ${inv.priority} | ${desc} | ${status} |`);
  }
  lines.push('');

  lines.push('');
  lines.push('*Generated by [Krait](https://github.com/ZealynxSecurity/krait) — Invariant Fuzzing by Zealynx Security*');

  return lines.join('\n');
}

export function writeFuzzMarkdownReport(report: FuzzReport, outputPath: string): void {
  mkdirSync(dirname(outputPath), { recursive: true });
  const md = generateFuzzMarkdownReport(report);
  writeFileSync(outputPath, md);
}
