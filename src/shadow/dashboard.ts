/**
 * Performance dashboard — track Krait's detection quality over time.
 * Stores historical results and renders them as a summary.
 */

import { existsSync, readFileSync, writeFileSync, mkdirSync } from 'fs';
import { join } from 'path';
import { ShadowAuditResult } from './runner.js';

export interface DashboardEntry {
  timestamp: string;
  contestId: string;
  contestName: string;
  precision: number;
  recall: number;
  f1: number;
  truePositives: number;
  falseNegatives: number;
  falsePositives: number;
  highRecall: number;
  mediumRecall: number;
  model: string;
  duration: number;
}

export interface DashboardData {
  lastUpdated: string;
  entries: DashboardEntry[];
}

const DASHBOARD_FILE = 'shadow-dashboard.json';

/**
 * Load existing dashboard data or create empty.
 */
export function loadDashboard(dataDir: string): DashboardData {
  const filePath = join(dataDir, DASHBOARD_FILE);
  if (existsSync(filePath)) {
    return JSON.parse(readFileSync(filePath, 'utf-8'));
  }
  return { lastUpdated: new Date().toISOString(), entries: [] };
}

/**
 * Add shadow audit results to the dashboard.
 */
export function updateDashboard(
  dataDir: string,
  results: ShadowAuditResult[],
  model: string
): DashboardData {
  if (!existsSync(dataDir)) {
    mkdirSync(dataDir, { recursive: true });
  }

  const dashboard = loadDashboard(dataDir);

  for (const result of results) {
    if (result.error) continue;

    const entry: DashboardEntry = {
      timestamp: result.timestamp,
      contestId: result.contestId,
      contestName: result.contestName,
      precision: result.comparison.precision,
      recall: result.comparison.recall,
      f1: result.comparison.f1,
      truePositives: result.comparison.truePositives,
      falseNegatives: result.comparison.falseNegatives,
      falsePositives: result.comparison.falsePositives,
      highRecall: result.comparison.byRisk.high.recall,
      mediumRecall: result.comparison.byRisk.medium.recall,
      model,
      duration: result.duration,
    };

    dashboard.entries.push(entry);
  }

  dashboard.lastUpdated = new Date().toISOString();

  const filePath = join(dataDir, DASHBOARD_FILE);
  writeFileSync(filePath, JSON.stringify(dashboard, null, 2));

  return dashboard;
}

/**
 * Format dashboard as a markdown table for console or file output.
 */
export function formatDashboard(dashboard: DashboardData): string {
  const lines: string[] = [];

  lines.push(`Last updated: ${dashboard.lastUpdated}`);
  lines.push(`Total runs: ${dashboard.entries.length}`);
  lines.push('');

  if (dashboard.entries.length === 0) {
    lines.push('No shadow audit results yet.');
    return lines.join('\n');
  }

  // Group by contest, show latest run for each
  const byContest = new Map<string, DashboardEntry[]>();
  for (const entry of dashboard.entries) {
    const existing = byContest.get(entry.contestId) || [];
    existing.push(entry);
    byContest.set(entry.contestId, existing);
  }

  // Latest results table
  lines.push('┌──────────────────────┬───────────┬────────┬────────┬─────────┬──────────┐');
  lines.push('│ Contest              │ Precision │ Recall │   F1   │ H-Recall │ M-Recall │');
  lines.push('├──────────────────────┼───────────┼────────┼────────┼─────────┼──────────┤');

  const latestEntries: DashboardEntry[] = [];
  for (const [contestId, entries] of byContest) {
    const latest = entries[entries.length - 1];
    latestEntries.push(latest);
    const name = latest.contestName.slice(0, 20).padEnd(20);
    const prec = (latest.precision * 100).toFixed(1).padStart(6) + '%';
    const rec = (latest.recall * 100).toFixed(1).padStart(5) + '%';
    const f1 = (latest.f1 * 100).toFixed(1).padStart(5) + '%';
    const hRec = (latest.highRecall * 100).toFixed(0).padStart(5) + '%';
    const mRec = (latest.mediumRecall * 100).toFixed(0).padStart(6) + '%';
    lines.push(`│ ${name} │ ${prec}   │ ${rec} │ ${f1} │  ${hRec}  │  ${mRec}  │`);
  }

  lines.push('├──────────────────────┼───────────┼────────┼────────┼─────────┼──────────┤');

  // Averages
  if (latestEntries.length > 0) {
    const avgPrec = latestEntries.reduce((s, e) => s + e.precision, 0) / latestEntries.length;
    const avgRec = latestEntries.reduce((s, e) => s + e.recall, 0) / latestEntries.length;
    const avgF1 = latestEntries.reduce((s, e) => s + e.f1, 0) / latestEntries.length;
    const avgH = latestEntries.reduce((s, e) => s + e.highRecall, 0) / latestEntries.length;
    const avgM = latestEntries.reduce((s, e) => s + e.mediumRecall, 0) / latestEntries.length;

    const prec = (avgPrec * 100).toFixed(1).padStart(6) + '%';
    const rec = (avgRec * 100).toFixed(1).padStart(5) + '%';
    const f1 = (avgF1 * 100).toFixed(1).padStart(5) + '%';
    const hRec = (avgH * 100).toFixed(0).padStart(5) + '%';
    const mRec = (avgM * 100).toFixed(0).padStart(6) + '%';
    lines.push(`│ ${'AVERAGE'.padEnd(20)} │ ${prec}   │ ${rec} │ ${f1} │  ${hRec}  │  ${mRec}  │`);
  }

  lines.push('└──────────────────────┴───────────┴────────┴────────┴─────────┴──────────┘');

  // Trend section (if we have multiple runs for the same contest)
  const contestsWithHistory = [...byContest.entries()].filter(([, entries]) => entries.length > 1);
  if (contestsWithHistory.length > 0) {
    lines.push('');
    lines.push('Trend (latest vs previous):');
    for (const [contestId, entries] of contestsWithHistory) {
      const prev = entries[entries.length - 2];
      const curr = entries[entries.length - 1];
      const recDelta = ((curr.recall - prev.recall) * 100).toFixed(1);
      const f1Delta = ((curr.f1 - prev.f1) * 100).toFixed(1);
      const arrow = parseFloat(f1Delta) >= 0 ? '↑' : '↓';
      lines.push(`  ${curr.contestName}: F1 ${arrow} ${f1Delta}pp | Recall ${recDelta}pp`);
    }
  }

  return lines.join('\n');
}
