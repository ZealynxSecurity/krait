/**
 * Multi-agent pipeline orchestrator.
 * Detector → (Deep Pass) → (Flow Analysis) → Reasoner → Critic → Ranker
 */

import Anthropic from '@anthropic-ai/sdk';
import { Finding, FileInfo, KraitConfig, ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { ProjectContext } from '../analysis/context-gatherer.js';
import { PatternLoader } from '../knowledge/pattern-loader.js';
import { AIAnalyzer } from '../analysis/ai-analyzer.js';
import { scoreFileComplexity } from '../core/file-scorer.js';
import { CandidateFinding, MultiAgentStats } from './types.js';
import { detect, CandidateCounter } from './detector.js';
import { reason } from './reasoner.js';
import { criticize } from './critic.js';
import { rank } from './ranker.js';

export interface MultiAgentOptions {
  architectureContext?: ArchitectureAnalysis | null;
  projectContext?: ProjectContext | null;
  soloditContext?: string;
  verbose?: boolean;
  threshold?: number;             // Ranker composite score threshold (default 40)
  config?: KraitConfig;           // Full config for deep pass model selection
}

/**
 * Run the full multi-agent audit pipeline.
 * Returns findings compatible with the existing report pipeline.
 */
export async function runMultiAgentPipeline(
  client: Anthropic,
  files: FileInfo[],
  fileContentsMap: Map<string, string>,
  patternLoader: PatternLoader,
  domainPatterns: ReturnType<PatternLoader['getPatternsByDomain']>,
  model: string,
  cache?: ResponseCache | null,
  options?: MultiAgentOptions,
): Promise<{ findings: Finding[]; stats: MultiAgentStats }> {
  const verbose = options?.verbose ?? false;
  const threshold = options?.threshold ?? 40;
  const counter = new CandidateCounter();
  const pipelineStart = Date.now();
  const stageTime = (label: string, start: number) => {
    if (verbose) console.error(`  [multi-agent] ${label} (${((Date.now() - start) / 1000).toFixed(1)}s)`);
  };

  // ─── Stage 1: DETECT (wide net per-file, parallel) ───
  if (verbose) console.error('\n  [multi-agent] Stage 1: Detection (wide net)...');
  const detectStart = Date.now();

  const allCandidates: CandidateFinding[] = [];
  const CONCURRENCY = 5;

  const detectTasks = files
    .filter(file => fileContentsMap.has(file.relativePath))
    .map(file => async () => {
      const content = fileContentsMap.get(file.relativePath)!;
      try {
        const filePatterns = patternLoader.filterPatternsForFile(domainPatterns, content);
        const patternContext = patternLoader.formatForPrompt(filePatterns);

        const candidates = await detect(
          client, file, content, patternContext, model, counter, cache,
          {
            architectureContext: options?.architectureContext,
            projectContext: options?.projectContext,
            soloditContext: options?.soloditContext,
            verbose,
          },
        );

        if (verbose) {
          console.error(`    ${file.relativePath}: ${candidates.length} candidates`);
        }
        return candidates;
      } catch (err) {
        if (verbose) {
          console.error(`    ${file.relativePath}: error — ${err instanceof Error ? err.message : err}`);
        }
        return [];
      }
    });

  const detectResults = await runParallel(detectTasks, CONCURRENCY);
  for (const candidates of detectResults) {
    allCandidates.push(...candidates);
  }

  stageTime(`Detection complete: ${allCandidates.length} total candidates`, detectStart);

  // ─── Stage 1b: Deep pass + flow analysis (recall boost) ───
  // Convert first-pass candidates to Finding-like objects so deep pass knows what to skip
  const firstPassAsFindings: Finding[] = allCandidates.map(c => ({
    id: c.id,
    title: c.title,
    severity: c.severity,
    confidence: c.detectorConfidence >= 70 ? 'high' as const : c.detectorConfidence >= 40 ? 'medium' as const : 'low' as const,
    file: c.file,
    line: c.line,
    description: c.description,
    impact: c.description,
    remediation: c.remediation,
    category: c.category,
    codeSnippet: c.codeSnippet,
  }));

  const deepModel = options?.config?.deepModel || model;
  const isQuick = options?.config?.quick ?? false;

  if (!isQuick) {
    // Deep pass on top-N files by complexity
    const fileScores = files.map(file => {
      const content = fileContentsMap.get(file.relativePath)!;
      return scoreFileComplexity(file, content);
    }).filter(s => s.decision !== 'skip');

    const deepLimit = fileScores.length <= 8 ? fileScores.length : 5;
    const ranked = fileScores
      .map(s => {
        const existingFindings = firstPassAsFindings.filter(f => f.file === s.file.relativePath);
        const deepScore = s.score + existingFindings.length * 3;
        return { file: s.file, score: deepScore, existingFindings };
      })
      .sort((a, b) => b.score - a.score)
      .slice(0, deepLimit);

    if (ranked.length > 0 && options?.config) {
      if (verbose) console.error(`\n  [multi-agent] Stage 1b: Deep pass on ${ranked.length} files (${deepModel.includes('opus') ? 'Opus' : 'Sonnet'})...`);

      const analyzer = new AIAnalyzer(options.config);
      if (options.projectContext) analyzer.setProjectContext(options.projectContext);
      if (options.architectureContext) analyzer.setArchitectureContext(options.architectureContext);
      if (options.soloditContext) analyzer.setSoloditContext(options.soloditContext);
      if (cache) analyzer.setCache(cache);

      let deepTotal = 0;
      for (const { file, existingFindings } of ranked) {
        const content = fileContentsMap.get(file.relativePath);
        if (!content) continue;
        try {
          const filePatterns = patternLoader.filterPatternsForFile(domainPatterns, content);
          const patternContext = patternLoader.formatForPrompt(filePatterns);
          const deepFindings = await analyzer.analyzeDeep(file, content, existingFindings, patternContext);

          // Convert deep findings to CandidateFindings and merge
          for (const df of deepFindings) {
            allCandidates.push({
              id: counter.next(),
              title: df.title,
              severity: df.severity === 'info' ? 'low' : df.severity as CandidateFinding['severity'],
              file: df.file,
              line: df.line,
              endLine: df.endLine,
              category: df.category,
              description: df.description,
              codeSnippet: df.codeSnippet || '',
              affectedFunctions: [],
              relatedContracts: [],
              detectorConfidence: df.confidence === 'high' ? 85 : df.confidence === 'medium' ? 65 : 40,
              remediation: df.remediation,
            });
          }
          deepTotal += deepFindings.length;
        } catch {
          // continue with other files
        }
      }

      if (verbose) {
        console.error(`  [multi-agent] Deep pass complete: +${deepTotal} candidates`);
      }

      // Uncovered function analysis — find bugs in functions that all passes missed
      const allCandidateFindings: Finding[] = allCandidates.map(c => ({
        id: c.id, title: c.title, severity: c.severity,
        confidence: c.detectorConfidence >= 70 ? 'high' as const : c.detectorConfidence >= 40 ? 'medium' as const : 'low' as const,
        file: c.file, line: c.line, description: c.description,
        impact: c.description, remediation: c.remediation, category: c.category,
        codeSnippet: c.codeSnippet,
      }));

      let uncoveredTotal = 0;
      for (const { file } of ranked) {
        const content = fileContentsMap.get(file.relativePath);
        if (!content) continue;
        try {
          const filePatterns = patternLoader.filterPatternsForFile(domainPatterns, content);
          const patternContext = patternLoader.formatForPrompt(filePatterns);
          const fileCandidates = allCandidateFindings.filter(f => f.file === file.relativePath);
          const uncoveredFindings = await analyzer.analyzeUncoveredFunctions(file, content, fileCandidates, patternContext);

          for (const uf of uncoveredFindings) {
            allCandidates.push({
              id: counter.next(),
              title: uf.title,
              severity: uf.severity === 'info' ? 'low' : uf.severity as CandidateFinding['severity'],
              file: uf.file, line: uf.line, endLine: uf.endLine,
              category: uf.category, description: uf.description,
              codeSnippet: uf.codeSnippet || '',
              affectedFunctions: [], relatedContracts: [],
              detectorConfidence: uf.confidence === 'high' ? 85 : uf.confidence === 'medium' ? 65 : 40,
              remediation: uf.remediation,
            });
          }
          uncoveredTotal += uncoveredFindings.length;
        } catch {
          // continue
        }
      }

      if (verbose && uncoveredTotal > 0) {
        console.error(`  [multi-agent] Uncovered functions: +${uncoveredTotal} candidates`);
      }
    }

    // Flow-based analysis (if architecture context available and multi-file)
    if (files.length > 1 && options?.architectureContext?.fundFlows?.length && options.config) {
      if (verbose) console.error(`  [multi-agent] Stage 1c: Flow analysis (${Math.min(3, options.architectureContext.fundFlows.length)} flows)...`);

      const analyzer = new AIAnalyzer(options.config);
      if (options.projectContext) analyzer.setProjectContext(options.projectContext);
      if (options.architectureContext) analyzer.setArchitectureContext(options.architectureContext);
      if (options.soloditContext) analyzer.setSoloditContext(options.soloditContext);
      if (cache) analyzer.setCache(cache);

      try {
        const fileContents = files.map(f => ({
          file: f,
          content: fileContentsMap.get(f.relativePath) || '',
        }));
        const crossPatternContext = patternLoader.formatForPrompt(domainPatterns);
        const flowFindings = await analyzer.analyzeFlows(
          options.architectureContext.fundFlows,
          fileContents,
          firstPassAsFindings,
          options.architectureContext,
          crossPatternContext,
        );

        for (const ff of flowFindings) {
          allCandidates.push({
            id: counter.next(),
            title: ff.title,
            severity: ff.severity === 'info' ? 'low' : ff.severity as CandidateFinding['severity'],
            file: ff.file,
            line: ff.line,
            endLine: ff.endLine,
            category: ff.category,
            description: ff.description,
            codeSnippet: ff.codeSnippet || '',
            affectedFunctions: [],
            relatedContracts: [],
            detectorConfidence: ff.confidence === 'high' ? 85 : ff.confidence === 'medium' ? 65 : 40,
            remediation: ff.remediation,
          });
        }

        if (verbose) {
          console.error(`  [multi-agent] Flow analysis complete: +${flowFindings.length} candidates`);
        }
      } catch (err) {
        if (verbose) {
          console.error(`  [multi-agent] Flow analysis failed: ${err instanceof Error ? err.message : err}`);
        }
      }
    }
  }

  // ─── Stage 1d: Filter obvious noise + pre-dedup ───
  let filtered = allCandidates.filter(c => c.detectorConfidence >= 20);
  if (verbose && filtered.length < allCandidates.length) {
    console.error(`  [multi-agent] Confidence filter: ${allCandidates.length} → ${filtered.length} (dropped ${allCandidates.length - filtered.length} with confidence < 20)`);
  }

  // Quick dedup before Reasoner to save API calls on near-identical candidates
  const beforeDedup = filtered.length;
  filtered = deduplicateCandidates(filtered);
  if (verbose && filtered.length < beforeDedup) {
    console.error(`  [multi-agent] Pre-dedup: ${beforeDedup} → ${filtered.length} (merged ${beforeDedup - filtered.length} near-duplicates)`);
  }

  if (filtered.length === 0) {
    return {
      findings: [],
      stats: {
        detectCandidates: allCandidates.length,
        afterConfidenceFilter: 0,
        reasonerExploitable: 0,
        criticValid: 0,
        criticUncertain: 0,
        criticInvalid: 0,
        finalFindings: 0,
      },
    };
  }

  // ─── Stage 2: REASON ───
  if (verbose) console.error(`\n  [multi-agent] Stage 2: Reasoning (exploit proofs for ${filtered.length} candidates)...`);
  const reasonStart = Date.now();

  const proofs = await reason(
    client, filtered, fileContentsMap,
    options?.architectureContext ?? null,
    model, cache, verbose,
  );

  // Filter non-exploitable
  const exploitableIds = new Set(
    proofs.filter(p => p.isExploitable).map(p => p.candidateId),
  );
  const exploitable = filtered.filter(c => exploitableIds.has(c.id));
  const exploitableProofs = proofs.filter(p => p.isExploitable);

  stageTime(`Reasoning complete: ${exploitable.length}/${filtered.length} exploitable`, reasonStart);
  if (verbose) {
    const dropped = filtered.filter(c => !exploitableIds.has(c.id));
    if (dropped.length > 0) {
      for (const d of dropped.slice(0, 5)) {
        const proof = proofs.find(p => p.candidateId === d.id);
        console.error(`    Dropped: "${d.title}" — ${proof?.attackScenario?.slice(0, 80) || 'no proof'}`);
      }
    }
  }

  if (exploitable.length === 0) {
    return {
      findings: [],
      stats: {
        detectCandidates: allCandidates.length,
        afterConfidenceFilter: filtered.length,
        reasonerExploitable: 0,
        criticValid: 0,
        criticUncertain: 0,
        criticInvalid: 0,
        finalFindings: 0,
      },
    };
  }

  // ─── Stage 3: CRITICIZE ───
  if (verbose) console.error(`\n  [multi-agent] Stage 3: Critic (falsification for ${exploitable.length} candidates)...`);
  const criticStart = Date.now();

  const verdicts = await criticize(
    client, exploitable, exploitableProofs, fileContentsMap, model, cache, verbose,
    options?.architectureContext,
  );

  const validCount = verdicts.filter(v => v.verdict === 'valid').length;
  const uncertainCount = verdicts.filter(v => v.verdict === 'uncertain').length;
  const invalidCount = verdicts.filter(v => v.verdict === 'invalid').length;

  stageTime(`Critic complete: ${validCount} valid, ${uncertainCount} uncertain, ${invalidCount} invalid`, criticStart);

  // ─── Stage 4: RANK ───
  if (verbose) console.error(`\n  [multi-agent] Stage 4: Ranking (threshold=${threshold})...`);

  const ranked = rank(exploitable, exploitableProofs, verdicts, threshold);

  // Convert to Finding[] with proper IDs
  const findings: Finding[] = ranked.map((r, i) => ({
    ...r.finding,
    id: `KRAIT-${String(i + 1).padStart(3, '0')}`,
    remediation: r.finding.remediation || extractRemediation(r.finding.description),
  }));

  if (verbose) {
    const totalTime = ((Date.now() - pipelineStart) / 1000).toFixed(1);
    console.error(`  [multi-agent] Final: ${findings.length} findings (total: ${totalTime}s)`);
    for (const f of findings) {
      console.error(`    [${f.severity}] ${f.title} (${f.file}:${f.line})`);
    }
  }

  return {
    findings,
    stats: {
      detectCandidates: allCandidates.length,
      afterConfidenceFilter: filtered.length,
      reasonerExploitable: exploitable.length,
      criticValid: validCount,
      criticUncertain: uncertainCount,
      criticInvalid: invalidCount,
      finalFindings: findings.length,
    },
  };
}

/**
 * Quick dedup of candidates before sending to Reasoner.
 * Merges near-identical candidates (same file, similar title, close lines).
 * Keeps the one with higher detector confidence.
 */
function deduplicateCandidates(candidates: CandidateFinding[]): CandidateFinding[] {
  if (candidates.length <= 1) return candidates;

  const result: CandidateFinding[] = [];
  const dropped = new Set<number>();

  for (let i = 0; i < candidates.length; i++) {
    if (dropped.has(i)) continue;
    for (let j = i + 1; j < candidates.length; j++) {
      if (dropped.has(j)) continue;
      const a = candidates[i], b = candidates[j];
      if (a.file !== b.file) continue;

      // Same category + close lines + similar title
      const lineDist = Math.abs(a.line - b.line);
      if (a.category === b.category && lineDist <= 5) {
        if (a.detectorConfidence >= b.detectorConfidence) {
          dropped.add(j);
        } else {
          dropped.add(i);
          break;
        }
      }
      // Very similar titles regardless of category
      if (lineDist <= 3) {
        const sim = quickTitleSimilarity(a.title, b.title);
        if (sim >= 0.5) {
          if (a.detectorConfidence >= b.detectorConfidence) {
            dropped.add(j);
          } else {
            dropped.add(i);
            break;
          }
        }
      }
    }
    if (!dropped.has(i)) result.push(candidates[i]);
  }
  return result;
}

function quickTitleSimilarity(a: string, b: string): number {
  const wordsA = new Set(a.toLowerCase().split(/\s+/).filter(w => w.length > 2));
  const wordsB = new Set(b.toLowerCase().split(/\s+/).filter(w => w.length > 2));
  if (wordsA.size === 0 && wordsB.size === 0) return 1;
  let intersection = 0;
  for (const w of wordsA) if (wordsB.has(w)) intersection++;
  const union = wordsA.size + wordsB.size - intersection;
  return union === 0 ? 0 : intersection / union;
}

/**
 * Run async tasks with a concurrency limit.
 */
async function runParallel<T>(tasks: Array<() => Promise<T>>, limit: number): Promise<T[]> {
  const results: T[] = new Array(tasks.length);
  let index = 0;

  async function worker() {
    while (index < tasks.length) {
      const i = index++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

function extractRemediation(description: string): string {
  const lines = description.split('\n');
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].toLowerCase().includes('fix') || lines[i].toLowerCase().includes('remediat')) {
      return lines.slice(i).join('\n').slice(0, 300);
    }
  }
  return 'Review the identified code path and apply appropriate fixes.';
}
