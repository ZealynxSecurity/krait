/**
 * File complexity scorer — determines which files to analyze, skip, or batch.
 *
 * Pure code analysis (no API calls). Used to reduce unnecessary API spending
 * by skipping trivially safe files and batching small ones.
 */

import { dirname } from 'path';
import { FileInfo } from './types.js';

export interface FileScore {
  file: FileInfo;
  score: number;
  decision: 'analyze' | 'skip' | 'batch';
  skipReason?: string;
  details: {
    loc: number;
    externalCalls: number;
    stateVars: number;
    publicFunctions: number;
    assemblyBlocks: number;
    uncheckedBlocks: number;
  };
}

export interface BatchGroup {
  files: FileInfo[];
  contents: Map<string, string>;
  totalLOC: number;
}

/**
 * Score a file's complexity to determine analysis strategy.
 *
 * Scoring: LOC × 0.1 + external calls × 5 + state vars × 2 + public functions × 3 + assembly × 8 + unchecked × 4
 */
export function scoreFileComplexity(file: FileInfo, content: string): FileScore {
  const lines = content.split('\n');
  const nonEmptyLines = lines.filter(l => {
    const t = l.trim();
    return t.length > 0 && !t.startsWith('//') && !t.startsWith('*') && !t.startsWith('/*');
  });

  const externalCalls = countMatches(content, /\.(call|delegatecall|staticcall)\s*[({]/g) +
    countMatches(content, /\.(transfer|send)\s*\(/g) +
    countMatches(content, /IERC\w+\(.*?\)\.\w+\(/g) +
    countMatches(content, /\.safeTransfer(From)?\s*\(/g);

  const stateVars = countMatches(content, /^\s+(mapping\s*\(|uint\d*\s|int\d*\s|address\s|bool\s|bytes\d*\s|string\s)/gm);
  const publicFunctions = countMatches(content, /function\s+\w+\s*\([^)]*\)[^{]*(external|public)[^{]*\{/g);
  const assemblyBlocks = countMatches(content, /\bassembly\s*\{/g);
  const uncheckedBlocks = countMatches(content, /\bunchecked\s*\{/g);

  const details = {
    loc: file.lines,
    externalCalls,
    stateVars,
    publicFunctions,
    assemblyBlocks,
    uncheckedBlocks,
  };

  const score = file.lines * 0.1 +
    externalCalls * 5 +
    stateVars * 2 +
    publicFunctions * 3 +
    assemblyBlocks * 8 +
    uncheckedBlocks * 4;

  // Check skip conditions
  const skipResult = shouldSkip(content, nonEmptyLines.length, file.lines, details);
  if (skipResult) {
    return { file, score, decision: 'skip', skipReason: skipResult, details };
  }

  // Batch: files <80 LOC
  if (file.lines < 80) {
    return { file, score, decision: 'batch', details };
  }

  return { file, score, decision: 'analyze', details };
}

/**
 * Check if a file should be skipped entirely.
 * Conservative — only clearly trivial files.
 */
function shouldSkip(
  content: string,
  nonEmptyLines: number,
  totalLines: number,
  details: FileScore['details']
): string | null {
  // Pure interfaces: no function bodies, only signatures
  if (isPureInterface(content)) {
    return 'pure interface (no implementation)';
  }

  // >90% comments/whitespace
  if (totalLines > 10 && nonEmptyLines / totalLines < 0.1) {
    return '>90% comments/whitespace';
  }

  // Pure libraries with only view/pure functions and zero external calls
  if (isPureLibrary(content, details)) {
    return 'pure library (only view/pure, no external calls)';
  }

  // Pure struct/enum/constant definitions (governance structs, error definitions)
  if (isPureDefinitions(content)) {
    return 'pure definitions (structs/enums/constants only)';
  }

  // Abstract base contracts with no implementation (just virtual function signatures)
  if (isAbstractBase(content)) {
    return 'abstract base (no function bodies)';
  }

  return null;
}

/**
 * Check if a file only contains struct/enum/constant/error definitions.
 * e.g., GovernanceStructs.sol, Errors.sol, Constants.sol
 */
function isPureDefinitions(content: string): boolean {
  // Must NOT have function bodies
  const functionBodies = content.match(/function\s+\w+[^;]*\{/g);
  if (functionBodies && functionBodies.length > 0) return false;

  // Must have at least one struct, enum, error, or constant
  return /\b(struct|enum|error|constant)\s+\w+/.test(content);
}

/**
 * Check if a file is an abstract base contract with no function implementations.
 */
function isAbstractBase(content: string): boolean {
  if (!/\babstract\s+contract\s+\w+/.test(content)) return false;
  // Allow simple internal setters but no real logic
  const functionBodies = content.match(/function\s+\w+[^;]*\{/g) || [];
  // If it has function bodies, check they're all trivial (single-line setters)
  if (functionBodies.length > 2) return false;
  // Must NOT have external calls
  if (/\.(call|delegatecall|transfer|send)\s*[({]/g.test(content)) return false;
  return true;
}

/**
 * Check if a file is a pure interface (no function bodies).
 */
function isPureInterface(content: string): boolean {
  // Must declare an interface
  if (!/\binterface\s+\w+/.test(content)) return false;

  // Must NOT have any contract/library declarations
  if (/\b(contract|library)\s+\w+/.test(content)) return false;

  // Must NOT have function bodies (functions ending with { ... })
  // Interface functions end with ;
  const functionBodies = content.match(/function\s+\w+[^;]*\{/g);
  return !functionBodies || functionBodies.length === 0;
}

/**
 * Check if a file is a pure utility library (all view/pure, no external calls).
 */
function isPureLibrary(content: string, details: FileScore['details']): boolean {
  if (!/\blibrary\s+\w+/.test(content)) return false;
  if (/\bcontract\s+\w+/.test(content)) return false;
  if (details.externalCalls > 0) return false;

  // All functions must be view or pure
  const allFunctions = content.match(/function\s+\w+[^}]*\{/g) || [];
  const viewPure = content.match(/function\s+\w+[^{]*(view|pure)[^{]*\{/g) || [];

  // If there are functions, all must be view/pure
  return allFunctions.length > 0 && allFunctions.length === viewPure.length;
}

/**
 * Group small files into batches for combined analysis.
 * Each batch has max 200 combined LOC and 2-3 files.
 */
export function batchSmallFiles(
  files: FileInfo[],
  contentsMap: Map<string, string>
): BatchGroup[] {
  // Sort by directory so related files end up in the same batch
  const sorted = [...files].sort((a, b) => {
    const dirA = dirname(a.relativePath);
    const dirB = dirname(b.relativePath);
    if (dirA !== dirB) return dirA.localeCompare(dirB);
    return a.relativePath.localeCompare(b.relativePath);
  });

  const batches: BatchGroup[] = [];
  let currentBatch: FileInfo[] = [];
  let currentLOC = 0;

  for (const file of sorted) {
    // Would this file push us over limits?
    if (currentBatch.length >= 3 || (currentLOC + file.lines > 200 && currentBatch.length > 0)) {
      // Flush current batch
      if (currentBatch.length > 0) {
        batches.push(makeBatchGroup(currentBatch, contentsMap));
      }
      currentBatch = [];
      currentLOC = 0;
    }

    currentBatch.push(file);
    currentLOC += file.lines;
  }

  // Flush remaining
  if (currentBatch.length > 0) {
    batches.push(makeBatchGroup(currentBatch, contentsMap));
  }

  return batches;
}

function makeBatchGroup(files: FileInfo[], contentsMap: Map<string, string>): BatchGroup {
  const contents = new Map<string, string>();
  let totalLOC = 0;
  for (const file of files) {
    const content = contentsMap.get(file.relativePath) || '';
    contents.set(file.relativePath, content);
    totalLOC += file.lines;
  }
  return { files: [...files], contents, totalLOC };
}

function countMatches(content: string, regex: RegExp): number {
  return (content.match(regex) || []).length;
}
