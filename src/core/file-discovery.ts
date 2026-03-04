import { readFileSync, statSync } from 'fs';
import { glob } from 'glob';
import { resolve, extname, basename } from 'path';
import { FileInfo, Language } from './types.js';

const LANGUAGE_MAP: Record<string, Language> = {
  '.sol': 'solidity',
  '.rs': 'rust',
  '.ts': 'typescript',
  '.tsx': 'typescript',
  '.js': 'javascript',
  '.jsx': 'javascript',
};

const SUPPORTED_EXTENSIONS = Object.keys(LANGUAGE_MAP);

// Filename patterns that indicate test/mock files
const TEST_FILE_PATTERNS = [
  /\.t\.sol$/,
  /_test\.sol$/,
  /_test\.rs$/,
  /\.test\.\w+$/,
  /\.spec\.\w+$/,
  /^Test\w+\.sol$/,
  /^Mock\w+\.sol$/,
];

export async function discoverFiles(
  projectPath: string,
  excludePatterns: string[],
  maxFileSizeKb: number,
  minLines: number = 20
): Promise<FileInfo[]> {
  const absPath = resolve(projectPath);
  const extensionGlob = `**/*{${SUPPORTED_EXTENSIONS.join(',')}}`;

  const files = await glob(extensionGlob, {
    cwd: absPath,
    ignore: excludePatterns,
    absolute: false,
    nodir: true,
  });

  const results: FileInfo[] = [];
  let skippedTest = 0;
  let skippedInterface = 0;
  let skippedSmall = 0;

  for (const relativePath of files) {
    const fullPath = resolve(absPath, relativePath);
    const fileName = basename(relativePath);

    // Skip test/mock files by name pattern
    if (TEST_FILE_PATTERNS.some(p => p.test(fileName))) {
      skippedTest++;
      continue;
    }

    try {
      const stat = statSync(fullPath);
      if (stat.size > maxFileSizeKb * 1024) continue;

      const content = readFileSync(fullPath, 'utf-8');
      const lineCount = content.split('\n').length;
      const ext = extname(relativePath);
      const language = LANGUAGE_MAP[ext];
      if (!language) continue;

      // Skip files below minimum line count
      if (lineCount < minLines) {
        skippedSmall++;
        continue;
      }

      // Skip pure interface files (Solidity: only function signatures, no implementation)
      if (language === 'solidity' && isPureInterface(content)) {
        skippedInterface++;
        continue;
      }

      results.push({
        path: fullPath,
        relativePath,
        language,
        lines: lineCount,
        size: stat.size,
      });
    } catch {
      // Skip unreadable files
    }
  }

  // Sort by size descending (analyze largest files first — more likely to have issues)
  results.sort((a, b) => b.lines - a.lines);

  return results;
}

/**
 * Detect if a Solidity file is a pure interface (no implementation logic to audit).
 * Pure interfaces have function declarations but no function bodies.
 */
function isPureInterface(content: string): boolean {
  // Must have "interface" keyword
  if (!content.match(/\b(interface|library)\s+\w+/)) return false;

  // If it also has "contract" keyword with implementation, it's not pure interface
  if (content.match(/\bcontract\s+\w+/)) return false;

  // Check: no function bodies (functions end with ; not {)
  const functions = content.match(/function\s+\w+[^;{]*/g) || [];
  if (functions.length === 0) return true;

  // Count functions with bodies vs without
  const withBody = (content.match(/function\s+\w+[^;]*\{/g) || []).length;
  const total = functions.length;

  // If less than 10% of functions have bodies, it's effectively an interface
  return total > 0 && withBody / total < 0.1;
}

export function detectDomain(files: FileInfo[]): string {
  const langCounts: Record<string, number> = {};
  for (const f of files) {
    langCounts[f.language] = (langCounts[f.language] || 0) + 1;
  }

  if (langCounts['solidity'] && langCounts['solidity'] > 0) return 'solidity';
  if (langCounts['rust'] && langCounts['rust'] > 0) return 'rust-solana';
  if ((langCounts['typescript'] || 0) + (langCounts['javascript'] || 0) > 0) return 'web2-typescript';
  return 'solidity'; // Default
}
