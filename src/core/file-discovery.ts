import { readFileSync, statSync } from 'fs';
import { glob } from 'glob';
import { resolve, relative, extname } from 'path';
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

export async function discoverFiles(
  projectPath: string,
  excludePatterns: string[],
  maxFileSizeKb: number
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

  for (const relativePath of files) {
    const fullPath = resolve(absPath, relativePath);
    try {
      const stat = statSync(fullPath);
      if (stat.size > maxFileSizeKb * 1024) continue;

      const content = readFileSync(fullPath, 'utf-8');
      const lineCount = content.split('\n').length;
      const ext = extname(relativePath);
      const language = LANGUAGE_MAP[ext];
      if (!language) continue;

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
