/**
 * Response cache for AI analyzer — avoids redundant API calls.
 *
 * Key: SHA-256 of (PROMPT_VERSION + systemPrompt + userPrompt + model)
 * Storage: JSON files in .krait-cache/ relative to the audited project.
 *
 * File content is embedded in userPrompt → file changes auto-invalidate.
 * Pattern changes are in systemPrompt → pattern updates auto-invalidate.
 * Bump PROMPT_VERSION when prompt logic changes.
 */

import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync, readdirSync, unlinkSync, appendFileSync } from 'fs';
import { join, dirname } from 'path';
import { Finding } from './types.js';

/** Bump this when prompt logic changes to invalidate all cached responses. */
export const PROMPT_VERSION = 'v1';

export interface CacheEntry {
  findings: Finding[];
  model: string;
  timestamp: string;
  promptVersion: string;
}

export interface GenericCacheEntry {
  data: unknown;
  model: string;
  timestamp: string;
  promptVersion: string;
}

export interface CacheStats {
  hits: number;
  misses: number;
  size: number;
}

export class ResponseCache {
  private cacheDir: string;
  private projectPath: string;
  private stats: CacheStats = { hits: 0, misses: 0, size: 0 };
  private gitignoreChecked = false;

  constructor(projectPath: string) {
    this.projectPath = projectPath;
    this.cacheDir = join(projectPath, '.krait-cache');
  }

  /**
   * Compute a deterministic cache key from prompt inputs.
   */
  computeKey(systemPrompt: string, userPrompt: string, model: string): string {
    const hash = createHash('sha256');
    hash.update(PROMPT_VERSION);
    hash.update(systemPrompt);
    hash.update(userPrompt);
    hash.update(model);
    return hash.digest('hex');
  }

  /**
   * Get cached findings for a given key. Returns null on miss.
   */
  get(key: string): Finding[] | null {
    const filePath = join(this.cacheDir, `${key}.json`);
    if (!existsSync(filePath)) {
      this.stats.misses++;
      return null;
    }

    try {
      const raw = readFileSync(filePath, 'utf-8');
      const entry: CacheEntry = JSON.parse(raw);

      // Invalidate if prompt version changed
      if (entry.promptVersion !== PROMPT_VERSION) {
        this.stats.misses++;
        return null;
      }

      this.stats.hits++;
      return entry.findings;
    } catch {
      this.stats.misses++;
      return null;
    }
  }

  /**
   * Get arbitrary JSON data from cache. Returns null on miss.
   */
  getJson<T>(key: string): T | null {
    const filePath = join(this.cacheDir, `${key}.json`);
    if (!existsSync(filePath)) {
      this.stats.misses++;
      return null;
    }

    try {
      const raw = readFileSync(filePath, 'utf-8');
      const entry: GenericCacheEntry = JSON.parse(raw);

      if (entry.promptVersion !== PROMPT_VERSION) {
        this.stats.misses++;
        return null;
      }

      this.stats.hits++;
      return entry.data as T;
    } catch {
      this.stats.misses++;
      return null;
    }
  }

  /**
   * Store arbitrary JSON data in cache.
   */
  setJson(key: string, data: unknown, model: string): void {
    if (!existsSync(this.cacheDir)) {
      mkdirSync(this.cacheDir, { recursive: true });
    }

    if (!this.gitignoreChecked) {
      this.ensureGitignore();
      this.gitignoreChecked = true;
    }

    const entry: GenericCacheEntry = {
      data,
      model,
      timestamp: new Date().toISOString(),
      promptVersion: PROMPT_VERSION,
    };

    const filePath = join(this.cacheDir, `${key}.json`);
    writeFileSync(filePath, JSON.stringify(entry, null, 2));
  }

  /**
   * Store findings in the cache.
   */
  set(key: string, findings: Finding[], model: string): void {
    if (!existsSync(this.cacheDir)) {
      mkdirSync(this.cacheDir, { recursive: true });
    }

    // Ensure .krait-cache/ is in .gitignore (once per session)
    if (!this.gitignoreChecked) {
      this.ensureGitignore();
      this.gitignoreChecked = true;
    }

    const entry: CacheEntry = {
      findings,
      model,
      timestamp: new Date().toISOString(),
      promptVersion: PROMPT_VERSION,
    };

    const filePath = join(this.cacheDir, `${key}.json`);
    writeFileSync(filePath, JSON.stringify(entry, null, 2));
  }

  /**
   * Ensure .krait-cache/ is listed in the nearest .gitignore.
   * Walks up from projectPath to find the git root.
   */
  private ensureGitignore(): void {
    try {
      // Find git root by walking up
      let dir = this.projectPath;
      while (dir !== dirname(dir)) {
        if (existsSync(join(dir, '.git'))) {
          const gitignorePath = join(dir, '.gitignore');
          if (existsSync(gitignorePath)) {
            const content = readFileSync(gitignorePath, 'utf-8');
            if (content.includes('.krait-cache')) return;
            appendFileSync(gitignorePath, '\n# Krait cache\n.krait-cache/\n');
          } else {
            writeFileSync(gitignorePath, '# Krait cache\n.krait-cache/\n');
          }
          return;
        }
        dir = dirname(dir);
      }
    } catch {
      // Best effort — don't break the audit over gitignore
    }
  }

  /**
   * Get cache statistics for the current session.
   */
  getStats(): CacheStats {
    return { ...this.stats, size: this.size() };
  }

  /**
   * Count cached entries on disk.
   */
  size(): number {
    if (!existsSync(this.cacheDir)) return 0;
    try {
      return readdirSync(this.cacheDir).filter(f => f.endsWith('.json')).length;
    } catch {
      return 0;
    }
  }

  /**
   * Clear all cached entries.
   */
  clear(): void {
    if (!existsSync(this.cacheDir)) return;
    try {
      const files = readdirSync(this.cacheDir).filter(f => f.endsWith('.json'));
      for (const file of files) {
        unlinkSync(join(this.cacheDir, file));
      }
    } catch {
      // Best effort
    }
  }
}
