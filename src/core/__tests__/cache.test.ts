import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { ResponseCache, PROMPT_VERSION } from '../cache.js';
import { Finding } from '../types.js';
import { mkdirSync, rmSync, existsSync, writeFileSync, readFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const TEST_DIR = join(tmpdir(), 'krait-cache-test-' + Date.now());

function makeFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'KRAIT-001',
    title: 'Test finding',
    severity: 'high',
    confidence: 'high',
    file: 'test.sol',
    line: 10,
    description: 'Test',
    impact: 'Test',
    remediation: 'Test',
    category: 'test',
    ...overrides,
  };
}

describe('ResponseCache', () => {
  let cache: ResponseCache;

  beforeEach(() => {
    mkdirSync(TEST_DIR, { recursive: true });
    cache = new ResponseCache(TEST_DIR);
  });

  afterEach(() => {
    rmSync(TEST_DIR, { recursive: true, force: true });
  });

  describe('computeKey', () => {
    it('produces deterministic keys', () => {
      const key1 = cache.computeKey('sys', 'user', 'model');
      const key2 = cache.computeKey('sys', 'user', 'model');
      expect(key1).toBe(key2);
    });

    it('produces different keys for different inputs', () => {
      const key1 = cache.computeKey('sys1', 'user', 'model');
      const key2 = cache.computeKey('sys2', 'user', 'model');
      expect(key1).not.toBe(key2);
    });

    it('different models produce different keys', () => {
      const key1 = cache.computeKey('sys', 'user', 'sonnet');
      const key2 = cache.computeKey('sys', 'user', 'opus');
      expect(key1).not.toBe(key2);
    });

    it('key is a hex SHA-256 hash', () => {
      const key = cache.computeKey('sys', 'user', 'model');
      expect(key).toMatch(/^[0-9a-f]{64}$/);
    });
  });

  describe('get/set', () => {
    it('returns null on cache miss', () => {
      const result = cache.get('nonexistent');
      expect(result).toBeNull();
    });

    it('returns findings on cache hit', () => {
      const findings = [makeFinding()];
      const key = cache.computeKey('sys', 'user', 'model');
      cache.set(key, findings, 'model');
      const result = cache.get(key);
      expect(result).toHaveLength(1);
      expect(result![0].title).toBe('Test finding');
    });

    it('stores findings as JSON files in .krait-cache/', () => {
      const key = cache.computeKey('sys', 'user', 'model');
      cache.set(key, [makeFinding()], 'model');
      const filePath = join(TEST_DIR, '.krait-cache', `${key}.json`);
      expect(existsSync(filePath)).toBe(true);
    });

    it('invalidates when prompt version changes', () => {
      const key = cache.computeKey('sys', 'user', 'model');
      cache.set(key, [makeFinding()], 'model');

      // Manually tamper with the stored version
      const filePath = join(TEST_DIR, '.krait-cache', `${key}.json`);
      const data = JSON.parse(readFileSync(filePath, 'utf-8'));
      data.promptVersion = 'v0-old';
      writeFileSync(filePath, JSON.stringify(data));

      const result = cache.get(key);
      expect(result).toBeNull();
    });

    it('handles corrupted cache files gracefully', () => {
      const key = 'badkey';
      const cacheDir = join(TEST_DIR, '.krait-cache');
      mkdirSync(cacheDir, { recursive: true });
      writeFileSync(join(cacheDir, `${key}.json`), 'not json');

      const result = cache.get(key);
      expect(result).toBeNull();
    });
  });

  describe('getStats', () => {
    it('tracks hits and misses', () => {
      const key = cache.computeKey('sys', 'user', 'model');
      cache.set(key, [makeFinding()], 'model');

      cache.get('miss1');
      cache.get('miss2');
      cache.get(key);

      const stats = cache.getStats();
      expect(stats.hits).toBe(1);
      expect(stats.misses).toBe(2);
    });
  });

  describe('size', () => {
    it('returns 0 for empty cache', () => {
      expect(cache.size()).toBe(0);
    });

    it('counts entries', () => {
      cache.set(cache.computeKey('a', 'b', 'c'), [], 'c');
      cache.set(cache.computeKey('d', 'e', 'f'), [], 'f');
      expect(cache.size()).toBe(2);
    });
  });

  describe('clear', () => {
    it('removes all entries', () => {
      cache.set(cache.computeKey('a', 'b', 'c'), [], 'c');
      cache.set(cache.computeKey('d', 'e', 'f'), [], 'f');
      expect(cache.size()).toBe(2);
      cache.clear();
      expect(cache.size()).toBe(0);
    });

    it('handles empty cache gracefully', () => {
      expect(() => cache.clear()).not.toThrow();
    });
  });
});
