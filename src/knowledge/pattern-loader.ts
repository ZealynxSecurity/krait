import { readFileSync, readdirSync, statSync } from 'fs';
import { join, extname } from 'path';
import yaml from 'js-yaml';
import { VulnerabilityPattern, Domain } from '../core/types.js';

export class PatternLoader {
  private patterns: VulnerabilityPattern[] = [];
  private loaded = false;

  constructor(private patternsDir: string) {}

  load(): VulnerabilityPattern[] {
    if (this.loaded) return this.patterns;

    const yamlFiles = this.findYamlFiles(this.patternsDir);
    for (const file of yamlFiles) {
      try {
        const content = readFileSync(file, 'utf-8');
        const parsed = yaml.load(content);
        let entries: unknown[] = [];
        if (Array.isArray(parsed)) {
          entries = parsed;
        } else if (parsed && typeof parsed === 'object' && 'patterns' in parsed) {
          const obj = parsed as Record<string, unknown>;
          if (Array.isArray(obj.patterns)) {
            entries = obj.patterns;
          }
        }
        for (const entry of entries) {
          if (this.isValidPattern(entry)) {
            this.patterns.push(entry as VulnerabilityPattern);
          }
        }
      } catch (err) {
        // Skip invalid files silently
      }
    }

    this.loaded = true;
    return this.patterns;
  }

  getPatterns(): VulnerabilityPattern[] {
    return this.loaded ? this.patterns : this.load();
  }

  getPatternsByDomain(domain: Domain): VulnerabilityPattern[] {
    const domainTagMap: Record<Domain, string[]> = {
      'solidity': ['solidity', 'defi', 'erc20', 'erc721'],
      'rust-solana': ['solana', 'anchor', 'rust', 'spl'],
      'web2-typescript': ['typescript', 'javascript', 'web2', 'api', 'node'],
      'ai-red-team': ['ai', 'llm', 'prompt', 'mcp'],
    };

    const relevantTags = domainTagMap[domain] || [];
    return this.getPatterns().filter(p =>
      p.tags.some(tag => relevantTags.includes(tag))
    );
  }

  formatForPrompt(patterns: VulnerabilityPattern[]): string {
    if (patterns.length === 0) return 'No specific patterns loaded.';

    const lines: string[] = ['# Known Vulnerability Patterns\n'];

    for (const p of patterns) {
      lines.push(`## ${p.id}: ${p.name}`);
      lines.push(`Severity: ${p.severity} | Category: ${p.category} | Confidence: ${p.confidence}`);
      lines.push(`Description: ${p.description}`);
      lines.push(`Detection strategy: ${p.detection.strategy}`);
      if (p.detection.indicators.length > 0) {
        lines.push(`Indicators: ${p.detection.indicators.join(', ')}`);
      }
      if (p.real_examples && p.real_examples.length > 0) {
        const ex = p.real_examples[0];
        lines.push(`Real example: ${ex.project} (${ex.source}) - ${ex.impact}`);
        if (ex.code_vulnerable) {
          lines.push(`Vulnerable code:\n\`\`\`\n${ex.code_vulnerable.trim()}\n\`\`\``);
        }
      }
      if (p.false_positive_notes) {
        lines.push(`False positive notes: ${p.false_positive_notes}`);
      }
      lines.push('');
    }

    return lines.join('\n');
  }

  filterPatternsForFile(
    patterns: VulnerabilityPattern[],
    fileContent: string,
    maxPatterns: number = 25
  ): VulnerabilityPattern[] {
    const contentLower = fileContent.toLowerCase();

    // Score each pattern by relevance to this file's content
    const scored = patterns.map(pattern => {
      let score = 0;

      // Check indicators against file content
      for (const indicator of pattern.detection.indicators) {
        if (typeof indicator === 'string' && contentLower.includes(indicator.toLowerCase())) {
          score += 3;
        }
      }

      // Check category-based keywords
      const categoryKeywords = this.getCategoryKeywords(pattern.category);
      for (const kw of categoryKeywords) {
        if (contentLower.includes(kw)) {
          score += 2;
        }
      }

      // Check tags against content
      for (const tag of pattern.tags) {
        if (contentLower.includes(tag.toLowerCase())) {
          score += 1;
        }
      }

      // Boost high-severity patterns slightly (always worth checking)
      if (pattern.severity === 'critical') score += 2;
      if (pattern.severity === 'high') score += 1;

      return { pattern, score };
    });

    // Sort by score descending, take top N
    scored.sort((a, b) => b.score - a.score);

    // Always include patterns with score > 0, up to max
    const relevant = scored.filter(s => s.score > 0).slice(0, maxPatterns);

    // If we have very few matches, include some high-severity patterns as baseline
    if (relevant.length < 5) {
      const baseline = scored
        .filter(s => s.score === 0 && ['critical', 'high'].includes(s.pattern.severity))
        .slice(0, 5 - relevant.length);
      relevant.push(...baseline);
    }

    return relevant.map(s => s.pattern);
  }

  private getCategoryKeywords(category: string): string[] {
    const map: Record<string, string[]> = {
      'reentrancy': ['call{', '.call(', 'transfer(', 'send(', 'external', 'callback'],
      'access-control': ['onlyowner', 'require(msg.sender', 'admin', 'owner', 'authorized', 'modifier'],
      'oracle-manipulation': ['oracle', 'price', 'getprice', 'latestrounddata', 'twap', 'chainlink'],
      'flash-loan': ['flashloan', 'flash', 'borrow', 'repay', 'callback'],
      'integer-overflow': ['unchecked', 'type(uint', 'max', 'overflow'],
      'missing-error-handling': ['transfer(', 'approve(', 'transferfrom(', 'return'],
      'price-manipulation': ['price', 'oracle', 'swap', 'reserve', 'getamount', 'liquidity'],
      'temporal-state': ['block.timestamp', 'block.number', 'deadline', 'expir'],
      'misconfiguration': ['initialize', 'constructor', 'setup', 'config', 'set'],
    };
    return map[category] || [];
  }

  getStats(): { total: number; byDomain: Record<string, number>; bySeverity: Record<string, number> } {
    const patterns = this.getPatterns();
    const byDomain: Record<string, number> = {};
    const bySeverity: Record<string, number> = {};

    for (const p of patterns) {
      bySeverity[p.severity] = (bySeverity[p.severity] || 0) + 1;
      const domain = this.inferDomain(p);
      byDomain[domain] = (byDomain[domain] || 0) + 1;
    }

    return { total: patterns.length, byDomain, bySeverity };
  }

  private inferDomain(p: VulnerabilityPattern): string {
    if (p.tags.some(t => ['solidity', 'defi', 'erc20'].includes(t))) return 'solidity';
    if (p.tags.some(t => ['solana', 'anchor', 'rust'].includes(t))) return 'rust-solana';
    if (p.tags.some(t => ['typescript', 'javascript', 'web2'].includes(t))) return 'web2-typescript';
    if (p.tags.some(t => ['ai', 'llm', 'prompt'].includes(t))) return 'ai-red-team';
    return 'unknown';
  }

  private findYamlFiles(dir: string): string[] {
    const files: string[] = [];
    try {
      const entries = readdirSync(dir);
      for (const entry of entries) {
        const fullPath = join(dir, entry);
        const stat = statSync(fullPath);
        if (stat.isDirectory()) {
          files.push(...this.findYamlFiles(fullPath));
        } else if (extname(entry) === '.yaml' || extname(entry) === '.yml') {
          if (entry !== 'schema.yaml') {
            files.push(fullPath);
          }
        }
      }
    } catch {
      // Directory doesn't exist or isn't readable
    }
    return files;
  }

  private isValidPattern(entry: unknown): boolean {
    if (typeof entry !== 'object' || entry === null) return false;
    const obj = entry as Record<string, unknown>;
    return (
      typeof obj.id === 'string' &&
      typeof obj.name === 'string' &&
      typeof obj.category === 'string' &&
      typeof obj.severity === 'string' &&
      typeof obj.description === 'string' &&
      typeof obj.detection === 'object' &&
      Array.isArray(obj.tags)
    );
  }
}
