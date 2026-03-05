/**
 * Solodit API client — fetches real audit findings from Solodit's database
 * to enrich Krait's analysis with real-world vulnerability examples.
 *
 * Uses Node 20 built-in fetch(). No new dependencies.
 */

const SOLODIT_API_BASE = 'https://solodit.cyfrin.io/api/v1/solodit';
const RATE_LIMIT_MAX = 20; // 20 requests per minute
const RATE_LIMIT_WINDOW_MS = 60_000;

export interface SoloditFinding {
  title: string;
  slug: string;
  impact: string;
  tags: string[];
  body: string;
  protocolCategory: string;
  qualityScore: number;
}

export interface SoloditSearchFilters {
  keywords?: string;
  impact?: string[];
  tags?: string[];
  protocolCategory?: string[];
  qualityScore?: number;
  sortField?: string;
  sortDirection?: string;
  page?: number;
  pageSize?: number;
}

interface SoloditApiResponse {
  data?: {
    items?: Array<{
      title?: string;
      slug?: string;
      impact?: string;
      tags?: string[];
      body?: string;
      protocol_category?: string;
      quality_score?: number;
    }>;
    total?: number;
  };
}

/**
 * Protocol type → Solodit filter mapping.
 * Maps Krait's protocolType strings (from context-gatherer) to Solodit's API filters.
 */
const PROTOCOL_CATEGORY_MAP: Record<string, { categories: string[]; keywords: string[] }> = {
  'Lending / Borrowing': {
    categories: ['Lending'],
    keywords: ['lending', 'borrow', 'collateral', 'liquidation'],
  },
  'DEX / AMM': {
    categories: ['DEX'],
    keywords: ['swap', 'liquidity', 'AMM', 'pool'],
  },
  'Staking / Yield': {
    categories: ['Staking', 'Yield'],
    keywords: ['staking', 'yield', 'rewards', 'vault'],
  },
  'NFT / Marketplace': {
    categories: ['NFT'],
    keywords: ['NFT', 'marketplace', 'royalty', 'auction'],
  },
  'Bridge / Cross-chain': {
    categories: ['Bridge'],
    keywords: ['bridge', 'cross-chain', 'relay', 'message'],
  },
  'Governance': {
    categories: ['Governance'],
    keywords: ['governance', 'voting', 'proposal', 'timelock'],
  },
  'Oracle': {
    categories: ['Oracle'],
    keywords: ['oracle', 'price feed', 'TWAP', 'chainlink'],
  },
};

export class SoloditClient {
  private apiKey: string;
  private cache = new Map<string, SoloditFinding[]>();
  private requestTimestamps: number[] = [];
  private verbose: boolean;

  constructor(apiKey: string, verbose = false) {
    this.apiKey = apiKey;
    this.verbose = verbose;
  }

  /**
   * Core search method with caching and rate limiting.
   */
  async search(filters: SoloditSearchFilters, pageSize = 15): Promise<SoloditFinding[]> {
    const cacheKey = JSON.stringify({ ...filters, pageSize });
    const cached = this.cache.get(cacheKey);
    if (cached) return cached;

    await this.waitForRateLimit();

    const body: Record<string, unknown> = {
      page: filters.page ?? 1,
      pageSize: filters.pageSize ?? pageSize,
      sortField: filters.sortField ?? 'quality_score',
      sortDirection: filters.sortDirection ?? 'desc',
    };
    if (filters.keywords) body.keywords = filters.keywords;
    if (filters.impact?.length) body.impact = filters.impact;
    if (filters.tags?.length) body.tags = filters.tags;
    if (filters.protocolCategory?.length) body.protocolCategory = filters.protocolCategory;
    if (filters.qualityScore != null) body.qualityScore = filters.qualityScore;

    const response = await fetch(`${SOLODIT_API_BASE}/findings`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Cyfrin-API-Key': this.apiKey,
      },
      body: JSON.stringify(body),
    });

    this.requestTimestamps.push(Date.now());

    if (!response.ok) {
      const text = await response.text().catch(() => '');
      throw new Error(`Solodit API error ${response.status}: ${text}`);
    }

    const json = (await response.json()) as SoloditApiResponse;
    const items = json.data?.items ?? [];

    const findings: SoloditFinding[] = items.map(item => ({
      title: item.title ?? '',
      slug: item.slug ?? '',
      impact: item.impact ?? '',
      tags: item.tags ?? [],
      body: item.body ?? '',
      protocolCategory: item.protocol_category ?? '',
      qualityScore: item.quality_score ?? 0,
    }));

    this.cache.set(cacheKey, findings);
    return findings;
  }

  /**
   * Pre-analysis enrichment: fetch high-quality findings for the protocol type.
   * Returns ~15 findings that Claude can use as reference during analysis.
   * Typically 1-2 API calls.
   */
  async getEnrichmentFindings(
    protocolType: string,
    dependencies: string[]
  ): Promise<SoloditFinding[]> {
    const mapping = this.getProtocolMapping(protocolType, dependencies);

    // Primary search: by protocol category + HIGH/CRITICAL impact
    const primary = await this.search({
      protocolCategory: mapping.categories,
      impact: ['High', 'Critical'],
      qualityScore: 70,
      pageSize: 15,
    });

    if (primary.length >= 10) return primary;

    // Supplement with keyword search if not enough results
    const keywordSearch = await this.search({
      keywords: mapping.keywords.slice(0, 3).join(' '),
      impact: ['High', 'Critical'],
      qualityScore: 60,
      pageSize: 15 - primary.length,
    });

    // Merge and deduplicate by slug
    const seen = new Set(primary.map(f => f.slug));
    const merged = [...primary];
    for (const f of keywordSearch) {
      if (!seen.has(f.slug)) {
        seen.add(f.slug);
        merged.push(f);
      }
    }

    return merged.slice(0, 15);
  }

  /**
   * Finding validation: search for similar findings in Solodit.
   * Returns match count and slugs for corroboration.
   * 1 API call per finding.
   */
  async validateFinding(
    title: string,
    category: string
  ): Promise<{ matchCount: number; slugs: string[] }> {
    // Extract meaningful keywords from the title
    const keywords = this.extractKeywords(title, category);

    try {
      const results = await this.search({
        keywords,
        impact: ['High', 'Critical', 'Medium'],
        pageSize: 10,
      });

      const slugs = results
        .filter(f => this.isSimilarFinding(title, f.title))
        .map(f => f.slug);

      return { matchCount: slugs.length, slugs };
    } catch {
      return { matchCount: 0, slugs: [] };
    }
  }

  /**
   * Gap analysis: find common HIGH findings for this protocol type
   * that Krait didn't already detect.
   * 1-2 API calls.
   */
  async getGapFindings(
    protocolType: string,
    existingCategories: string[]
  ): Promise<SoloditFinding[]> {
    const mapping = this.getProtocolMapping(protocolType, []);
    const normalizedExisting = new Set(existingCategories.map(c => c.toLowerCase()));

    const results = await this.search({
      protocolCategory: mapping.categories,
      impact: ['High', 'Critical'],
      qualityScore: 75,
      pageSize: 20,
    });

    // Filter out findings whose category/tags overlap with what Krait already found
    const gaps = results.filter(f => {
      const findingCategories = [
        ...f.tags.map(t => t.toLowerCase()),
        f.protocolCategory.toLowerCase(),
      ];
      // Keep if none of the finding's categories match existing ones
      return !findingCategories.some(c => normalizedExisting.has(c));
    });

    return gaps.slice(0, 10);
  }

  /**
   * Format findings concisely for inclusion in system prompts.
   * ~200-300 tokens per finding, ~3K-4.5K total for 15 findings.
   */
  formatForPrompt(findings: SoloditFinding[], max = 15): string {
    if (findings.length === 0) return '';

    const formatted = findings.slice(0, max).map((f, i) => {
      const snippet = this.extractCodeSnippet(f.body);
      const description = this.extractDescription(f.body);
      return `${i + 1}. **[${f.impact}] ${f.title}**
   Category: ${f.protocolCategory || 'General'}
   ${description}${snippet ? `\n   \`\`\`\n   ${snippet}\n   \`\`\`` : ''}`;
    });

    return `## Real-World Vulnerability Examples (from past audits)\n\nThese are real findings from professional security audits of similar protocols. Use them as reference for what vulnerability patterns look like in practice.\n\n${formatted.join('\n\n')}`;
  }

  // --- Private helpers ---

  private getProtocolMapping(
    protocolType: string,
    dependencies: string[]
  ): { categories: string[]; keywords: string[] } {
    // Try direct match
    const direct = PROTOCOL_CATEGORY_MAP[protocolType];
    if (direct) return direct;

    // Try partial match
    for (const [key, mapping] of Object.entries(PROTOCOL_CATEGORY_MAP)) {
      if (protocolType.toLowerCase().includes(key.toLowerCase().split(' ')[0])) {
        return mapping;
      }
    }

    // Fallback: derive keywords from protocol type and dependencies
    const keywords = protocolType
      .split(/[\s/]+/)
      .filter(w => w.length > 2)
      .slice(0, 3);

    // Add dependency-based keywords
    if (dependencies.some(d => d.toLowerCase().includes('openzeppelin'))) {
      keywords.push('ERC20', 'access control');
    }
    if (dependencies.some(d => d.toLowerCase().includes('uniswap'))) {
      keywords.push('swap', 'liquidity');
    }
    if (dependencies.some(d => d.toLowerCase().includes('chainlink'))) {
      keywords.push('oracle', 'price feed');
    }

    return { categories: [], keywords };
  }

  private extractKeywords(title: string, category: string): string {
    // Remove common filler words, keep meaningful terms
    const stopWords = new Set([
      'the', 'a', 'an', 'in', 'of', 'to', 'for', 'is', 'can', 'may', 'will',
      'be', 'by', 'on', 'at', 'with', 'from', 'or', 'and', 'not', 'no',
      'due', 'when', 'if', 'that', 'this', 'are', 'was', 'has', 'have',
      'possible', 'potential', 'missing', 'lack', 'without',
    ]);

    const words = title
      .toLowerCase()
      .replace(/[^a-z0-9\s]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2 && !stopWords.has(w));

    // Add category as a keyword
    const categoryWords = category
      .replace(/[-_]/g, ' ')
      .split(/\s+/)
      .filter(w => w.length > 2);

    const combined = [...new Set([...words, ...categoryWords])];
    return combined.slice(0, 5).join(' ');
  }

  private isSimilarFinding(kraitTitle: string, soloditTitle: string): boolean {
    const normalize = (s: string) =>
      s.toLowerCase().replace(/[^a-z0-9\s]/g, '').split(/\s+/).filter(w => w.length > 2);

    const kraitWords = new Set(normalize(kraitTitle));
    const soloditWords = new Set(normalize(soloditTitle));

    if (kraitWords.size === 0 || soloditWords.size === 0) return false;

    let overlap = 0;
    for (const w of kraitWords) {
      if (soloditWords.has(w)) overlap++;
    }

    const minSize = Math.min(kraitWords.size, soloditWords.size);
    return overlap / minSize >= 0.4;
  }

  private extractDescription(body: string): string {
    if (!body) return '';
    // Take first 2-3 meaningful sentences (skip headers, code blocks)
    const lines = body.split('\n');
    const sentences: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      if (!trimmed) continue;
      if (trimmed.startsWith('#')) continue;
      if (trimmed.startsWith('```')) break; // Stop at first code block
      if (trimmed.startsWith('|')) continue; // Skip tables
      if (trimmed.startsWith('-') || trimmed.startsWith('*')) continue; // Skip lists initially

      sentences.push(trimmed);
      if (sentences.length >= 3) break;
    }

    const desc = sentences.join(' ').slice(0, 300);
    return desc ? `Description: ${desc}` : '';
  }

  private extractCodeSnippet(body: string): string {
    if (!body) return '';
    // Extract first code block
    const match = body.match(/```[\w]*\n([\s\S]*?)```/);
    if (!match) return '';

    const code = match[1].trim();
    // Limit to ~8 lines
    const lines = code.split('\n').slice(0, 8);
    if (code.split('\n').length > 8) lines.push('...');
    return lines.join('\n');
  }

  private async waitForRateLimit(): Promise<void> {
    const now = Date.now();
    // Remove timestamps older than the rate limit window
    this.requestTimestamps = this.requestTimestamps.filter(
      ts => now - ts < RATE_LIMIT_WINDOW_MS
    );

    if (this.requestTimestamps.length >= RATE_LIMIT_MAX) {
      const oldestInWindow = this.requestTimestamps[0];
      const waitMs = RATE_LIMIT_WINDOW_MS - (now - oldestInWindow) + 100;
      if (this.verbose) {
        console.error(`  Solodit rate limit: waiting ${Math.ceil(waitMs / 1000)}s...`);
      }
      await new Promise(resolve => setTimeout(resolve, waitMs));
    }
  }
}
