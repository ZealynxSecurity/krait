#!/usr/bin/env node

/**
 * Krait Solodit MCP Server
 *
 * Exposes three tools for live Solodit search during Krait skill execution:
 *   - search_similar_findings: find similar exploits for a detected vulnerability
 *   - get_enrichment: fetch high-quality findings for a protocol type
 *   - validate_hypothesis: check if a suspected bug has historical precedent
 *
 * Requires CYFRIN_API_KEY environment variable.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";

// ── Solodit API Client (embedded, self-contained) ──

const SOLODIT_API_BASE = "https://solodit.cyfrin.io/api/v1/solodit";

interface SoloditFinding {
  title: string;
  slug: string;
  impact: string;
  tags: string[];
  body: string;
  protocolCategory: string;
  qualityScore: number;
}

const cache = new Map<string, SoloditFinding[]>();
const requestTimestamps: number[] = [];
const RATE_LIMIT_MAX = 20;
const RATE_LIMIT_WINDOW_MS = 60_000;

function getApiKey(): string | null {
  return process.env.CYFRIN_API_KEY || null;
}

function requireApiKey(): string {
  const key = getApiKey();
  if (!key) {
    throw new Error("CYFRIN_API_KEY not set. Get a free key at https://solodit.cyfrin.io — the MCP server runs without it but all searches will fail.");
  }
  return key;
}

async function waitForRateLimit(): Promise<void> {
  const now = Date.now();
  while (requestTimestamps.length > 0 && now - requestTimestamps[0] > RATE_LIMIT_WINDOW_MS) {
    requestTimestamps.shift();
  }
  if (requestTimestamps.length >= RATE_LIMIT_MAX) {
    const waitMs = RATE_LIMIT_WINDOW_MS - (now - requestTimestamps[0]) + 100;
    console.error(`  Rate limit: waiting ${Math.ceil(waitMs / 1000)}s...`);
    await new Promise((r) => setTimeout(r, waitMs));
  }
  if (requestTimestamps.length > 0) {
    const elapsed = now - requestTimestamps[requestTimestamps.length - 1];
    if (elapsed < 3000) await new Promise((r) => setTimeout(r, 3000 - elapsed));
  }
}

async function searchSolodit(
  filters: {
    keywords?: string;
    impact?: string[];
    protocolCategory?: string[];
    pageSize?: number;
  }
): Promise<SoloditFinding[]> {
  const cacheKey = JSON.stringify(filters);
  const cached = cache.get(cacheKey);
  if (cached) return cached;

  await waitForRateLimit();

  const apiFilters: Record<string, unknown> = {
    sortField: "Quality",
    sortDirection: "Desc",
  };
  if (filters.keywords) apiFilters.keywords = filters.keywords;
  if (filters.impact?.length) apiFilters.impact = filters.impact.map((i) => i.toUpperCase());
  if (filters.protocolCategory?.length)
    apiFilters.protocolCategory = filters.protocolCategory.map((c) => ({ value: c }));

  const res = await fetch(`${SOLODIT_API_BASE}/findings`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-Cyfrin-API-Key": requireApiKey(),
    },
    body: JSON.stringify({
      page: 1,
      pageSize: filters.pageSize ?? 10,
      filters: apiFilters,
    }),
  });

  requestTimestamps.push(Date.now());

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(`Solodit API error ${res.status}: ${text}`);
  }

  const json = await res.json() as { findings?: Array<Record<string, unknown>> };
  const findings: SoloditFinding[] = (json.findings ?? []).map((f) => ({
    title: (f.title as string) ?? "",
    slug: (f.slug as string) ?? "",
    impact: (f.impact as string) ?? "",
    tags: (f.tags as string[]) ?? [],
    body: (f.body as string) ?? "",
    protocolCategory: (f.protocolCategory as string) ?? "",
    qualityScore: (f.qualityScore as number) ?? 0,
  }));

  cache.set(cacheKey, findings);
  return findings;
}

function formatFinding(f: SoloditFinding): string {
  const bodyPreview = f.body
    .split("\n")
    .filter((l) => l.trim() && !l.startsWith("#") && !l.startsWith("```") && !l.startsWith("|"))
    .slice(0, 3)
    .join(" ")
    .slice(0, 300);

  return `**[${f.impact}] ${f.title}**
Category: ${f.protocolCategory || "General"} | Quality: ${f.qualityScore}/100
${bodyPreview}${bodyPreview.length >= 300 ? "..." : ""}
URL: https://solodit.cyfrin.io/issues/${f.slug}`;
}

// ── MCP Server ──

const server = new McpServer({
  name: "krait-solodit",
  version: "1.0.0",
});

/**
 * Tool 1: Search for similar findings.
 * Use during detection when you suspect a vulnerability — check if it has historical precedent.
 */
server.tool(
  "search_similar_findings",
  "Search Solodit for real audit findings similar to a suspected vulnerability. Returns matching exploits from past audits with titles, impact, descriptions, and URLs.",
  {
    query: z.string().describe("Description of the vulnerability to search for (e.g., 'oracle price staleness in lending protocol')"),
    impact: z.enum(["HIGH", "MEDIUM", "LOW"]).optional().describe("Filter by impact severity. Default: HIGH"),
    max_results: z.number().min(1).max(20).optional().describe("Maximum results. Default: 10"),
  },
  async ({ query, impact, max_results }) => {
    try {
      const findings = await searchSolodit({
        keywords: query,
        impact: [impact ?? "HIGH"],
        pageSize: max_results ?? 10,
      });

      if (findings.length === 0) {
        return { content: [{ type: "text" as const, text: `No Solodit findings found for: "${query}"` }] };
      }

      const text = `Found ${findings.length} similar findings on Solodit:\n\n${findings.map(formatFinding).join("\n\n---\n\n")}`;
      return { content: [{ type: "text" as const, text }] };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { content: [{ type: "text" as const, text: `Solodit search failed: ${msg}` }] };
    }
  }
);

/**
 * Tool 2: Get enrichment findings for a protocol type.
 * Use during recon to load relevant exploit context for the protocol being audited.
 */
server.tool(
  "get_enrichment",
  "Fetch high-quality Solodit findings for a specific protocol type. Returns real exploits as context for analysis.",
  {
    protocol_type: z.string().describe("Protocol type (e.g., 'DEX / AMM', 'Lending', 'Staking', 'Bridge', 'Oracle', 'Governance', 'NFT')"),
    max_results: z.number().min(1).max(20).optional().describe("Maximum results. Default: 15"),
  },
  async ({ protocol_type, max_results }) => {
    const CATEGORY_MAP: Record<string, { categories: string[]; keywords: string[] }> = {
      "dex": { categories: ["DEX"], keywords: ["swap", "liquidity", "AMM", "pool"] },
      "lending": { categories: ["Lending"], keywords: ["lending", "borrow", "collateral", "liquidation"] },
      "staking": { categories: ["Staking", "Yield"], keywords: ["staking", "yield", "rewards", "vault"] },
      "bridge": { categories: ["Bridge"], keywords: ["bridge", "cross-chain", "relay", "message"] },
      "oracle": { categories: ["Oracle"], keywords: ["oracle", "price feed", "TWAP", "chainlink"] },
      "governance": { categories: ["Governance"], keywords: ["governance", "voting", "proposal", "timelock"] },
      "nft": { categories: ["NFT"], keywords: ["NFT", "marketplace", "royalty", "auction"] },
    };

    const key = Object.keys(CATEGORY_MAP).find((k) => protocol_type.toLowerCase().includes(k));
    const mapping = key ? CATEGORY_MAP[key] : { categories: [], keywords: protocol_type.split(/[\s/]+/).filter((w) => w.length > 2) };

    try {
      let findings: SoloditFinding[] = [];

      if (mapping.categories.length > 0) {
        findings = await searchSolodit({
          protocolCategory: mapping.categories,
          impact: ["HIGH"],
          pageSize: max_results ?? 15,
        });
      }

      if (findings.length < 5 && mapping.keywords.length > 0) {
        const supplement = await searchSolodit({
          keywords: mapping.keywords.slice(0, 3).join(" "),
          impact: ["HIGH", "MEDIUM"],
          pageSize: (max_results ?? 15) - findings.length,
        });
        const seen = new Set(findings.map((f) => f.slug));
        for (const f of supplement) {
          if (!seen.has(f.slug)) { seen.add(f.slug); findings.push(f); }
        }
      }

      if (findings.length === 0) {
        return { content: [{ type: "text" as const, text: `No Solodit findings found for protocol type: "${protocol_type}"` }] };
      }

      const text = `${findings.length} real-world exploits for ${protocol_type} protocols:\n\n${findings.map(formatFinding).join("\n\n---\n\n")}`;
      return { content: [{ type: "text" as const, text }] };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { content: [{ type: "text" as const, text: `Solodit enrichment failed: ${msg}` }] };
    }
  }
);

/**
 * Tool 3: Validate a hypothesis against historical findings.
 * Use during verification to check if a suspected bug has real-world precedent.
 */
server.tool(
  "validate_hypothesis",
  "Check if a vulnerability hypothesis has historical precedent on Solodit. Returns the number of similar findings and their details. High match count = higher confidence the bug is real.",
  {
    title: z.string().describe("Title of the suspected vulnerability"),
    category: z.string().describe("Category (e.g., 'reentrancy', 'oracle', 'access-control', 'flash-loan')"),
  },
  async ({ title, category }) => {
    const stopWords = new Set(["the", "a", "an", "in", "of", "to", "for", "is", "can", "may", "will", "be", "by", "on", "at", "with", "from", "or", "and", "not", "no", "due", "when", "if", "that", "this", "are", "was", "has", "have", "possible", "potential", "missing", "lack", "without"]);
    const words = title.toLowerCase().replace(/[^a-z0-9\s]/g, " ").split(/\s+/).filter((w) => w.length > 2 && !stopWords.has(w));
    const categoryWords = category.replace(/[-_]/g, " ").split(/\s+/).filter((w) => w.length > 2);
    const keywords = [...new Set([...words, ...categoryWords])].slice(0, 5).join(" ");

    try {
      const results = await searchSolodit({
        keywords,
        impact: ["HIGH", "MEDIUM"],
        pageSize: 10,
      });

      // Check title similarity
      const similar = results.filter((f) => {
        const normalize = (s: string) => s.toLowerCase().replace(/[^a-z0-9\s]/g, "").split(/\s+/).filter((w) => w.length > 2);
        const aWords = new Set(normalize(title));
        const bWords = new Set(normalize(f.title));
        if (aWords.size === 0 || bWords.size === 0) return false;
        let overlap = 0;
        for (const w of aWords) { if (bWords.has(w)) overlap++; }
        return overlap / Math.min(aWords.size, bWords.size) >= 0.3;
      });

      const confidence = similar.length >= 3 ? "HIGH" : similar.length >= 1 ? "MEDIUM" : "LOW";

      let text = `Hypothesis: "${title}"\nCategory: ${category}\nSolodit matches: ${similar.length} similar findings\nHistorical confidence: ${confidence}\n`;

      if (similar.length > 0) {
        text += `\nMatching findings:\n\n${similar.slice(0, 5).map(formatFinding).join("\n\n---\n\n")}`;
      } else {
        text += `\nNo similar findings found. This could be a novel bug or a false positive — verify carefully.`;
      }

      return { content: [{ type: "text" as const, text }] };
    } catch (e) {
      const msg = e instanceof Error ? e.message : String(e);
      return { content: [{ type: "text" as const, text: `Validation failed: ${msg}` }] };
    }
  }
);

// ── Start ──

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  const hasKey = !!getApiKey();
  console.error(`Krait Solodit MCP server running${hasKey ? "" : " (no CYFRIN_API_KEY — searches will fail)"}`);
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
