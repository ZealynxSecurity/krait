#!/usr/bin/env node

/**
 * Krait Solodit MCP Server — Local Pattern Search
 *
 * Searches Krait's local YAML vulnerability patterns for relevant exploits.
 * No external API needed — all data is bundled in patterns/solidity/*.yaml.
 *
 * Three tools:
 *   - search_similar_findings: find patterns matching a vulnerability description
 *   - get_enrichment: fetch patterns relevant to a protocol type
 *   - validate_hypothesis: check if a suspected bug has pattern precedent
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { readFileSync, readdirSync } from "fs";
import { join, resolve, dirname } from "path";
import { fileURLToPath } from "url";
import yaml from "js-yaml";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// ── Load and index patterns at startup ──

interface Pattern {
  id: string;
  name: string;
  category: string;
  severity: string;
  description: string;
  indicators: string[];
  realExamples: Array<{
    source: string;
    project: string;
    description: string;
    codeVulnerable: string;
    codeFixed: string;
  }>;
  falsePositiveNotes: string;
  tags: string[];
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function toStringArray(val: any): string[] {
  if (Array.isArray(val)) return val.map(String);
  return [];
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
function parseRawPattern(raw: any, fallbackCategory: string): Pattern | null {
  if (!raw || typeof raw !== "object" || !raw.id) return null;

  const detection = raw.detection || {};
  const indicators = toStringArray(detection.indicators || raw.indicators);
  const tags = toStringArray(raw.tags);

  const examples: Pattern["realExamples"] = [];
  const rawExamples = raw.real_examples || [];
  for (const ex of rawExamples) {
    if (!ex || typeof ex !== "object") continue;
    examples.push({
      source: String(ex.source || ""),
      project: String(ex.project || ""),
      description: String(ex.finding_id || ex.description || ""),
      codeVulnerable: String(ex.code_vulnerable || ""),
      codeFixed: String(ex.code_fixed || ""),
    });
  }

  return {
    id: String(raw.id),
    name: String(raw.name || ""),
    category: String(raw.category || fallbackCategory),
    severity: String(raw.severity || "medium"),
    description: String(detection.strategy || raw.description || ""),
    indicators,
    realExamples: examples,
    falsePositiveNotes: String(raw.false_positive_notes || ""),
    tags,
  };
}

const patterns: Pattern[] = [];

function loadPatterns() {
  // Resolve patterns dir relative to the MCP server location
  // mcp-servers/solodit/build/index.js → ../../../patterns/solidity/
  const patternsDir = resolve(__dirname, "..", "..", "..", "patterns", "solidity");

  let files: string[];
  try {
    files = readdirSync(patternsDir).filter((f) => f.endsWith(".yaml"));
  } catch {
    console.error(`Warning: patterns directory not found at ${patternsDir}`);
    return;
  }

  for (const file of files) {
    try {
      const content = readFileSync(join(patternsDir, file), "utf-8");
      const parsed = yaml.load(content);
      const fallbackCategory = file.replace(".yaml", "");

      // Handle both formats:
      // 1. Top-level array: [{ id: ..., name: ... }, ...]
      // 2. Wrapped in "patterns" key: { patterns: [{ id: ..., name: ... }, ...] }
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      let rawPatterns: any[];
      if (Array.isArray(parsed)) {
        rawPatterns = parsed;
      } else if (parsed && typeof parsed === "object" && Array.isArray((parsed as Record<string, unknown>).patterns)) {
        rawPatterns = (parsed as Record<string, unknown>).patterns as unknown[];
      } else {
        console.error(`Warning: unexpected YAML structure in ${file} — skipping`);
        continue;
      }

      let fileCount = 0;
      for (const raw of rawPatterns) {
        const pattern = parseRawPattern(raw, fallbackCategory);
        if (pattern) {
          patterns.push(pattern);
          fileCount++;
        }
      }
      console.error(`  ${file}: ${fileCount} patterns`);
    } catch (e) {
      console.error(`Warning: failed to parse ${file}: ${e}`);
    }
  }

  console.error(`Loaded ${patterns.length} vulnerability patterns from ${files.length} files`);
}

// ── Search logic ──

function searchPatterns(query: string, maxResults: number): Pattern[] {
  const queryWords = query.toLowerCase().split(/\s+/).filter((w) => w.length > 2);
  if (queryWords.length === 0) return [];

  const scored = patterns.map((p) => {
    const searchable = [
      p.name,
      p.category,
      p.description,
      p.falsePositiveNotes,
      ...p.indicators,
      ...p.tags,
      ...p.realExamples.map((e) => `${e.source} ${e.project} ${e.description}`),
    ]
      .join(" ")
      .toLowerCase();

    let score = 0;
    for (const word of queryWords) {
      if (searchable.includes(word)) score++;
    }
    // Boost for category/name match
    const nameAndCat = `${p.name} ${p.category}`.toLowerCase();
    for (const word of queryWords) {
      if (nameAndCat.includes(word)) score += 2;
    }
    // Boost for severity
    if (p.severity === "critical") score += 1;
    if (p.severity === "high") score += 0.5;

    return { pattern: p, score };
  });

  return scored
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, maxResults)
    .map((s) => s.pattern);
}

function formatPattern(p: Pattern): string {
  let text = `**[${p.severity.toUpperCase()}] ${p.name}** (${p.id})
Category: ${p.category}
${p.description}`;

  if (p.indicators.length > 0) {
    text += `\nIndicators: ${p.indicators.slice(0, 3).join("; ")}`;
  }

  if (p.realExamples.length > 0) {
    const ex = p.realExamples[0];
    text += `\nReal example: ${ex.source} — ${ex.project}`;
    if (ex.codeVulnerable) {
      text += `\nVulnerable:\n\`\`\`\n${ex.codeVulnerable.slice(0, 200)}\n\`\`\``;
    }
  }

  if (p.falsePositiveNotes) {
    text += `\nFP notes: ${p.falsePositiveNotes.slice(0, 150)}`;
  }

  return text;
}

// ── Load patterns on startup ──
loadPatterns();

// ── MCP Server ──

const server = new McpServer({
  name: "krait-solodit",
  version: "2.0.0",
});

server.tool(
  "search_similar_findings",
  "Search Krait's vulnerability pattern database for patterns matching a suspected vulnerability. Returns matching patterns with real exploit examples, indicators, and false positive notes.",
  {
    query: z.string().describe("Description of the vulnerability (e.g., 'oracle price staleness in lending protocol')"),
    max_results: z.number().min(1).max(20).optional().describe("Maximum results. Default: 5"),
  },
  async ({ query, max_results }) => {
    const results = searchPatterns(query, max_results ?? 5);
    if (results.length === 0) {
      return { content: [{ type: "text" as const, text: `No matching patterns found for: "${query}". This could be a novel vulnerability — verify manually.` }] };
    }
    const text = `Found ${results.length} matching vulnerability patterns:\n\n${results.map(formatPattern).join("\n\n---\n\n")}`;
    return { content: [{ type: "text" as const, text }] };
  }
);

server.tool(
  "get_enrichment",
  "Fetch vulnerability patterns relevant to a specific protocol type. Returns real exploit patterns as context for analysis.",
  {
    protocol_type: z.string().describe("Protocol type (e.g., 'DEX', 'Lending', 'Staking', 'Bridge', 'Oracle', 'Governance', 'NFT')"),
    max_results: z.number().min(1).max(20).optional().describe("Maximum results. Default: 10"),
  },
  async ({ protocol_type, max_results }) => {
    const results = searchPatterns(protocol_type, max_results ?? 10);
    if (results.length === 0) {
      return { content: [{ type: "text" as const, text: `No patterns found for protocol type: "${protocol_type}"` }] };
    }
    const text = `${results.length} vulnerability patterns for ${protocol_type} protocols:\n\n${results.map(formatPattern).join("\n\n---\n\n")}`;
    return { content: [{ type: "text" as const, text }] };
  }
);

server.tool(
  "validate_hypothesis",
  "Check if a vulnerability hypothesis has precedent in Krait's pattern database. High match count = higher confidence the bug is real.",
  {
    title: z.string().describe("Title of the suspected vulnerability"),
    category: z.string().describe("Category (e.g., 'reentrancy', 'oracle', 'access-control', 'flash-loan')"),
  },
  async ({ title, category }) => {
    const results = searchPatterns(`${title} ${category}`, 10);

    // Check title similarity for confidence scoring
    const similar = results.filter((p) => {
      const pWords = new Set(`${p.name} ${p.category}`.toLowerCase().split(/\s+/).filter((w) => w.length > 2));
      const tWords = title.toLowerCase().split(/\s+/).filter((w) => w.length > 2);
      let overlap = 0;
      for (const w of tWords) { if (pWords.has(w)) overlap++; }
      return tWords.length > 0 && overlap / tWords.length >= 0.3;
    });

    const confidence = similar.length >= 3 ? "HIGH" : similar.length >= 1 ? "MEDIUM" : "LOW";

    let text = `Hypothesis: "${title}"\nCategory: ${category}\nPattern matches: ${similar.length}\nHistorical confidence: ${confidence}\n`;

    if (similar.length > 0) {
      text += `\nMatching patterns:\n\n${similar.slice(0, 5).map(formatPattern).join("\n\n---\n\n")}`;
    } else if (results.length > 0) {
      text += `\nNo direct title matches, but ${results.length} related patterns found:\n\n${results.slice(0, 3).map(formatPattern).join("\n\n---\n\n")}`;
    } else {
      text += `\nNo matching patterns. This could be a novel vulnerability or a false positive — verify carefully.`;
    }

    return { content: [{ type: "text" as const, text }] };
  }
);

// ── Start ──

async function main() {
  const transport = new StdioServerTransport();
  await server.connect(transport);
  console.error(`Krait Solodit MCP server v2.0 running (${patterns.length} patterns loaded)`);
}

main().catch((e) => {
  console.error("Fatal:", e);
  process.exit(1);
});
