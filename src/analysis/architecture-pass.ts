import Anthropic from '@anthropic-ai/sdk';
import { FileInfo, ArchitectureAnalysis, FundFlow, ContractRole } from '../core/types.js';
import { summarizeContract, formatSummariesForPrompt, ContractSummary } from './contract-summarizer.js';
import { ResponseCache } from '../core/cache.js';

const ARCHITECTURE_TOOL: Anthropic.Tool = {
  name: 'report_architecture',
  description: 'Report the protocol architecture analysis. Call this once with the full analysis.',
  input_schema: {
    type: 'object' as const,
    properties: {
      protocolSummary: {
        type: 'string',
        description: 'One paragraph summary of what this protocol does',
      },
      fundFlows: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Flow name (e.g., "deposit", "withdrawal", "liquidation")' },
            contracts: { type: 'array', items: { type: 'string' }, description: 'Contract names involved, in order' },
            description: { type: 'string', description: 'Step-by-step flow description' },
            riskNotes: { type: 'string', description: 'Risk considerations for this flow' },
          },
          required: ['name', 'contracts', 'description', 'riskNotes'],
        },
        description: 'How money/tokens flow through the protocol',
      },
      invariants: {
        type: 'array',
        items: { type: 'string' },
        description: 'Key invariants that must hold (e.g., "total deposits == sum of user balances")',
      },
      trustAssumptions: {
        type: 'array',
        items: { type: 'string' },
        description: 'Trust assumptions the protocol makes (e.g., "oracle returns correct prices")',
      },
      contractRoles: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            name: { type: 'string', description: 'Contract name' },
            file: { type: 'string', description: 'File path' },
            role: { type: 'string', description: 'Role in the protocol (e.g., "core vault", "price oracle adapter")' },
            riskLevel: { type: 'string', enum: ['high', 'medium', 'low'] },
            keyFunctions: { type: 'array', items: { type: 'string' }, description: 'Most important functions to audit' },
          },
          required: ['name', 'file', 'role', 'riskLevel', 'keyFunctions'],
        },
      },
      criticalPaths: {
        type: 'array',
        items: { type: 'string' },
        description: 'Critical execution paths that must be audited carefully',
      },
    },
    required: ['protocolSummary', 'fundFlows', 'invariants', 'trustAssumptions', 'contractRoles', 'criticalPaths'],
  },
};

/**
 * Run a single architecture analysis pass before per-file analysis.
 * Produces protocol understanding that gets injected into every file prompt.
 */
export async function runArchitecturePass(
  client: Anthropic,
  files: FileInfo[],
  fileContentsMap: Map<string, string>,
  summaries: ContractSummary[],
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
): Promise<ArchitectureAnalysis> {
  const totalLOC = files.reduce((sum, f) => sum + f.lines, 0);
  const isSmall = files.length <= 8 && totalLOC < 4000;

  const systemPrompt = `You are a protocol architect reviewing a smart contract codebase before a security audit.

Your job is to understand the ARCHITECTURE — what the protocol does, how money flows, and what invariants must hold. This analysis will guide per-file security analysis.

Focus on:
1. What does this protocol DO? (lending, DEX, NFT marketplace, vault, etc.)
2. How does money/tokens flow through the system? Trace each major flow (deposit, withdraw, swap, liquidation, etc.) through the contracts involved.
3. What invariants MUST hold? (e.g., "total deposits == sum of balances", "reserves * price >= debt")
4. What trust assumptions does the protocol make? (e.g., "oracle is accurate", "admin won't rug")
5. Which contracts handle the most money/risk?
6. What are the critical execution paths an attacker would target?

Be specific and concrete. Reference actual contract names and function names from the code.`;

  let userPrompt: string;

  if (isSmall) {
    // Small codebase: send all contract code
    const codeSections = files.map(f => {
      const content = fileContentsMap.get(f.relativePath) || '';
      return `### ${f.relativePath} (${f.lines} lines)\n\`\`\`solidity\n${content}\n\`\`\``;
    }).join('\n\n');

    userPrompt = `Analyze this protocol's architecture. All ${files.length} contracts are included below.

${codeSections}

Identify the protocol type, fund flows, invariants, trust assumptions, contract roles, and critical paths.`;
  } else {
    // Large codebase: summaries + top 8 files by importance
    const summaryText = formatSummariesForPrompt(summaries);
    const rankedFiles = rankFilesByImportance(summaries, files);
    const topFiles = rankedFiles.slice(0, 8);

    const codeSections = topFiles.map(f => {
      const content = fileContentsMap.get(f.relativePath) || '';
      return `### ${f.relativePath} (${f.lines} lines)\n\`\`\`solidity\n${content}\n\`\`\``;
    }).join('\n\n');

    userPrompt = `Analyze this protocol's architecture. There are ${files.length} contracts total.

## Contract Summaries (all contracts)

${summaryText}

## Full Code (top ${topFiles.length} most important contracts)

${codeSections}

Identify the protocol type, fund flows, invariants, trust assumptions, contract roles, and critical paths.`;
  }

  // Check cache (we store ArchitectureAnalysis disguised as Finding[] via cast)
  if (cache) {
    const cacheKey = cache.computeKey(systemPrompt, userPrompt, model);
    const cached = cache.get(cacheKey);
    if (cached) {
      if (verbose) {
        console.error('  [cache hit] architecture pass');
      }
      return cached as unknown as ArchitectureAnalysis;
    }
  }

  const response = await client.messages.create({
    model,
    max_tokens: 4096,
    system: systemPrompt,
    tools: [ARCHITECTURE_TOOL],
    tool_choice: { type: 'any' },
    messages: [{ role: 'user', content: userPrompt }],
  });

  const analysis = extractArchitecture(response);

  // Cache the result (cast to any to store non-Finding data)
  if (cache) {
    const cacheKey = cache.computeKey(systemPrompt, userPrompt, model);
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    cache.set(cacheKey, analysis as any, model);
  }

  return analysis;
}

function extractArchitecture(response: Anthropic.Message): ArchitectureAnalysis {
  for (const block of response.content) {
    if (block.type === 'tool_use' && block.name === 'report_architecture') {
      const input = block.input as Record<string, unknown>;
      return {
        protocolSummary: String(input.protocolSummary || ''),
        fundFlows: Array.isArray(input.fundFlows)
          ? (input.fundFlows as Array<Record<string, unknown>>).map(f => ({
              name: String(f.name || ''),
              contracts: Array.isArray(f.contracts) ? f.contracts.map(String) : [],
              description: String(f.description || ''),
              riskNotes: String(f.riskNotes || ''),
            }))
          : [],
        invariants: Array.isArray(input.invariants) ? input.invariants.map(String) : [],
        trustAssumptions: Array.isArray(input.trustAssumptions) ? input.trustAssumptions.map(String) : [],
        contractRoles: Array.isArray(input.contractRoles)
          ? (input.contractRoles as Array<Record<string, unknown>>).map(r => ({
              name: String(r.name || ''),
              file: String(r.file || ''),
              role: String(r.role || ''),
              riskLevel: (['high', 'medium', 'low'].includes(String(r.riskLevel)) ? String(r.riskLevel) : 'medium') as 'high' | 'medium' | 'low',
              keyFunctions: Array.isArray(r.keyFunctions) ? r.keyFunctions.map(String) : [],
            }))
          : [],
        criticalPaths: Array.isArray(input.criticalPaths) ? input.criticalPaths.map(String) : [],
      };
    }
  }

  // Fallback: empty analysis
  return {
    protocolSummary: '',
    fundFlows: [],
    invariants: [],
    trustAssumptions: [],
    contractRoles: [],
    criticalPaths: [],
  };
}

/**
 * Rank files by importance for architecture analysis (most interconnected first).
 */
function rankFilesByImportance(
  summaries: ContractSummary[],
  files: FileInfo[]
): FileInfo[] {
  const scores = summaries.map((s, i) => {
    let score = 0;
    score += s.externalCalls.length * 2;
    score += s.functions.filter(f => f.visibility === 'external' || f.visibility === 'public').length;
    score += s.functions.filter(f => f.externalCalls.length > 0).length * 3;
    score += s.stateVariables.length;
    const lowerName = s.contractName.toLowerCase();
    if (lowerName.includes('controller') || lowerName.includes('vault') ||
        lowerName.includes('pool') || lowerName.includes('router') ||
        lowerName.includes('manager') || lowerName.includes('core')) {
      score += 10;
    }
    return { index: i, score };
  });

  scores.sort((a, b) => b.score - a.score);
  return scores.map(s => files[s.index]).filter(Boolean);
}

/**
 * Format architecture analysis for injection into per-file prompts.
 */
export function formatArchitectureForSystemPrompt(arch: ArchitectureAnalysis): string {
  if (!arch.protocolSummary) return '';

  const parts: string[] = [];
  parts.push(`## Protocol Architecture`);
  parts.push(arch.protocolSummary);

  if (arch.invariants.length > 0) {
    parts.push(`\n**Key Invariants (must hold — violations are HIGH/CRITICAL):**`);
    for (const inv of arch.invariants) {
      parts.push(`- ${inv}`);
    }
  }

  if (arch.trustAssumptions.length > 0) {
    parts.push(`\n**Trust Assumptions (violations are attack vectors):**`);
    for (const ta of arch.trustAssumptions) {
      parts.push(`- ${ta}`);
    }
  }

  return parts.join('\n');
}

/**
 * Format architecture context specific to a file for per-file prompts.
 */
export function formatArchitectureForFilePrompt(
  arch: ArchitectureAnalysis,
  file: FileInfo,
  fileContent: string
): string {
  if (!arch.protocolSummary) return '';

  const parts: string[] = [];

  // Find this file's contract role
  const contractMatch = fileContent.match(/contract\s+(\w+)/);
  const contractName = contractMatch ? contractMatch[1] : '';

  const role = arch.contractRoles.find(r =>
    r.file === file.relativePath ||
    r.name === contractName ||
    file.relativePath.toLowerCase().includes(r.name.toLowerCase())
  );

  if (role) {
    parts.push(`\n**This contract's role**: ${role.role} (risk: ${role.riskLevel})`);
    if (role.keyFunctions.length > 0) {
      parts.push(`**Key functions to audit**: ${role.keyFunctions.join(', ')}`);
    }
  }

  // Find fund flows that reference this contract
  const relevantFlows = arch.fundFlows.filter(f =>
    f.contracts.some(c =>
      c === contractName ||
      c.toLowerCase() === contractName.toLowerCase() ||
      file.relativePath.toLowerCase().includes(c.toLowerCase())
    )
  );

  if (relevantFlows.length > 0) {
    parts.push(`\n**Fund flows through this contract:**`);
    for (const flow of relevantFlows) {
      parts.push(`- **${flow.name}**: ${flow.description}`);
      if (flow.riskNotes) {
        parts.push(`  Risk: ${flow.riskNotes}`);
      }
    }
  }

  // Include relevant critical paths
  const relevantPaths = arch.criticalPaths.filter(p =>
    p.toLowerCase().includes(contractName.toLowerCase()) ||
    p.toLowerCase().includes(file.relativePath.toLowerCase())
  );

  if (relevantPaths.length > 0) {
    parts.push(`\n**Critical paths involving this contract:**`);
    for (const path of relevantPaths) {
      parts.push(`- ${path}`);
    }
  }

  return parts.join('\n');
}
