/**
 * Project context gatherer — collects protocol-level context BEFORE
 * any file-by-file analysis begins. This gives Claude the same
 * understanding a human auditor would have after reading the docs.
 *
 * Extracts:
 * - README / project description
 * - Scope file (which files matter)
 * - Compiler version and build config
 * - External dependencies (OpenZeppelin, Chainlink, etc.)
 * - Interface signatures (public API surface)
 * - Inheritance/import graph
 * - NatSpec / top-level comments from each contract
 */

import { readFileSync, existsSync } from 'fs';
import { resolve, join, basename, dirname, extname, relative } from 'path';
import { glob } from 'glob';
import { FileInfo } from '../core/types.js';

export interface ProjectContext {
  /** Protocol name (inferred from README or directory) */
  protocolName: string;
  /** Protocol description from README */
  description: string;
  /** Protocol type: DEX, lending, stablecoin, NFT, etc. */
  protocolType: string;
  /** Solidity compiler version (from pragma or config) */
  compilerVersion: string;
  /** External dependencies (OpenZeppelin, Chainlink, etc.) */
  dependencies: string[];
  /** Scope: files explicitly in scope (from scope.txt or similar) */
  scopeFiles: string[];
  /** Architecture summary: contract name → role description */
  contractRoles: Map<string, string>;
  /** Inheritance graph: contract → parents */
  inheritanceGraph: Map<string, string[]>;
  /** Import map: file → imported files */
  importGraph: Map<string, string[]>;
  /** Interface signatures: interface name → function signatures */
  interfaceSignatures: Map<string, string[]>;
  /** Key protocol parameters mentioned in docs or config */
  keyParameters: string[];
}

/**
 * Gather all available context about a project before analysis.
 */
export async function gatherProjectContext(
  projectPath: string,
  files: FileInfo[]
): Promise<ProjectContext> {
  const absPath = resolve(projectPath);

  // Walk up to find the project root (where README/foundry.toml live)
  const projectRoot = findProjectRoot(absPath);

  const context: ProjectContext = {
    protocolName: '',
    description: '',
    protocolType: '',
    compilerVersion: '',
    dependencies: [],
    scopeFiles: [],
    contractRoles: new Map(),
    inheritanceGraph: new Map(),
    importGraph: new Map(),
    interfaceSignatures: new Map(),
    keyParameters: [],
  };

  // 1. README
  const readmeContent = readReadme(projectRoot);
  if (readmeContent) {
    context.protocolName = extractProtocolName(readmeContent);
    context.description = extractDescription(readmeContent);
    context.protocolType = inferProtocolType(readmeContent);
    context.keyParameters = extractKeyParameters(readmeContent);
  }

  // 2. Scope file
  context.scopeFiles = readScopeFile(projectRoot);

  // 3. Compiler and build config
  const buildConfig = readBuildConfig(projectRoot);
  context.compilerVersion = buildConfig.compilerVersion;
  context.dependencies = buildConfig.dependencies;

  // 4. Extract from source files
  for (const file of files) {
    try {
      const content = readFileSync(file.path, 'utf-8');

      // Compiler version from pragma (most reliable)
      if (!context.compilerVersion) {
        const pragma = content.match(/pragma\s+solidity\s+([^;]+)/);
        if (pragma) context.compilerVersion = pragma[1].trim();
      }

      // Inheritance
      const inheritance = extractInheritance(content);
      if (inheritance.length > 0) {
        const contractName = extractContractName(content) || basename(file.relativePath, extname(file.relativePath));
        context.inheritanceGraph.set(contractName, inheritance);
      }

      // Imports
      const imports = extractImports(content);
      if (imports.length > 0) {
        context.importGraph.set(file.relativePath, imports);
      }

      // Contract role from NatSpec
      const role = extractContractRole(content);
      if (role) {
        const contractName = extractContractName(content) || basename(file.relativePath, extname(file.relativePath));
        context.contractRoles.set(contractName, role);
      }
    } catch {
      // Skip unreadable files
    }
  }

  // 5. Interface signatures (from interface files that we normally skip)
  await extractInterfaceSignatures(absPath, projectRoot, context);

  return context;
}

/**
 * Format the gathered context into a prompt section for the AI analyzer.
 */
export function formatContextForPrompt(context: ProjectContext): string {
  const sections: string[] = [];

  sections.push('## Project Context');
  sections.push('Use this context to IMPROVE your analysis — understanding the protocol helps you identify real attack paths and avoid false positives. This context should NOT make you more conservative; it should help you catch domain-specific vulnerabilities.\n');

  // Protocol info
  if (context.protocolName) {
    sections.push(`**Protocol**: ${context.protocolName}`);
  }
  if (context.protocolType) {
    sections.push(`**Type**: ${context.protocolType}`);
  }
  if (context.compilerVersion) {
    sections.push(`**Solidity**: ${context.compilerVersion}`);
  }
  if (context.dependencies.length > 0) {
    sections.push(`**Dependencies**: ${context.dependencies.join(', ')}`);
  }
  sections.push('');

  // Description
  if (context.description) {
    sections.push(`### Protocol Description\n${context.description}\n`);
  }

  // Contract architecture (limit to 15 most important to keep prompt focused)
  if (context.contractRoles.size > 0) {
    sections.push('### Contract Architecture');
    const entries = [...context.contractRoles.entries()];
    const displayEntries = entries.slice(0, 15);
    for (const [name, role] of displayEntries) {
      const parents = context.inheritanceGraph.get(name);
      const parentStr = parents && parents.length > 0 ? ` (inherits: ${parents.join(', ')})` : '';
      // Truncate long role descriptions
      const shortRole = role.length > 120 ? role.slice(0, 120) + '...' : role;
      sections.push(`- **${name}**${parentStr}: ${shortRole}`);
    }
    if (entries.length > 15) {
      sections.push(`- ... and ${entries.length - 15} more contracts`);
    }
    sections.push('');
  }

  // Interface signatures (abbreviated)
  if (context.interfaceSignatures.size > 0) {
    sections.push('### Key Interfaces');
    for (const [name, sigs] of context.interfaceSignatures) {
      // Only show first 10 signatures per interface to keep context manageable
      const display = sigs.slice(0, 10);
      sections.push(`**${name}**:`);
      for (const sig of display) {
        sections.push(`  - ${sig}`);
      }
      if (sigs.length > 10) {
        sections.push(`  - ... and ${sigs.length - 10} more functions`);
      }
    }
    sections.push('');
  }

  // Key parameters
  if (context.keyParameters.length > 0) {
    sections.push('### Key Protocol Parameters');
    for (const param of context.keyParameters) {
      sections.push(`- ${param}`);
    }
    sections.push('');
  }

  // Scope
  if (context.scopeFiles.length > 0) {
    sections.push(`### Scope (${context.scopeFiles.length} files in scope)`);
    sections.push('Only report findings for files that are in scope.');
    sections.push('');
  }

  return sections.join('\n');
}

// --- Internal helpers ---

function findProjectRoot(startPath: string): string {
  let current = startPath;
  for (let i = 0; i < 5; i++) {
    if (existsSync(join(current, 'README.md')) ||
        existsSync(join(current, 'foundry.toml')) ||
        existsSync(join(current, 'hardhat.config.ts')) ||
        existsSync(join(current, 'hardhat.config.js'))) {
      return current;
    }
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return startPath;
}

function readReadme(projectRoot: string): string | null {
  for (const name of ['README.md', 'readme.md', 'Readme.md']) {
    const readmePath = join(projectRoot, name);
    if (existsSync(readmePath)) {
      try {
        // Read up to 8000 chars — READMEs can be very long
        const content = readFileSync(readmePath, 'utf-8');
        return content.slice(0, 8000);
      } catch {
        return null;
      }
    }
  }
  return null;
}

function extractProtocolName(readme: string): string {
  // Try # heading first
  const heading = readme.match(/^#\s+(.+)/m);
  if (heading) {
    // Clean up "Salty.IO audit details" → "Salty.IO"
    let name = heading[1].trim();
    name = name.replace(/\s*(audit|security|review|details|contest|findings).*/i, '').trim();
    if (name.length > 0 && name.length < 60) return name;
  }
  return '';
}

function extractDescription(readme: string): string {
  // Look for # Overview or the first substantial paragraph after the heading
  const overviewMatch = readme.match(/##?\s*Overview\s*\n([\s\S]*?)(?=\n##?\s|\n\n---)/i);
  if (overviewMatch) {
    return overviewMatch[1].trim().slice(0, 1500);
  }

  // Look for a paragraph that describes what the protocol does
  const paragraphs = readme.split(/\n\n/).filter(p =>
    p.trim().length > 50 &&
    !p.startsWith('#') &&
    !p.startsWith('*') &&
    !p.startsWith('-') &&
    !p.startsWith('|') &&
    !p.includes('discord') &&
    !p.includes('Submit findings')
  );

  if (paragraphs.length > 0) {
    return paragraphs.slice(0, 3).join('\n\n').slice(0, 1500);
  }

  // Fallback: first 500 chars after skipping the title
  const afterTitle = readme.replace(/^#.*\n/, '').trim();
  return afterTitle.slice(0, 500);
}

function inferProtocolType(readme: string): string {
  const lower = readme.toLowerCase();
  const types: Array<[string, string[]]> = [
    ['DEX / AMM', ['decentralized exchange', 'dex', 'amm', 'automated market', 'swap', 'liquidity pool']],
    ['Lending / Borrowing', ['lending', 'borrowing', 'borrow', 'collateral', 'liquidation', 'interest rate']],
    ['Stablecoin', ['stablecoin', 'stable coin', 'usds', 'usdc peg', 'overcollateralized']],
    ['NFT / Marketplace', ['nft', 'erc721', 'erc1155', 'marketplace', 'auction', 'royalt']],
    ['Yield / Vault', ['yield', 'vault', 'strategy', 'farming', 'harvest', 'compound']],
    ['Governance / DAO', ['governance', 'dao', 'voting', 'proposal', 'timelock']],
    ['Bridge / Cross-chain', ['bridge', 'cross-chain', 'multichain', 'layer 2', 'l2']],
    ['Oracle', ['oracle', 'price feed', 'chainlink', 'twap']],
    ['Staking', ['staking', 'stake', 'unstake', 'delegation', 'validator']],
    ['RWA / Tokenization', ['rwa', 'real world', 'tokeniz', 'asset-backed']],
  ];

  const matched: string[] = [];
  for (const [type, keywords] of types) {
    const count = keywords.filter(k => lower.includes(k)).length;
    if (count >= 2) matched.push(type);
  }

  return matched.join(' + ') || 'DeFi Protocol';
}

function readScopeFile(projectRoot: string): string[] {
  for (const name of ['scope.txt', 'scope.md', 'SCOPE.txt']) {
    const scopePath = join(projectRoot, name);
    if (existsSync(scopePath)) {
      try {
        const content = readFileSync(scopePath, 'utf-8');
        return content
          .split('\n')
          .map(l => l.trim())
          .filter(l => l.length > 0 && l.endsWith('.sol'));
      } catch {
        return [];
      }
    }
  }
  return [];
}

interface BuildConfig {
  compilerVersion: string;
  dependencies: string[];
}

function readBuildConfig(projectRoot: string): BuildConfig {
  const config: BuildConfig = { compilerVersion: '', dependencies: [] };

  // Foundry
  const foundryPath = join(projectRoot, 'foundry.toml');
  if (existsSync(foundryPath)) {
    try {
      const content = readFileSync(foundryPath, 'utf-8');
      const solcMatch = content.match(/solc_version\s*=\s*"([^"]+)"/);
      if (solcMatch) config.compilerVersion = solcMatch[1];
    } catch {}
  }

  // Remappings → dependencies
  const remappingsPath = join(projectRoot, 'remappings.txt');
  if (existsSync(remappingsPath)) {
    try {
      const content = readFileSync(remappingsPath, 'utf-8');
      const knownDeps: Record<string, string> = {
        'openzeppelin': 'OpenZeppelin',
        '@openzeppelin': 'OpenZeppelin',
        'solmate': 'Solmate',
        'chainlink': 'Chainlink',
        'uniswap': 'Uniswap',
        'v3-core': 'Uniswap V3',
        'v2-core': 'Uniswap V2',
        'aave': 'Aave',
        'compound': 'Compound',
        'solady': 'Solady',
        'prb-math': 'PRBMath',
      };
      for (const [key, name] of Object.entries(knownDeps)) {
        if (content.toLowerCase().includes(key) && !config.dependencies.includes(name)) {
          config.dependencies.push(name);
        }
      }
    } catch {}
  }

  // Package.json → dependencies
  const pkgPath = join(projectRoot, 'package.json');
  if (existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(readFileSync(pkgPath, 'utf-8'));
      const allDeps = { ...pkg.dependencies, ...pkg.devDependencies };
      const knownNpmDeps: Record<string, string> = {
        '@openzeppelin/contracts': 'OpenZeppelin',
        '@chainlink/contracts': 'Chainlink',
        '@uniswap/v3-core': 'Uniswap V3',
        '@uniswap/v2-core': 'Uniswap V2',
      };
      for (const [key, name] of Object.entries(knownNpmDeps)) {
        if (allDeps[key] && !config.dependencies.includes(name)) {
          config.dependencies.push(name);
        }
      }
    } catch {}
  }

  return config;
}

function extractContractName(content: string): string | null {
  const match = content.match(/\b(contract|library|abstract\s+contract)\s+(\w+)/);
  return match ? match[2] : null;
}

function extractInheritance(content: string): string[] {
  // Match: contract Foo is Bar, Baz, IQux
  const match = content.match(/\b(?:contract|abstract\s+contract)\s+\w+\s+is\s+([^{]+)/);
  if (!match) return [];

  return match[1]
    .split(',')
    .map(s => s.trim())
    .filter(s => s.length > 0 && !s.includes('{'));
}

function extractImports(content: string): string[] {
  const imports: string[] = [];
  const importRegex = /import\s+(?:{[^}]+}\s+from\s+)?["']([^"']+)["']/g;
  let match;
  while ((match = importRegex.exec(content)) !== null) {
    imports.push(match[1]);
  }
  return imports;
}

function extractContractRole(content: string): string | null {
  // Look for NatSpec @title or @notice on the contract
  const titleMatch = content.match(/\/\/\/?\s*@title\s+(.+)/);
  if (titleMatch) return titleMatch[1].trim();

  // Look for a comment block right before the contract declaration
  const contractIdx = content.search(/\b(contract|abstract\s+contract|library)\s+\w+/);
  if (contractIdx < 0) return null;

  // Get the 500 chars before the contract declaration
  const before = content.slice(Math.max(0, contractIdx - 500), contractIdx);

  // Look for // or /** comment describing the contract
  const lines = before.split('\n').reverse();
  const commentLines: string[] = [];
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*') || trimmed.startsWith('/**')) {
      const cleaned = trimmed.replace(/^\/\/+\s*/, '').replace(/^\*+\s*/, '').replace(/^\/\*+\s*/, '').trim();
      if (cleaned.length > 10 && !cleaned.startsWith('@') && !cleaned.startsWith('SPDX')) {
        commentLines.unshift(cleaned);
      }
    } else if (trimmed.length > 0 && !trimmed.startsWith('pragma') && !trimmed.startsWith('import')) {
      break;
    }
  }

  if (commentLines.length > 0) {
    return commentLines.join(' ').slice(0, 200);
  }

  return null;
}

function extractKeyParameters(readme: string): string[] {
  const params: string[] = [];

  // Look for percentage values, ratios, thresholds mentioned in the README
  const paramPatterns = [
    /collateral(?:ization)?\s*ratio\s*(?:of|is|:)?\s*([\d.]+%?)/gi,
    /(?:minimum|min|max|maximum|default)\s+[\w\s]*(?:ratio|threshold|fee|rate|limit)\s*(?:of|is|:)?\s*([\d.]+%?)/gi,
    /(?:liquidation|borrow|lending)\s*(?:ratio|threshold|fee|penalty)\s*(?:of|is|:)?\s*([\d.]+%?)/gi,
  ];

  for (const pattern of paramPatterns) {
    let match;
    while ((match = pattern.exec(readme)) !== null) {
      const param = match[0].trim().slice(0, 100);
      if (!params.includes(param)) params.push(param);
    }
  }

  return params.slice(0, 10);
}

async function extractInterfaceSignatures(
  auditPath: string,
  projectRoot: string,
  context: ProjectContext
): Promise<void> {
  // Find interface files
  const searchPaths = [auditPath, projectRoot];
  const seen = new Set<string>();

  for (const searchPath of searchPaths) {
    try {
      const interfaceFiles = await glob('**/interfaces/I*.sol', {
        cwd: searchPath,
        absolute: true,
        nodir: true,
        ignore: ['**/node_modules/**', '**/lib/**', '**/test/**'],
      });

      for (const filePath of interfaceFiles.slice(0, 20)) { // Max 20 interfaces
        if (seen.has(filePath)) continue;
        seen.add(filePath);

        try {
          const content = readFileSync(filePath, 'utf-8');
          const interfaceName = extractContractName(content);
          if (!interfaceName) continue;

          // Extract function signatures
          const sigRegex = /function\s+(\w+\s*\([^)]*\))\s*external[^;]*/g;
          const sigs: string[] = [];
          let match;
          while ((match = sigRegex.exec(content)) !== null) {
            sigs.push(match[1].trim());
          }

          if (sigs.length > 0) {
            context.interfaceSignatures.set(interfaceName, sigs);
          }
        } catch {}
      }
    } catch {}
  }
}
