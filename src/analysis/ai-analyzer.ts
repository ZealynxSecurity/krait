import Anthropic from '@anthropic-ai/sdk';
import { Finding, FileInfo, KraitConfig, VulnerabilityPattern, ArchitectureAnalysis, FundFlow } from '../core/types.js';
import { summarizeContract, formatSummariesForPrompt, ContractSummary } from './contract-summarizer.js';
import { ProjectContext, formatContextForPrompt } from './context-gatherer.js';
import { getProtocolChecklist } from './domain-checklists.js';
import { formatArchitectureForSystemPrompt, formatArchitectureForFilePrompt } from './architecture-pass.js';
import { getHeuristicsForFile, formatHeuristicsForPrompt } from '../knowledge/audit-heuristics.js';
import { ResponseCache } from '../core/cache.js';
import { BatchGroup } from '../core/file-scorer.js';

/**
 * Shared false-positive avoidance rules injected into ALL analysis prompts.
 * The main buildSystemPrompt has these inline; deep/cross/gap prompts were missing them.
 */
const FP_AVOIDANCE = `## False Positive Avoidance (CRITICAL — apply to every finding):

- Do NOT report missing zero-address validation — it's a best practice, not a vulnerability.
- Do NOT report integer overflow/underflow in Solidity ≥0.8.0 unless inside unchecked{} blocks.
- Do NOT report centralization risk (owner can do X) — this is a design choice.
- Do NOT report missing event emissions, gas optimizations, or floating pragmas.
- Do NOT report "missing feature" findings (no circuit breaker, no pause, no timelock).
- Every finding MUST have a concrete 3-step exploit scenario: (1) attacker does X, (2) this causes Y, (3) resulting in Z loss/damage.
- If you cannot articulate a specific exploit path, do NOT report the finding.
- When in doubt about severity, grade LOWER. A medium is better than a false high.
- Do NOT report first-depositor/share-inflation attacks if the contract uses OpenZeppelin's virtual offset, _decimalsOffset, or has minimum deposit checks. Check the code before reporting.
- Do NOT report "donation attack" unless you verify the contract uses balanceOf() for accounting (not internal tracking) AND lacks protection.
- Each finding must describe a DIFFERENT bug. Do not report the same underlying issue (e.g., "first depositor") as multiple findings from different analysis angles.`;

const FINDING_TOOL: Anthropic.Tool = {
  name: 'report_findings',
  description: 'Report security vulnerabilities found in the code. Call this once with ALL findings.',
  input_schema: {
    type: 'object' as const,
    properties: {
      findings: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            title: { type: 'string', description: 'Short descriptive title of the vulnerability' },
            file: { type: 'string', description: 'File path where the vulnerability exists (required for batch analysis)' },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low', 'info'] },
            confidence: { type: 'string', enum: ['high', 'medium', 'low'] },
            line: { type: 'number', description: 'Line number where the vulnerability exists' },
            endLine: { type: 'number', description: 'End line number of the vulnerable code span' },
            description: { type: 'string', description: 'Detailed explanation of the vulnerability' },
            impact: { type: 'string', description: 'What could happen if exploited' },
            remediation: { type: 'string', description: 'How to fix the vulnerability' },
            category: { type: 'string', description: 'Vulnerability category (e.g. reentrancy, access-control)' },
            patternId: { type: 'string', description: 'ID of the matched pattern, if any' },
            codeSnippet: { type: 'string', description: 'The vulnerable code snippet' },
          },
          required: ['title', 'severity', 'confidence', 'line', 'description', 'impact', 'remediation', 'category'],
        },
      },
    },
    required: ['findings'],
  },
};

export class AIAnalyzer {
  private client: Anthropic;
  private config: KraitConfig;
  private findingCounter = 0;
  private projectContext: ProjectContext | null = null;
  private architectureContext: ArchitectureAnalysis | null = null;
  private soloditContext = '';
  private cache: ResponseCache | null = null;

  constructor(config: KraitConfig) {
    this.config = config;
    // Only create the Anthropic client if we're not in dry-run mode
    if (!config.dryRun) {
      this.client = new Anthropic({ apiKey: config.apiKey });
    } else {
      this.client = null as unknown as Anthropic;
    }
  }

  /**
   * Attach a response cache. When set, callClaude checks cache before API calls.
   */
  setCache(cache: ResponseCache): void {
    this.cache = cache;
  }

  /**
   * Set the project context gathered before analysis.
   * This gives Claude protocol-level understanding for every file.
   */
  setProjectContext(context: ProjectContext): void {
    this.projectContext = context;
  }

  /**
   * Set pre-formatted Solodit enrichment context.
   * This is injected into system prompts so Claude sees real-world examples.
   */
  setSoloditContext(context: string): void {
    this.soloditContext = context;
  }

  /**
   * Set architecture context from the architecture pass.
   * This gives Claude protocol-level understanding (fund flows, invariants, roles).
   */
  setArchitectureContext(context: ArchitectureAnalysis): void {
    this.architectureContext = context;
  }

  async analyzeFile(
    file: FileInfo,
    fileContent: string,
    patternContext: string
  ): Promise<Finding[]> {
    const heuristics = getHeuristicsForFile(fileContent);
    const heuristicContext = formatHeuristicsForPrompt(heuristics);
    const systemPrompt = this.buildSystemPrompt(patternContext, heuristicContext);
    const userPrompt = this.buildFilePrompt(file, fileContent);

    const findings = await this.callClaude(systemPrompt, userPrompt, file.relativePath);
    return findings;
  }

  /**
   * Analyze a batch of small files in a single API call.
   * Files are combined into one prompt with clear separators.
   */
  async analyzeBatch(
    batch: BatchGroup,
    patternContext: string
  ): Promise<Finding[]> {
    const systemPrompt = this.buildSystemPrompt(patternContext);

    // Build combined prompt with all files in the batch
    const sections = batch.files.map(file => {
      const content = batch.contents.get(file.relativePath) || '';
      const numbered = content.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
      return `### File: ${file.relativePath} (${file.lines} lines)\n\`\`\`${file.language}\n${numbered}\n\`\`\``;
    }).join('\n\n');

    const fileList = batch.files.map(f => f.relativePath).join(', ');

    const userPrompt = `Analyze these ${batch.files.length} small files for security vulnerabilities.

IMPORTANT: For each finding, include the \`file\` field with the exact file path where the vulnerability exists.

${sections}

Report findings with exact file paths and line numbers. Empty findings array is fine.`;

    const knownFiles = batch.files.map(f => f.relativePath);
    return this.callClaude(systemPrompt, userPrompt, 'batch', undefined, knownFiles);
  }

  /**
   * Run first-pass analysis twice and merge results for consensus.
   * Findings appearing in both runs get boosted confidence.
   * Findings appearing in only one run keep original confidence.
   * This fights non-determinism in LLM output.
   */
  async analyzeFileWithConsensus(
    file: FileInfo,
    fileContent: string,
    patternContext: string
  ): Promise<Finding[]> {
    const systemPrompt = this.buildSystemPrompt(patternContext);
    const userPrompt = this.buildFilePrompt(file, fileContent);

    // Run two passes
    const [run1, run2] = await Promise.all([
      this.callClaude(systemPrompt, userPrompt, file.relativePath),
      this.callClaude(systemPrompt, userPrompt, file.relativePath),
    ]);

    // Merge: match findings across runs by line proximity + category
    const merged: Finding[] = [];
    const used2 = new Set<number>();

    for (const f1 of run1) {
      let matched = false;
      for (let j = 0; j < run2.length; j++) {
        if (used2.has(j)) continue;
        const f2 = run2[j];
        if (f1.category === f2.category && Math.abs(f1.line - f2.line) <= 15) {
          // Consensus: boost confidence, keep the more detailed one
          const best = f1.description.length >= f2.description.length ? { ...f1 } : { ...f2 };
          best.confidence = 'high';
          // Keep the lower line number (more precise)
          best.line = Math.min(f1.line, f2.line);
          merged.push(best);
          used2.add(j);
          matched = true;
          break;
        }
      }
      if (!matched) {
        // Only in run1 — keep but don't boost
        merged.push(f1);
      }
    }

    // Add findings only in run2
    for (let j = 0; j < run2.length; j++) {
      if (!used2.has(j)) {
        merged.push(run2[j]);
      }
    }

    return merged;
  }

  /**
   * Deep analysis pass — focuses on business logic bugs, economic attacks,
   * and edge cases that the first pass might miss.
   */
  async analyzeDeep(
    file: FileInfo,
    fileContent: string,
    firstPassFindings: Finding[],
    patternContext: string
  ): Promise<Finding[]> {
    const projectBrief = this.projectContext ? formatContextForPrompt(this.projectContext) : '';

    const existingText = firstPassFindings.length > 0
      ? firstPassFindings.map(f => `- [${f.severity}] ${f.title} (line ${f.line})`).join('\n')
      : 'None found in first pass.';

    const systemPrompt = `You are Krait, performing a DEEP second-pass security analysis. The first pass already found generic vulnerabilities. Your job is to find what it MISSED.

${projectBrief}

## Focus Areas (these are the most commonly missed bug classes):

1. **Fee/royalty calculation errors**: Wrong fee amounts, fees taken from wrong party, fees not distributed correctly, missing fee collection, double-counting fees. Look at EVERY arithmetic operation involving fees, royalties, or protocol revenue.

2. **Token-specific edge cases**: What happens with fee-on-transfer tokens? Rebasing tokens? Low decimal tokens (e.g., USDC with 6 decimals)? Tokens that revert on zero-amount transfers? ERC777 hooks?

3. **Economic/game-theoretic attacks**: Can a user exploit ordering of operations? Can someone front-run/sandwich a transaction? Flash loan attack vectors? Can someone profit from rounding in their favor?

4. **State manipulation across functions**: Can calling function A before function B put the protocol in an inconsistent state? Are there functions that should be atomic but aren't?

5. **Access control subtleties**: Not "missing onlyOwner" but rather — can a user bypass intended restrictions by calling a sequence of public functions? Can the owner rug users?

6. **Incorrect assumptions**: What does the code assume about external contracts or inputs that might be wrong?

${this.soloditContext}

${this.getChecklistContext()}
${patternContext}

## Rules:
- Do NOT repeat findings from the first pass (listed below).
- Every finding MUST have a concrete exploit scenario with specific steps an attacker would take. "This could be problematic" is NOT enough.
- Focus on BUSINESS LOGIC, not generic patterns. Do NOT report: missing events, gas optimization, centralization risk, missing zero-address checks, or generic best practices.
- Only report findings at medium severity or above. If it's not worth a medium, don't report it.
- Quality bar: Would a senior auditor include this in a paid audit report? If not, skip it.

${FP_AVOIDANCE}`;

    const numbered = fileContent.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');

    // Add function inventory so deep pass knows which functions to examine
    const functionInventory = file.lines > 150 ? this.extractFunctionInventory(fileContent) : '';

    // Identify which functions already have findings
    const coveredLines = new Set(firstPassFindings.map(f => f.line));
    const uncoveredNote = functionInventory ? this.identifyUncoveredFunctions(fileContent, firstPassFindings) : '';

    const userPrompt = `## Deep Analysis: ${file.relativePath}

### First-pass findings (do NOT repeat):
${existingText}
${functionInventory}${uncoveredNote}
### Code:
\`\`\`${file.language}
${numbered}
\`\`\`

IMPORTANT: Systematically analyze each uncovered function listed above. For each one:
1. Read the function body line by line
2. Trace every arithmetic operation — is the fee/price/amount computed correctly?
3. Check: are all payments/transfers accounted for? Does the protocol collect its share?
4. What happens with edge-case inputs (zero, max, low-decimal tokens)?
5. Can a caller exploit the function's interaction with other contract functions?`;

    return this.callClaude(systemPrompt, userPrompt, file.relativePath, this.config.deepModel);
  }

  /**
   * Function-level targeted analysis — analyzes individual uncovered functions
   * that the first + deep pass missed entirely.
   *
   * For large files, Claude tends to focus on the first few functions and skip
   * ones later in the file. This pass extracts each uncovered function with
   * surrounding context and analyzes it individually.
   */
  async analyzeUncoveredFunctions(
    file: FileInfo,
    fileContent: string,
    existingFindings: Finding[],
    patternContext: string
  ): Promise<Finding[]> {
    const functions = this.extractFunctionsWithBodies(fileContent);
    if (functions.length === 0) return [];

    // Find which functions already have findings (by line range overlap)
    const coveredRanges = existingFindings
      .filter(f => f.file === file.relativePath)
      .map(f => ({ start: f.line - 5, end: (f.endLine || f.line) + 5 }));

    const uncovered = functions.filter(fn => {
      // Skip trivial functions (setters, getters, pure view with < 5 lines)
      if (fn.bodyLines < 5) return false;
      // Skip internal/private
      if (fn.visibility === 'internal' || fn.visibility === 'private') return false;
      // Check if any finding covers this function's line range
      return !coveredRanges.some(r => fn.startLine >= r.start && fn.startLine <= r.end);
    });

    if (uncovered.length === 0) return [];

    // Extract state variables and imports for context
    const stateContext = this.extractStateContext(fileContent);
    const projectBrief = this.projectContext ? formatContextForPrompt(this.projectContext) : '';

    const allFindings: Finding[] = [];

    // Batch uncovered functions into groups of 3 to reduce API calls
    const batches: typeof uncovered[] = [];
    for (let i = 0; i < uncovered.length; i += 3) {
      batches.push(uncovered.slice(i, i + 3));
    }

    for (const batch of batches) {
      const funcSections = batch.map(fn => {
        const lines = fileContent.split('\n');
        const body = lines.slice(fn.startLine - 1, fn.endLine).map(
          (line, i) => `${fn.startLine + i}: ${line}`
        ).join('\n');
        return `### ${fn.name}() — line ${fn.startLine} (${fn.visibility}, ${fn.mutability})\n\`\`\`solidity\n${body}\n\`\`\``;
      }).join('\n\n');

      const systemPrompt = `You are Krait, performing TARGETED function-level analysis. Previous analysis passes looked at this file but did NOT find issues in these specific functions. Your job is to examine each function carefully for bugs.

${projectBrief}

${patternContext}

${FP_AVOIDANCE}

## Rules:
- Analyze EACH function below independently.
- Focus on: incorrect arithmetic, wrong recipients, fee errors, token edge cases, state inconsistency.
- Every finding MUST have a concrete exploit scenario.
- Only report medium severity or above.
- An empty findings array is expected if the functions are correct.`;

      const userPrompt = `## Targeted Analysis: ${file.relativePath}

### Contract context (state variables and key types):
\`\`\`solidity
${stateContext}
\`\`\`

### Functions to analyze (these had NO findings in previous passes):

${funcSections}

Check each function for: incorrect fee/price math, wrong transfer amounts/recipients, type casting overflow, token compatibility issues, state that should be updated but isn't.`;

      try {
        const findings = await this.callClaude(systemPrompt, userPrompt, file.relativePath, this.config.deepModel);
        allFindings.push(...findings);
      } catch {
        // Continue with other batches
      }
    }

    return allFindings;
  }

  /**
   * Extract function definitions with their bodies from Solidity source.
   */
  private extractFunctionsWithBodies(content: string): Array<{
    name: string;
    startLine: number;
    endLine: number;
    bodyLines: number;
    visibility: string;
    mutability: string;
  }> {
    const lines = content.split('\n');
    const functions: Array<{
      name: string; startLine: number; endLine: number;
      bodyLines: number; visibility: string; mutability: string;
    }> = [];

    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(/function\s+(\w+)\s*\(/);
      if (!match) continue;
      const trimmed = lines[i].trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      const name = match[1];
      // Build context from function signature only (up to opening brace)
      let contextEnd = i;
      for (let k = i; k < Math.min(i + 12, lines.length); k++) {
        contextEnd = k;
        if (lines[k].includes('{')) break;
      }
      const context = lines.slice(i, contextEnd + 1).join(' ');
      const visibility = context.includes('external') ? 'external' :
        context.includes('public') ? 'public' :
        context.includes('internal') ? 'internal' :
        context.includes('private') ? 'private' : 'public';
      const mutability = context.includes('view') ? 'view' :
        context.includes('pure') ? 'pure' : 'mutable';

      // Find function body end by brace matching
      let braceCount = 0;
      let started = false;
      let endLine = i;
      for (let j = i; j < lines.length; j++) {
        for (const ch of lines[j]) {
          if (ch === '{') { braceCount++; started = true; }
          if (ch === '}') braceCount--;
        }
        if (started && braceCount === 0) {
          endLine = j;
          break;
        }
      }

      functions.push({
        name,
        startLine: i + 1,
        endLine: endLine + 1,
        bodyLines: endLine - i + 1,
        visibility,
        mutability,
      });
    }

    return functions;
  }

  /**
   * Extract state variables, imports, and key type definitions for context.
   */
  private extractStateContext(content: string): string {
    const lines = content.split('\n');
    const contextLines: string[] = [];

    for (const line of lines) {
      const trimmed = line.trim();
      // Imports
      if (trimmed.startsWith('import ')) {
        contextLines.push(trimmed);
        continue;
      }
      // Contract declaration
      if (trimmed.match(/^(contract|abstract contract|library)\s+/)) {
        contextLines.push(trimmed);
        continue;
      }
      // State variables (indented, not inside functions)
      if (trimmed.match(/^\s*(mapping|uint\d*|int\d*|address|bool|bytes\d*|string|enum|struct|event|error|modifier)\b/) ||
          trimmed.match(/^\s*(public|private|internal|immutable|constant)\s/)) {
        contextLines.push(trimmed);
      }
    }

    // Cap at 50 lines to keep context manageable
    return contextLines.slice(0, 50).join('\n');
  }

  async analyzeCrossContract(
    files: Array<{ file: FileInfo; content: string }>,
    perFileFindings: Finding[],
    patternContext: string
  ): Promise<Finding[]> {
    if (files.length < 2) return [];

    // Build structured summaries of all contracts
    const summaries = files.map(({ file, content }) => summarizeContract(file, content));
    const summaryText = formatSummariesForPrompt(summaries);

    // Identify core contracts (most external interactions) and include their full code
    const rankedFiles = this.rankFilesByImportance(summaries, files);
    const coreFiles = rankedFiles.slice(0, 5); // Top 5 most interconnected

    const projectBrief = this.projectContext ? formatContextForPrompt(this.projectContext) : '';

    const systemPrompt = `You are a senior security auditor performing cross-contract analysis.
You have already analyzed individual files. Now analyze how these contracts INTERACT with each other.

${projectBrief}

Focus on:
- Cross-contract reentrancy (Contract A calls Contract B which calls back into A)
- State dependency issues (reading stale or manipulable state from other contracts)
- Trust boundary violations (contracts trusting unvalidated external data or return values)
- Privilege escalation through contract interactions (chaining calls across contracts)
- Economic attack vectors spanning multiple contracts (flash loans, oracle manipulation, sandwich attacks)
- Functions that can be called by anyone on behalf of other contracts

${this.soloditContext}

${this.getChecklistContext()}
${patternContext}

CRITICAL RULES:
- Only report issues that arise from CONTRACT INTERACTIONS, not single-file issues.
- Every finding MUST reference a specific file and line number.
- Be precise. No generic warnings. Describe the concrete attack path across contracts.
- Every hop in the attack path must be verified for callability and access control.
- Max 3 hops in any attack chain — more is likely not exploitable in practice.
- Report AT MOST 2 cross-contract findings. Quality over quantity.
- An empty findings array is the EXPECTED result. Most contract interactions are safe.
- Apply the same severity calibration as per-file analysis.

${FP_AVOIDANCE}`;

    const existingFindingsText = perFileFindings.length > 0
      ? `\n\nAlready found per-file issues (do NOT re-report these):\n${perFileFindings.map(f => `- [${f.severity}] ${f.title} at ${f.file}:${f.line}`).join('\n')}`
      : '';

    // Build user prompt with summaries + full code of core contracts
    const coreCodeSections = coreFiles.map(({ file, content }) => {
      const numbered = content.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
      return `### Full code: ${file.relativePath}\n\`\`\`solidity\n${numbered}\n\`\`\``;
    }).join('\n\n');

    const userPrompt = `## Contract Architecture Summary\n\n${summaryText}\n\n## Core Contract Code (most interconnected)\n\n${coreCodeSections}${existingFindingsText}\n\nAnalyze the interactions between these contracts for cross-contract vulnerabilities. Focus on attack paths that span multiple contracts.`;

    return this.callClaude(systemPrompt, userPrompt, 'cross-contract', this.config.deepModel);
  }

  private rankFilesByImportance(
    summaries: ContractSummary[],
    files: Array<{ file: FileInfo; content: string }>
  ): Array<{ file: FileInfo; content: string }> {
    // Score files by how many external interactions they have
    const scores = summaries.map((s, i) => {
      let score = 0;
      score += s.externalCalls.length * 2;
      score += s.functions.filter(f => f.visibility === 'external' || f.visibility === 'public').length;
      score += s.functions.filter(f => f.externalCalls.length > 0).length * 3;
      score += s.stateVariables.length;
      // Boost if contract name suggests it's a core contract
      if (s.contractName.toLowerCase().includes('controller') ||
          s.contractName.toLowerCase().includes('vault') ||
          s.contractName.toLowerCase().includes('pool') ||
          s.contractName.toLowerCase().includes('router')) {
        score += 10;
      }
      return { index: i, score };
    });

    scores.sort((a, b) => b.score - a.score);
    return scores.map(s => files[s.index]);
  }

  /**
   * Gap analysis — looks for vulnerability classes that previous passes missed,
   * guided by Solodit findings that are common for this protocol type.
   */
  async analyzeGaps(
    gapContext: string,
    files: Array<{ file: FileInfo; content: string }>,
    existingFindings: Finding[]
  ): Promise<Finding[]> {
    if (!gapContext || files.length === 0) return [];

    const projectBrief = this.projectContext ? formatContextForPrompt(this.projectContext) : '';
    const existingText = existingFindings.length > 0
      ? existingFindings.map(f => `- [${f.severity}] ${f.title} at ${f.file}:${f.line}`).join('\n')
      : 'None.';

    const systemPrompt = `You are Krait, performing a GAP ANALYSIS pass. Professional auditors commonly find the vulnerabilities described below in protocols like this, but previous analysis passes did NOT find them.

${projectBrief}

${gapContext}

## Already-found findings (do NOT repeat):
${existingText}

## Rules:
- Look SPECIFICALLY for the vulnerability patterns described above. These are real bugs from real audits.
- Every finding MUST have a concrete exploit scenario with specific steps.
- Only report medium severity or above.
- Report AT MOST 2 findings per file. Quality over quantity.
- An empty findings array is perfectly acceptable — only report if genuinely confident.

${FP_AVOIDANCE}`;

    const allGapFindings: Finding[] = [];
    const topFiles = files.slice(0, 5);

    for (const { file, content } of topFiles) {
      const numbered = content.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
      const userPrompt = `## Gap Analysis: ${file.relativePath}

\`\`\`${file.language}
${numbered}
\`\`\`

Look specifically for the vulnerability patterns from real audits described in the system prompt. Focus on what previous passes missed.`;

      try {
        const findings = await this.callClaude(systemPrompt, userPrompt, file.relativePath, this.config.deepModel);
        allGapFindings.push(...findings);
      } catch {
        // Continue with other files
      }
    }

    return allGapFindings;
  }

  /**
   * Flow-based analysis — traces critical fund flows end-to-end across contracts.
   * Replaces generic cross-contract analysis with targeted flow tracing.
   */
  async analyzeFlows(
    flows: FundFlow[],
    files: Array<{ file: FileInfo; content: string }>,
    perFileFindings: Finding[],
    architectureContext: ArchitectureAnalysis,
    patternContext: string
  ): Promise<Finding[]> {
    if (flows.length === 0 || files.length < 2) return [];

    const projectBrief = this.projectContext ? formatContextForPrompt(this.projectContext) : '';
    const existingText = perFileFindings.length > 0
      ? perFileFindings.map(f => `- [${f.severity}] ${f.title} at ${f.file}:${f.line}`).join('\n')
      : 'None.';

    const allFindings: Finding[] = [];

    // Analyze top 3 flows by risk
    const topFlows = flows.slice(0, 3);

    for (const flow of topFlows) {
      // Find files involved in this flow
      const involvedFiles = files.filter(({ file, content }) => {
        const contractMatch = content.match(/contract\s+(\w+)/);
        const contractName = contractMatch ? contractMatch[1] : '';
        return flow.contracts.some(c =>
          c === contractName ||
          c.toLowerCase() === contractName.toLowerCase() ||
          file.relativePath.toLowerCase().includes(c.toLowerCase())
        );
      });

      // If we can't find the files, skip this flow
      if (involvedFiles.length === 0) continue;

      // Cap at 4 files per flow to manage token costs
      const flowFiles = involvedFiles.slice(0, 4);

      const codeSections = flowFiles.map(({ file, content }) => {
        const numbered = content.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
        return `### ${file.relativePath}\n\`\`\`solidity\n${numbered}\n\`\`\``;
      }).join('\n\n');

      const invariantsText = architectureContext.invariants.length > 0
        ? `\nInvariants that must hold:\n${architectureContext.invariants.map(i => `- ${i}`).join('\n')}`
        : '';

      const systemPrompt = `You are a senior security auditor tracing a critical fund flow end-to-end across multiple contracts.

${projectBrief}

## Already-found findings (do NOT repeat):
${existingText}

## Rules:
- Trace the SPECIFIC flow described below step by step through the code.
- At each step, verify: amounts correct, recipients correct, state consistent.
- Focus on what goes WRONG at boundaries between contracts.
- Every finding MUST reference specific file:line.
- Report AT MOST 2 findings per flow. Only report genuine bugs.
- An empty findings array is the EXPECTED result.

${FP_AVOIDANCE}`;

      const userPrompt = `## Trace the "${flow.name}" flow end-to-end

**Flow**: ${flow.description}
**Contracts involved**: ${flow.contracts.join(' → ')}
**Risk notes**: ${flow.riskNotes}
${invariantsText}

${codeSections}

ANALYSIS METHOD — for each step in this flow:
1. Find the entry function. What parameters does the user control?
2. For EACH arithmetic operation: write out the formula. Is the denominator correct? Can it be zero? Does it round in the protocol's favor?
3. For EACH transfer/payment: who is the recipient? Is it the correct address? What is the amount — is it the pre-fee or post-fee value?
4. For EACH external call: what does the called contract return? Is the return value checked? Can the called contract revert and brick this flow?
5. After ALL state changes: does the sum of outflows equal inflows? Are any tokens stuck or unaccounted for?
6. At boundaries: what happens with amount=0, amount=1, amount=MAX, first user, last user?

Only report bugs where you can identify the SPECIFIC line where the math is wrong, the SPECIFIC recipient that is incorrect, or the SPECIFIC state that becomes inconsistent. Do not report generic concerns.`;

      try {
        const knownFiles = flowFiles.map(f => f.file.relativePath);
        const findings = await this.callClaude(
          systemPrompt, userPrompt, 'flow-' + flow.name, this.config.deepModel, knownFiles
        );
        allFindings.push(...findings);
      } catch {
        // Continue with other flows
      }
    }

    return allFindings;
  }

  private async callClaude(
    systemPrompt: string,
    userPrompt: string,
    contextLabel: string,
    model?: string,
    knownFiles?: string[]
  ): Promise<Finding[]> {
    const useModel = model || this.config.model;

    // Dry-run guard: return empty findings without calling the API
    if (this.config.dryRun) {
      return [];
    }

    // Check cache before API call
    if (this.cache && !this.config.noCache) {
      const cacheKey = this.cache.computeKey(systemPrompt, userPrompt, useModel);
      const cached = this.cache.get(cacheKey);
      if (cached) {
        // Re-assign finding IDs from counter for continuity
        const findings = cached.map(f => {
          this.findingCounter++;
          return { ...f, id: `KRAIT-${String(this.findingCounter).padStart(3, '0')}` };
        });
        if (this.config.verbose) {
          console.error(`  [cache hit] ${contextLabel} (${findings.length} findings)`);
        }
        return findings;
      }
    }

    const maxRetries = 3;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const response = await this.client.messages.create({
          model: useModel,
          max_tokens: 4096,
          system: systemPrompt,
          tools: [FINDING_TOOL],
          tool_choice: { type: 'any' },
          messages: [{ role: 'user', content: userPrompt }],
        });

        const findings = this.extractFindings(response, contextLabel, knownFiles);

        // Write to cache after successful API call
        if (this.cache && !this.config.noCache) {
          const cacheKey = this.cache.computeKey(systemPrompt, userPrompt, useModel);
          this.cache.set(cacheKey, findings, useModel);
        }

        return findings;
      } catch (err: unknown) {
        lastError = err instanceof Error ? err : new Error(String(err));
        if (this.isRateLimitError(err)) {
          const waitMs = Math.min(1000 * Math.pow(2, attempt), 30000);
          if (this.config.verbose) {
            console.error(`Rate limited on ${contextLabel}, retrying in ${waitMs}ms...`);
          }
          await this.sleep(waitMs);
          continue;
        }
        throw lastError;
      }
    }

    throw lastError || new Error('Max retries exceeded');
  }

  private extractFindings(
    response: Anthropic.Message,
    contextLabel: string,
    knownFiles?: string[]
  ): Finding[] {
    const findings: Finding[] = [];

    for (const block of response.content) {
      if (block.type === 'tool_use' && block.name === 'report_findings') {
        const input = block.input as { findings: Array<Record<string, unknown>> };
        if (Array.isArray(input.findings)) {
          for (const raw of input.findings) {
            this.findingCounter++;
            let file: string;
            if (contextLabel === 'batch') {
              // Validate returned file path against known batch files
              const reportedFile = String(raw.file || '');
              if (knownFiles && knownFiles.includes(reportedFile)) {
                file = reportedFile;
              } else if (knownFiles && knownFiles.length > 0) {
                // Try partial match (Claude might return just filename or relative variant)
                const match = knownFiles.find(kf =>
                  kf.endsWith(reportedFile) || reportedFile.endsWith(kf)
                );
                file = match || knownFiles[0];
              } else {
                file = reportedFile || contextLabel;
              }
            } else if (contextLabel === 'cross-contract') {
              file = String(raw.file || contextLabel);
            } else {
              file = contextLabel;
            }

            findings.push({
              id: `KRAIT-${String(this.findingCounter).padStart(3, '0')}`,
              title: String(raw.title || 'Untitled'),
              severity: this.normalizeSeverity(raw.severity),
              confidence: this.normalizeConfidence(raw.confidence),
              file,
              line: Number(raw.line) || 0,
              endLine: raw.endLine ? Number(raw.endLine) : undefined,
              description: String(raw.description || ''),
              impact: String(raw.impact || ''),
              remediation: String(raw.remediation || ''),
              category: String(raw.category || 'unknown'),
              patternId: raw.patternId ? String(raw.patternId) : undefined,
              codeSnippet: raw.codeSnippet ? String(raw.codeSnippet) : undefined,
            });
          }
        }
      }
    }

    return findings;
  }

  private buildSystemPrompt(patternContext: string, heuristicContext?: string): string {
    return `You are Krait, an expert security auditor AI. Your job is to find bugs that LOSE MONEY or BREAK PROTOCOL LOGIC — not generic code quality issues.

## How to Analyze

Read the code like an attacker would:
1. **Trace the money**: Follow every token transfer, fee calculation, and balance update. Check the arithmetic. Does the fee get taken from the right amount? Does the recipient get the right share? Is the protocol fee sent to the right address?
2. **Trace the state**: After each function, is the contract state consistent? Can calling functions in an unexpected order break invariants?
3. **Think about edge cases**: What happens with zero amounts? With tokens that have 6 decimals instead of 18? With fee-on-transfer tokens? With the first/last depositor?
4. **Check trust boundaries**: What can untrusted callers control? Can a callback recipient exploit the calling function?

## What to Look For (PRIORITY ORDER — spend most analysis time on #1-#4):

1. **Incorrect fee/royalty/reward math** → HIGH/CRITICAL. Fee on wrong base, double-counting, fee not collected, fee sent to wrong address, spec mismatch (e.g., bps denominator wrong).
2. **Token handling edge cases** → HIGH/MEDIUM. Fee-on-transfer tokens breaking accounting, low-decimal tokens causing precision loss, zero-value transfers reverting, rebasing tokens breaking cached balances.
3. **Rounding/precision errors** → HIGH/MEDIUM. Two distinct sub-classes:
   (a) **Rounding direction**: In dual-conversion systems (deposit↔withdraw, mint↔burn, wrap↔unwrap), check that EACH direction rounds in the protocol's favor. If both round down, mint(small) can cost 0. This is different from share inflation.
   (b) **Share inflation**: First depositor donating tokens to inflate share price. Only report if no virtual offset protection exists.
4. **Business logic flaws** → HIGH/MEDIUM. Functions callable in wrong order, missing invariant checks, flash loan fee bypass, protocol fee not distributed, state inconsistency after partial failure.
5. **Unsafe external interactions** → HIGH if exploitable. Unchecked return values causing state corruption, callbacks enabling state manipulation, arbitrary calls allowing theft.
6. **Silent overflow in type casting** → HIGH. Even in Solidity 0.8+, explicit type casts like uint128(value) silently truncate without reverting. This is NOT caught by 0.8+ overflow protection.
7. **Access control** → HIGH if actually bypassable. Only report if a specific unauthorized call path exists — not "this function should have onlyOwner."
8. **Reentrancy** → ONLY if state is modified after an external call AND the reentrancy enables concrete value extraction. Do NOT report reentrancy if: the function has nonReentrant, or the contract inherits ReentrancyGuard, or there is no state change after the external call, or the reentrancy doesn't lead to profit for the attacker.

## Severity Guidelines

- **critical**: Direct, unconditional loss of user funds. Clear exploit path, no extraordinary conditions needed.
- **high**: Significant financial risk exploitable under realistic conditions. Concrete attack path required.
- **medium**: Conditional exploits, griefing with meaningful impact, or state manipulation causing material harm.
- **low**: Minor issues, theoretical concerns. Best practice violations with unlikely security consequence.

## What is NOT a finding (do NOT report):

- Missing zero-address validation, missing events, centralization risk, gas optimization
- Integer overflow/underflow in Solidity ≥0.8.0 (UNLESS inside unchecked{} blocks or via explicit type casting like uint128())
- Missing features (no pause, no timelock, no circuit breaker)
- Admin can do X (trusted roles are trusted)
- Generic reentrancy where no concrete value extraction is possible
- "Potential" issues without a concrete exploit scenario

${this.architectureContext ? formatArchitectureForSystemPrompt(this.architectureContext) : ''}

${this.soloditContext}

${this.getChecklistContext()}
${patternContext}

${this.projectContext ? formatContextForPrompt(this.projectContext) : ''}

${heuristicContext || ''}

## Output Rules:

- Every finding MUST have a concrete exploit scenario: attacker does X → causes Y → extracts Z.
- Every finding MUST reference the exact line number.
- Quality over quantity. An empty findings array is perfectly acceptable and EXPECTED for clean code.
- When in doubt about severity, grade LOWER.`;
  }

  private buildFilePrompt(file: FileInfo, content: string): string {
    const lines = content.split('\n');
    const numberedContent = lines.map((line, i) => `${i + 1}: ${line}`).join('\n');

    // Add contract role context if available
    let roleContext = '';
    if (this.projectContext) {
      const contractName = this.extractContractNameFromContent(content);
      if (contractName) {
        const role = this.projectContext.contractRoles.get(contractName);
        const parents = this.projectContext.inheritanceGraph.get(contractName);
        if (role) roleContext += `\nContract role: ${role}`;
        if (parents && parents.length > 0) roleContext += `\nInherits from: ${parents.join(', ')}`;
      }
    }

    // Detect what the file does and generate targeted analysis hints
    const analysisHints = this.detectFileAnalysisHints(content);

    // Architecture-level context for this specific file
    const archFileContext = this.architectureContext
      ? formatArchitectureForFilePrompt(this.architectureContext, file, content)
      : '';

    // For large files, extract function inventory so Claude analyzes each one
    const functionInventory = file.lines > 150 ? this.extractFunctionInventory(content) : '';

    return `Analyze this ${file.language} file for security vulnerabilities.

File: ${file.relativePath}
Lines: ${file.lines}${roleContext}${archFileContext}
${analysisHints}${functionInventory}
\`\`\`${file.language}
${numberedContent}
\`\`\`

INSTRUCTIONS:
1. Read EVERY function listed above. Do not skip functions in the middle or end of the file.
2. For each function: trace token flows, check arithmetic, verify recipients and amounts.
3. Check for edge cases: zero amounts, first/last user, type casting truncation, low-decimal tokens.
4. Only then consider reentrancy, access control, etc.

Report findings with exact line numbers. Empty findings array is fine.`;
  }

  /**
   * Detect what a file does and return targeted analysis hints.
   * This tells Claude what to focus on for THIS specific file.
   */
  private detectFileAnalysisHints(content: string): string {
    const lower = content.toLowerCase();
    const hints: string[] = [];

    // Fee/royalty logic
    if (lower.includes('fee') || lower.includes('royalt') || lower.includes('bps') ||
        lower.includes('commission') || lower.includes('protocol fee')) {
      hints.push('- This file has FEE/ROYALTY logic. Check: Is the fee calculated on the correct base amount (before or after other deductions)? Is the fee sent to the correct recipient? Is the fee denominator correct (bps = /10000)?');
    }

    // Flash loan logic
    if (lower.includes('flashloan') || lower.includes('flash loan') || lower.includes('flashfee')) {
      hints.push('- This file has FLASH LOAN logic. Check: Is the flash loan fee calculated correctly? Is the fee taken from the right address? Can the flash loan mechanism be used to bypass fees in other functions?');
    }

    // Token transfer logic
    if (lower.includes('transferfrom') || lower.includes('safetransferfrom') || lower.includes('safetransfer')) {
      hints.push('- This file transfers tokens. Check: Does it handle fee-on-transfer tokens (actual received != amount)? Does it handle zero-amount transfers? Does it handle low-decimal tokens?');
    }

    // Virtual reserves / AMM math
    if (lower.includes('reserve') || lower.includes('getamount') || lower.includes('quote')) {
      hints.push('- This file has RESERVE/AMM math. Check: Can reserves be manipulated? Is there silent overflow in reserve updates (uint128 casting)? Does the price calculation handle edge cases?');
    }

    // Share/vault/wrapper math
    if (lower.includes('totalsupply') && (lower.includes('totalassets') || lower.includes('share') ||
        lower.includes('wrapper') || lower.includes('wrapped') ||
        (lower.includes('deposit') && lower.includes('withdraw') && lower.includes('mint')))) {
      hints.push('- This file has SHARE/VAULT/WRAPPER math. Check SEPARATELY: (1) ROUNDING DIRECTION: In dual-conversion functions (deposit↔withdraw, mint↔burn, wrap↔unwrap), does each direction round in the protocol\'s favor? If both round DOWN, mint(1 wei) can cost 0 tokens — this is exploitable. (2) FIRST DEPOSITOR: Can the first depositor inflate share price via donation? Division by zero when supply is 0?');
    }

    // Callback patterns
    if (lower.includes('onerc721received') || lower.includes('onerc1155received') ||
        lower.includes('callback') || lower.includes('fallback')) {
      hints.push('- This file has CALLBACK patterns. Check: Is state consistent before callbacks? Can callback recipients manipulate state?');
    }

    // Type casting
    if (lower.includes('uint128(') || lower.includes('uint96(') || lower.includes('uint64(') ||
        lower.includes('uint32(') || lower.includes('int128(')) {
      hints.push('- This file has EXPLICIT TYPE CASTS (uint128, etc). These silently truncate in Solidity 0.8+ — check if values can exceed the target type range.');
    }

    // Owner/execute patterns
    if (lower.includes('execute') || lower.includes('multicall') || lower.includes('delegatecall')) {
      hints.push('- This file has ARBITRARY EXECUTION logic. Check: Can the caller steal tokens via crafted call data? Can approved tokens be drained?');
    }

    // ERC2981 royalty — external call trusting return value
    if (lower.includes('royaltyinfo') || lower.includes('erc2981') || lower.includes('royalty')) {
      hints.push('- This file calls ERC2981 royaltyInfo(). Check: What if the NFT returns an excessive royalty (e.g., 100%)? Can a malicious NFT contract drain the pool/buyer by claiming all proceeds as royalty? Is the royalty amount bounded?');
    }

    // Flash loan fee distribution
    if (lower.includes('flashloan') || lower.includes('flashfee')) {
      hints.push('- FLASH LOAN FEE DISTRIBUTION: Does the flash loan fee get split correctly? Is the protocol fee portion sent to the factory/treasury? Or does it all stay in the pool?');
    }

    // ETH transfers to arbitrary addresses (revert risk)
    if ((lower.includes('.call{value') || lower.includes('.transfer(') || lower.includes('.send(')) &&
        (lower.includes('royalt') || lower.includes('recipient') || lower.includes('receiver'))) {
      hints.push('- This file sends ETH to external addresses. Check: What if the recipient is a contract that reverts (no receive/fallback)? Does this brick the entire function (sell, buy, etc.)?');
    }

    // Zero-amount transfer edge case
    if (lower.includes('changefee') || (lower.includes('fee') && lower.includes('transfer'))) {
      hints.push('- FEE TRANSFER EDGE CASE: What happens when the fee amount is zero? Some ERC20 tokens revert on transfer(0). Does this brick the function?');
    }

    // CREATE2 / deterministic deployment
    if (lower.includes('create2') || lower.includes('clonedeterministic') || lower.includes('salt')) {
      hints.push('- This file uses deterministic deployment. Check: Can an attacker predict the address and front-run creation? Can they deploy a malicious contract at the expected address?');
    }

    // Ownership transfer + token approval
    if (lower.includes('transferownership') || lower.includes('setowner') ||
        (lower.includes('owner') && lower.includes('approve'))) {
      hints.push('- This file has OWNERSHIP logic. Check: After ownership transfer, are token approvals still valid? Can the old owner exploit stale approvals?');
    }

    if (hints.length === 0) return '';
    return '\n**File-specific analysis focus:**\n' + hints.join('\n') + '\n';
  }

  /**
   * Extract a function inventory from the file so Claude knows what to analyze.
   * For large files, Claude tends to focus on the first few functions and skip
   * functions later in the file (flashLoan, changeFeeQuote, etc).
   */
  private extractFunctionInventory(content: string): string {
    const funcRegex = /function\s+(\w+)\s*\(([^)]*)\)[^{]*(?:external|public|internal|private)?[^{]*/g;
    const functions: Array<{ name: string; line: number; visibility: string; mutability: string }> = [];
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      // Match function name — params may span multiple lines so just match the start
      const match = lines[i].match(/function\s+(\w+)\s*\(/);
      if (!match) continue;
      // Skip comments
      const trimmed = lines[i].trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      const name = match[1];
      // Build context from function signature only (up to opening brace)
      let sigEnd = i;
      for (let k = i; k < Math.min(i + 12, lines.length); k++) {
        sigEnd = k;
        if (lines[k].includes('{')) break;
      }
      const context = lines.slice(i, sigEnd + 1).join(' ');
      const visibility = context.includes('external') ? 'external' :
        context.includes('public') ? 'public' :
        context.includes('internal') ? 'internal' :
        context.includes('private') ? 'private' : 'public';
      const mutability = context.includes('view') ? 'view' :
        context.includes('pure') ? 'pure' : 'mutable';

      functions.push({ name, line: i + 1, visibility, mutability });
    }

    if (functions.length < 3) return '';

    // Categorize functions by risk level
    const stateChanging = functions.filter(f => f.mutability === 'mutable' && f.visibility !== 'private' && f.visibility !== 'internal');
    const viewFuncs = functions.filter(f => f.mutability !== 'mutable');

    let inventory = '\n**Functions in this file (analyze EACH state-changing function):**\n';
    for (const f of stateChanging) {
      inventory += `- \`${f.name}()\` (line ${f.line}, ${f.visibility}) — STATE-CHANGING, must analyze\n`;
    }
    if (viewFuncs.length > 0) {
      // Flag view functions that compute prices/fees/quotes — bugs here affect callers
      const criticalViews = viewFuncs.filter(f =>
        /quote|price|fee|rate|amount|balance|value|convert|preview/i.test(f.name)
      );
      const otherViews = viewFuncs.filter(f =>
        !/quote|price|fee|rate|amount|balance|value|convert|preview/i.test(f.name)
      );
      if (criticalViews.length > 0) {
        for (const f of criticalViews) {
          inventory += `- \`${f.name}()\` (line ${f.line}, view) — COMPUTES PRICES/FEES, check math carefully\n`;
        }
      }
      if (otherViews.length > 0) {
        inventory += `- Plus ${otherViews.length} other view/pure functions: ${otherViews.map(f => f.name + '()').join(', ')}\n`;
      }
    }

    return inventory;
  }

  /**
   * Identify which functions have NO findings from the first pass.
   * Returns a focused instruction for the deep pass.
   */
  private identifyUncoveredFunctions(content: string, findings: Finding[]): string {
    const lines = content.split('\n');
    const funcStarts: Array<{ name: string; line: number; endLine: number }> = [];

    for (let i = 0; i < lines.length; i++) {
      const match = lines[i].match(/function\s+(\w+)\s*\(/);
      if (!match) continue;
      const trimmed = lines[i].trim();
      if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

      // Find end of function (brace counting)
      let braceCount = 0;
      let started = false;
      let endLine = i;
      for (let j = i; j < lines.length; j++) {
        for (const ch of lines[j]) {
          if (ch === '{') { braceCount++; started = true; }
          if (ch === '}') braceCount--;
        }
        if (started && braceCount === 0) { endLine = j; break; }
      }
      funcStarts.push({ name: match[1], line: i + 1, endLine: endLine + 1 });
    }

    // A function is "covered" if any finding falls within its line range
    const uncovered = funcStarts.filter(func => {
      return !findings.some(f => f.line >= func.line && f.line <= func.endLine);
    });

    if (uncovered.length === 0) return '';

    return `\n**UNCOVERED functions (zero findings from first pass — prioritize these):**\n` +
      uncovered.map(f => `- \`${f.name}()\` lines ${f.line}-${f.endLine}`).join('\n') + '\n';
  }

  private getChecklistContext(): string {
    if (!this.projectContext) return '';
    return getProtocolChecklist(
      this.projectContext.protocolType || '',
      this.projectContext.dependencies || []
    );
  }

  private extractContractNameFromContent(content: string): string | null {
    const match = content.match(/\b(?:contract|library|abstract\s+contract)\s+(\w+)/);
    return match ? match[1] : null;
  }

  private normalizeSeverity(val: unknown): Finding['severity'] {
    const s = String(val).toLowerCase();
    if (['critical', 'high', 'medium', 'low', 'info'].includes(s)) {
      return s as Finding['severity'];
    }
    return 'info';
  }

  private normalizeConfidence(val: unknown): Finding['confidence'] {
    const c = String(val).toLowerCase();
    if (['high', 'medium', 'low'].includes(c)) {
      return c as Finding['confidence'];
    }
    return 'medium';
  }

  private isRateLimitError(err: unknown): boolean {
    if (err instanceof Error) {
      return err.message.includes('rate') || err.message.includes('429');
    }
    return false;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}
