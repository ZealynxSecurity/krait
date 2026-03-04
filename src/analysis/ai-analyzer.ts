import Anthropic from '@anthropic-ai/sdk';
import { Finding, FileInfo, KraitConfig, VulnerabilityPattern } from '../core/types.js';
import { summarizeContract, formatSummariesForPrompt, ContractSummary } from './contract-summarizer.js';
import { ProjectContext, formatContextForPrompt } from './context-gatherer.js';

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

  constructor(config: KraitConfig) {
    this.config = config;
    this.client = new Anthropic({ apiKey: config.apiKey });
  }

  /**
   * Set the project context gathered before analysis.
   * This gives Claude protocol-level understanding for every file.
   */
  setProjectContext(context: ProjectContext): void {
    this.projectContext = context;
  }

  async analyzeFile(
    file: FileInfo,
    fileContent: string,
    patternContext: string
  ): Promise<Finding[]> {
    const systemPrompt = this.buildSystemPrompt(patternContext);
    const userPrompt = this.buildFilePrompt(file, fileContent);

    const findings = await this.callClaude(systemPrompt, userPrompt, file.relativePath);
    return findings;
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

${patternContext}

CRITICAL RULES:
- Only report issues that arise from CONTRACT INTERACTIONS, not single-file issues.
- Every finding MUST reference a specific file and line number.
- Be precise. No generic warnings. Describe the concrete attack path across contracts.
- Apply the same severity calibration as per-file analysis.`;

    const existingFindingsText = perFileFindings.length > 0
      ? `\n\nAlready found per-file issues (do NOT re-report these):\n${perFileFindings.map(f => `- [${f.severity}] ${f.title} at ${f.file}:${f.line}`).join('\n')}`
      : '';

    // Build user prompt with summaries + full code of core contracts
    const coreCodeSections = coreFiles.map(({ file, content }) => {
      const numbered = content.split('\n').map((line, i) => `${i + 1}: ${line}`).join('\n');
      return `### Full code: ${file.relativePath}\n\`\`\`solidity\n${numbered}\n\`\`\``;
    }).join('\n\n');

    const userPrompt = `## Contract Architecture Summary\n\n${summaryText}\n\n## Core Contract Code (most interconnected)\n\n${coreCodeSections}${existingFindingsText}\n\nAnalyze the interactions between these contracts for cross-contract vulnerabilities. Focus on attack paths that span multiple contracts.`;

    return this.callClaude(systemPrompt, userPrompt, 'cross-contract');
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

  private async callClaude(
    systemPrompt: string,
    userPrompt: string,
    contextLabel: string
  ): Promise<Finding[]> {
    const maxRetries = 3;
    let lastError: Error | null = null;

    for (let attempt = 0; attempt < maxRetries; attempt++) {
      try {
        const response = await this.client.messages.create({
          model: this.config.model,
          max_tokens: 4096,
          system: systemPrompt,
          tools: [FINDING_TOOL],
          tool_choice: { type: 'any' },
          messages: [{ role: 'user', content: userPrompt }],
        });

        return this.extractFindings(response, contextLabel);
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
    contextLabel: string
  ): Finding[] {
    const findings: Finding[] = [];

    for (const block of response.content) {
      if (block.type === 'tool_use' && block.name === 'report_findings') {
        const input = block.input as { findings: Array<Record<string, unknown>> };
        if (Array.isArray(input.findings)) {
          for (const raw of input.findings) {
            this.findingCounter++;
            const file = contextLabel === 'cross-contract'
              ? String(raw.file || contextLabel)
              : contextLabel;

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

  private buildSystemPrompt(patternContext: string): string {
    return `You are Krait, an expert security auditor AI. You analyze smart contract and application code for vulnerabilities.

Your analysis must be:
1. PRECISE: Every finding must reference a specific line number in the code.
2. ACTIONABLE: Every finding must include a concrete remediation.
3. HONEST: Only report real issues you are confident about. Do NOT hallucinate vulnerabilities.
4. SELECTIVE: Only report issues that a senior auditor would include in a professional audit report. Prefer fewer, higher-quality findings over volume.

## Severity Guidelines

- **critical**: Direct, unconditional loss of user funds or complete protocol takeover. The exploit path must be clear and achievable without extraordinary conditions.
- **high**: Significant financial risk or privilege escalation that is exploitable under realistic conditions. Must have a concrete attack path.
- **medium**: Conditional exploits requiring specific circumstances, griefing attacks with meaningful impact, or state manipulation that could cause material harm.
- **low**: Minor issues with limited security impact. Best practice violations that have a theoretical but unlikely security consequence.
- **info**: Code quality, gas optimization, style issues with no direct security impact.

## Severity Calibration — What is NOT high/critical:

- Missing zero-address validation → low (at most). Admin misconfiguration is not an exploit.
- Missing event emissions → info. No security impact.
- Missing input validation on admin/owner functions → low. Trusted roles are trusted.
- Centralization risk (owner can do X) → info or low. This is a design choice, not a vulnerability.
- Gas inefficiency or unbounded loops → low (unless it causes permanent DoS of critical functions).
- Integer overflow/underflow in Solidity ≥0.8.0 → NOT a finding. Built-in checks revert automatically. Only report if unchecked{} blocks are used incorrectly.
- "Missing feature" findings (no circuit breaker, no pause mechanism, no timelock) → info. Report what IS broken, not what COULD be added.
- Using a single oracle without fallback → medium at most (not high), and only if the oracle can be manipulated.

## Severity Calibration — What IS high/critical:

- Reentrancy that enables fund theft (state updated after external call in a function handling value) → critical
- Access control bypass allowing unauthorized users to call privileged functions → critical or high
- Price/oracle manipulation with a concrete profitable attack path → high or critical
- Rounding errors that allow value extraction (e.g., deposit/withdraw rounding exploits) → high
- Cross-function or cross-contract reentrancy → high or critical
- Unchecked external call return values where failure causes inconsistent state → medium or high

Use the vulnerability patterns below as reference for what to look for. They are real patterns from past audits.

${patternContext}

${this.projectContext ? formatContextForPrompt(this.projectContext) : ''}

## Critical Rules:

- Do NOT report issues in test files, mock contracts, or example code.
- Do NOT report standard library usage as vulnerable unless misused.
- If a function has proper access control (onlyOwner, modifier, require(msg.sender == X)), do not flag it as missing access control.
- If the contract uses Solidity ≥0.8.0, do NOT flag arithmetic overflow/underflow unless inside unchecked{} blocks.
- Look for the ACTUAL vulnerability, not just code that looks similar to a pattern.
- When in doubt about severity, grade it LOWER. A medium is better than a false high.
- Report the findings array. If no vulnerabilities are found, report an empty findings array — this is perfectly acceptable.`;
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

    return `Analyze the following ${file.language} file for security vulnerabilities.

File: ${file.relativePath}
Language: ${file.language}
Lines: ${file.lines}${roleContext}

\`\`\`${file.language}
${numberedContent}
\`\`\`

Report security vulnerabilities you find. Focus on exploitable issues — quality over quantity.
Each finding MUST include the exact line number.
If there are no real vulnerabilities, report an empty findings array.`;
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
