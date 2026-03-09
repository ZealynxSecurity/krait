/**
 * Detector agent — maximizes recall by casting a wide net.
 * Reports EVERY potential issue, even uncertain ones. Validation comes later.
 */

import Anthropic from '@anthropic-ai/sdk';
import { FileInfo, ArchitectureAnalysis } from '../core/types.js';
import { ResponseCache } from '../core/cache.js';
import { CandidateFinding } from './types.js';
import { formatArchitectureForSystemPrompt, formatArchitectureForFilePrompt } from '../analysis/architecture-pass.js';
import { getHeuristicsForFile, formatHeuristicsForPrompt } from '../knowledge/audit-heuristics.js';
import { ProjectContext, formatContextForPrompt } from '../analysis/context-gatherer.js';
import { getProtocolChecklist } from '../analysis/domain-checklists.js';

const CANDIDATE_TOOL: Anthropic.Tool = {
  name: 'report_candidates',
  description: 'Report ALL potential security issues found. Include even uncertain findings — validation happens later.',
  input_schema: {
    type: 'object' as const,
    properties: {
      candidates: {
        type: 'array',
        items: {
          type: 'object',
          properties: {
            title: { type: 'string', description: 'Short descriptive title' },
            severity: { type: 'string', enum: ['critical', 'high', 'medium', 'low'] },
            line: { type: 'number', description: 'Line number of the vulnerability' },
            endLine: { type: 'number', description: 'End line number' },
            category: { type: 'string', description: 'Vulnerability category' },
            description: { type: 'string', description: 'What is wrong and why' },
            codeSnippet: { type: 'string', description: 'The vulnerable code' },
            affectedFunctions: {
              type: 'array',
              items: { type: 'string' },
              description: 'Function names involved',
            },
            relatedContracts: {
              type: 'array',
              items: { type: 'string' },
              description: 'Other contracts referenced',
            },
            confidence: { type: 'number', description: 'Confidence 0-100' },
            remediation: { type: 'string', description: 'How to fix the vulnerability' },
          },
          required: ['title', 'severity', 'line', 'category', 'description', 'confidence'],
        },
      },
    },
    required: ['candidates'],
  },
};

interface DetectorOptions {
  architectureContext?: ArchitectureAnalysis | null;
  projectContext?: ProjectContext | null;
  soloditContext?: string;
  verbose?: boolean;
}

/**
 * Counter for generating unique candidate IDs within a pipeline run.
 * Create a new instance per pipeline invocation to avoid cross-run collisions.
 */
export class CandidateCounter {
  private value = 0;
  next(): string {
    this.value++;
    return `candidate-${String(this.value).padStart(3, '0')}`;
  }
  get count(): number {
    return this.value;
  }
}

/**
 * Run detection on a single file. Maximizes recall — no caps, no confidence filtering.
 */
export async function detect(
  client: Anthropic,
  file: FileInfo,
  fileContent: string,
  patternContext: string,
  model: string,
  counter: CandidateCounter,
  cache?: ResponseCache | null,
  options?: DetectorOptions,
): Promise<CandidateFinding[]> {
  const heuristics = getHeuristicsForFile(fileContent);
  const heuristicContext = formatHeuristicsForPrompt(heuristics);
  const systemPrompt = buildDetectorSystemPrompt(patternContext, heuristicContext, options);
  const userPrompt = buildDetectorFilePrompt(file, fileContent, options);

  const raw = await callDetector(client, systemPrompt, userPrompt, model, cache, options?.verbose);

  return raw.map(r => ({
    id: counter.next(),
    title: String(r.title || 'Untitled'),
    severity: normalizeSeverity(r.severity),
    file: file.relativePath,
    line: Number(r.line) || 0,
    endLine: r.endLine ? Number(r.endLine) : undefined,
    category: String(r.category || 'unknown'),
    description: String(r.description || ''),
    codeSnippet: String(r.codeSnippet || ''),
    affectedFunctions: Array.isArray(r.affectedFunctions) ? r.affectedFunctions.map(String) : [],
    relatedContracts: Array.isArray(r.relatedContracts) ? r.relatedContracts.map(String) : [],
    detectorConfidence: Number(r.confidence) || 50,
    remediation: String(r.remediation || ''),
  }));
}

function buildDetectorSystemPrompt(
  patternContext: string,
  heuristicContext: string,
  options?: DetectorOptions,
): string {
  const archContext = options?.architectureContext
    ? formatArchitectureForSystemPrompt(options.architectureContext)
    : '';

  const projectBrief = options?.projectContext
    ? formatContextForPrompt(options.projectContext)
    : '';

  const checklistContext = options?.projectContext
    ? getProtocolChecklist(
        options.projectContext.protocolType || '',
        options.projectContext.dependencies || [],
      )
    : '';

  return `You are a security vulnerability DETECTOR — the first stage of a multi-agent pipeline. Your ONLY job is to surface every POSSIBLE vulnerability. A separate Reasoner will build exploit proofs, and a Critic will disprove false positives. So DO NOT self-censor. Report anything suspicious.

## How to Analyze

Read the code like an attacker:
1. **Trace the money**: Follow every token transfer, fee calculation, and balance update. Check the arithmetic. Does the fee get taken from the right amount? Does the recipient get the right share? Is the protocol fee sent to the right address?
2. **Trace the state**: After each function, is the contract state consistent? Can calling functions in an unexpected order break invariants?
3. **Think about edge cases**: What happens with zero amounts? With tokens that have 6 decimals instead of 18? With fee-on-transfer tokens? With the first/last depositor? With max uint values?
4. **Check trust boundaries**: What can untrusted callers control? Can a callback recipient exploit the calling function? What do external calls return?

## What to Look For (PRIORITY ORDER — spend most analysis time on #1-#5):

1. **Incorrect fee/royalty/reward math** — fee on wrong base, double-counting, fee not collected, fee sent to wrong address, spec mismatch (e.g., bps denominator wrong). REPORT even if unsure.
2. **Token handling edge cases** — fee-on-transfer tokens breaking accounting, low-decimal tokens causing precision loss, zero-value transfers reverting, rebasing tokens breaking cached balances.
3. **Silent overflow in type casting** — **CRITICAL**: In Solidity 0.8+, explicit casts like \`uint128(value)\`, \`uint96(value)\`, \`uint64(value)\` do NOT revert on overflow — they silently truncate. This is different from arithmetic overflow which DOES revert. Look for ANY line with \`uint128(...)\`, \`uint96(...)\`, or \`uint64(...)\` where the input could grow large over time (reserves, accumulated fees, total supplies, running sums). These are HIGH/CRITICAL findings. Report EVERY instance you find.
4. **Rounding/precision errors** — Two distinct sub-classes:
   (a) **Rounding direction**: In dual-conversion systems (deposit↔withdraw, mint↔burn, wrap↔unwrap), check that EACH direction rounds in the protocol's favor. If both round down, mint(small) can cost 0.
   (b) **Share inflation**: First depositor donating tokens to inflate share price. Only flag if no virtual offset protection exists.
5. **Business logic flaws** — functions callable in wrong order, missing invariant checks, flash loan fee bypass, protocol fee not distributed, state inconsistency after partial failure, wrong return values.
6. **Unsafe external interactions** — unchecked return values causing state corruption, callbacks enabling state manipulation, arbitrary calls allowing theft.
7. **Access control** — if actually bypassable via specific call path (not just "this function should have onlyOwner").
8. **Reentrancy** — ONLY if state is modified after an external call AND the reentrancy enables concrete value extraction. Skip if nonReentrant/ReentrancyGuard exists.
9. **Cross-function interactions** — can calling A then B produce an unintended state? Can read-only reentrancy manipulate view functions during callbacks?
10. **Assumptions about external contracts** — what if an oracle returns stale/zero/negative price? What if a callback reenters?

## Severity Guidelines (use these when setting severity):
- **critical**: Direct, unconditional loss of user funds. Clear exploit path, no extraordinary conditions needed.
- **high**: Significant financial risk exploitable under realistic conditions.
- **medium**: Conditional exploits, griefing with meaningful impact, or state manipulation causing material harm.
- **low**: Minor issues, theoretical concerns, best practice violations.

## Reporting Rules:
- Report EVERY potential issue. Use confidence scores (0-100) to indicate uncertainty.
- Low confidence is FINE. Report partial concerns, suspicious patterns, "this looks wrong but I'm not sure."
- You do NOT need a full exploit scenario — just identify WHAT looks wrong and WHERE.
- The Reasoner will later determine if each finding is actually exploitable.
- Include a suggested remediation for each finding.

## What is genuinely NOT a finding (skip these):
- Missing zero-address validation, missing events, gas optimization
- Integer overflow in Solidity ≥0.8.0 (UNLESS inside unchecked{} blocks or via explicit type casting like uint128())
- Centralization risk / admin-can-do-X (trusted roles are trusted)
- Missing features (no pause, no timelock, no circuit breaker)
- Generic reentrancy where no concrete value extraction is possible
- "Potential" issues that are purely cosmetic (naming, documentation, style)

${archContext}

${options?.soloditContext || ''}

${checklistContext}
${patternContext}

${projectBrief}

${heuristicContext}`;
}

function buildDetectorFilePrompt(
  file: FileInfo,
  content: string,
  options?: DetectorOptions,
): string {
  const lines = content.split('\n');
  const numbered = lines.map((line, i) => `${i + 1}: ${line}`).join('\n');

  const archFileContext = options?.architectureContext
    ? formatArchitectureForFilePrompt(options.architectureContext, file, content)
    : '';

  // Detect file analysis hints (fee logic, flash loans, etc.)
  const hints = detectFileHints(content);

  // Function inventory for large files
  const inventory = file.lines > 150 ? extractFunctionInventory(content) : '';

  return `Analyze this ${file.language} file for ALL potential security vulnerabilities. You are the DETECTION stage — report everything suspicious. The Reasoner and Critic stages will validate later.

File: ${file.relativePath}
Lines: ${file.lines}${archFileContext}
${hints}${inventory}
\`\`\`${file.language}
${numbered}
\`\`\`

INSTRUCTIONS:
1. Read EVERY function. Do not skip functions in the middle or end of the file.
2. For each function: trace token flows, check arithmetic, verify recipients and amounts.
3. Report ALL potential issues with confidence scores (0-100). Low confidence is encouraged — better to flag it and let the Reasoner evaluate than to miss it.
4. For each issue, suggest how to fix it (remediation field).
5. Think about what happens at boundaries: amount=0, amount=1, amount=MAX, first user, last user.`;
}

function detectFileHints(content: string): string {
  const lower = content.toLowerCase();
  const hints: string[] = [];

  if (lower.includes('fee') || lower.includes('royalt') || lower.includes('bps') || lower.includes('commission')) {
    hints.push('- FEE/ROYALTY logic detected. Check fee base, recipient, denominator.');
  }
  if (lower.includes('flashloan') || lower.includes('flash loan') || lower.includes('flashfee')) {
    hints.push('- FLASH LOAN logic. Check fee calculation, bypass vectors.');
  }
  if (lower.includes('transferfrom') || lower.includes('safetransferfrom')) {
    hints.push('- Token transfers. Check fee-on-transfer handling, zero-amount edge cases.');
  }
  if (lower.includes('reserve') || lower.includes('getamount') || lower.includes('quote')) {
    hints.push('- RESERVE/AMM math. Check manipulation, overflow in reserve updates.');
  }
  if (lower.includes('totalsupply') && (lower.includes('totalassets') || lower.includes('share'))) {
    hints.push('- SHARE/VAULT math. Check rounding direction in both conversions, first depositor attack.');
  }
  if (lower.includes('uint128(') || lower.includes('uint96(') || lower.includes('uint64(')) {
    hints.push('- **EXPLICIT TYPE CASTS FOUND** — uint128()/uint96()/uint64() silently truncate in Solidity 0.8+ (no revert!). Report EVERY instance where the value being cast could grow over time (reserves, fees, totals). This is HIGH/CRITICAL severity.');
  }
  if (lower.includes('royaltyinfo') || lower.includes('erc2981')) {
    hints.push('- ERC2981 royaltyInfo. Check for unbounded royalty amounts draining funds.');
  }
  if (lower.includes('execute') || lower.includes('multicall') || lower.includes('delegatecall')) {
    hints.push('- ARBITRARY EXECUTION. Check for token theft via crafted calldata.');
  }

  if (hints.length === 0) return '';
  return '\n**File-specific focus:**\n' + hints.join('\n') + '\n';
}

function extractFunctionInventory(content: string): string {
  const lines = content.split('\n');
  const functions: Array<{ name: string; line: number; visibility: string; mutability: string }> = [];

  for (let i = 0; i < lines.length; i++) {
    const match = lines[i].match(/function\s+(\w+)\s*\(/);
    if (!match) continue;
    const trimmed = lines[i].trim();
    if (trimmed.startsWith('//') || trimmed.startsWith('*')) continue;

    let sigEnd = i;
    for (let k = i; k < Math.min(i + 12, lines.length); k++) {
      sigEnd = k;
      if (lines[k].includes('{')) break;
    }
    const ctx = lines.slice(i, sigEnd + 1).join(' ');
    const visibility = ctx.includes('external') ? 'external' :
      ctx.includes('public') ? 'public' :
      ctx.includes('internal') ? 'internal' :
      ctx.includes('private') ? 'private' : 'public';
    const mutability = ctx.includes('view') ? 'view' :
      ctx.includes('pure') ? 'pure' : 'mutable';

    functions.push({ name: match[1], line: i + 1, visibility, mutability });
  }

  if (functions.length < 3) return '';

  const stateChanging = functions.filter(f => f.mutability === 'mutable' && f.visibility !== 'private' && f.visibility !== 'internal');
  let inv = '\n**Functions (analyze ALL):**\n';
  for (const f of stateChanging) {
    inv += `- \`${f.name}()\` (line ${f.line}, ${f.visibility}) — STATE-CHANGING\n`;
  }
  const criticalViews = functions.filter(f =>
    f.mutability !== 'mutable' && /quote|price|fee|rate|amount|balance|value|convert|preview/i.test(f.name)
  );
  for (const f of criticalViews) {
    inv += `- \`${f.name}()\` (line ${f.line}, view) — COMPUTES PRICES/FEES\n`;
  }
  return inv;
}

async function callDetector(
  client: Anthropic,
  systemPrompt: string,
  userPrompt: string,
  model: string,
  cache?: ResponseCache | null,
  verbose?: boolean,
): Promise<Array<Record<string, unknown>>> {
  // Check cache
  if (cache) {
    const key = cache.computeKey(systemPrompt, userPrompt, model);
    const cached = cache.getJson<Array<Record<string, unknown>>>(key);
    if (cached) {
      if (verbose) console.error(`  [detector cache hit]`);
      return cached;
    }
  }

  const maxRetries = 3;
  let lastError: Error | null = null;

  for (let attempt = 0; attempt < maxRetries; attempt++) {
    try {
      // Scale max_tokens based on prompt size (large files need more output room)
      const estimatedLines = userPrompt.split('\n').length;
      const maxTokens = estimatedLines > 400 ? 8192 : 4096;

      const response = await client.messages.create({
        model,
        max_tokens: maxTokens,
        system: systemPrompt,
        tools: [CANDIDATE_TOOL],
        tool_choice: { type: 'any' },
        messages: [{ role: 'user', content: userPrompt }],
      });

      const results: Array<Record<string, unknown>> = [];
      for (const block of response.content) {
        if (block.type === 'tool_use' && block.name === 'report_candidates') {
          const input = block.input as { candidates: Array<Record<string, unknown>> };
          if (Array.isArray(input.candidates)) {
            results.push(...input.candidates);
          }
        }
      }

      // Cache raw results directly
      if (cache) {
        const key = cache.computeKey(systemPrompt, userPrompt, model);
        cache.setJson(key, results, model);
      }

      return results;
    } catch (err: unknown) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (lastError.message.includes('rate') || lastError.message.includes('429')) {
        const waitMs = Math.min(1000 * Math.pow(2, attempt), 30000);
        await new Promise(r => setTimeout(r, waitMs));
        continue;
      }
      throw lastError;
    }
  }

  throw lastError || new Error('Detector: max retries exceeded');
}

function normalizeSeverity(val: unknown): CandidateFinding['severity'] {
  const s = String(val).toLowerCase();
  if (['critical', 'high', 'medium', 'low'].includes(s)) return s as CandidateFinding['severity'];
  return 'low';
}
