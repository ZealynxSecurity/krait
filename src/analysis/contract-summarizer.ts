import { FileInfo } from '../core/types.js';

export interface ContractSummary {
  file: FileInfo;
  contractName: string;
  inherits: string[];
  stateVariables: string[];
  modifiers: string[];
  functions: FunctionSummary[];
  externalCalls: ExternalCall[];
  events: string[];
}

export interface FunctionSummary {
  name: string;
  visibility: string;
  modifiers: string[];
  line: number;
  parameters: string;
  stateChanges: string[];
  externalCalls: string[];
  emitsEvents: string[];
}

export interface ExternalCall {
  line: number;
  target: string;
  method: string;
  context: string;
}

export function summarizeContract(file: FileInfo, content: string): ContractSummary {
  const lines = content.split('\n');

  const summary: ContractSummary = {
    file,
    contractName: extractContractName(lines),
    inherits: extractInheritance(lines),
    stateVariables: extractStateVariables(lines),
    modifiers: extractModifiers(lines),
    functions: extractFunctions(lines),
    externalCalls: extractExternalCalls(lines),
    events: extractEvents(lines),
  };

  return summary;
}

function extractContractName(lines: string[]): string {
  for (const line of lines) {
    const match = line.match(/contract\s+(\w+)/);
    if (match) return match[1];
  }
  return 'Unknown';
}

function extractInheritance(lines: string[]): string[] {
  for (const line of lines) {
    const match = line.match(/contract\s+\w+\s+is\s+(.+?)\s*\{/);
    if (match) {
      return match[1].split(',').map(s => s.trim());
    }
  }
  return [];
}

function extractStateVariables(lines: string[]): string[] {
  const vars: string[] = [];
  let inContract = false;
  let braceDepth = 0;

  for (const line of lines) {
    if (line.match(/contract\s+\w+/)) inContract = true;
    if (!inContract) continue;

    for (const ch of line) {
      if (ch === '{') braceDepth++;
      if (ch === '}') braceDepth--;
    }

    // State vars are at brace depth 1 (inside contract, outside functions)
    if (braceDepth === 1) {
      const varMatch = line.match(/^\s+(mapping|uint|int|address|bool|bytes|string|I\w+|IERC\w+)\S*\s+.*\b(\w+)\s*[;=]/);
      if (varMatch) {
        vars.push(line.trim().replace(/;$/, ''));
      }
    }
  }

  return vars.slice(0, 30); // Cap to avoid huge lists
}

function extractModifiers(lines: string[]): string[] {
  const mods: string[] = [];
  for (const line of lines) {
    const match = line.match(/modifier\s+(\w+)/);
    if (match) mods.push(match[1]);
  }
  return mods;
}

function extractFunctions(lines: string[]): FunctionSummary[] {
  const functions: FunctionSummary[] = [];
  let i = 0;

  while (i < lines.length) {
    const line = lines[i];
    const funcMatch = line.match(/function\s+(\w+)\s*\(([^)]*)\)/);
    if (funcMatch) {
      const name = funcMatch[1];
      const parameters = funcMatch[2].trim();

      // Get visibility and modifiers from this line and possibly next lines
      const headerLines: string[] = [];
      let j = i;
      while (j < lines.length && !lines[j].includes('{') && j < i + 5) {
        headerLines.push(lines[j]);
        j++;
      }
      if (j < lines.length) headerLines.push(lines[j]);
      const header = headerLines.join(' ');

      const visibility = extractVisibility(header);
      const modifiers = extractFunctionModifiers(header);

      // Scan function body for state changes and external calls
      const bodyStart = j;
      let braceCount = 0;
      let bodyStarted = false;
      const stateChanges: string[] = [];
      const externalCalls: string[] = [];
      const emitsEvents: string[] = [];

      for (let k = i; k < lines.length; k++) {
        for (const ch of lines[k]) {
          if (ch === '{') { braceCount++; bodyStarted = true; }
          if (ch === '}') braceCount--;
        }

        if (bodyStarted && k > bodyStart) {
          const bodyLine = lines[k].trim();
          // State changes
          if (bodyLine.match(/\w+\[.*\]\s*[+\-*/]?=/) || bodyLine.match(/\w+\s*[+\-*/]?=\s*\w/)) {
            stateChanges.push(bodyLine.slice(0, 80));
          }
          // External calls
          if (bodyLine.match(/\.\w+\(/) && !bodyLine.startsWith('//')) {
            externalCalls.push(bodyLine.slice(0, 80));
          }
          // Events
          const eventMatch = bodyLine.match(/emit\s+(\w+)/);
          if (eventMatch) emitsEvents.push(eventMatch[1]);
        }

        if (bodyStarted && braceCount === 0) break;
      }

      functions.push({
        name,
        visibility,
        modifiers,
        line: i + 1,
        parameters,
        stateChanges: stateChanges.slice(0, 5),
        externalCalls: externalCalls.slice(0, 5),
        emitsEvents,
      });
    }
    i++;
  }

  return functions;
}

function extractVisibility(header: string): string {
  if (header.includes('external')) return 'external';
  if (header.includes('public')) return 'public';
  if (header.includes('internal')) return 'internal';
  if (header.includes('private')) return 'private';
  return 'public'; // default
}

function extractFunctionModifiers(header: string): string[] {
  const mods: string[] = [];
  // Common modifier patterns
  const modPatterns = [
    'onlyOwner', 'nonReentrant', 'whenNotPaused', 'onlyAdmin',
    'onlyMinter', 'onlyVaultController', 'onlyPauser',
    'paysInterest', 'whenMintEnabled', 'override', 'virtual',
  ];
  for (const mod of modPatterns) {
    if (header.includes(mod)) mods.push(mod);
  }
  // Also catch custom modifiers (word before { that's not a keyword)
  const customMod = header.match(/\)\s+(?:external|public|internal|private)?\s*(?:view|pure|payable)?\s*(?:returns\s*\([^)]*\))?\s+(\w+)/);
  if (customMod && !['returns', 'override', 'virtual', 'view', 'pure', 'payable'].includes(customMod[1])) {
    if (!mods.includes(customMod[1])) mods.push(customMod[1]);
  }
  return mods.filter(m => !['override', 'virtual'].includes(m));
}

function extractExternalCalls(lines: string[]): ExternalCall[] {
  const calls: ExternalCall[] = [];

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();
    if (line.startsWith('//') || line.startsWith('*')) continue;

    // .call{value:
    const callMatch = line.match(/(\w+)\.call\{/);
    if (callMatch) {
      calls.push({ line: i + 1, target: callMatch[1], method: 'call', context: line.slice(0, 100) });
    }

    // Interface calls: IERC20(addr).transfer(...)
    const ifaceMatch = line.match(/(\w+)\(([^)]*)\)\.(\w+)\(/);
    if (ifaceMatch) {
      calls.push({ line: i + 1, target: ifaceMatch[1], method: ifaceMatch[3], context: line.slice(0, 100) });
    }

    // Variable.method() calls to known contract types
    const varCallMatch = line.match(/(\w+)\.(\w+)\(/);
    if (varCallMatch && !['abi', 'msg', 'block', 'tx', 'type', 'super', 'this'].includes(varCallMatch[1])) {
      // Skip common non-external calls
      if (!['push', 'pop', 'length', 'encode', 'decode', 'add', 'sub', 'mul', 'div'].includes(varCallMatch[2])) {
        calls.push({ line: i + 1, target: varCallMatch[1], method: varCallMatch[2], context: line.slice(0, 100) });
      }
    }
  }

  return calls.slice(0, 50);
}

function extractEvents(lines: string[]): string[] {
  const events: string[] = [];
  for (const line of lines) {
    const match = line.match(/event\s+(\w+)/);
    if (match) events.push(match[1]);
  }
  return events;
}

export function formatSummariesForPrompt(summaries: ContractSummary[]): string {
  const parts: string[] = [];

  for (const s of summaries) {
    const lines: string[] = [];
    lines.push(`### ${s.contractName} (${s.file.relativePath}, ${s.file.lines} lines)`);
    if (s.inherits.length > 0) lines.push(`Inherits: ${s.inherits.join(', ')}`);

    if (s.stateVariables.length > 0) {
      lines.push(`State variables: ${s.stateVariables.join('; ')}`);
    }

    if (s.modifiers.length > 0) {
      lines.push(`Modifiers: ${s.modifiers.join(', ')}`);
    }

    lines.push('');
    lines.push('Functions:');
    for (const f of s.functions) {
      const modStr = f.modifiers.length > 0 ? ` [${f.modifiers.join(', ')}]` : '';
      lines.push(`  - ${f.visibility} ${f.name}(${f.parameters}) @ L${f.line}${modStr}`);
      if (f.externalCalls.length > 0) {
        lines.push(`    External calls: ${f.externalCalls.join('; ')}`);
      }
      if (f.stateChanges.length > 0) {
        lines.push(`    State changes: ${f.stateChanges.join('; ')}`);
      }
    }

    if (s.externalCalls.length > 0) {
      lines.push('');
      lines.push('Key external calls:');
      // Deduplicate by target+method
      const seen = new Set<string>();
      for (const c of s.externalCalls) {
        const key = `${c.target}.${c.method}`;
        if (!seen.has(key)) {
          seen.add(key);
          lines.push(`  - L${c.line}: ${c.context}`);
        }
      }
    }

    parts.push(lines.join('\n'));
  }

  return parts.join('\n\n---\n\n');
}
