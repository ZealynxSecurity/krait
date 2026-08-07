export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Language = 'solidity' | 'rust' | 'typescript' | 'javascript';

export type Domain = 'solidity' | 'rust-solana' | 'web2-typescript' | 'ai-red-team';

export interface Finding {
  id: string;
  title: string;
  severity: Severity;
  confidence: 'high' | 'medium' | 'low';
  file: string;
  line: number;
  endLine?: number;
  description: string;
  impact: string;
  remediation: string;
  category: string;
  patternId?: string;
  codeSnippet?: string;
  soloditRefs?: string[];
  // A1/A2/A4 metadata, propagated from pipeline agents.
  // All optional — pre-existing findings without these still validate.
  stepExecution?: string;
  rulesApplied?: Array<{ code: string; applied: boolean; reason?: string }>;
  depthEvidence?: string[];
  missingPrecondition?: string;
  preconditionType?: 'STATE' | 'ACCESS' | 'TIMING' | 'EXTERNAL' | 'BALANCE';
  postconditionsCreated?: string;
  postconditionTypes?: Array<'STATE' | 'ACCESS' | 'TIMING' | 'EXTERNAL' | 'BALANCE'>;
  whoBenefits?: string;
  // A3 — Impact Premise: the concrete harm (WHO loses WHAT), not the mechanism
  harmStatement?: string;
  // A5 — trust-assumption downgrade. Present when severity was reduced one tier
  // because the attack path requires a trusted actor to violate a stated assumption.
  trustAdjustment?: {
    actor: string;              // e.g. "owner", "keeper", "governance"
    assumption: string;         // the stated trust assumption being violated
    originalSeverity: Severity; // severity before the -1 tier adjustment
  };
  // A7 — root-cause consolidation. Present when several findings sharing one root
  // cause and fix were merged into this finding.
  consolidatedFrom?: string[];  // titles of the absorbed findings
  locations?: Array<{ file: string; line: number; note?: string }>;
}

export interface Report {
  projectName: string;
  projectPath: string;
  timestamp: string;
  duration: number;
  summary: ReportSummary;
  findings: Finding[];
  filesAnalyzed: FileInfo[];
  patternsUsed: number;
  model: string;
}

export interface ReportSummary {
  totalFindings: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
  filesAnalyzed: number;
  linesOfCode: number;
}

export interface FileInfo {
  path: string;
  relativePath: string;
  language: Language;
  lines: number;
  size: number;
}

export interface VulnerabilityPattern {
  id: string;
  name: string;
  category: string;
  severity: Severity;
  description: string;
  detection: {
    strategy: string;
    regex?: string;
    ast_pattern?: string;
    indicators: string[];
  };
  real_examples?: Array<{
    source: string;
    project: string;
    finding_id: string;
    impact: string;
    amount_lost?: string;
    code_vulnerable?: string;
    code_fixed?: string;
  }>;
  false_positive_notes?: string;
  tags: string[];
  added_date?: string;
  confidence: 'high' | 'medium' | 'low';
}

export interface ArchitectureAnalysis {
  protocolSummary: string;
  fundFlows: FundFlow[];
  invariants: string[];
  trustAssumptions: string[];
  contractRoles: ContractRole[];
  criticalPaths: string[];
}

export interface FundFlow {
  name: string;
  contracts: string[];
  description: string;
  riskNotes: string;
}

export interface ContractRole {
  name: string;
  file: string;
  role: string;
  riskLevel: 'high' | 'medium' | 'low';
  keyFunctions: string[];
}

export interface KraitConfig {
  apiKey: string;
  model: string;
  deepModel: string;
  patternsDir: string;
  maxFileSizeKb: number;
  minLines: number;
  excludePatterns: string[];
  outputFormat: 'json' | 'markdown' | 'both';
  verbose: boolean;
  quick: boolean;
  noCache: boolean;
  dryRun: boolean;
  soloditApiKey?: string;
  // Fuzzer options
  fuzzRuns?: number;          // Foundry fuzz runs per test (default 1000)
  maxIterations?: number;     // Max fix iterations per test file (default 3)
  testOutputDir?: string;     // Output dir for generated tests (default '.audit/invariant-tests')
}

export const DEFAULT_CONFIG: Omit<KraitConfig, 'apiKey'> = {
  model: 'claude-sonnet-4-20250514',
  deepModel: 'claude-opus-4-20250514',
  patternsDir: 'patterns',
  maxFileSizeKb: 500,
  minLines: 20,
  excludePatterns: [
    // Dependencies
    '**/node_modules/**',
    '**/lib/**',
    '**/libraries/**',
    '**/vendor/**',
    // Test files and directories
    '**/test/**',
    '**/tests/**',
    '**/root_tests/**',
    '**/scenario_tests/**',
    '**/forge-test/**',
    '**/*.test.*',
    '**/*.spec.*',
    '**/*.t.sol',
    '**/*_test.sol',
    '**/*_test.rs',
    // Mocks
    '**/mock/**',
    '**/mocks/**',
    '**/Mock*.sol',
    // Interfaces (no implementation to audit)
    '**/interfaces/**',
    '**/interface/**',
    // Scripts and deployment
    '**/script/**',
    '**/scripts/**',
    '**/deploy/**',
    // Build artifacts
    '**/.git/**',
    '**/build/**',
    '**/dist/**',
    '**/artifacts/**',
    '**/cache/**',
    '**/coverage/**',
    '**/out/**',
    '**/typechain-types/**',
  ],
  outputFormat: 'both',
  verbose: false,
  quick: false,
  noCache: false,
  dryRun: false,
};
