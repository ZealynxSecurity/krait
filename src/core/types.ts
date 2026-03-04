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

export interface KraitConfig {
  apiKey: string;
  model: string;
  deepModel: string;
  patternsDir: string;
  maxFileSizeKb: number;
  excludePatterns: string[];
  outputFormat: 'json' | 'markdown' | 'both';
  verbose: boolean;
  quick: boolean;
}

export const DEFAULT_CONFIG: Omit<KraitConfig, 'apiKey'> = {
  model: 'claude-sonnet-4-20250514',
  deepModel: 'claude-opus-4-20250514',
  patternsDir: 'patterns',
  maxFileSizeKb: 500,
  excludePatterns: [
    '**/node_modules/**',
    '**/test/**',
    '**/tests/**',
    '**/*.test.*',
    '**/*.spec.*',
    '**/mock/**',
    '**/mocks/**',
    '**/lib/**',
    '**/libraries/**',
    '**/vendor/**',
    '**/.git/**',
    '**/build/**',
    '**/dist/**',
    '**/artifacts/**',
    '**/cache/**',
    '**/coverage/**',
  ],
  outputFormat: 'both',
  verbose: false,
  quick: false,
};
