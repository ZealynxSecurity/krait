/**
 * Invariant-based fuzzing pipeline types.
 * Invariant Extractor → Test Generator → Test Runner (iterative) → Reporter
 */

// ─── Invariant Extraction ───

export type InvariantCategory =
  | 'accounting'         // totalSupply == sum(balances), fee consistency
  | 'access-control'     // only owner can call X
  | 'state-transition'   // state machine constraints, valid state flows
  | 'economic'           // price/exchange rate bounds, economic invariants
  | 'token-conservation' // tokens in == tokens out, no creation/destruction
  | 'ordering'           // operations must happen in sequence
  | 'bounds'             // value within range, no underflow scenarios
  | 'relationship'       // relationship between state variables
  | 'custom';

export type InvariantStatus = 'HOLDS' | 'VIOLATED' | 'INCONCLUSIVE';

export interface Invariant {
  /** Unique ID within pipeline run (INV-001, INV-002, ...) */
  id: string;
  /** Human-readable description of what must always hold */
  description: string;
  category: InvariantCategory;
  /** Contract this invariant applies to */
  contractName: string;
  /** Source file path (relative) */
  file: string;
  /** State variables involved in the invariant */
  stateVariables: string[];
  /** Solidity boolean expression, e.g. "totalDeposits == sum(balances)" */
  formalExpression?: string;
  priority: 'high' | 'medium' | 'low';
  /** Functions that read/write the involved state and could violate it */
  relatedFunctions: string[];
}

// ─── Test Generation ───

export interface FuzzTestFile {
  /** Unique ID within pipeline run (TEST-001, ...) */
  id: string;
  /** Which invariants this test file covers */
  invariantIds: string[];
  /** File name (e.g. InvariantTest_Vault.t.sol) */
  fileName: string;
  /** Full path under the test output directory */
  filePath: string;
  /** The generated Solidity test contract source */
  solidityCode: string;
  /** Names of invariant_xxx() functions in the file */
  testFunctions: string[];
  /** Description of what setUp() does */
  setupDescription: string;
}

// ─── Forge Execution ───

export interface ForgeTestResult {
  testName: string;
  passed: boolean;
  gasUsed?: number;
  /** Forge's counterexample if the invariant was violated */
  counterexample?: string;
  /** Revert reason if the test reverted */
  revertReason?: string;
  logs?: string[];
  rawOutput: string;
}

export interface TestRunResult {
  testFileId: string;
  compileSuccess: boolean;
  compileErrors?: string[];
  results: ForgeTestResult[];
  rawStdout: string;
  rawStderr: string;
  /** Duration in milliseconds */
  duration: number;
}

// ─── Iterative Fix Loop ───

export type FixAction =
  | 'initial'
  | 'fix-setup'
  | 'fix-assertion'
  | 'fix-compile'
  | 'fix-import';

export interface IterationRecord {
  iteration: number;
  action: FixAction;
  description: string;
  testCodeBefore: string;
  testCodeAfter: string;
  runResult: TestRunResult;
}

export type FailureClassification =
  | 'real-violation'      // Invariant truly broken in the contract
  | 'test-setup-bug'      // setUp() doesn't correctly initialize state
  | 'import-error'        // Missing imports or wrong remappings
  | 'compile-error'       // Solidity compilation error in test
  | 'assertion-bug'       // Assertion doesn't match the invariant
  | 'environment-issue';  // forge not found, wrong version, etc.

// ─── Results ───

export interface InvariantResult {
  invariantId: string;
  invariant: Invariant;
  status: InvariantStatus;
  testFileId: string;
  iterations: IterationRecord[];
  finalClassification: FailureClassification | null;
  /** Forge counterexample that broke the invariant */
  counterexample?: string;
  notes: string;
}

// ─── Pipeline Stats ───

export interface FuzzPipelineStats {
  invariantsExtracted: number;
  testsGenerated: number;
  testsCompiled: number;
  testsPassed: number;
  testsFailed: number;
  invariantsHold: number;
  invariantsViolated: number;
  invariantsInconclusive: number;
  totalIterations: number;
  totalForgeRuns: number;
  /** Duration in milliseconds */
  duration: number;
}

// ─── Report ───

export interface FuzzReport {
  projectName: string;
  projectPath: string;
  timestamp: string;
  /** Total duration in milliseconds */
  duration: number;
  model: string;
  fuzzRuns: number;
  maxIterations: number;
  summary: FuzzPipelineStats;
  invariants: Invariant[];
  results: InvariantResult[];
  filesAnalyzed: string[];
}

// ─── Pipeline Options ───

export interface FuzzPipelineOptions {
  fuzzRuns?: number;          // Default 1000
  maxIterations?: number;     // Default 3
  testOutputDir?: string;     // Default '.audit/invariant-tests'
  verbose?: boolean;
  projectContext?: import('../analysis/context-gatherer.js').ProjectContext | null;
  architectureContext?: import('../core/types.js').ArchitectureAnalysis | null;
}

// ─── Foundry Config ───

export interface FoundryConfig {
  solcVersion?: string;
  remappings: string[];
  srcPath: string;
  testPath: string;
  libPaths: string[];
  evmVersion?: string;
}

// ─── Counters ───

export class InvariantCounter {
  private value = 0;
  next(): string {
    this.value++;
    return `INV-${String(this.value).padStart(3, '0')}`;
  }
  get count(): number {
    return this.value;
  }
}

export class TestFileCounter {
  private value = 0;
  next(): string {
    this.value++;
    return `TEST-${String(this.value).padStart(3, '0')}`;
  }
  get count(): number {
    return this.value;
  }
}
