#!/usr/bin/env node

/**
 * Krait Forge MCP Server — Foundry build/test gateway.
 *
 * Exposes a small surface of `forge` invocations so Claude can build and run
 * tests directly instead of round-tripping through pasted shell output. Used
 * by Krait's fuzz pipeline (test → fix → re-run) and any audit skill that
 * needs to verify a PoC compiles.
 *
 * Tools:
 *   - forge_version  : check forge availability
 *   - forge_build    : compile a Foundry project
 *   - forge_test     : run tests, optionally filtered
 *   - forge_fmt_check: check formatting (no writes)
 *
 * Safety
 * ------
 * The server NEVER invokes a shell. All commands go through execFile with an
 * argv array. The `cwd` argument MUST resolve under the directory where the
 * MCP client started this server (PWD at startup). This blocks an attacker
 * who controls a project file from steering forge to run against an arbitrary
 * absolute path.
 *
 * Output is truncated to MAX_OUTPUT_BYTES so a runaway test suite cannot
 * exhaust the model's context.
 */

import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { execFile } from "child_process";
import { promisify } from "util";
import { resolve, relative, isAbsolute } from "path";
import { z } from "zod";

const execFileP = promisify(execFile);

const ROOT = process.cwd();
const MAX_OUTPUT_BYTES = 200_000;
const DEFAULT_TIMEOUT_MS = 300_000;

interface RunResult {
  exitCode: number;
  stdout: string;
  stderr: string;
  truncated: boolean;
  command: string;
  cwd: string;
}

/** Resolve a user-supplied cwd, refusing anything outside ROOT. */
function safeCwd(cwd: string): string {
  if (!cwd || typeof cwd !== "string") {
    throw new Error("cwd is required");
  }
  const abs = isAbsolute(cwd) ? resolve(cwd) : resolve(ROOT, cwd);
  const rel = relative(ROOT, abs);
  if (rel.startsWith("..") || isAbsolute(rel)) {
    throw new Error(`cwd ${JSON.stringify(cwd)} resolves outside the MCP root ${JSON.stringify(ROOT)}`);
  }
  return abs;
}

/** Truncate to byte length with a marker (UTF-8-safe at the boundary is not required for diagnostic output). */
function truncate(s: string): { text: string; truncated: boolean } {
  const buf = Buffer.from(s, "utf8");
  if (buf.byteLength <= MAX_OUTPUT_BYTES) {
    return { text: s, truncated: false };
  }
  const head = buf.subarray(0, MAX_OUTPUT_BYTES).toString("utf8");
  return { text: head + `\n\n[... truncated, output exceeded ${MAX_OUTPUT_BYTES} bytes ...]`, truncated: true };
}

async function runForge(args: string[], cwd: string, timeoutMs: number = DEFAULT_TIMEOUT_MS): Promise<RunResult> {
  const command = ["forge", ...args].map(a => /\s/.test(a) ? JSON.stringify(a) : a).join(" ");
  try {
    const { stdout, stderr } = await execFileP("forge", args, {
      cwd,
      timeout: timeoutMs,
      maxBuffer: MAX_OUTPUT_BYTES * 2,
      encoding: "utf8",
    });
    const out = truncate(stdout);
    const err = truncate(stderr);
    return { exitCode: 0, stdout: out.text, stderr: err.text, truncated: out.truncated || err.truncated, command, cwd };
  } catch (e: unknown) {
    // execFile rejects on non-zero exit OR on timeout/spawn errors.
    const err = e as { code?: number | string; stdout?: string; stderr?: string; message?: string; killed?: boolean };
    const exitCode = typeof err.code === "number" ? err.code : (err.killed ? 124 : 1);
    const stdout = truncate(err.stdout ?? "");
    const stderr = truncate(err.stderr ?? err.message ?? "unknown error");
    return {
      exitCode,
      stdout: stdout.text,
      stderr: stderr.text,
      truncated: stdout.truncated || stderr.truncated,
      command,
      cwd,
    };
  }
}

function formatResult(r: RunResult): string {
  const parts = [
    `$ ${r.command}`,
    `cwd: ${r.cwd}`,
    `exit: ${r.exitCode}`,
    r.truncated ? "[output truncated]" : "",
    r.stdout ? `--- stdout ---\n${r.stdout}` : "",
    r.stderr ? `--- stderr ---\n${r.stderr}` : "",
  ];
  return parts.filter(Boolean).join("\n");
}

// ── Server ──

const server = new McpServer({
  name: "krait-forge",
  version: "1.0.0",
});

server.tool(
  "forge_version",
  "Return the installed forge version, or an error if forge is not on PATH.",
  {},
  async () => {
    const r = await runForge(["--version"], ROOT, 10_000);
    return { content: [{ type: "text", text: formatResult(r) }] };
  },
);

server.tool(
  "forge_build",
  "Run `forge build` in the given Foundry project. cwd is resolved under the MCP root.",
  {
    cwd: z.string().describe("Path to the Foundry project (relative to MCP root or absolute under it)."),
    force: z.boolean().optional().describe("Pass --force to force a full rebuild."),
    via_ir: z.boolean().optional().describe("Pass --via-ir."),
  },
  async ({ cwd, force, via_ir }) => {
    const safe = safeCwd(cwd);
    const args = ["build"];
    if (force) args.push("--force");
    if (via_ir) args.push("--via-ir");
    const r = await runForge(args, safe);
    return { content: [{ type: "text", text: formatResult(r) }] };
  },
);

server.tool(
  "forge_test",
  "Run `forge test` in the given Foundry project. Filters by --match-test and --match-contract if provided.",
  {
    cwd: z.string().describe("Path to the Foundry project."),
    match_test: z.string().optional().describe("Pattern passed to --match-test."),
    match_contract: z.string().optional().describe("Pattern passed to --match-contract."),
    fuzz_runs: z.number().int().positive().optional().describe("Override foundry.toml fuzz runs."),
    verbosity: z.number().int().min(1).max(5).optional().describe("Log verbosity 1-5 (translates to -v..-vvvvv). Default 3."),
    fork_url: z.string().url().optional().describe("Run against a fork URL."),
  },
  async ({ cwd, match_test, match_contract, fuzz_runs, verbosity, fork_url }) => {
    const safe = safeCwd(cwd);
    const v = verbosity ?? 3;
    const args = ["test", "-" + "v".repeat(v)];
    if (match_test) args.push("--match-test", match_test);
    if (match_contract) args.push("--match-contract", match_contract);
    if (fuzz_runs) args.push("--fuzz-runs", String(fuzz_runs));
    if (fork_url) args.push("--fork-url", fork_url);
    const r = await runForge(args, safe);
    return { content: [{ type: "text", text: formatResult(r) }] };
  },
);

server.tool(
  "forge_fmt_check",
  "Run `forge fmt --check`. Read-only — does not modify files.",
  {
    cwd: z.string().describe("Path to the Foundry project."),
  },
  async ({ cwd }) => {
    const safe = safeCwd(cwd);
    const r = await runForge(["fmt", "--check"], safe, 60_000);
    return { content: [{ type: "text", text: formatResult(r) }] };
  },
);

await server.connect(new StdioServerTransport());
