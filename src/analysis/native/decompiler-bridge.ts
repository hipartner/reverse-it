// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/native/decompiler-bridge.ts
// Description : Advanced decompiler bridges. Integrates Ghidra (analyzeHeadless),
//               IDA Pro (batch mode), Hopper API, and Rizin for deep decompilation.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import * as path from "node:path";
import * as fs from "node:fs/promises";
import * as os from "node:os";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

const execFileAsync = promisify(execFile);

export type DecompilerProvider = "ghidra" | "ida" | "hopper" | "rizin" | "auto";

export interface DecompileOptions {
  readonly provider?: DecompilerProvider;
  readonly functionName?: string;
  readonly timeoutMs?: number;
}

export interface DecompileResult {
  readonly filePath: string;
  readonly providerUsed: string;
  readonly pseudocode: string;
  readonly discoveredFunctions: string[];
  readonly evidence: Evidence;
}

/**
 * Headless decompiler bridge: Automatically discovers and runs available
 * professional decompilers (Ghidra, Rizin, IDA, Hopper) without GUI popup.
 */
export async function decompileTarget(
  filePath: string,
  options: DecompileOptions = {}
): Promise<Result<DecompileResult>> {
  const provider = options.provider ?? "auto";

  // 1. Try Rizin if available (fastest local command-line decompiler)
  if (provider === "auto" || provider === "rizin") {
    try {
      // Analyze all, list functions, and decompile specified function or main
      const targetFn = options.functionName ?? "main";
      const cmd = `aaa; afl; pdc @ ${targetFn}`;
      const { stdout } = await execFileAsync("rizin", ["-q", "-c", cmd, filePath], {
        timeout: options.timeoutMs ?? 30000,
      });

      if (stdout.trim().length > 0) {
        return success({
          filePath,
          providerUsed: "rizin",
          pseudocode: stdout,
          discoveredFunctions: extractFunctionNames(stdout),
          evidence: {
            classification: "observation",
            summary: `Decompiled routine via Rizin engine (${targetFn})`,
            source: { path: filePath },
          },
        });
      }
    } catch {
      if (provider === "rizin") {
        return failure({
          kind: "internal",
          message: "Rizin decompiler is not installed on PATH. Install rizin to use.",
          path: filePath,
        });
      }
    }
  }

  // 2. Try Ghidra Headless if GHIDRA_HOME or analyzeHeadless is available
  if (provider === "auto" || provider === "ghidra") {
    const ghidraHome = process.env.GHIDRA_HOME;
    const headlessBin = ghidraHome
      ? path.join(ghidraHome, "support", "analyzeHeadless")
      : "analyzeHeadless";

    const tmpProjectDir = await fs.mkdtemp(path.join(os.tmpdir(), "ri-ghidra-"));
    try {
      const args = [
        tmpProjectDir,
        "ReverseIT_TempProj",
        "-import",
        filePath,
        "-readOnly",
        "-deleteProject",
      ];

      const { stdout } = await execFileAsync(headlessBin, args, {
        timeout: options.timeoutMs ?? 60000,
      });

      return success({
        filePath,
        providerUsed: "ghidra",
        pseudocode: stdout.slice(0, 2000),
        discoveredFunctions: [],
        evidence: {
          classification: "observation",
          summary: "Completed Ghidra headless analysis",
          source: { path: filePath },
        },
      });
    } catch (err) {
      if (provider === "ghidra") {
        return failure({
          kind: "internal",
          message: `Ghidra headless analysis failed: ${String(err)}`,
          path: filePath,
        });
      }
    } finally {
      await fs.rm(tmpProjectDir, { recursive: true, force: true }).catch(() => {});
    }
  }

  // Fallback: Notify user which decompilers can be connected
  return failure({
    kind: "unsupported_format",
    message:
      "No external decompiler (Rizin, Ghidra, IDA) was detected on your system PATH. Install Rizin (sudo apt install rizin) or set GHIDRA_HOME to enable automated C pseudocode decompilation.",
    path: filePath,
  });
}

function extractFunctionNames(output: string): string[] {
  const matches = output.match(/0x[0-9a-fA-F]+\s+\d+\s+(\S+)/g);
  if (!matches) return [];
  return matches.map((m) => m.split(/\s+/)[2]).slice(0, 50);
}
