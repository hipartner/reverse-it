// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/native/disassembly-bridge.ts
// Description : Disassembly engine bridge. Disassembles native instructions
//               and function routines using host objdump / llvm-objdump without
//               launching or executing the target binary.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { execFile } from "node:child_process";
import { promisify } from "node:util";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

const execFileAsync = promisify(execFile);

export interface DisassemblyLine {
  readonly address: string;
  readonly instructionBytes: string;
  readonly mnemonic: string;
  readonly operands: string;
}

export interface DisassembledFunction {
  readonly name: string;
  readonly address: string;
  readonly instructions: DisassemblyLine[];
}

export interface DisassemblyResult {
  readonly filePath: string;
  readonly toolUsed: string;
  readonly functions: DisassembledFunction[];
  readonly rawSnippet?: string;
  readonly evidence: Evidence;
}

/** Disassemble specified function or address range using system objdump. */
export async function disassembleTarget(
  filePath: string,
  options: { functionName?: string; maxInstructions?: number } = {}
): Promise<Result<DisassemblyResult>> {
  const maxInst = options.maxInstructions ?? 150;
  const tool = "objdump";

  try {
    const args = ["-d", "-C", "--no-show-raw-insn"];
    if (options.functionName) {
      args.push(`--disassemble=${options.functionName}`);
    }
    args.push(filePath);

    const { stdout } = await execFileAsync(tool, args, { maxBuffer: 10 * 1024 * 1024 });

    const functions: DisassembledFunction[] = [];
    const lines = stdout.split("\n");
    let currentFunc: DisassembledFunction | null = null;
    let count = 0;

    for (const line of lines) {
      if (count >= maxInst) break;

      // Function header format: "0000000000001000 <main>:"
      const funcMatch = line.match(/^([0-9a-fA-F]+)\s+<([^>]+)>:/);
      if (funcMatch) {
        if (currentFunc) functions.push(currentFunc);
        currentFunc = {
          name: funcMatch[2],
          address: `0x${funcMatch[1]}`,
          instructions: [],
        };
        continue;
      }

      // Instruction format: "  1000:       mov    rax, rbx"
      const instMatch = line.match(/^\s*([0-9a-fA-F]+):\s+([a-zA-Z0-9_.]+)(?:\s+(.*))?$/);
      if (instMatch && currentFunc) {
        currentFunc.instructions.push({
          address: `0x${instMatch[1]}`,
          instructionBytes: "",
          mnemonic: instMatch[2],
          operands: instMatch[3] ? instMatch[3].trim() : "",
        });
        count++;
      }
    }

    if (currentFunc) functions.push(currentFunc);

    return success({
      filePath,
      toolUsed: tool,
      functions,
      rawSnippet: stdout.slice(0, 1000),
      evidence: {
        classification: "observation",
        summary: `Disassembled ${functions.length} function routines via ${tool}`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Disassembly failed: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  }
}
