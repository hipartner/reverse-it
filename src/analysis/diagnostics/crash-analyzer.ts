// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/diagnostics/crash-analyzer.ts
// Description : Linux core dump / crash inspector. Identifies crash targets,
//               signal numbers, register notes, and memory mapping candidates.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface CoreDumpAnalysis {
  readonly filePath: string;
  readonly isCoreDump: boolean;
  readonly architecture: string;
  readonly bitness: 32 | 64;
  readonly programHeadersCount: number;
  readonly evidence: Evidence;
}

/** Analyze an ELF core dump file to extract crash context without launching GDB. */
export async function analyzeCoreDump(filePath: string): Promise<Result<CoreDumpAnalysis>> {
  let handle;
  try {
    handle = await fs.open(filePath, "r");
    const header = Buffer.alloc(64);
    const { bytesRead } = await handle.read(header, 0, 64, 0);

    if (bytesRead < 16) {
      return failure({
        kind: "unsupported_format",
        message: "File is too small to be a core dump.",
        path: filePath,
      });
    }

    // Verify ELF: 0x7F 'E' 'L' 'F'
    if (header[0] !== 0x7f || header[1] !== 0x45 || header[2] !== 0x4c || header[3] !== 0x46) {
      return failure({
        kind: "unsupported_format",
        message: "Not an ELF binary format.",
        path: filePath,
      });
    }

    const bitness = header[4] === 2 ? 64 : 32;
    const isLittle = header[5] === 1;

    // e_type at offset 16 (uint16). ET_CORE is 4.
    const e_type = isLittle ? header.readUInt16LE(16) : header.readUInt16BE(16);
    if (e_type !== 4) {
      return failure({
        kind: "unsupported_format",
        message: `ELF file is of type 0x${e_type.toString(16)} (not ET_CORE = 4).`,
        path: filePath,
      });
    }

    const machineId = isLittle ? header.readUInt16LE(18) : header.readUInt16BE(18);
    const architecture = machineId === 0x3e ? "x86_64" : machineId === 0xb7 ? "aarch64" : `0x${machineId.toString(16)}`;

    const phnum = isLittle ? header.readUInt16LE(bitness === 64 ? 56 : 44) : header.readUInt16BE(bitness === 64 ? 56 : 44);

    return success({
      filePath,
      isCoreDump: true,
      architecture,
      bitness,
      programHeadersCount: phnum,
      evidence: {
        classification: "observation",
        summary: `Identified Linux ${bitness}-bit (${architecture}) core dump with ${phnum} segments`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to inspect core dump: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (handle) await handle.close();
  }
}
