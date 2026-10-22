// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/wasm/wasm-analyzer.ts
// Description : WebAssembly (.wasm) binary module inspection. Validates headers,
//               enumerates sections, and extracts imports, exports, and functions.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface WasmExport {
  readonly name: string;
  readonly kind: "func" | "table" | "mem" | "global";
  readonly index: number;
}

export interface WasmSection {
  readonly id: number;
  readonly name: string;
  readonly sizeBytes: number;
}

export interface WasmAnalysis {
  readonly filePath: string;
  readonly version: number;
  readonly sections: WasmSection[];
  readonly exports: WasmExport[];
  readonly importsCount: number;
  readonly functionsCount: number;
  readonly evidence: Evidence;
}

const SECTION_NAMES: Record<number, string> = {
  0: "custom",
  1: "type",
  2: "import",
  3: "function",
  4: "table",
  5: "memory",
  6: "global",
  7: "export",
  8: "start",
  9: "element",
  10: "code",
  11: "data",
};

/** Inspect WebAssembly binary artifact without running a WASM VM. */
export async function analyzeWasmModule(filePath: string): Promise<Result<WasmAnalysis>> {
  let handle;
  try {
    handle = await fs.open(filePath, "r");
    const stat = await handle.stat();
    const readSize = Math.min(stat.size, 10 * 1024 * 1024);
    const buffer = Buffer.alloc(readSize);
    await handle.read(buffer, 0, readSize, 0);

    // Verify WASM Magic: \0asm (0x6d736100 LE)
    if (buffer.length < 8 || buffer.readUInt32LE(0) !== 0x6d736100) {
      return failure({
        kind: "unsupported_format",
        message: "Not a valid WebAssembly binary (missing \\0asm magic).",
        path: filePath,
      });
    }

    const version = buffer.readUInt32LE(4);
    const sections: WasmSection[] = [];
    const exports: WasmExport[] = [];
    let importsCount = 0;
    let functionsCount = 0;

    let offset = 8;
    while (offset < buffer.length - 2) {
      const sectionId = buffer[offset++];
      // Read LEB128 section size
      let size = 0;
      let shift = 0;
      let b = 0;
      do {
        if (offset >= buffer.length) break;
        b = buffer[offset++];
        size |= (b & 0x7f) << shift;
        shift += 7;
      } while ((b & 0x80) !== 0);

      const sectionName = SECTION_NAMES[sectionId] ?? `unknown_${sectionId}`;
      sections.push({ id: sectionId, name: sectionName, sizeBytes: size });

      // If export section (id 7), parse export names
      if (sectionId === 7 && offset + size <= buffer.length) {
        parseExportSection(buffer.subarray(offset, offset + size), exports);
      } else if (sectionId === 2) {
        importsCount++;
      } else if (sectionId === 3) {
        functionsCount++;
      }

      offset += size;
    }

    return success({
      filePath,
      version,
      sections,
      exports,
      importsCount,
      functionsCount,
      evidence: {
        classification: "observation",
        summary: `Parsed WASM v${version} with ${sections.length} sections and ${exports.length} exports`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze WASM module: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (handle) await handle.close();
  }
}

function parseExportSection(buf: Buffer, outExports: WasmExport[]) {
  try {
    let off = 0;
    // Read count (LEB128)
    let count = buf[off++];
    for (let i = 0; i < count && off < buf.length; i++) {
      const nameLen = buf[off++];
      if (off + nameLen > buf.length) break;
      const name = buf.toString("utf8", off, off + nameLen);
      off += nameLen;
      const kindByte = buf[off++];
      const kind = kindByte === 0 ? "func" : kindByte === 1 ? "table" : kindByte === 2 ? "mem" : "global";
      const index = buf[off++];
      outExports.push({ name, kind, index });
    }
  } catch {
    // Continue
  }
}
