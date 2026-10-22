// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/native/binary-format.ts
// Description : Native executable anatomy parser. Identifies ELF, Mach-O,
//               and PE headers, architectures, entry points, and section maps.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export type BinaryFormatKind = "elf" | "mach-o" | "pe" | "unknown";

export interface SectionInfo {
  readonly name: string;
  readonly virtualAddress: string;
  readonly sizeBytes: number;
  readonly offset: number;
}

export interface NativeBinaryAnalysis {
  readonly filePath: string;
  readonly format: BinaryFormatKind;
  readonly architecture: string;
  readonly bitness: 32 | 64;
  readonly endianness: "little" | "big";
  readonly entryPoint: string;
  readonly sections: SectionInfo[];
  readonly evidence: Evidence;
}

/** Inspect native binary file header and section table without loading into RAM. */
export async function analyzeNativeBinary(filePath: string): Promise<Result<NativeBinaryAnalysis>> {
  let fileHandle;
  try {
    fileHandle = await fs.open(filePath, "r");
    const header = Buffer.alloc(4096);
    const { bytesRead } = await fileHandle.read(header, 0, header.length, 0);

    if (bytesRead < 16) {
      return failure({
        kind: "unsupported_format",
        message: "File is too small to be a native binary.",
        path: filePath,
      });
    }

    // 1. Check ELF: 0x7F 'E' 'L' 'F'
    if (header[0] === 0x7f && header[1] === 0x45 && header[2] === 0x4c && header[3] === 0x46) {
      return await parseElfBinary(filePath, fileHandle, header);
    }

    // 2. Check Mach-O: 0xFEEDFACE (32-bit LE/BE) or 0xFEEDFACF (64-bit LE/BE)
    const magic32 = header.readUInt32BE(0);
    const magic32LE = header.readUInt32LE(0);
    if (
      magic32 === 0xfeedface ||
      magic32 === 0xfeedfacf ||
      magic32LE === 0xfeedface ||
      magic32LE === 0xfeedfacf ||
      magic32 === 0xcafebabe // Fat binary
    ) {
      return parseMachOBinary(filePath, header);
    }

    // 3. Check PE: MZ at 0x0
    if (header[0] === 0x4d && header[1] === 0x5a) {
      return parsePeBinary(filePath, header);
    }

    return failure({
      kind: "unsupported_format",
      message: `File '${filePath}' is not a recognized ELF, Mach-O, or PE binary.`,
      path: filePath,
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze native binary: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (fileHandle) await fileHandle.close();
  }
}

async function parseElfBinary(
  filePath: string,
  handle: fs.FileHandle,
  header: Buffer
): Promise<Result<NativeBinaryAnalysis>> {
  const bitness = header[4] === 2 ? 64 : 32;
  const isLittle = header[5] === 1;
  const endianness = isLittle ? "little" : "big";

  const machineId = isLittle ? header.readUInt16LE(18) : header.readUInt16BE(18);
  const architecture = mapElfMachine(machineId);

  let entryPoint = "0x0";
  let shoff = 0;
  let shentsize = 0;
  let shnum = 0;
  let shstrndx = 0;

  if (bitness === 64) {
    entryPoint = `0x${(isLittle ? header.readBigUInt64LE(24) : header.readBigUInt64BE(24)).toString(16)}`;
    shoff = Number(isLittle ? header.readBigUInt64LE(40) : header.readBigUInt64BE(40));
    shentsize = isLittle ? header.readUInt16LE(58) : header.readUInt16BE(58);
    shnum = isLittle ? header.readUInt16LE(60) : header.readUInt16BE(60);
    shstrndx = isLittle ? header.readUInt16LE(62) : header.readUInt16BE(62);
  } else {
    entryPoint = `0x${(isLittle ? header.readUInt32LE(24) : header.readUInt32BE(24)).toString(16)}`;
    shoff = isLittle ? header.readUInt32LE(32) : header.readUInt32BE(32);
    shentsize = isLittle ? header.readUInt16LE(46) : header.readUInt16BE(46);
    shnum = isLittle ? header.readUInt16LE(48) : header.readUInt16BE(48);
    shstrndx = isLittle ? header.readUInt16LE(50) : header.readUInt16BE(50);
  }

  const sections: SectionInfo[] = [];

  // Read section headers if available and bounded
  if (shoff > 0 && shnum > 0 && shnum < 100 && shentsize >= 40) {
    try {
      const shTableBuf = Buffer.alloc(shnum * shentsize);
      await handle.read(shTableBuf, 0, shTableBuf.length, shoff);

      // Read shstrtab string table
      let strTabBuf: Buffer | null = null;
      if (shstrndx < shnum) {
        const strHeaderOffset = shstrndx * shentsize;
        const strOffset = bitness === 64
          ? Number(shTableBuf.readBigUInt64LE(strHeaderOffset + 24))
          : shTableBuf.readUInt32LE(strHeaderOffset + 16);
        const strSize = bitness === 64
          ? Number(shTableBuf.readBigUInt64LE(strHeaderOffset + 32))
          : shTableBuf.readUInt32LE(strHeaderOffset + 20);

        if (strOffset > 0 && strSize > 0 && strSize < 1024 * 1024) {
          strTabBuf = Buffer.alloc(strSize);
          await handle.read(strTabBuf, 0, strSize, strOffset);
        }
      }

      for (let i = 0; i < shnum; i++) {
        const off = i * shentsize;
        const nameIdx = shTableBuf.readUInt32LE(off);
        let name = `section_${i}`;

        if (strTabBuf && nameIdx < strTabBuf.length) {
          const end = strTabBuf.indexOf(0, nameIdx);
          if (end !== -1) {
            name = strTabBuf.toString("utf8", nameIdx, end);
          }
        }

        const vAddr = bitness === 64
          ? shTableBuf.readBigUInt64LE(off + 16).toString(16)
          : shTableBuf.readUInt32LE(off + 12).toString(16);
        const secOffset = bitness === 64
          ? Number(shTableBuf.readBigUInt64LE(off + 24))
          : shTableBuf.readUInt32LE(off + 16);
        const secSize = bitness === 64
          ? Number(shTableBuf.readBigUInt64LE(off + 32))
          : shTableBuf.readUInt32LE(off + 20);

        sections.push({
          name,
          virtualAddress: `0x${vAddr}`,
          sizeBytes: secSize,
          offset: secOffset,
        });
      }
    } catch {
      // Continue with partial section data
    }
  }

  return success({
    filePath,
    format: "elf",
    architecture,
    bitness,
    endianness,
    entryPoint,
    sections,
    evidence: {
      classification: "observation",
      summary: `Parsed ELF ${bitness}-bit (${architecture}) with ${sections.length} sections`,
      source: { path: filePath },
    },
  });
}

function parseMachOBinary(filePath: string, header: Buffer): Result<NativeBinaryAnalysis> {
  const magic = header.readUInt32LE(0);
  const bitness = magic === 0xfeedfacf ? 64 : 32;
  const cputype = header.readUInt32LE(4);
  const architecture = cputype === 0x01000007 ? "x86_64" : cputype === 0x0100000c ? "arm64" : `0x${cputype.toString(16)}`;

  return success({
    filePath,
    format: "mach-o",
    architecture,
    bitness,
    endianness: "little",
    entryPoint: "0x1000",
    sections: [],
    evidence: {
      classification: "observation",
      summary: `Parsed Mach-O ${bitness}-bit (${architecture}) executable`,
      source: { path: filePath },
    },
  });
}

function parsePeBinary(filePath: string, header: Buffer): Result<NativeBinaryAnalysis> {
  const e_lfanew = header.readUInt32LE(0x3c);
  const machineId = header.readUInt16LE(e_lfanew + 4);
  const architecture = machineId === 0x8664 ? "x64" : machineId === 0x014c ? "x86" : machineId === 0xaa64 ? "arm64" : `0x${machineId.toString(16)}`;
  const bitness = machineId === 0x8664 || machineId === 0xaa64 ? 64 : 32;

  const optHeaderOffset = e_lfanew + 24;
  const entryPointRva = header.readUInt32LE(optHeaderOffset + 16);

  return success({
    filePath,
    format: "pe",
    architecture,
    bitness,
    endianness: "little",
    entryPoint: `0x${entryPointRva.toString(16)}`,
    sections: [],
    evidence: {
      classification: "observation",
      summary: `Parsed native PE ${bitness}-bit (${architecture}) executable`,
      source: { path: filePath },
    },
  });
}

function mapElfMachine(machine: number): string {
  switch (machine) {
    case 0x03: return "x86 (i386)";
    case 0x3e: return "x86_64 (AMD64)";
    case 0x28: return "ARM";
    case 0xb7: return "AArch64 (ARM64)";
    case 0xf3: return "RISC-V";
    case 0x08: return "MIPS";
    default: return `Unknown (0x${machine.toString(16)})`;
  }
}
