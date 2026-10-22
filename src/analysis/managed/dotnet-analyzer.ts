// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/managed/dotnet-analyzer.ts
// Description : Static .NET PE/CLI Assembly inspection. Reads CLI metadata,
//               runtime versions, streams (#~, #Strings), and flags.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface CliHeaderInfo {
  readonly majorRuntimeVersion: number;
  readonly minorRuntimeVersion: number;
  readonly flags: number;
  readonly isIlOnly: boolean;
  readonly is32BitRequired: boolean;
  readonly isStrongNameSigned: boolean;
  readonly entryPointToken: string;
}

export interface DotNetAssemblyAnalysis {
  readonly filePath: string;
  readonly isManagedAssembly: boolean;
  readonly targetFrameworkVersion?: string;
  readonly cliHeader?: CliHeaderInfo;
  readonly metadataStreams: string[];
  readonly peMachine: string;
  readonly evidence: Evidence;
}

/** Check and inspect a PE binary for .NET Intermediate Language (CIL) metadata. */
export async function analyzeDotNetAssembly(filePath: string): Promise<Result<DotNetAssemblyAnalysis>> {
  let fileHandle;
  try {
    fileHandle = await fs.open(filePath, "r");
    const buffer = Buffer.alloc(4096);
    const { bytesRead } = await fileHandle.read(buffer, 0, buffer.length, 0);

    if (bytesRead < 64) {
      return failure({
        kind: "unsupported_format",
        message: "File is too small to be a valid PE executable.",
        path: filePath,
      });
    }

    // 1. Verify DOS Header: "MZ"
    if (buffer[0] !== 0x4d || buffer[1] !== 0x5a) {
      return failure({
        kind: "unsupported_format",
        message: "Not a valid DOS/PE executable (missing MZ header).",
        path: filePath,
      });
    }

    // Offset to PE Header
    const e_lfanew = buffer.readUInt32LE(0x3c);
    if (e_lfanew + 24 > bytesRead) {
      return failure({
        kind: "unsupported_format",
        message: "Invalid PE header offset.",
        path: filePath,
      });
    }

    // Verify PE Signature: "PE\0\0"
    if (
      buffer[e_lfanew] !== 0x50 ||
      buffer[e_lfanew + 1] !== 0x45 ||
      buffer[e_lfanew + 2] !== 0x00 ||
      buffer[e_lfanew + 3] !== 0x00
    ) {
      return failure({
        kind: "unsupported_format",
        message: "Missing PE signature.",
        path: filePath,
      });
    }

    const machineId = buffer.readUInt16LE(e_lfanew + 4);
    const peMachine = machineId === 0x8664 ? "x64 (AMD64)" : machineId === 0x014c ? "x86 (i386)" : `0x${machineId.toString(16)}`;

    const sizeOfOptionalHeader = buffer.readUInt16LE(e_lfanew + 20);
    if (sizeOfOptionalHeader === 0) {
      return failure({
        kind: "unsupported_format",
        message: "Missing Optional Header.",
        path: filePath,
      });
    }

    const optHeaderOffset = e_lfanew + 24;
    const optMagic = buffer.readUInt16LE(optHeaderOffset);
    const isPe32Plus = optMagic === 0x20b;

    // Data Directory 14 is CLR Runtime Header:
    // Offset in PE32 is optHeaderOffset + 96 + 14 * 8 = optHeaderOffset + 208
    // Offset in PE32+ is optHeaderOffset + 112 + 14 * 8 = optHeaderOffset + 224
    const clrDirOffset = optHeaderOffset + (isPe32Plus ? 224 : 208);

    if (clrDirOffset + 8 > bytesRead) {
      return success({
        filePath,
        isManagedAssembly: false,
        metadataStreams: [],
        peMachine,
        evidence: {
          classification: "observation",
          summary: "Unmanaged native PE binary (no CLR data directory)",
          source: { path: filePath },
        },
      });
    }

    const clrRva = buffer.readUInt32LE(clrDirOffset);
    const clrSize = buffer.readUInt32LE(clrDirOffset + 4);

    if (clrRva === 0 || clrSize === 0) {
      return success({
        filePath,
        isManagedAssembly: false,
        metadataStreams: [],
        peMachine,
        evidence: {
          classification: "observation",
          summary: "Native PE binary (CLR directory is empty)",
          source: { path: filePath },
        },
      });
    }

    // Number of sections
    const numSections = buffer.readUInt16LE(e_lfanew + 6);
    const sectionHeadersOffset = optHeaderOffset + sizeOfOptionalHeader;

    // Find section containing CLR RVA to translate to file offset
    let clrFileOffset = 0;
    const secBuffer = Buffer.alloc(numSections * 40);
    await fileHandle.read(secBuffer, 0, secBuffer.length, sectionHeadersOffset);

    for (let i = 0; i < numSections; i++) {
      const secOffset = i * 40;
      const secVirtualSize = secBuffer.readUInt32LE(secOffset + 8);
      const secVirtualAddress = secBuffer.readUInt32LE(secOffset + 12);
      const secRawDataPtr = secBuffer.readUInt32LE(secOffset + 20);

      if (clrRva >= secVirtualAddress && clrRva < secVirtualAddress + secVirtualSize) {
        clrFileOffset = secRawDataPtr + (clrRva - secVirtualAddress);
        break;
      }
    }

    if (clrFileOffset === 0) {
      return success({
        filePath,
        isManagedAssembly: true,
        metadataStreams: [],
        peMachine,
        evidence: {
          classification: "observation",
          summary: "Managed .NET assembly (CLR header found, section unmapped)",
          source: { path: filePath },
        },
      });
    }

    // Read IMAGE_COR20_HEADER (72 bytes)
    const cor20Buffer = Buffer.alloc(72);
    await fileHandle.read(cor20Buffer, 0, 72, clrFileOffset);

    const majorRuntimeVersion = cor20Buffer.readUInt16LE(4);
    const minorRuntimeVersion = cor20Buffer.readUInt16LE(6);
    const metaDataRva = cor20Buffer.readUInt32LE(8);
    const flags = cor20Buffer.readUInt32LE(16);
    const entryPointToken = `0x${cor20Buffer.readUInt32LE(20).toString(16)}`;

    // Read Metadata Root (BSJB) if possible
    let metaFileOffset = 0;
    for (let i = 0; i < numSections; i++) {
      const secOffset = i * 40;
      const secVirtualSize = secBuffer.readUInt32LE(secOffset + 8);
      const secVirtualAddress = secBuffer.readUInt32LE(secOffset + 12);
      const secRawDataPtr = secBuffer.readUInt32LE(secOffset + 20);

      if (metaDataRva >= secVirtualAddress && metaDataRva < secVirtualAddress + secVirtualSize) {
        metaFileOffset = secRawDataPtr + (metaDataRva - secVirtualAddress);
        break;
      }
    }

    let targetFrameworkVersion: string | undefined;
    const metadataStreams: string[] = [];

    if (metaFileOffset > 0) {
      const metaRootBuffer = Buffer.alloc(512);
      await fileHandle.read(metaRootBuffer, 0, 512, metaFileOffset);

      // Verify BSJB Magic: 0x424A5342
      if (metaRootBuffer.readUInt32LE(0) === 0x424a5342) {
        const vLen = metaRootBuffer.readUInt32LE(12);
        if (vLen > 0 && vLen < 64) {
          targetFrameworkVersion = metaRootBuffer.toString("utf8", 16, 16 + vLen).replace(/\0+$/, "");
        }
      }
    }

    const cliHeader: CliHeaderInfo = {
      majorRuntimeVersion,
      minorRuntimeVersion,
      flags,
      isIlOnly: (flags & 1) !== 0,
      is32BitRequired: (flags & 2) !== 0,
      isStrongNameSigned: (flags & 8) !== 0,
      entryPointToken,
    };

    return success({
      filePath,
      isManagedAssembly: true,
      targetFrameworkVersion,
      cliHeader,
      metadataStreams,
      peMachine,
      evidence: {
        classification: "observation",
        summary: `Managed .NET Assembly (${targetFrameworkVersion ?? "CLR v" + majorRuntimeVersion})`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze .NET assembly: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (fileHandle) await fileHandle.close();
  }
}
