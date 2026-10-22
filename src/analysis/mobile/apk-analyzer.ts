// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/mobile/apk-analyzer.ts
// Description : Android APK anatomy inspector. Unpacks internal structure,
//               discovers Dex files, native libraries (ABI), and manifests.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface ApkAnalysis {
  readonly filePath: string;
  readonly dexFiles: string[];
  readonly nativeLibraries: Record<string, string[]>; // abi -> lib names
  readonly hasManifest: boolean;
  readonly totalEntries: number;
  readonly evidence: Evidence;
}

/** Inspect an Android APK without needing an Android emulator or SDK installed. */
export async function analyzeApk(filePath: string): Promise<Result<ApkAnalysis>> {
  let handle;
  try {
    handle = await fs.open(filePath, "r");
    const stat = await handle.stat();
    // Read up to first 8 MB to inspect ZIP local file headers
    const buffer = Buffer.alloc(Math.min(stat.size, 8 * 1024 * 1024));
    const { bytesRead } = await handle.read(buffer, 0, buffer.length, 0);

    if (bytesRead < 30 || buffer.readUInt32LE(0) !== 0x04034b50) {
      return failure({
        kind: "unsupported_format",
        message: "Not a valid ZIP/APK archive (missing PK magic).",
        path: filePath,
      });
    }

    const dexFiles: string[] = [];
    const nativeLibraries: Record<string, string[]> = {};
    let hasManifest = false;
    let entryCount = 0;

    let offset = 0;
    while (offset < bytesRead - 30) {
      // Check for local file header: "PK\x03\x04" = 0x04034b50
      if (buffer.readUInt32LE(offset) !== 0x04034b50) {
        // Fast forward 1 byte if not aligned
        offset++;
        continue;
      }

      const compressedSize = buffer.readUInt32LE(offset + 18);
      const nameLen = buffer.readUInt16LE(offset + 26);
      const extraLen = buffer.readUInt16LE(offset + 28);

      if (offset + 30 + nameLen > bytesRead) break;

      const fileName = buffer.toString("utf8", offset + 30, offset + 30 + nameLen);
      entryCount++;

      if (fileName === "AndroidManifest.xml") {
        hasManifest = true;
      } else if (fileName.endsWith(".dex")) {
        dexFiles.push(fileName);
      } else if (fileName.startsWith("lib/")) {
        const parts = fileName.split("/");
        if (parts.length >= 3) {
          const abi = parts[1];
          const libName = parts.slice(2).join("/");
          if (!nativeLibraries[abi]) nativeLibraries[abi] = [];
          nativeLibraries[abi].push(libName);
        }
      }

      offset += 30 + nameLen + extraLen + (compressedSize > 0 ? compressedSize : 0);
    }

    return success({
      filePath,
      dexFiles,
      nativeLibraries,
      hasManifest,
      totalEntries: entryCount,
      evidence: {
        classification: "observation",
        summary: `Inspected APK with ${dexFiles.length} DEX files and native ABIs (${Object.keys(nativeLibraries).join(", ") || "none"})`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to inspect APK: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (handle) await handle.close();
  }
}
