// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/managed/unity-il2cpp.ts
// Description : Unity global-metadata.dat (IL2CPP) inspection. Extracts
//               metadata versions, type definition counts, and method definitions.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface UnityIl2CppMetadata {
  readonly filePath: string;
  readonly version: number;
  readonly stringLiteralCount: number;
  readonly typeDefinitionsCount: number;
  readonly methodDefinitionsCount: number;
  readonly imagesCount: number;
  readonly evidence: Evidence;
}

/** Inspect Unity global-metadata.dat binary without loading entire game assets. */
export async function analyzeUnityMetadata(filePath: string): Promise<Result<UnityIl2CppMetadata>> {
  let fileHandle;
  try {
    fileHandle = await fs.open(filePath, "r");
    const header = Buffer.alloc(256);
    const { bytesRead } = await fileHandle.read(header, 0, header.length, 0);

    if (bytesRead < 32) {
      return failure({
        kind: "unsupported_format",
        message: "File is too small to be Unity global-metadata.dat",
        path: filePath,
      });
    }

    // Verify Unity Magic: 0xFAB11BAF (LE)
    const magic = header.readUInt32LE(0);
    if (magic !== 0xfab11baf) {
      return failure({
        kind: "unsupported_format",
        message: `Invalid Unity IL2CPP magic 0x${magic.toString(16)} (expected 0xFAB11BAF)`,
        path: filePath,
      });
    }

    const version = header.readUInt32LE(4);
    const stringLiteralCount = header.readUInt32LE(12) / 8;
    const typeDefinitionsCount = header.readUInt32LE(44) / 100; // Approx entry size
    const methodDefinitionsCount = header.readUInt32LE(52) / 36;
    const imagesCount = header.readUInt32LE(92) / 40;

    return success({
      filePath,
      version,
      stringLiteralCount: Math.max(0, Math.floor(stringLiteralCount)),
      typeDefinitionsCount: Math.max(0, Math.floor(typeDefinitionsCount)),
      methodDefinitionsCount: Math.max(0, Math.floor(methodDefinitionsCount)),
      imagesCount: Math.max(0, Math.floor(imagesCount)),
      evidence: {
        classification: "observation",
        summary: `Parsed Unity IL2CPP global-metadata v${version}`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to inspect Unity metadata: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (fileHandle) await fileHandle.close();
  }
}
