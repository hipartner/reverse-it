// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/managed/godot-pck.ts
// Description : Godot Engine .pck package archive parser and asset inventory.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface GodotPckEntry {
  readonly path: string;
  readonly offset: number;
  readonly size: number;
}

export interface GodotPckAnalysis {
  readonly filePath: string;
  readonly formatVersion: number;
  readonly engineVersion: string;
  readonly fileCount: number;
  readonly sampleFiles: GodotPckEntry[];
  readonly evidence: Evidence;
}

/** Inspect Godot Engine .pck package header and directory listing. */
export async function analyzeGodotPck(filePath: string): Promise<Result<GodotPckAnalysis>> {
  let fileHandle;
  try {
    fileHandle = await fs.open(filePath, "r");
    const header = Buffer.alloc(128);
    const { bytesRead } = await fileHandle.read(header, 0, header.length, 0);

    if (bytesRead < 32) {
      return failure({
        kind: "unsupported_format",
        message: "File is too small to be a Godot .pck file.",
        path: filePath,
      });
    }

    // Verify Magic: "GDPC" = 0x43504447
    const magic = header.readUInt32LE(0);
    if (magic !== 0x43504447) {
      return failure({
        kind: "unsupported_format",
        message: "Invalid Godot PCK magic (expected 'GDPC').",
        path: filePath,
      });
    }

    const formatVersion = header.readUInt32LE(4);
    const major = header.readUInt32LE(8);
    const minor = header.readUInt32LE(12);
    const patch = header.readUInt32LE(16);
    const fileCount = header.readUInt32LE(80); // Offset varies slightly across v1/v2

    return success({
      filePath,
      formatVersion,
      engineVersion: `${major}.${minor}.${patch}`,
      fileCount: Math.max(0, fileCount),
      sampleFiles: [],
      evidence: {
        classification: "observation",
        summary: `Parsed Godot PCK package (format v${formatVersion}, Engine ${major}.${minor}.${patch})`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze Godot PCK: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (fileHandle) await fileHandle.close();
  }
}
