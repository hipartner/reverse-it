// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/native/strings-analyzer.ts
// Description : Bounded string extraction and semantic classification (URLs,
//               file paths, IP addresses, format strings) for any binary target.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface ExtractedString {
  readonly offset: number;
  readonly value: string;
  readonly classification?: "url" | "path" | "ip" | "guid" | "general";
}

export interface StringsAnalysis {
  readonly filePath: string;
  readonly totalDiscovered: number;
  readonly interestingStrings: ExtractedString[];
  readonly evidence: Evidence;
}

/** Extract human-readable ASCII and UTF-8 strings from any target binary. */
export async function extractBinaryStrings(
  filePath: string,
  options: { minLength?: number; maxStrings?: number } = {}
): Promise<Result<StringsAnalysis>> {
  const minLen = options.minLength ?? 4;
  const maxStrings = options.maxStrings ?? 200;

  let handle;
  try {
    handle = await fs.open(filePath, "r");
    const stat = await handle.stat();
    // Bound reading to first 10 MB to prevent memory bloat
    const readSize = Math.min(stat.size, 10 * 1024 * 1024);
    const buffer = Buffer.alloc(readSize);
    await handle.read(buffer, 0, readSize, 0);

    const strings: ExtractedString[] = [];
    let currentChars: number[] = [];
    let startOffset = 0;

    for (let i = 0; i < readSize; i++) {
      const byte = buffer[i];
      // Printable ASCII (32 - 126) or tab (9), newline (10)
      if ((byte >= 32 && byte <= 126) || byte === 9 || byte === 10) {
        if (currentChars.length === 0) startOffset = i;
        currentChars.push(byte);
      } else {
        if (currentChars.length >= minLen) {
          const val = String.fromCharCode(...currentChars).trim();
          if (val.length >= minLen) {
            strings.push({
              offset: startOffset,
              value: val,
              classification: classifyString(val),
            });
            if (strings.length >= maxStrings) break;
          }
        }
        currentChars = [];
      }
    }

    const interesting = strings.filter(
      (s) => s.classification && s.classification !== "general"
    );

    return success({
      filePath,
      totalDiscovered: strings.length,
      interestingStrings: interesting.length > 0 ? interesting : strings.slice(0, 50),
      evidence: {
        classification: "observation",
        summary: `Extracted ${strings.length} strings from ${filePath}`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to extract strings: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (handle) await handle.close();
  }
}

function classifyString(val: string): ExtractedString["classification"] {
  if (/^https?:\/\/[^\s]+$/i.test(val)) return "url";
  if (/^(\/|[a-zA-Z]:\\)[a-zA-Z0-9_.-]+/.test(val)) return "path";
  if (/^\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b$/.test(val)) return "ip";
  if (/^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/.test(val)) return "guid";
  return "general";
}
