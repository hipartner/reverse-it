// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/sourcemap/sourcemap-analyzer.ts
// Description : Source map inspection and unpacking. Extracts original source
//               files, paths, and content from embedded and external source maps.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface SourceMapEntry {
  readonly originalPath: string;
  readonly hasContent: boolean;
  readonly contentSnippet?: string;
  readonly sizeBytes?: number;
}

export interface SourceMapAnalysis {
  readonly mapFilePath?: string;
  readonly targetFilePath: string;
  readonly version: number;
  readonly originalSourcesCount: number;
  readonly sources: SourceMapEntry[];
  readonly evidence: Evidence;
}

/**
 * Inspect a JavaScript file for linked or embedded source maps, and unpack
 * original filenames and sources where available.
 */
export async function analyzeSourceMap(
  jsFilePath: string,
  sourceContent?: string
): Promise<Result<SourceMapAnalysis>> {
  try {
    const code = sourceContent ?? (await fs.readFile(jsFilePath, "utf8"));

    // Check for inline base64 source map
    const inlineMatch = code.match(
      /\/\/[#@]\s*sourceMappingURL=data:application\/json;(?:charset=utf-8;)?base64,([A-Za-z0-9+/=]+)/
    );

    let rawJson: string | null = null;
    let mapPath: string | undefined;

    if (inlineMatch && inlineMatch[1]) {
      const buffer = Buffer.from(inlineMatch[1], "base64");
      rawJson = buffer.toString("utf8");
    } else {
      // Check for external file link
      const externalMatch = code.match(/\/\/[#@]\s*sourceMappingURL=([^\s]+)/);
      if (externalMatch && externalMatch[1]) {
        mapPath = path.resolve(path.dirname(jsFilePath), externalMatch[1]);
        try {
          rawJson = await fs.readFile(mapPath, "utf8");
        } catch {
          rawJson = null;
        }
      }
    }

    // Also check standard adjacent .map file
    if (!rawJson) {
      const adjacentMapPath = `${jsFilePath}.map`;
      try {
        rawJson = await fs.readFile(adjacentMapPath, "utf8");
        mapPath = adjacentMapPath;
      } catch {
        // No map file found
      }
    }

    if (!rawJson) {
      return failure({
        kind: "file_not_found",
        message: `No inline or external source map found for ${jsFilePath}`,
        path: jsFilePath,
      });
    }

    const parsedMap = JSON.parse(rawJson);
    const sources: SourceMapEntry[] = [];
    const rawSources: string[] = Array.isArray(parsedMap.sources) ? parsedMap.sources : [];
    const sourcesContent: (string | null)[] = Array.isArray(parsedMap.sourcesContent)
      ? parsedMap.sourcesContent
      : [];

    for (let i = 0; i < rawSources.length; i++) {
      const originalPath = rawSources[i];
      const content = sourcesContent[i];
      const hasContent = typeof content === "string" && content.length > 0;

      sources.push({
        originalPath,
        hasContent,
        contentSnippet: hasContent ? content.slice(0, 150) + "..." : undefined,
        sizeBytes: hasContent ? Buffer.byteLength(content, "utf8") : undefined,
      });
    }

    return success({
      mapFilePath: mapPath,
      targetFilePath: jsFilePath,
      version: parsedMap.version || 3,
      originalSourcesCount: sources.length,
      sources,
      evidence: {
        classification: "observation",
        summary: `Discovered source map with ${sources.length} original source files`,
        source: { path: mapPath ?? jsFilePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "unsupported_format",
      message: `Failed to parse source map: ${String(err)}`,
      path: jsFilePath,
      cause: err,
    });
  }
}
