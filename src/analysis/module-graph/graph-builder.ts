// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/module-graph/graph-builder.ts
// Description : Application dependency graph builder. Recursively scans
//               directories, resolves imports, and constructs module trees.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { parseJavaScriptFile } from "../parser/javascript-parser.js";
import type {
  ModuleInfo,
  FileIdentity,
} from "../../domain/common/types.js";

export interface ScanOptions {
  readonly maxFiles?: number;
  readonly ignorePatterns?: string[];
}

/** Recursively collect all relevant JavaScript / TypeScript / JSON files. */
export async function collectSourceFiles(
  dirPath: string,
  options: ScanOptions = {}
): Promise<string[]> {
  const max = options.maxFiles ?? 2000;
  const files: string[] = [];
  const validExtensions = new Set([".js", ".mjs", ".cjs", ".ts", ".jsx", ".tsx", ".json"]);

  async function walkDir(current: string) {
    if (files.length >= max) return;
    let entries;
    try {
      entries = await fs.readdir(current, { withFileTypes: true });
    } catch {
      return;
    }

    for (const entry of entries) {
      if (files.length >= max) return;
      const fullPath = path.join(current, entry.name);

      if (entry.isDirectory()) {
        if (
          entry.name === "node_modules" ||
          entry.name === ".git" ||
          entry.name === "dist" ||
          entry.name === "build" ||
          entry.name === ".cache"
        ) {
          continue;
        }
        await walkDir(fullPath);
      } else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (validExtensions.has(ext)) {
          files.push(fullPath);
        }
      }
    }
  }

  await walkDir(dirPath);
  return files;
}

/** Build module summaries for a list of file paths. */
export async function buildModuleGraph(
  rootPath: string,
  filePaths: string[]
): Promise<ModuleInfo[]> {
  const modules: ModuleInfo[] = [];

  for (const filePath of filePaths) {
    try {
      const stat = await fs.stat(filePath);
      const relativePath = path.relative(rootPath, filePath);
      const identity: FileIdentity = {
        absolutePath: filePath,
        relativePath,
        sizeBytes: stat.size,
      };

      const ext = path.extname(filePath).toLowerCase();
      if (ext === ".json") {
        modules.push({
          identity,
          kind: "json",
          imports: [],
          exports: [],
          evidence: {
            classification: "observation",
            summary: `JSON data artifact (${stat.size} bytes)`,
            source: { path: filePath },
          },
        });
        continue;
      }

      const content = await fs.readFile(filePath, "utf8");
      const parseRes = parseJavaScriptFile({ filePath, source: content });

      if (parseRes.ok) {
        modules.push({
          identity,
          kind: parseRes.value.kind,
          imports: parseRes.value.imports,
          exports: parseRes.value.exports,
          evidence: parseRes.value.evidence,
        });
      } else {
        modules.push({
          identity,
          kind: "unknown",
          imports: [],
          exports: [],
          evidence: {
            classification: "observation",
            summary: `Unparsed source module: ${parseRes.error.message}`,
            source: { path: filePath },
            limitations: ["Syntax was too complex or non-standard for basic ECMAScript parser"],
          },
        });
      }
    } catch {
      // Skip unreadable files cleanly
    }
  }

  return modules;
}
