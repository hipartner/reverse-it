// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : tests/unit/parser.test.ts
// Description : Unit tests for JavaScript AST parser and module detection.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { describe, it, expect } from "vitest";
import { parseJavaScriptFile } from "../../src/analysis/parser/javascript-parser.js";

describe("JavaScript AST Parser", () => {
  it("should parse ESM static imports and exports", () => {
    const sampleCode = `
      import { useState } from 'react';
      import path from 'node:path';

      export const version = '1.0.0';
      export default function main() { return 42; }
    `;

    const result = parseJavaScriptFile({
      filePath: "test.js",
      source: sampleCode,
      isModule: true,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.value.imports).toHaveLength(2);
    expect(result.value.imports[0].specifier).toBe("react");
    expect(result.value.imports[1].specifier).toBe("node:path");
    expect(result.value.exports.some((e) => e.name === "version")).toBe(true);
    expect(result.value.exports.some((e) => e.name === "default")).toBe(true);
  });
});
