// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : tests/unit/packages.test.ts
// Description : Unit tests for universal application package & installer inspectors (.deb, NSIS, .app).
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { describe, it, expect } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { analyzePackage } from "../../src/analysis/packages/package-analyzer.js";

describe("Universal Application Package Inspector", () => {
  it("should identify a Debian (.deb) GNU AR archive", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ri-pkg-test-"));
    const testDeb = path.join(tmpDir, "test.deb");

    // Construct mock .deb header: "!<arch>\ndebian-binary   "
    const arMagic = Buffer.from("!<arch>\n", "ascii");
    const entryHeader = Buffer.alloc(60, 0x20); // space-padded
    entryHeader.write("debian-binary", 0, "ascii");
    entryHeader.write("4", 48, "ascii"); // size 4
    entryHeader.write("\x60\n", 58, "ascii");
    const content = Buffer.from("2.0\n", "ascii");

    await fs.writeFile(testDeb, Buffer.concat([arMagic, entryHeader, content]));

    const result = await analyzePackage(testDeb);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.value.packageType).toBe("deb");
    expect(result.value.entries.some((e) => e.name === "debian-binary")).toBe(true);

    await fs.rm(tmpDir, { recursive: true, force: true });
  });
});
