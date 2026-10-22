// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : tests/unit/native.test.ts
// Description : Unit tests for native ELF, Mach-O, and PE binary anatomy parsers.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { describe, it, expect } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { analyzeNativeBinary } from "../../src/analysis/native/binary-format.js";

describe("Native Binary Anatomy Analyzer", () => {
  it("should parse ELF x86_64 header", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ri-native-test-"));
    const testElf = path.join(tmpDir, "sample.elf");

    // Construct mock 64-bit ELF header
    const elfBuf = Buffer.alloc(64);
    elfBuf[0] = 0x7f; elfBuf[1] = 0x45; elfBuf[2] = 0x4c; elfBuf[3] = 0x46; // \x7fELF
    elfBuf[4] = 2; // 64-bit
    elfBuf[5] = 1; // little endian
    elfBuf[6] = 1; // EV_CURRENT
    elfBuf.writeUInt16LE(2, 16); // ET_EXEC
    elfBuf.writeUInt16LE(0x3e, 18); // x86_64 machine
    elfBuf.writeBigUInt64LE(0x401000n, 24); // entry point

    await fs.writeFile(testElf, elfBuf);

    const result = await analyzeNativeBinary(testElf);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.value.format).toBe("elf");
    expect(result.value.bitness).toBe(64);
    expect(result.value.architecture).toBe("x86_64 (AMD64)");
    expect(result.value.entryPoint).toBe("0x401000");

    await fs.rm(tmpDir, { recursive: true, force: true });
  });
});
