// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : tests/unit/models.test.ts
// Description : Unit tests for GGUF & Safetensors model artifact inspectors.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { describe, it, expect } from "vitest";
import * as fs from "node:fs/promises";
import * as path from "node:path";
import * as os from "node:os";
import { analyzeModelArtifact } from "../../src/analysis/models/model-analyzer.js";

describe("AI Model Artifact Analyzer", () => {
  it("should parse a valid Safetensors header", async () => {
    const tmpDir = await fs.mkdtemp(path.join(os.tmpdir(), "ri-model-test-"));
    const testFile = path.join(tmpDir, "test.safetensors");

    const headerObj = {
      __metadata__: { format: "pt", framework: "pytorch" },
      "model.embed_tokens.weight": { dtype: "F16", shape: [32000, 4096], data_offsets: [0, 262144000] },
    };

    const headerStr = JSON.stringify(headerObj);
    const headerBuf = Buffer.from(headerStr, "utf8");
    const lenBuf = Buffer.alloc(8);
    lenBuf.writeBigUInt64LE(BigInt(headerBuf.length), 0);

    await fs.writeFile(testFile, Buffer.concat([lenBuf, headerBuf]));

    const result = await analyzeModelArtifact(testFile);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.value.format).toBe("safetensors");
    expect(result.value.tensorCount).toBe(1);
    expect(result.value.sampleTensors[0].name).toBe("model.embed_tokens.weight");

    await fs.rm(tmpDir, { recursive: true, force: true });
  });
});
