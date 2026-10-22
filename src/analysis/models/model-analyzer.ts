// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/models/model-analyzer.ts
// Description : Static inspection for AI model artifacts (GGUF and Safetensors).
//               Extracts architectures, tensor counts, shapes, dtypes and metadata.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export type ModelFormat = "gguf" | "safetensors" | "unknown";

export interface TensorInfo {
  readonly name: string;
  readonly shape?: number[];
  readonly dtype?: string;
  readonly offset?: number;
  readonly sizeBytes?: number;
}

export interface ModelAnalysis {
  readonly filePath: string;
  readonly format: ModelFormat;
  readonly version?: number | string;
  readonly tensorCount: number;
  readonly architecture?: string;
  readonly quantization?: string;
  readonly contextLength?: number;
  readonly metadata: Record<string, unknown>;
  readonly sampleTensors: TensorInfo[];
  readonly evidence: Evidence;
}

/** Inspect GGUF or Safetensors model file header and metadata without loading weights. */
export async function analyzeModelArtifact(filePath: string): Promise<Result<ModelAnalysis>> {
  let fileHandle;
  try {
    fileHandle = await fs.open(filePath, "r");
    const headerBuffer = Buffer.alloc(1024 * 1024); // 1 MB buffer for header
    const { bytesRead } = await fileHandle.read(headerBuffer, 0, headerBuffer.length, 0);

    if (bytesRead < 8) {
      return failure({
        kind: "unsupported_format",
        message: `File is too small (${bytesRead} bytes) to be a valid model artifact.`,
        path: filePath,
      });
    }

    // 1. Check GGUF Magic: 0x46554747 ("GGUF" in ASCII LE)
    if (
      headerBuffer[0] === 0x47 &&
      headerBuffer[1] === 0x47 &&
      headerBuffer[2] === 0x55 &&
      headerBuffer[3] === 0x46
    ) {
      return parseGgufHeader(filePath, headerBuffer);
    }

    // 2. Check Safetensors: First 8 bytes are uint64 LE specifying JSON header length
    const jsonHeaderLength = Number(headerBuffer.readBigUInt64LE(0));
    if (jsonHeaderLength > 0 && jsonHeaderLength < 500 * 1024 * 1024) {
      // Valid JSON header length candidate
      return await parseSafetensorsHeader(filePath, fileHandle, jsonHeaderLength);
    }

    return failure({
      kind: "unsupported_format",
      message: `File '${filePath}' is neither a recognized GGUF nor Safetensors model.`,
      path: filePath,
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to inspect model artifact: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (fileHandle) await fileHandle.close();
  }
}

function parseGgufHeader(filePath: string, buffer: Buffer): Result<ModelAnalysis> {
  try {
    const version = buffer.readUInt32LE(4);
    const tensorCount = Number(buffer.readBigUInt64LE(8));
    const kvCount = Number(buffer.readBigUInt64LE(16));

    let offset = 24;
    const metadata: Record<string, unknown> = {};

    // Read metadata key-value pairs (up to buffer limit)
    for (let i = 0; i < kvCount && offset < buffer.length - 16; i++) {
      const keyLen = Number(buffer.readBigUInt64LE(offset));
      offset += 8;
      if (offset + keyLen > buffer.length) break;

      const key = buffer.toString("utf8", offset, offset + keyLen);
      offset += keyLen;

      const valType = buffer.readUInt32LE(offset);
      offset += 4;

      // Handle common GGUF value types
      if (valType === 8) {
        // String
        const strLen = Number(buffer.readBigUInt64LE(offset));
        offset += 8;
        if (offset + strLen > buffer.length) break;
        metadata[key] = buffer.toString("utf8", offset, offset + strLen);
        offset += strLen;
      } else if (valType === 4 || valType === 5) {
        // uint32 / int32
        metadata[key] = buffer.readUInt32LE(offset);
        offset += 4;
      } else if (valType === 6 || valType === 11) {
        // float32
        metadata[key] = buffer.readFloatLE(offset);
        offset += 4;
      } else if (valType === 7) {
        // bool
        metadata[key] = buffer.readUInt8(offset) !== 0;
        offset += 1;
      } else if (valType === 10 || valType === 12) {
        // uint64
        metadata[key] = Number(buffer.readBigUInt64LE(offset));
        offset += 8;
      } else {
        // Skip unknown/array types for safety
        break;
      }
    }

    const arch = typeof metadata["general.architecture"] === "string"
      ? (metadata["general.architecture"] as string)
      : undefined;

    const quant = typeof metadata["general.quantization_version"] === "number"
      ? `GGUF-Q${metadata["general.quantization_version"]}`
      : undefined;

    const ctx = typeof metadata[`${arch}.context_length`] === "number"
      ? (metadata[`${arch}.context_length`] as number)
      : undefined;

    return success({
      filePath,
      format: "gguf",
      version,
      tensorCount,
      architecture: arch,
      quantization: quant,
      contextLength: ctx,
      metadata,
      sampleTensors: [],
      evidence: {
        classification: "observation",
        summary: `Parsed GGUF v${version} with ${tensorCount} tensors (${arch ?? "generic arch"})`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "unsupported_format",
      message: `Failed to decode GGUF metadata: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  }
}

async function parseSafetensorsHeader(
  filePath: string,
  handle: fs.FileHandle,
  headerLength: number
): Promise<Result<ModelAnalysis>> {
  try {
    const jsonBuffer = Buffer.alloc(headerLength);
    await handle.read(jsonBuffer, 0, headerLength, 8);
    const jsonString = jsonBuffer.toString("utf8");
    const parsed = JSON.parse(jsonString);

    const metadata: Record<string, unknown> = parsed.__metadata__ ?? {};
    const sampleTensors: TensorInfo[] = [];
    let count = 0;

    for (const [key, val] of Object.entries(parsed)) {
      if (key === "__metadata__") continue;
      count++;
      if (sampleTensors.length < 20 && typeof val === "object" && val !== null) {
        const item = val as { dtype?: string; shape?: number[]; data_offsets?: [number, number] };
        sampleTensors.push({
          name: key,
          dtype: item.dtype,
          shape: item.shape,
          sizeBytes: item.data_offsets ? item.data_offsets[1] - item.data_offsets[0] : undefined,
        });
      }
    }

    return success({
      filePath,
      format: "safetensors",
      version: 1,
      tensorCount: count,
      metadata,
      sampleTensors,
      evidence: {
        classification: "observation",
        summary: `Parsed Safetensors header with ${count} tensors`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "unsupported_format",
      message: `Failed to decode Safetensors JSON header: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  }
}
