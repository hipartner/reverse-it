// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/firmware/firmware-analyzer.ts
// Description : Firmware partition scanner. Identifies SquashFS, U-Boot,
//               DeviceTree, CramFS, and compressed kernels across binary images.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface FirmwareSignature {
  readonly offset: number;
  readonly type: string;
  readonly description: string;
}

export interface FirmwareAnalysis {
  readonly filePath: string;
  readonly sizeBytes: number;
  readonly signatures: FirmwareSignature[];
  readonly evidence: Evidence;
}

/** Scan firmware image for known headers and embedded filesystems without flashing. */
export async function analyzeFirmware(filePath: string): Promise<Result<FirmwareAnalysis>> {
  let handle;
  try {
    handle = await fs.open(filePath, "r");
    const stat = await handle.stat();
    // Scan up to 50 MB
    const readSize = Math.min(stat.size, 50 * 1024 * 1024);
    const buffer = Buffer.alloc(readSize);
    await handle.read(buffer, 0, readSize, 0);

    const signatures: FirmwareSignature[] = [];

    for (let i = 0; i < readSize - 8; i++) {
      // 1. SquashFS: "hsqs" (0x68737173) or "shsq" (0x73687371)
      const u32be = buffer.readUInt32BE(i);
      const u32le = buffer.readUInt32LE(i);

      if (u32be === 0x68737173 || u32le === 0x68737173) {
        signatures.push({
          offset: i,
          type: "squashfs",
          description: "SquashFS filesystem image",
        });
        i += 64; // skip header
        continue;
      }

      // 2. U-Boot Header: 0x27051956
      if (u32be === 0x27051956) {
        signatures.push({
          offset: i,
          type: "u-boot",
          description: "U-Boot Legacy Image Header",
        });
        i += 64;
        continue;
      }

      // 3. Device Tree Blob (DTB): 0xd00dfeed
      if (u32be === 0xd00dfeed) {
        signatures.push({
          offset: i,
          type: "devicetree",
          description: "Flattened Device Tree Blob (DTB)",
        });
        i += 40;
        continue;
      }

      // 4. Gzip compressed block: 0x1f 0x8b 0x08
      if (buffer[i] === 0x1f && buffer[i + 1] === 0x8b && buffer[i + 2] === 0x08) {
        signatures.push({
          offset: i,
          type: "gzip",
          description: "Gzip compressed data block",
        });
        i += 10;
        continue;
      }

      // 5. XZ archive: 0xFD 0x37 0x7A 0x58 0x5A 0x00
      if (
        buffer[i] === 0xfd &&
        buffer[i + 1] === 0x37 &&
        buffer[i + 2] === 0x7a &&
        buffer[i + 3] === 0x58 &&
        buffer[i + 4] === 0x5a &&
        buffer[i + 5] === 0x00
      ) {
        signatures.push({
          offset: i,
          type: "xz",
          description: "XZ compressed archive",
        });
        i += 12;
        continue;
      }
    }

    return success({
      filePath,
      sizeBytes: stat.size,
      signatures,
      evidence: {
        classification: "observation",
        summary: `Discovered ${signatures.length} firmware partitions & signatures`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze firmware image: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  } finally {
    if (handle) await handle.close();
  }
}
