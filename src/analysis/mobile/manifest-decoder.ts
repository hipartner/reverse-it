// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/mobile/manifest-decoder.ts
// Description : Android binary XML (AXML) string pool decoder. Recovers package
//               names, permissions, activities, and exported components from APKs.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface DecodedManifest {
  readonly packageName?: string;
  readonly permissions: string[];
  readonly activities: string[];
  readonly services: string[];
  readonly allStringsCount: number;
  readonly evidence: Evidence;
}

/** Decode binary AndroidManifest.xml buffer by parsing the AXML string pool chunk. */
export function decodeBinaryManifest(buffer: Buffer): Result<DecodedManifest> {
  try {
    if (buffer.length < 8) {
      return failure({
        kind: "unsupported_format",
        message: "Buffer too small for binary AXML.",
      });
    }

    const magic = buffer.readUInt32LE(0);
    // AXML Magic: 0x00080003
    if (magic !== 0x00080003) {
      return failure({
        kind: "unsupported_format",
        message: `Invalid AXML magic 0x${magic.toString(16)} (expected 0x00080003).`,
      });
    }

    // String Pool Chunk starts at offset 8
    const chunkType = buffer.readUInt32LE(8);
    // 0x001C0001 is String Pool chunk type
    if ((chunkType & 0xffff) !== 0x0001 && (chunkType & 0xffff) !== 0x001c) {
      return failure({
        kind: "unsupported_format",
        message: "String pool chunk not found at expected offset.",
      });
    }

    const stringCount = buffer.readUInt32LE(16);
    const stringsStart = 8 + buffer.readUInt32LE(28); // stringsStart relative to chunk
    const isUtf8 = (buffer.readUInt32LE(24) & (1 << 8)) !== 0;

    const strings: string[] = [];
    const offsetTableStart = 36;

    for (let i = 0; i < stringCount && offsetTableStart + i * 4 < buffer.length; i++) {
      const strOffset = stringsStart + buffer.readUInt32LE(offsetTableStart + i * 4);
      if (strOffset >= buffer.length) continue;

      if (isUtf8) {
        // UTF-8 string: length prefixed
        const len = buffer[strOffset + 1];
        const text = buffer.toString("utf8", strOffset + 2, strOffset + 2 + len);
        strings.push(text);
      } else {
        // UTF-16 string: length prefixed by 2 bytes
        const len = buffer.readUInt16LE(strOffset) * 2;
        const text = buffer.toString("utf16le", strOffset + 2, strOffset + 2 + len);
        strings.push(text);
      }
    }

    const permissions: string[] = [];
    const activities: string[] = [];
    const services: string[] = [];
    let packageName: string | undefined;

    for (const str of strings) {
      if (str.startsWith("android.permission.")) {
        permissions.push(str);
      } else if (/^[a-zA-Z0-9_]+(\.[a-zA-Z0-9_]+){2,}$/.test(str) && !str.startsWith("android.")) {
        if (!packageName && !str.includes("Activity")) {
          packageName = str;
        }
      }
      if (str.endsWith("Activity") || str.includes(".activity.")) {
        activities.push(str);
      }
      if (str.endsWith("Service") || str.includes(".service.")) {
        services.push(str);
      }
    }

    return success({
      packageName,
      permissions: Array.from(new Set(permissions)),
      activities: Array.from(new Set(activities)),
      services: Array.from(new Set(services)),
      allStringsCount: strings.length,
      evidence: {
        classification: "observation",
        summary: `Decoded AXML manifest: ${permissions.length} permissions, ${activities.length} activities`,
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to decode AXML buffer: ${String(err)}`,
      cause: err,
    });
  }
}
