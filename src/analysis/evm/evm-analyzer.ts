// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/evm/evm-analyzer.ts
// Description : Ethereum EVM bytecode function selector recoverer. Scans
//               runtime bytecode for dispatchers, function hashes, and jump offsets.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface EvmFunctionSelector {
  readonly selector: string;
  readonly byteOffset: number;
  readonly jumpDest?: number;
  readonly standardMatch?: string;
}

export interface EvmAnalysis {
  readonly totalSelectors: number;
  readonly selectors: EvmFunctionSelector[];
  readonly detectedStandards: string[];
  readonly evidence: Evidence;
}

// Well-known ERC standards function selectors
const KNOWN_SELECTORS: Record<string, { name: string; standard: string }> = {
  "0xa9059cbb": { name: "transfer(address,uint256)", standard: "ERC-20" },
  "0x70a08231": { name: "balanceOf(address)", standard: "ERC-20" },
  "0x095ea7b3": { name: "approve(address,uint256)", standard: "ERC-20" },
  "0x23b872dd": { name: "transferFrom(address,address,uint256)", standard: "ERC-20" },
  "0x18160ddd": { name: "totalSupply()", standard: "ERC-20" },
  "0x6352211e": { name: "ownerOf(uint256)", standard: "ERC-721" },
  "0x42842e0e": { name: "safeTransferFrom(address,address,uint256)", standard: "ERC-721" },
  "0x01ffc9a7": { name: "supportsInterface(bytes4)", standard: "ERC-165" },
};

/** Recover function dispatch selectors from EVM runtime bytecode (hex string or raw bytes). */
export function analyzeEvmBytecode(input: string | Buffer): Result<EvmAnalysis> {
  try {
    let hex = typeof input === "string" ? input.trim() : input.toString("hex");
    if (hex.startsWith("0x")) hex = hex.slice(2);

    if (hex.length < 8) {
      return failure({
        kind: "unsupported_format",
        message: "Bytecode too short to contain function selectors.",
      });
    }

    const selectors: EvmFunctionSelector[] = [];
    const standards = new Set<string>();

    // Scan for PUSH4 (0x63) opcode in hex: "63" followed by 8 hex characters (4 bytes)
    const regex = /63([0-9a-fA-F]{8})/g;
    let match: RegExpExecArray | null;

    while ((match = regex.exec(hex)) !== null) {
      const selector = `0x${match[1].toLowerCase()}`;
      const byteOffset = Math.floor(match.index / 2);

      // Verify dispatcher context: look ahead up to 20 hex chars (10 bytes) for EQ (14) or JUMPI (57)
      const lookahead = hex.slice(match.index + 10, match.index + 30);
      if (lookahead.includes("14") || lookahead.includes("57") || lookahead.includes("56")) {
        const known = KNOWN_SELECTORS[selector];
        if (known) standards.add(known.standard);

        selectors.push({
          selector,
          byteOffset,
          standardMatch: known ? `${known.name} (${known.standard})` : undefined,
        });
      }
    }

    return success({
      totalSelectors: selectors.length,
      selectors,
      detectedStandards: Array.from(standards),
      evidence: {
        classification: "observation",
        summary: `Recovered ${selectors.length} function selectors from EVM runtime bytecode`,
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze EVM bytecode: ${String(err)}`,
      cause: err,
    });
  }
}
