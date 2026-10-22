// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : tests/unit/evm.test.ts
// Description : Unit tests for EVM bytecode dispatcher and function selector recovery.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { describe, it, expect } from "vitest";
import { analyzeEvmBytecode } from "../../src/analysis/evm/evm-analyzer.js";

describe("EVM Bytecode Selector Recovery", () => {
  it("should extract ERC-20 transfer and balanceOf selectors", () => {
    // Mock EVM dispatcher snippet:
    // PUSH4 0xa9059cbb (transfer) EQ PUSH2 0x0040 JUMPI
    // PUSH4 0x70a08231 (balanceOf) EQ PUSH2 0x0060 JUMPI
    const mockBytecode = "6080604052348015600f57600080fd5b5063a9059cbb14610040576370a082311461006057";

    const result = analyzeEvmBytecode(mockBytecode);
    expect(result.ok).toBe(true);
    if (!result.ok) return;

    expect(result.value.totalSelectors).toBe(2);
    expect(result.value.selectors[0].selector).toBe("0xa9059cbb");
    expect(result.value.selectors[1].selector).toBe("0x70a08231");
    expect(result.value.detectedStandards).toContain("ERC-20");
  });
});
