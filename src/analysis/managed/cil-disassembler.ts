// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/managed/cil-disassembler.ts
// Description : ECMA-335 Common Intermediate Language (CIL) opcode decoder.
//               Disassembles raw MSIL method bytecode into human-readable instructions.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

export interface CilInstruction {
  readonly offset: number;
  readonly opcodeHex: string;
  readonly mnemonic: string;
  readonly operand?: string;
}

const SINGLE_BYTE_OPCODES: Record<number, { mnemonic: string; operandSize: number }> = {
  0x00: { mnemonic: "nop", operandSize: 0 },
  0x01: { mnemonic: "break", operandSize: 0 },
  0x02: { mnemonic: "ldarg.0", operandSize: 0 },
  0x03: { mnemonic: "ldarg.1", operandSize: 0 },
  0x04: { mnemonic: "ldarg.2", operandSize: 0 },
  0x05: { mnemonic: "ldarg.3", operandSize: 0 },
  0x06: { mnemonic: "ldloc.0", operandSize: 0 },
  0x07: { mnemonic: "ldloc.1", operandSize: 0 },
  0x08: { mnemonic: "ldloc.2", operandSize: 0 },
  0x09: { mnemonic: "ldloc.3", operandSize: 0 },
  0x0a: { mnemonic: "stloc.0", operandSize: 0 },
  0x0b: { mnemonic: "stloc.1", operandSize: 0 },
  0x0c: { mnemonic: "stloc.2", operandSize: 0 },
  0x0d: { mnemonic: "stloc.3", operandSize: 0 },
  0x14: { mnemonic: "ldnull", operandSize: 0 },
  0x15: { mnemonic: "ldc.i4.m1", operandSize: 0 },
  0x16: { mnemonic: "ldc.i4.0", operandSize: 0 },
  0x17: { mnemonic: "ldc.i4.1", operandSize: 0 },
  0x18: { mnemonic: "ldc.i4.2", operandSize: 0 },
  0x19: { mnemonic: "ldc.i4.3", operandSize: 0 },
  0x1a: { mnemonic: "ldc.i4.4", operandSize: 0 },
  0x1b: { mnemonic: "ldc.i4.5", operandSize: 0 },
  0x1c: { mnemonic: "ldc.i4.6", operandSize: 0 },
  0x1d: { mnemonic: "ldc.i4.7", operandSize: 0 },
  0x1e: { mnemonic: "ldc.i4.8", operandSize: 0 },
  0x1f: { mnemonic: "ldc.i4.s", operandSize: 1 },
  0x20: { mnemonic: "ldc.i4", operandSize: 4 },
  0x25: { mnemonic: "dup", operandSize: 0 },
  0x26: { mnemonic: "pop", operandSize: 0 },
  0x28: { mnemonic: "call", operandSize: 4 },
  0x2a: { mnemonic: "ret", operandSize: 0 },
  0x2b: { mnemonic: "br.s", operandSize: 1 },
  0x2c: { mnemonic: "brfalse.s", operandSize: 1 },
  0x2d: { mnemonic: "brtrue.s", operandSize: 1 },
  0x2e: { mnemonic: "beq.s", operandSize: 1 },
  0x38: { mnemonic: "br", operandSize: 4 },
  0x39: { mnemonic: "brfalse", operandSize: 4 },
  0x3a: { mnemonic: "brtrue", operandSize: 4 },
  0x6f: { mnemonic: "callvirt", operandSize: 4 },
  0x72: { mnemonic: "ldstr", operandSize: 4 },
  0x73: { mnemonic: "newobj", operandSize: 4 },
  0x74: { mnemonic: "castclass", operandSize: 4 },
  0x75: { mnemonic: "isinst", operandSize: 4 },
  0x7a: { mnemonic: "throw", operandSize: 0 },
  0x8c: { mnemonic: "box", operandSize: 4 },
  0x8d: { mnemonic: "newarr", operandSize: 4 },
  0x8e: { mnemonic: "ldlen", operandSize: 0 },
};

/** Disassemble raw CIL bytecode buffer into instructions. */
export function disassembleCilBytecode(buffer: Buffer): CilInstruction[] {
  const instructions: CilInstruction[] = [];
  let offset = 0;

  while (offset < buffer.length) {
    const instOffset = offset;
    const byte = buffer[offset++];
    const op = SINGLE_BYTE_OPCODES[byte];

    if (op) {
      let operandStr: string | undefined;
      if (op.operandSize === 1 && offset < buffer.length) {
        const val = buffer.readInt8(offset);
        operandStr = `0x${val.toString(16)}`;
        offset += 1;
      } else if (op.operandSize === 4 && offset + 4 <= buffer.length) {
        const val = buffer.readUInt32LE(offset);
        operandStr = `0x${val.toString(16)}`;
        offset += 4;
      }
      instructions.push({
        offset: instOffset,
        opcodeHex: `0x${byte.toString(16).padStart(2, "0")}`,
        mnemonic: op.mnemonic,
        operand: operandStr,
      });
    } else {
      // Unrecognized opcode
      instructions.push({
        offset: instOffset,
        opcodeHex: `0x${byte.toString(16).padStart(2, "0")}`,
        mnemonic: `db 0x${byte.toString(16)}`,
      });
    }
  }

  return instructions;
}
