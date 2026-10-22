// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/mcp/server.ts
// Description : Model Context Protocol (MCP) server for Reverse IT. Provides
//               tools for AI coding assistants to reverse-engineer targets.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { Server } from "@modelcontextprotocol/sdk/server/index.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  CallToolRequestSchema,
  ListToolsRequestSchema,
} from "@modelcontextprotocol/sdk/types.js";
import { analyzeApplication } from "../application/analyze-app.js";
import { analyzeSourceMap } from "../analysis/sourcemap/sourcemap-analyzer.js";
import { analyzeModelArtifact } from "../analysis/models/model-analyzer.js";
import { analyzeDotNetAssembly } from "../analysis/managed/dotnet-analyzer.js";
import { analyzeNativeBinary } from "../analysis/native/binary-format.js";
import { disassembleTarget } from "../analysis/native/disassembly-bridge.js";
import { decompileTarget } from "../analysis/native/decompiler-bridge.js";
import { extractBinaryStrings } from "../analysis/native/strings-analyzer.js";
import { analyzeApk } from "../analysis/mobile/apk-analyzer.js";
import { analyzeFirmware } from "../analysis/firmware/firmware-analyzer.js";
import { analyzeHarCapture } from "../analysis/network/har-analyzer.js";
import { analyzeCoreDump } from "../analysis/diagnostics/crash-analyzer.js";
import { analyzeWasmModule } from "../analysis/wasm/wasm-analyzer.js";
import { analyzeEvmBytecode } from "../analysis/evm/evm-analyzer.js";

export async function runMcpServer() {
  const server = new Server(
    { name: "io.github.hipartner/reverse-it", version: "1.0.0" },
    { capabilities: { tools: {} } }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "analyze_javascript_application",
          description: "Reverse engineer a JavaScript, Electron, or web application directory.",
          inputSchema: {
            type: "object",
            properties: {
              targetPath: { type: "string", description: "Path to app directory." },
              maxFiles: { type: "number", description: "Max files to inspect." },
            },
            required: ["targetPath"],
          },
        },
        {
          name: "decompile_target",
          description: "Decompile binary routine into C pseudocode using Ghidra or Rizin.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Path to binary executable." },
              functionName: { type: "string", description: "Target function routine." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_native_binary",
          description: "Inspect ELF, Mach-O, or PE binary headers, architecture, and section table.",
          inputSchema: {
            type: "object",
            properties: { filePath: { type: "string", description: "Path to binary." } },
            required: ["filePath"],
          },
        },
        {
          name: "disassemble_target",
          description: "Disassemble function instructions via host objdump without execution.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Path to binary." },
              functionName: { type: "string", description: "Function to disassemble." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "extract_binary_strings",
          description: "Extract and classify URLs, IPs, file paths, and GUIDs from any binary.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Path to binary." },
              minLength: { type: "number", description: "Min length." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_model_artifact",
          description: "Inspect GGUF or Safetensors model metadata without loading weights into RAM.",
          inputSchema: {
            type: "object",
            properties: { filePath: { type: "string", description: "Path to model." } },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_managed_artifact",
          description: "Inspect .NET PE/CLI Assembly headers and target framework runtime.",
          inputSchema: {
            type: "object",
            properties: { filePath: { type: "string", description: "Path to .dll / .exe." } },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_wasm_module",
          description: "Inspect WebAssembly (.wasm) sections, imports, exports, and functions.",
          inputSchema: {
            type: "object",
            properties: { filePath: { type: "string", description: "Path to .wasm file." } },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_evm_bytecode",
          description: "Recover 4-byte function dispatch selectors and ERC standards from EVM bytecode.",
          inputSchema: {
            type: "object",
            properties: { bytecodeHex: { type: "string", description: "Runtime hex bytecode." } },
            required: ["bytecodeHex"],
          },
        },
        {
          name: "analyze_apk",
          description: "Inspect Android APK for Dex files, native ABIs, and manifest.",
          inputSchema: {
            type: "object",
            properties: { filePath: { type: "string", description: "Path to .apk." } },
            required: ["filePath"],
          },
        },
        {
          name: "analyze_firmware",
          description: "Scan firmware image for SquashFS, U-Boot, DeviceTree, and XZ partitions.",
          inputSchema: {
            type: "object",
            properties: { filePath: { type: "string", description: "Path to firmware." } },
            required: ["filePath"],
          },
        },
        {
          name: "analyze_har_capture",
          description: "Inspect HTTP Archive (.har) capture for endpoints and auth headers.",
          inputSchema: {
            type: "object",
            properties: { filePath: { type: "string", description: "Path to .har." } },
            required: ["filePath"],
          },
        },
        {
          name: "analyze_core_dump",
          description: "Inspect Linux ELF core dump for architecture and memory segments.",
          inputSchema: {
            type: "object",
            properties: { filePath: { type: "string", description: "Path to core dump." } },
            required: ["filePath"],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;
    const filePath = String(args?.filePath ?? "");

    switch (name) {
      case "analyze_javascript_application":
        return formatMcpResult(
          await analyzeApplication({
            targetPath: String(args?.targetPath),
            maxFiles: args?.maxFiles ? Number(args.maxFiles) : undefined,
          })
        );
      case "decompile_target":
        return formatMcpResult(
          await decompileTarget(filePath, {
            functionName: args?.functionName ? String(args.functionName) : undefined,
          })
        );
      case "inspect_native_binary":
        return formatMcpResult(await analyzeNativeBinary(filePath));
      case "disassemble_target":
        return formatMcpResult(
          await disassembleTarget(filePath, {
            functionName: args?.functionName ? String(args.functionName) : undefined,
          })
        );
      case "extract_binary_strings":
        return formatMcpResult(
          await extractBinaryStrings(filePath, {
            minLength: args?.minLength ? Number(args.minLength) : undefined,
          })
        );
      case "inspect_model_artifact":
        return formatMcpResult(await analyzeModelArtifact(filePath));
      case "inspect_managed_artifact":
        return formatMcpResult(await analyzeDotNetAssembly(filePath));
      case "inspect_wasm_module":
        return formatMcpResult(await analyzeWasmModule(filePath));
      case "inspect_evm_bytecode":
        return formatMcpResult(analyzeEvmBytecode(String(args?.bytecodeHex)));
      case "analyze_apk":
        return formatMcpResult(await analyzeApk(filePath));
      case "analyze_firmware":
        return formatMcpResult(await analyzeFirmware(filePath));
      case "analyze_har_capture":
        return formatMcpResult(await analyzeHarCapture(filePath));
      case "analyze_core_dump":
        return formatMcpResult(await analyzeCoreDump(filePath));
      default:
        throw new Error(`Unknown tool: ${name}`);
    }
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function formatMcpResult(result: { ok: boolean; value?: unknown; error?: { message: string } }) {
  if (result.ok) {
    return {
      content: [{ type: "text" as const, text: JSON.stringify(result.value, null, 2) }],
    };
  } else {
    return {
      isError: true,
      content: [{ type: "text" as const, text: `Operation failed: ${result.error?.message ?? "Unknown error"}` }],
    };
  }
}

if (process.argv[1]?.endsWith("server.ts") || process.argv[1]?.endsWith("server.js")) {
  runMcpServer().catch((err) => {
    console.error("Failed to start MCP server:", err);
    process.exit(1);
  });
}
