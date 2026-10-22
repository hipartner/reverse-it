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
import { analyzeUnityMetadata } from "../analysis/managed/unity-il2cpp.js";
import { analyzeGodotPck } from "../analysis/managed/godot-pck.js";
import { analyzeNativeBinary } from "../analysis/native/binary-format.js";
import { disassembleTarget } from "../analysis/native/disassembly-bridge.js";
import { extractBinaryStrings } from "../analysis/native/strings-analyzer.js";
import { analyzeApk } from "../analysis/mobile/apk-analyzer.js";
import { analyzeFirmware } from "../analysis/firmware/firmware-analyzer.js";
import { analyzeHarCapture } from "../analysis/network/har-analyzer.js";
import { analyzeCoreDump } from "../analysis/diagnostics/crash-analyzer.js";

export async function runMcpServer() {
  const server = new Server(
    {
      name: "io.github.hipartner/reverse-it",
      version: "1.0.0",
    },
    {
      capabilities: {
        tools: {},
      },
    }
  );

  server.setRequestHandler(ListToolsRequestSchema, async () => {
    return {
      tools: [
        {
          name: "analyze_javascript_application",
          description:
            "Reverse engineer a JavaScript, Electron, or web application directory. Returns module dependencies, imports, exports, IPC channels, and framework evidence.",
          inputSchema: {
            type: "object",
            properties: {
              targetPath: { type: "string", description: "Absolute path to the extracted application directory." },
              maxFiles: { type: "number", description: "Maximum number of files to inspect (default: 2000)." },
            },
            required: ["targetPath"],
          },
        },
        {
          name: "inspect_sourcemap",
          description:
            "Inspect an external or inline source map for a JavaScript file to recover original source paths and source code.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the JavaScript file or .map file." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_model_artifact",
          description:
            "Inspect an AI model artifact (GGUF or Safetensors) without loading weights into RAM.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the model file." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_managed_artifact",
          description:
            "Inspect a .NET assembly (.dll / .exe) for CLI headers, target framework version, and metadata streams.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the .NET PE assembly." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_native_binary",
          description:
            "Inspect ELF, Mach-O, or PE native binary anatomy, architecture, bitness, entry point, and section map.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the binary executable or shared library." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "disassemble_target",
          description:
            "Disassemble specified function routines or address ranges using host objdump without executing the binary.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the native binary." },
              functionName: { type: "string", description: "Specific symbol or function to disassemble." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "extract_binary_strings",
          description:
            "Extract and classify printable ASCII/UTF-8 strings (URLs, file paths, IPs, GUIDs) from any binary.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the target binary." },
              minLength: { type: "number", description: "Minimum string length (default: 4)." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "analyze_apk",
          description:
            "Inspect an Android APK package for Dex bytecode files, native libraries per ABI, and AndroidManifest.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the .apk file." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "analyze_firmware",
          description:
            "Scan a firmware binary image for partitions (SquashFS, U-Boot, DeviceTree, compressed archives).",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the firmware binary image." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "analyze_har_capture",
          description:
            "Inspect an HTTP Archive (.har) capture for requests, responses, authorization headers, and API domains.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the .har file." },
            },
            required: ["filePath"],
          },
        },
        {
          name: "analyze_core_dump",
          description:
            "Inspect a Linux ELF core dump for architecture, signal numbers, and memory segments.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: { type: "string", description: "Absolute path to the core dump file." },
            },
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
      case "inspect_sourcemap":
        return formatMcpResult(await analyzeSourceMap(filePath));
      case "inspect_model_artifact":
        return formatMcpResult(await analyzeModelArtifact(filePath));
      case "inspect_managed_artifact":
        return formatMcpResult(await analyzeDotNetAssembly(filePath));
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
