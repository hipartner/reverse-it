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
              targetPath: {
                type: "string",
                description: "Absolute path to the extracted application directory.",
              },
              maxFiles: {
                type: "number",
                description: "Maximum number of files to inspect (default: 2000).",
              },
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
              filePath: {
                type: "string",
                description: "Absolute path to the JavaScript file or .map file.",
              },
            },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_model_artifact",
          description:
            "Inspect an AI model artifact (GGUF or Safetensors). Returns tensor counts, quantization, architecture, context length, and metadata without loading weights into RAM.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: {
                type: "string",
                description: "Absolute path to the .gguf or .safetensors model file.",
              },
            },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_managed_artifact",
          description:
            "Inspect a .NET assembly (.dll / .exe) for CLI headers, target framework version, flags, and metadata streams without executing code.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: {
                type: "string",
                description: "Absolute path to the .NET PE assembly file.",
              },
            },
            required: ["filePath"],
          },
        },
        {
          name: "inspect_game_metadata",
          description:
            "Inspect game engine metadata: Unity global-metadata.dat (IL2CPP) or Godot .pck packages.",
          inputSchema: {
            type: "object",
            properties: {
              filePath: {
                type: "string",
                description: "Absolute path to global-metadata.dat or .pck file.",
              },
              engine: {
                type: "string",
                enum: ["unity", "godot"],
                description: "Game engine format to parse.",
              },
            },
            required: ["filePath", "engine"],
          },
        },
      ],
    };
  });

  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === "analyze_javascript_application") {
      const targetPath = String(args?.targetPath);
      const maxFiles = args?.maxFiles ? Number(args.maxFiles) : undefined;
      const result = await analyzeApplication({ targetPath, maxFiles });
      return formatMcpResult(result);
    }

    if (name === "inspect_sourcemap") {
      const filePath = String(args?.filePath);
      const result = await analyzeSourceMap(filePath);
      return formatMcpResult(result);
    }

    if (name === "inspect_model_artifact") {
      const filePath = String(args?.filePath);
      const result = await analyzeModelArtifact(filePath);
      return formatMcpResult(result);
    }

    if (name === "inspect_managed_artifact") {
      const filePath = String(args?.filePath);
      const result = await analyzeDotNetAssembly(filePath);
      return formatMcpResult(result);
    }

    if (name === "inspect_game_metadata") {
      const filePath = String(args?.filePath);
      const engine = String(args?.engine);

      if (engine === "unity") {
        const result = await analyzeUnityMetadata(filePath);
        return formatMcpResult(result);
      } else if (engine === "godot") {
        const result = await analyzeGodotPck(filePath);
        return formatMcpResult(result);
      }
    }

    throw new Error(`Unknown tool: ${name}`);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

function formatMcpResult(result: { ok: boolean; value?: unknown; error?: { message: string } }) {
  if (result.ok) {
    return {
      content: [
        {
          type: "text" as const,
          text: JSON.stringify(result.value, null, 2),
        },
      ],
    };
  } else {
    return {
      isError: true,
      content: [
        {
          type: "text" as const,
          text: `Operation failed: ${result.error?.message ?? "Unknown error"}`,
        },
      ],
    };
  }
}

if (process.argv[1]?.endsWith("server.ts") || process.argv[1]?.endsWith("server.js")) {
  runMcpServer().catch((err) => {
    console.error("Failed to start MCP server:", err);
    process.exit(1);
  });
}
