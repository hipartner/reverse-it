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

  // List available tools
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
      ],
    };
  });

  // Handle tool calls
  server.setRequestHandler(CallToolRequestSchema, async (request) => {
    const { name, arguments: args } = request.params;

    if (name === "analyze_javascript_application") {
      const targetPath = String(args?.targetPath);
      const maxFiles = args?.maxFiles ? Number(args.maxFiles) : undefined;

      const result = await analyzeApplication({ targetPath, maxFiles });

      if (result.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result.value, null, 2),
            },
          ],
        };
      } else {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `Analysis failed: ${result.error.message}`,
            },
          ],
        };
      }
    }

    if (name === "inspect_sourcemap") {
      const filePath = String(args?.filePath);
      const result = await analyzeSourceMap(filePath);

      if (result.ok) {
        return {
          content: [
            {
              type: "text",
              text: JSON.stringify(result.value, null, 2),
            },
          ],
        };
      } else {
        return {
          isError: true,
          content: [
            {
              type: "text",
              text: `Source map inspection failed: ${result.error.message}`,
            },
          ],
        };
      }
    }

    throw new Error(`Unknown tool: ${name}`);
  });

  const transport = new StdioServerTransport();
  await server.connect(transport);
}

// Start if executed directly
if (process.argv[1]?.endsWith("server.ts") || process.argv[1]?.endsWith("server.js")) {
  runMcpServer().catch((err) => {
    console.error("Failed to start MCP server:", err);
    process.exit(1);
  });
}
