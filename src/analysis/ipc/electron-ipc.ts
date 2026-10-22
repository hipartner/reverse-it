// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/ipc/electron-ipc.ts
// Description : Electron IPC and window analysis; identifies channels,
//               directions, handlers, and BrowserWindow instantiation.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as acorn from "acorn";
import * as walk from "acorn-walk";
import type {
  IpcChannel,
  BrowserWindowInfo,
} from "../../domain/common/types.js";

/** Extract Electron IPC channels and BrowserWindow configurations from source. */
export function extractElectronDetails(
  filePath: string,
  source: string
): { ipcChannels: IpcChannel[]; browserWindows: BrowserWindowInfo[] } {
  const ipcChannels: IpcChannel[] = [];
  const browserWindows: BrowserWindowInfo[] = [];

  try {
    const ast = acorn.parse(source, {
      ecmaVersion: "latest",
      sourceType: "module",
      locations: true,
    });

    walk.simple(ast, {
      CallExpression(node: acorn.CallExpression) {
        if (node.callee.type === "MemberExpression") {
          const callee = node.callee as acorn.MemberExpression;
          const obj = callee.object;
          const prop = callee.property;

          if (obj.type === "Identifier" && prop.type === "Identifier") {
            const objectName = (obj as acorn.Identifier).name;
            const methodName = (prop as acorn.Identifier).name;

            // Detect ipcRenderer.send / invoke / on
            if (objectName === "ipcRenderer") {
              const channelArg = node.arguments[0];
              if (channelArg && channelArg.type === "Literal" && typeof (channelArg as acorn.Literal).value === "string") {
                const channelName = (channelArg as acorn.Literal).value as string;
                const direction = methodName === "on" ? "main-to-renderer" : "renderer-to-main";
                ipcChannels.push({
                  name: channelName,
                  direction,
                  handler: methodName,
                  evidence: {
                    classification: "observation",
                    summary: `ipcRenderer.${methodName} call for channel '${channelName}'`,
                    source: {
                      path: filePath,
                      line: node.loc?.start.line,
                      column: node.loc?.start.column,
                    },
                  },
                });
              }
            }

            // Detect ipcMain.on / handle
            if (objectName === "ipcMain") {
              const channelArg = node.arguments[0];
              if (channelArg && channelArg.type === "Literal" && typeof (channelArg as acorn.Literal).value === "string") {
                const channelName = (channelArg as acorn.Literal).value as string;
                ipcChannels.push({
                  name: channelName,
                  direction: "renderer-to-main",
                  handler: methodName,
                  evidence: {
                    classification: "observation",
                    summary: `ipcMain.${methodName} listener for channel '${channelName}'`,
                    source: {
                      path: filePath,
                      line: node.loc?.start.line,
                      column: node.loc?.start.column,
                    },
                  },
                });
              }
            }
          }
        }
      },

      NewExpression(node: acorn.NewExpression) {
        if (
          node.callee.type === "Identifier" &&
          (node.callee as acorn.Identifier).name === "BrowserWindow"
        ) {
          let preloadScript: string | undefined;

          const optionsArg = node.arguments[0];
          if (optionsArg && optionsArg.type === "ObjectExpression") {
            for (const prop of (optionsArg as acorn.ObjectExpression).properties) {
              if (
                prop.type === "Property" &&
                prop.key.type === "Identifier" &&
                (prop.key as acorn.Identifier).name === "webPreferences" &&
                prop.value.type === "ObjectExpression"
              ) {
                for (const webPref of (prop.value as acorn.ObjectExpression).properties) {
                  if (
                    webPref.type === "Property" &&
                    webPref.key.type === "Identifier" &&
                    (webPref.key as acorn.Identifier).name === "preload" &&
                    webPref.value.type === "Literal"
                  ) {
                    preloadScript = String((webPref.value as acorn.Literal).value);
                  }
                }
              }
            }
          }

          browserWindows.push({
            createdIn: filePath,
            line: node.loc?.start.line,
            preload: preloadScript,
            evidence: {
              classification: "observation",
              summary: `BrowserWindow created${preloadScript ? ` with preload: ${preloadScript}` : ""}`,
              source: { path: filePath, line: node.loc?.start.line },
            },
          });
        }
      },
    });
  } catch {
    const ipcRegex = /(?:ipcRenderer|ipcMain)\.(send|invoke|on|handle)\s*\(\s*['"`]([^'"`]+)['"`]/g;
    let match: RegExpExecArray | null;
    while ((match = ipcRegex.exec(source)) !== null) {
      const handler = match[1];
      const channelName = match[2];
      ipcChannels.push({
        name: channelName,
        direction: handler === "on" ? "main-to-renderer" : "renderer-to-main",
        handler,
        evidence: {
          classification: "observation",
          summary: `Regex-detected IPC channel '${channelName}' via .${handler}`,
          source: { path: filePath },
          limitations: ["Extracted via regex fallback because full AST parse failed"],
        },
      });
    }
  }

  return { ipcChannels, browserWindows };
}
