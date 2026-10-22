// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/application/analyze-app.ts
// Description : Application analysis coordinator; ties together module graph,
//               framework detection, Electron IPC extraction and source maps.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import * as path from "node:path";
import { collectSourceFiles, buildModuleGraph } from "../analysis/module-graph/graph-builder.js";
import { extractElectronDetails } from "../analysis/ipc/electron-ipc.js";
import type {
  ApplicationAnalysis,
  FrameworkDetection,
  ElectronAnalysis,
  IpcChannel,
  BrowserWindowInfo,
  Result,
} from "../domain/common/types.js";
import { success, failure } from "../domain/common/types.js";

export interface AnalysisOptions {
  readonly targetPath: string;
  readonly maxFiles?: number;
}

/**
 * Perform a comprehensive reverse-engineering inspection of an extracted
 * JavaScript, Electron, or web application directory.
 */
export async function analyzeApplication(
  options: AnalysisOptions
): Promise<Result<ApplicationAnalysis>> {
  const resolvedTarget = path.resolve(options.targetPath);

  try {
    const stat = await fs.stat(resolvedTarget);
    if (!stat.isDirectory()) {
      return failure({
        kind: "unsupported_format",
        message: `Target '${resolvedTarget}' is not a directory. For single files, pass the parent directory.`,
        path: resolvedTarget,
      });
    }

    // 1. Detect framework & package properties
    let framework: FrameworkDetection | undefined;
    let mainEntryPoint: string | undefined;
    const entryPoints: string[] = [];

    const pkgJsonPath = path.join(resolvedTarget, "package.json");
    try {
      const pkgContent = await fs.readFile(pkgJsonPath, "utf8");
      const pkg = JSON.parse(pkgContent);

      if (pkg.main) {
        mainEntryPoint = path.resolve(resolvedTarget, pkg.main);
        entryPoints.push(pkg.main);
      }

      const allDeps = {
        ...(pkg.dependencies || {}),
        ...(pkg.devDependencies || {}),
      };

      if (allDeps.electron) {
        framework = {
          name: "Electron",
          version: allDeps.electron,
          evidence: {
            classification: "observation",
            summary: `Detected Electron runtime v${allDeps.electron} in package.json`,
            source: { path: pkgJsonPath },
          },
        };
      } else if (allDeps.next) {
        framework = {
          name: "Next.js",
          version: allDeps.next,
          evidence: {
            classification: "observation",
            summary: `Detected Next.js framework v${allDeps.next}`,
            source: { path: pkgJsonPath },
          },
        };
      } else if (allDeps.react) {
        framework = {
          name: "React",
          version: allDeps.react,
          evidence: {
            classification: "observation",
            summary: `Detected React framework v${allDeps.react}`,
            source: { path: pkgJsonPath },
          },
        };
      }
    } catch {
      // package.json is optional
    }

    // 2. Discover files
    const filePaths = await collectSourceFiles(resolvedTarget, {
      maxFiles: options.maxFiles ?? 2000,
    });

    // 3. Build module graph
    const modules = await buildModuleGraph(resolvedTarget, filePaths);

    // 4. Electron IPC and BrowserWindow analysis
    const allIpcChannels: IpcChannel[] = [];
    const allBrowserWindows: BrowserWindowInfo[] = [];
    const preloadScripts: string[] = [];
    let sourceMapCount = 0;

    for (const file of filePaths) {
      if (file.endsWith(".map")) {
        sourceMapCount++;
        continue;
      }

      try {
        const content = await fs.readFile(file, "utf8");
        // Electron inspection
        const electronData = extractElectronDetails(file, content);
        if (electronData.ipcChannels.length > 0) {
          allIpcChannels.push(...electronData.ipcChannels);
        }
        if (electronData.browserWindows.length > 0) {
          allBrowserWindows.push(...electronData.browserWindows);
          for (const win of electronData.browserWindows) {
            if (win.preload) preloadScripts.push(win.preload);
          }
        }

        // Inline source map check
        if (content.includes("sourceMappingURL=")) {
          sourceMapCount++;
        }
      } catch {
        // Continue
      }
    }

    let electron: ElectronAnalysis | undefined;
    if (framework?.name === "Electron" || allIpcChannels.length > 0 || allBrowserWindows.length > 0) {
      electron = {
        mainProcess: mainEntryPoint,
        preloadScripts: Array.from(new Set(preloadScripts)),
        ipcChannels: allIpcChannels,
        browserWindows: allBrowserWindows,
        evidence: {
          classification: "derivation",
          summary: `Identified ${allIpcChannels.length} IPC channels and ${allBrowserWindows.length} BrowserWindow calls`,
          limitations: [
            "Dynamic IPC channels computed with string concatenation cannot be resolved statically",
          ],
        },
      };
    }

    return success({
      targetPath: resolvedTarget,
      modules,
      entryPoints,
      framework,
      electron,
      sourceMapCount,
      totalFiles: filePaths.length,
      analyzedFiles: modules.length,
      evidence: {
        classification: "observation",
        summary: `Analyzed ${modules.length} modules in ${resolvedTarget}`,
        source: { path: resolvedTarget },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze application at ${resolvedTarget}: ${String(err)}`,
      path: resolvedTarget,
      cause: err,
    });
  }
}
