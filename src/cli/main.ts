#!/usr/bin/env node
// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/cli/main.ts
// Description : CLI main entry point for `ri` and `reverse-it`.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import { Command } from "commander";
import chalk from "chalk";
import ora from "ora";
import { analyzeApplication } from "../application/analyze-app.js";
import { analyzeSourceMap } from "../analysis/sourcemap/sourcemap-analyzer.js";
import { analyzeModelArtifact } from "../analysis/models/model-analyzer.js";
import { analyzeDotNetAssembly } from "../analysis/managed/dotnet-analyzer.js";
import { analyzeUnityMetadata } from "../analysis/managed/unity-il2cpp.js";
import { analyzeGodotPck } from "../analysis/managed/godot-pck.js";
import { runMcpServer } from "../mcp/server.js";

const program = new Command();

program
  .name("ri")
  .description(
    chalk.cyan(
      "Reverse IT — Advanced static reverse-engineering for JavaScript, Electron, .NET, AI Models & Game Assets"
    )
  )
  .version("1.0.0");

// Command: analyze
program
  .command("analyze <path>")
  .description("Analyze an extracted JavaScript, Electron, or web application directory")
  .option("--json", "Output raw JSON evidence")
  .option("--max-files <number>", "Max number of files to inspect", "2000")
  .action(async (targetPath: string, options: { json?: boolean; maxFiles: string }) => {
    const spinner = options.json
      ? null
      : ora(`Reverse IT analyzing target: ${chalk.bold(targetPath)}...`).start();

    const maxFiles = parseInt(options.maxFiles, 10);
    const result = await analyzeApplication({ targetPath, maxFiles });

    if (!result.ok) {
      if (spinner) spinner.fail(chalk.red(`Analysis failed: ${result.error.message}`));
      else console.error(JSON.stringify(result.error, null, 2));
      process.exit(1);
    }

    if (options.json) {
      console.log(JSON.stringify(result.value, null, 2));
      return;
    }

    spinner?.succeed(chalk.green("Analysis completed successfully!"));

    const app = result.value;
    console.log();
    console.log(chalk.bold.cyan("=== REVERSE IT: APPLICATION SUMMARY ==="));
    console.log(chalk.white(`Target Path      : `) + chalk.yellow(app.targetPath));
    console.log(chalk.white(`Total Modules    : `) + chalk.green(app.analyzedFiles));
    console.log(chalk.white(`Source Maps      : `) + chalk.green(app.sourceMapCount));

    if (app.framework) {
      console.log(chalk.white(`Framework        : `) + chalk.magenta(`${app.framework.name} (${app.framework.version ?? "unknown"})`));
    }

    if (app.electron) {
      console.log();
      console.log(chalk.bold.yellow("--- Electron Architecture ---"));
      if (app.electron.mainProcess) {
        console.log(chalk.white(`Main Process     : `) + chalk.cyan(app.electron.mainProcess));
      }
      console.log(chalk.white(`IPC Channels     : `) + chalk.green(app.electron.ipcChannels.length));
      console.log(chalk.white(`Browser Windows  : `) + chalk.green(app.electron.browserWindows.length));

      if (app.electron.ipcChannels.length > 0) {
        console.log();
        console.log(chalk.bold("Top Discovered IPC Channels:"));
        for (const channel of app.electron.ipcChannels.slice(0, 10)) {
          console.log(`  • ${chalk.cyan(channel.name)} [${channel.direction}] (via ${channel.handler})`);
        }
      }
    }
  });

// Command: sourcemap
program
  .command("sourcemap <file>")
  .description("Inspect and unpack source map for a JavaScript file")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeSourceMap(file);
    if (!result.ok) {
      console.error(chalk.red(`Source map analysis failed: ${result.error.message}`));
      process.exit(1);
    }
    if (options.json) {
      console.log(JSON.stringify(result.value, null, 2));
      return;
    }
    const sm = result.value;
    console.log(chalk.bold.cyan("=== REVERSE IT: SOURCE MAP RECOVERY ==="));
    console.log(`Target           : ${sm.targetFilePath}`);
    console.log(`Recovered Files  : ${sm.originalSourcesCount}`);
    for (const src of sm.sources.slice(0, 15)) {
      console.log(`  • ${chalk.green(src.originalPath)} ${src.hasContent ? chalk.gray(`(${src.sizeBytes ?? 0} bytes)`) : chalk.red("(no embedded content)")}`);
    }
  });

// Command: inspect-model
program
  .command("inspect-model <file>")
  .description("Inspect AI model artifact (GGUF / Safetensors) metadata and tensors")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeModelArtifact(file);
    if (!result.ok) {
      console.error(chalk.red(`Model inspection failed: ${result.error.message}`));
      process.exit(1);
    }
    if (options.json) {
      console.log(JSON.stringify(result.value, null, 2));
      return;
    }
    const m = result.value;
    console.log(chalk.bold.cyan("=== REVERSE IT: MODEL ARTIFACT ==="));
    console.log(chalk.white("Format       : ") + chalk.yellow(m.format.toUpperCase()));
    console.log(chalk.white("Tensors      : ") + chalk.green(m.tensorCount));
    if (m.architecture) console.log(chalk.white("Architecture : ") + chalk.cyan(m.architecture));
    if (m.quantization) console.log(chalk.white("Quantization : ") + chalk.magenta(m.quantization));
    if (m.contextLength) console.log(chalk.white("Context Len  : ") + chalk.green(m.contextLength));
  });

// Command: inspect-dotnet
program
  .command("inspect-dotnet <file>")
  .description("Inspect .NET PE Assembly for CIL headers and target framework")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeDotNetAssembly(file);
    if (!result.ok) {
      console.error(chalk.red(`DotNet inspection failed: ${result.error.message}`));
      process.exit(1);
    }
    if (options.json) {
      console.log(JSON.stringify(result.value, null, 2));
      return;
    }
    const d = result.value;
    console.log(chalk.bold.cyan("=== REVERSE IT: .NET ASSEMBLY ==="));
    console.log(chalk.white("Managed CIL  : ") + (d.isManagedAssembly ? chalk.green("YES") : chalk.red("NO (Native PE)")));
    console.log(chalk.white("Machine      : ") + chalk.yellow(d.peMachine));
    if (d.targetFrameworkVersion) {
      console.log(chalk.white("Framework    : ") + chalk.cyan(d.targetFrameworkVersion));
    }
    if (d.cliHeader) {
      console.log(chalk.white("IL Only      : ") + (d.cliHeader.isIlOnly ? chalk.green("true") : chalk.gray("false")));
      console.log(chalk.white("Entry Token  : ") + chalk.yellow(d.cliHeader.entryPointToken));
    }
  });

// Command: inspect-unity
program
  .command("inspect-unity <file>")
  .description("Inspect Unity global-metadata.dat (IL2CPP) method and type tables")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeUnityMetadata(file);
    if (!result.ok) {
      console.error(chalk.red(`Unity metadata inspection failed: ${result.error.message}`));
      process.exit(1);
    }
    if (options.json) {
      console.log(JSON.stringify(result.value, null, 2));
      return;
    }
    const u = result.value;
    console.log(chalk.bold.cyan("=== REVERSE IT: UNITY IL2CPP METADATA ==="));
    console.log(chalk.white("Metadata Ver : ") + chalk.yellow(u.version));
    console.log(chalk.white("Types Count  : ") + chalk.green(u.typeDefinitionsCount));
    console.log(chalk.white("Methods Count: ") + chalk.green(u.methodDefinitionsCount));
  });

// Command: inspect-pck
program
  .command("inspect-pck <file>")
  .description("Inspect Godot Engine .pck package archive")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeGodotPck(file);
    if (!result.ok) {
      console.error(chalk.red(`Godot PCK inspection failed: ${result.error.message}`));
      process.exit(1);
    }
    if (options.json) {
      console.log(JSON.stringify(result.value, null, 2));
      return;
    }
    const g = result.value;
    console.log(chalk.bold.cyan("=== REVERSE IT: GODOT PCK ==="));
    console.log(chalk.white("Format Ver   : ") + chalk.yellow(g.formatVersion));
    console.log(chalk.white("Engine Ver   : ") + chalk.cyan(g.engineVersion));
  });

// Command: mcp
program
  .command("mcp")
  .description("Start the Reverse IT Model Context Protocol (MCP) server over stdio")
  .action(async () => {
    await runMcpServer();
  });

program.parse(process.argv);
