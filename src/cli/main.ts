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
import { runMcpServer } from "../mcp/server.js";

const program = new Command();

program
  .name("ri")
  .description(
    chalk.cyan(
      "Reverse IT — Advanced static reverse-engineering for JavaScript, Electron & Web applications"
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
    console.log(chalk.bold.cyan("=== REVERSE IT: ANALYSIS SUMMARY ==="));
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
        if (app.electron.ipcChannels.length > 10) {
          console.log(chalk.gray(`  ... and ${app.electron.ipcChannels.length - 10} more channels`));
        }
      }
    }

    console.log();
    console.log(chalk.gray("Evidence recorded. Use --json to export complete machine evidence."));
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
    console.log();
    for (const src of sm.sources.slice(0, 15)) {
      console.log(`  • ${chalk.green(src.originalPath)} ${src.hasContent ? chalk.gray(`(${src.sizeBytes ?? 0} bytes)`) : chalk.red("(no embedded content)")}`);
    }
  });

// Command: mcp
program
  .command("mcp")
  .description("Start the Reverse IT Model Context Protocol (MCP) server over stdio")
  .action(async () => {
    await runMcpServer();
  });

program.parse(process.argv);
