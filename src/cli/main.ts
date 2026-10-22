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
import * as fs from "node:fs/promises";
import { analyzeApplication } from "../application/analyze-app.js";
import { analyzeSourceMap } from "../analysis/sourcemap/sourcemap-analyzer.js";
import { analyzeModelArtifact } from "../analysis/models/model-analyzer.js";
import { analyzeDotNetAssembly } from "../analysis/managed/dotnet-analyzer.js";
import { analyzeUnityMetadata } from "../analysis/managed/unity-il2cpp.js";
import { analyzeGodotPck } from "../analysis/managed/godot-pck.js";
import { analyzeNativeBinary } from "../analysis/native/binary-format.js";
import { disassembleTarget } from "../analysis/native/disassembly-bridge.js";
import { decompileTarget } from "../analysis/native/decompiler-bridge.js";
import { extractBinaryStrings } from "../analysis/native/strings-analyzer.js";
import { analyzeApk } from "../analysis/mobile/apk-analyzer.js";
import { decodeBinaryManifest } from "../analysis/mobile/manifest-decoder.js";
import { analyzePackage } from "../analysis/packages/package-analyzer.js";
import { analyzeFirmware } from "../analysis/firmware/firmware-analyzer.js";
import { analyzeHarCapture } from "../analysis/network/har-analyzer.js";
import { analyzeCoreDump } from "../analysis/diagnostics/crash-analyzer.js";
import { analyzeWasmModule } from "../analysis/wasm/wasm-analyzer.js";
import { analyzeEvmBytecode } from "../analysis/evm/evm-analyzer.js";
import { runMcpServer } from "../mcp/server.js";

const program = new Command();

program
  .name("ri")
  .description(
    chalk.cyan(
      "Reverse IT — Universal multi-domain reverse-engineering CLI & MCP server"
    )
  )
  .version("1.0.0");

// Command: inspect-package (.deb, .rpm, .pkg, .msi, NSIS/Inno .exe, macOS .app)
program
  .command("inspect-package <target>")
  .description("Inspect application installer or package (.deb, .rpm, .pkg, .msi, NSIS/Inno .exe, macOS .app)")
  .option("--json", "Output raw JSON evidence")
  .action(async (target: string, options: { json?: boolean }) => {
    const spinner = options.json ? null : ora(`Inspecting package: ${chalk.bold(target)}...`).start();
    const result = await analyzePackage(target);
    if (!result.ok) {
      if (spinner) spinner.fail(chalk.red(result.error.message));
      else console.error(JSON.stringify(result.error, null, 2));
      process.exit(1);
    }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    spinner?.succeed(chalk.green("Package parsed successfully!"));
    const p = result.value;
    console.log();
    console.log(chalk.bold.cyan("=== REVERSE IT: APPLICATION PACKAGE ==="));
    console.log(`Package Type : ${chalk.yellow(p.packageType.toUpperCase())}`);
    if (p.packageName) console.log(`Name         : ${chalk.green(p.packageName)}`);
    if (p.installerType) console.log(`Installer    : ${chalk.magenta(p.installerType)}`);
    if (p.version) console.log(`Version      : ${chalk.cyan(p.version)}`);
    if (p.entries.length > 0) {
      console.log(`\nDiscovered Contained Archives / Files (${p.entries.length}):`);
      for (const entry of p.entries.slice(0, 15)) {
        console.log(`  • ${chalk.white(entry.name)} ${entry.sizeBytes > 0 ? chalk.gray(`(${entry.sizeBytes} bytes)`) : ""}`);
      }
    }
  });

// Command: decompile
program
  .command("decompile <file>")
  .description("Decompile binary routine into C pseudocode using Ghidra or Rizin")
  .option("--function <name>", "Specific function routine")
  .option("--provider <name>", "Decompiler engine: ghidra, rizin, ida (default: auto)")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { function?: string; provider?: string; json?: boolean }) => {
    const spinner = options.json ? null : ora(`Decompiling ${chalk.bold(file)}...`).start();
    const result = await decompileTarget(file, { functionName: options.function, provider: options.provider as any });
    if (!result.ok) {
      if (spinner) spinner.fail(chalk.red(result.error.message));
      else console.error(JSON.stringify(result.error, null, 2));
      process.exit(1);
    }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    spinner?.succeed(chalk.green(`Decompilation completed via ${result.value.providerUsed}!`));
    console.log();
    console.log(chalk.bold.cyan("=== REVERSE IT: PSEUDOCODE ==="));
    console.log(result.value.pseudocode);
  });

// Command: inspect-unity
program
  .command("inspect-unity <file>")
  .description("Inspect Unity global-metadata.dat (IL2CPP) method and type tables")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeUnityMetadata(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: UNITY IL2CPP METADATA ==="));
    console.log(`Version: ${result.value.version} | Types: ${result.value.typeDefinitionsCount} | Methods: ${result.value.methodDefinitionsCount}`);
  });

// Command: inspect-pck
program
  .command("inspect-pck <file>")
  .description("Inspect Godot Engine .pck package archive")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeGodotPck(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: GODOT PCK ==="));
    console.log(`Format: ${result.value.formatVersion} | Engine: ${result.value.engineVersion}`);
  });

// All commands: analyze, inspect-native, disassemble, strings, inspect-apk, inspect-manifest, inspect-firmware, inspect-wasm, inspect-evm, inspect-model, inspect-dotnet, inspect-har, inspect-crash, sourcemap, mcp
program
  .command("analyze <path>")
  .description("Analyze an extracted JavaScript, Electron, or web application directory")
  .option("--json", "Output raw JSON evidence")
  .action(async (targetPath: string, options: { json?: boolean }) => {
    const result = await analyzeApplication({ targetPath });
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: APPLICATION SUMMARY ==="));
    console.log(`Path: ${result.value.targetPath} | Modules: ${result.value.analyzedFiles}`);
  });

program
  .command("inspect-native <file>")
  .description("Inspect native binary (ELF, Mach-O, PE) headers and architecture")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeNativeBinary(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: NATIVE BINARY ==="));
    console.log(`Format: ${result.value.format.toUpperCase()} (${result.value.architecture}, ${result.value.bitness}-bit)`);
  });

program
  .command("disassemble <file>")
  .description("Disassemble binary routine using host objdump without execution")
  .option("--function <name>", "Specific function routine")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { function?: string; json?: boolean }) => {
    const result = await disassembleTarget(file, { functionName: options.function });
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: DISASSEMBLY ==="));
    for (const fn of result.value.functions) {
      console.log(chalk.yellow(`<${fn.name}> (${fn.address}):`));
      for (const ins of fn.instructions.slice(0, 20)) {
        console.log(`  ${chalk.gray(ins.address)}  ${chalk.cyan(ins.mnemonic.padEnd(8))} ${ins.operands}`);
      }
    }
  });

program
  .command("strings <file>")
  .description("Extract and classify URLs, IPs, file paths, and ASCII/UTF-8 strings")
  .option("--min-length <n>", "Minimum string length", "4")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { minLength: string; json?: boolean }) => {
    const result = await extractBinaryStrings(file, { minLength: parseInt(options.minLength, 10) });
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: EXTRACTED STRINGS ==="));
    for (const s of result.value.interestingStrings.slice(0, 25)) {
      console.log(`[${chalk.magenta(s.classification ?? "str")}] ${chalk.green(s.value)}`);
    }
  });

program
  .command("inspect-apk <file>")
  .description("Inspect Android APK package for Dex files, native ABIs, and manifest")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeApk(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: ANDROID APK ==="));
    console.log(`DEX Files: ${result.value.dexFiles.length} | ABIs: ${Object.keys(result.value.nativeLibraries).join(", ") || "none"}`);
  });

program
  .command("inspect-manifest <axmlFile>")
  .description("Decode binary AndroidManifest.xml string pool (permissions, activities)")
  .option("--json", "Output raw JSON evidence")
  .action(async (axmlFile: string, options: { json?: boolean }) => {
    const buf = await fs.readFile(axmlFile);
    const result = decodeBinaryManifest(buf);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: DECODED MANIFEST ==="));
    console.log(`Permissions: ${result.value.permissions.length} | Activities: ${result.value.activities.length}`);
  });

program
  .command("inspect-wasm <file>")
  .description("Inspect WebAssembly (.wasm) sections, imports, and exports")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeWasmModule(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: WEBASSEMBLY (WASM) ==="));
    console.log(`Version: ${result.value.version} | Exports: ${result.value.exports.length}`);
  });

program
  .command("inspect-evm <bytecode>")
  .description("Recover 4-byte function dispatch selectors from EVM runtime bytecode")
  .option("--json", "Output raw JSON evidence")
  .action((bytecode: string, options: { json?: boolean }) => {
    const result = analyzeEvmBytecode(bytecode);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: EVM DISPATCH SELECTORS ==="));
    console.log(`Selectors: ${result.value.totalSelectors}`);
  });

program
  .command("inspect-firmware <file>")
  .description("Scan firmware binary image for partitions (SquashFS, U-Boot, DeviceTree, XZ)")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeFirmware(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: FIRMWARE PARTITIONS ==="));
    for (const sig of result.value.signatures) {
      console.log(`  • 0x${sig.offset.toString(16).padEnd(8)} [${chalk.yellow(sig.type)}] ${sig.description}`);
    }
  });

program
  .command("inspect-har <file>")
  .description("Inspect HTTP Archive (.har) capture for endpoints and auth headers")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeHarCapture(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: HAR CAPTURE ==="));
    console.log(`Total Requests: ${result.value.totalRequests}`);
  });

program
  .command("inspect-crash <file>")
  .description("Inspect Linux ELF core dump for crash architecture and program segments")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeCoreDump(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: CORE DUMP ==="));
    console.log(`Architecture: ${result.value.architecture} (${result.value.bitness}-bit)`);
  });

program
  .command("inspect-model <file>")
  .description("Inspect AI model artifact (GGUF / Safetensors) metadata and tensors")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeModelArtifact(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: MODEL ARTIFACT ==="));
    console.log(`Format: ${result.value.format} | Tensors: ${result.value.tensorCount}`);
  });

program
  .command("inspect-dotnet <file>")
  .description("Inspect .NET PE Assembly for CIL headers and target framework")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeDotNetAssembly(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: .NET ASSEMBLY ==="));
    console.log(`Managed CIL: ${result.value.isManagedAssembly} | Machine: ${result.value.peMachine}`);
  });

program
  .command("sourcemap <file>")
  .description("Inspect and unpack source map for a JavaScript file")
  .option("--json", "Output raw JSON evidence")
  .action(async (file: string, options: { json?: boolean }) => {
    const result = await analyzeSourceMap(file);
    if (!result.ok) { console.error(chalk.red(result.error.message)); process.exit(1); }
    if (options.json) { console.log(JSON.stringify(result.value, null, 2)); return; }
    console.log(chalk.bold.cyan("=== REVERSE IT: SOURCE MAP RECOVERY ==="));
    console.log(`Recovered Files: ${result.value.originalSourcesCount}`);
  });

program
  .command("mcp")
  .description("Start the Reverse IT Model Context Protocol (MCP) server over stdio")
  .action(async () => {
    await runMcpServer();
  });

program.parse(process.argv);
