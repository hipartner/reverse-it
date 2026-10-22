# Reverse IT (`ri-agents`)

> **The Unified Reverse-Engineering CLI & Model Context Protocol (MCP) Suite across Native Binaries, Mobile, JavaScript, AI Models, and Network Captures.**

[![Author: R Kiran Kumar](https://img.shields.io/badge/Author-R%20Kiran%20Kumar-blue.svg)](https://sadafiles.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Website: Sada Files](https://img.shields.io/badge/Website-sadafiles.com-cyan.svg)](https://sadafiles.com/)
[![Repository: GitHub](https://img.shields.io/badge/GitHub-hipartner%2Freverse--it-purple.svg)](https://github.com/hipartner/reverse-it)

---

## ⚡ What is Reverse IT?

**Reverse IT** (`ri-agents`) is a ground-up, fail-closed reverse-engineering toolkit and MCP server designed by **R Kiran Kumar** (Fullstack Developer & System Engineer) under **ChronoSpark Solutions**.

It bridges terminal workflows and AI coding agents (Claude Code, Cursor, Codex, Gemini CLI) to inspect compiled binaries, application bundles, and network captures **without source code** and **without launching untrusted targets**.

---

## 🛠️ Complete Feature Matrix

| Target Domain | Analyzers Included | Supported Formats | CLI Command |
| :--- | :--- | :--- | :--- |
| **JavaScript / Web** | Acorn AST parser, ESM/CJS imports/exports | `.js`, `.mjs`, `.cjs`, `.ts`, `.json` | `ri analyze <dir>` |
| **Electron Apps** | IPC channels, `BrowserWindow` preloads | Extracted directories & `.asar` | `ri analyze <dir>` |
| **Source Maps** | Inline Base64 & external maps unpacker | `.map`, inline mappings | `ri sourcemap <file>` |
| **Native Binaries** | ELF, Mach-O, PE headers & section maps | Executables, `.so`, `.dylib`, `.dll` | `ri inspect-native <file>` |
| **Disassembly** | Static function disassembler (objdump bridge) | ELF/PE/Mach-O text sections | `ri disassemble <file>` |
| **String Extraction** | Classified strings (URLs, IPs, paths, GUIDs) | Any binary target | `ri strings <file>` |
| **AI Models** | GGUF & Safetensors header/tensor parser | `.gguf`, `.safetensors` | `ri inspect-model <file>` |
| **Managed Assemblies** | .NET PE/CLI headers, `BSJB` metadata | `.dll`, `.exe` | `ri inspect-dotnet <file>` |
| **Game Engines** | Unity IL2CPP & Godot PCK unpacker | `global-metadata.dat`, `.pck` | `ri inspect-unity` / `inspect-pck` |
| **Mobile** | Android APK anatomy, Dex files, native ABIs | `.apk` packages | `ri inspect-apk <file>` |
| **Firmware** | SquashFS, U-Boot, DeviceTree, XZ partitions | Raw binary firmware ROMs | `ri inspect-firmware <file>` |
| **Network Captures** | HTTP Archive requests, responses, auth headers | `.har` captures | `ri inspect-har <file>` |
| **Linux Diagnostics** | ELF core dump crash context & segments | `core`, `core.*` dumps | `ri inspect-crash <file>` |

---

## 🚀 CLI Usage

```bash
# Analyze JavaScript / Electron app
npx -y ri-agents analyze /path/to/app

# Inspect native ELF/PE/Mach-O binary
npx -y ri-agents inspect-native /bin/ls

# Disassemble a specific function
npx -y ri-agents disassemble /bin/ls --function main

# Extract URLs and IPs from a binary
npx -y ri-agents strings /path/to/binary --min-length 6

# Inspect AI model metadata without loading weights
npx -y ri-agents inspect-model /models/llama-3-8b.gguf

# Inspect Android APK
npx -y ri-agents inspect-apk /path/to/app.apk

# Output machine-readable JSON for any command:
npx -y ri-agents inspect-native /bin/ls --json
```

---

## 🤖 Connect to AI Coding Agents (MCP)

Add Reverse IT to your agent's MCP configuration file (Claude Code, Cursor, Claude Desktop):

```json
{
  "mcpServers": {
    "reverse-it": {
      "command": "npx",
      "args": ["-y", "ri-agents", "mcp"]
    }
  }
}
```

Reverse IT exposes 11 native MCP tools over stdio:
- `analyze_javascript_application`
- `inspect_sourcemap`
- `inspect_native_binary`
- `disassemble_target`
- `extract_binary_strings`
- `inspect_model_artifact`
- `inspect_managed_artifact`
- `analyze_apk`
- `analyze_firmware`
- `analyze_har_capture`
- `analyze_core_dump`

---

## 📜 Author & License

* **Author**: **R Kiran Kumar** (Fullstack Developer & System Engineer)
* **Organization**: **ChronoSpark Solutions — Where Time Meets Technology**
* **Website**: [https://sadafiles.com/](https://sadafiles.com/)
* **Repository**: [https://github.com/hipartner/reverse-it](https://github.com/hipartner/reverse-it)
* **License**: [MIT License](LICENSE)
