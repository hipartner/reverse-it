# Reverse IT (`ri-agents`)

> **Reverse Engineer Anything across JavaScript, Electron, and Web Applications with your Terminal and AI Coding Agents.**

[![Author: R Kiran Kumar](https://img.shields.io/badge/Author-R%20Kiran%20Kumar-blue.svg)](https://sadafiles.com/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Website: Sada Files](https://img.shields.io/badge/Website-sadafiles.com-cyan.svg)](https://sadafiles.com/)
[![Repository: GitHub](https://img.shields.io/badge/GitHub-hipartner%2Freverse--it-purple.svg)](https://github.com/hipartner/reverse-it)

---

## Overview

**Reverse IT** (packaged on npm as `ri-agents` with CLI command `ri`) is an advanced static analysis and reverse-engineering suite created by **R Kiran Kumar** (Fullstack Developer & System Engineer) under **ChronoSpark Solutions**.

It provides:
- **Terminal CLI (`ri` / `reverse-it`)**: Rapid inspection of extracted JavaScript files, bundles, and Electron apps.
- **Model Context Protocol (MCP) Server**: Seamless bridge allowing Claude Code, Cursor, Codex, Gemini CLI, and other agents to deconstruct applications and extract verified evidence.
- **Evidence-First Engine**: Complete provenance tracking distinguishing direct observations, derived facts, and explicit unknowns.

---

## Quick Start

### 1. Terminal CLI

Inspect any extracted application directory or bundle:

```bash
npx -y ri-agents analyze /path/to/app
```

Output machine-readable JSON evidence:

```bash
npx -y ri-agents analyze /path/to/app --json
```

Inspect and unpack source maps:

```bash
npx -y ri-agents sourcemap /path/to/bundle.js.map
```

### 2. Connect to your AI Agent (MCP)

Add Reverse IT to your MCP client configuration (such as Claude Desktop, Cursor, or Claude Code):

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

---

## Architecture & Capabilities

- **JavaScript / TypeScript Parsing**: Pure static ECMAScript analysis using Acorn. Zero runtime execution of untrusted target code.
- **Electron IPC Analysis**: Maps `ipcRenderer.send`, `ipcRenderer.invoke`, `ipcMain.on`, `ipcMain.handle`, and `BrowserWindow` preload scripts.
- **Source Map Extraction**: Discovers external and Base64-inlined source maps, extracting original file paths and unminified source code.
- **Module Dependency Trees**: Detects imports, exports, re-exports, and cyclic dependencies.

---

## Author & Copyright

- **Author**: **R Kiran Kumar** (Fullstack Developer & System Engineer)
- **Organization**: **ChronoSpark Solutions — Where Time Meets Technology**
- **Website**: [https://sadafiles.com/](https://sadafiles.com/)
- **Repository**: [https://github.com/hipartner/reverse-it](https://github.com/hipartner/reverse-it)
- **License**: [MIT License](LICENSE)
