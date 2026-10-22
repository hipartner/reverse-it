// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/packages/package-analyzer.ts
// Description : Universal application package & installer inspector.
//               Supports .deb, .rpm, .pkg, macOS .app, Windows .msi/.exe installers
//               (NSIS, Inno Setup), AppImage, and PyInstaller executables.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import * as path from "node:path";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export type PackageKind =
  | "deb"
  | "rpm"
  | "pkg"
  | "macos-app"
  | "msi"
  | "nsis-installer"
  | "inno-setup"
  | "pyinstaller"
  | "appimage"
  | "unknown";

export interface PackageEntry {
  readonly name: string;
  readonly sizeBytes: number;
}

export interface UniversalPackageAnalysis {
  readonly targetPath: string;
  readonly packageType: PackageKind;
  readonly packageName?: string;
  readonly version?: string;
  readonly architecture?: string;
  readonly installerType?: string;
  readonly entries: PackageEntry[];
  readonly totalEntries: number;
  readonly metadata: Record<string, string>;
  readonly evidence: Evidence;
}

/** Universal application package inspection for .deb, .exe installers, .msi, .pkg, .app, and more. */
export async function analyzePackage(targetPath: string): Promise<Result<UniversalPackageAnalysis>> {
  const resolved = path.resolve(targetPath);
  try {
    const stat = await fs.stat(resolved);

    // 1. Check if directory is a macOS .app bundle
    if (stat.isDirectory()) {
      if (resolved.endsWith(".app") || (await fileExists(path.join(resolved, "Contents", "Info.plist")))) {
        return await parseMacOsAppBundle(resolved);
      }
      return failure({
        kind: "unsupported_format",
        message: "Target is a regular directory. Use 'ri analyze <dir>' for web/Electron apps.",
        path: resolved,
      });
    }

    const handle = await fs.open(resolved, "r");
    const header = Buffer.alloc(Math.min(stat.size, 4 * 1024 * 1024));
    const { bytesRead } = await handle.read(header, 0, header.length, 0);
    await handle.close();

    if (bytesRead < 8) {
      return failure({
        kind: "unsupported_format",
        message: "File is too small to be an application package.",
        path: resolved,
      });
    }

    // 2. Check Debian (.deb) package: AR Archive magic "!<arch>\n"
    if (header.subarray(0, 8).toString("ascii") === "!<arch>\n") {
      return parseDebPackage(resolved, header, stat.size);
    }

    // 3. Check Red Hat (.rpm) package: magic 0xedabeedb
    if (header.readUInt32BE(0) === 0xedabeedb) {
      return parseRpmPackage(resolved, header);
    }

    // 4. Check macOS / iOS .pkg package: XAR Archive magic "xar!" = 0x78617221
    if (header.subarray(0, 4).toString("ascii") === "xar!") {
      return parseXarPkg(resolved, header);
    }

    // 5. Check Microsoft Installer (.msi): OLE2 Compound File (0xd0cf11e0a1b11ae1)
    if (
      header[0] === 0xd0 &&
      header[1] === 0xcf &&
      header[2] === 0x11 &&
      header[3] === 0xe0 &&
      header[4] === 0xa1 &&
      header[5] === 0xb1 &&
      header[6] === 0x1a &&
      header[7] === 0xe1
    ) {
      return parseMsiPackage(resolved);
    }

    // 6. Check Windows PE Installers & PyInstaller (.exe)
    if (header[0] === 0x4d && header[1] === 0x5a) {
      return scanExeInstallerSignatures(resolved, header, stat.size);
    }

    return failure({
      kind: "unsupported_format",
      message: `File '${resolved}' is not a recognized installer/package format (.deb, .rpm, .pkg, .msi, NSIS/Inno .exe).`,
      path: resolved,
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze application package: ${String(err)}`,
      path: resolved,
      cause: err,
    });
  }
}

/** Debian .deb parser */
function parseDebPackage(filePath: string, buffer: Buffer, fileSize: number): Result<UniversalPackageAnalysis> {
  const entries: PackageEntry[] = [];
  let offset = 8; // skip "!<arch>\n"

  while (offset < buffer.length - 60) {
    const filename = buffer.toString("ascii", offset, offset + 16).trim().replace(/\/$/, "");
    const sizeStr = buffer.toString("ascii", offset + 48, offset + 58).trim();
    const entrySize = parseInt(sizeStr, 10);

    if (filename.length > 0) {
      entries.push({ name: filename, sizeBytes: entrySize || 0 });
    }

    offset += 60 + (entrySize || 0);
    if (offset % 2 !== 0) offset++; // AR 2-byte alignment
  }

  return success({
    targetPath: filePath,
    packageType: "deb",
    packageName: path.basename(filePath, ".deb"),
    entries,
    totalEntries: entries.length,
    metadata: { container: "GNU AR archive", totalSizeBytes: String(fileSize) },
    evidence: {
      classification: "observation",
      summary: `Parsed Debian package (.deb) containing ${entries.map((e) => e.name).join(", ")}`,
      source: { path: filePath },
    },
  });
}

/** RedHat .rpm parser */
function parseRpmPackage(filePath: string, buffer: Buffer): Result<UniversalPackageAnalysis> {
  const major = buffer[4];
  const minor = buffer[5];
  const type = buffer.readUInt16BE(6) === 0 ? "binary" : "source";

  return success({
    targetPath: filePath,
    packageType: "rpm",
    packageName: path.basename(filePath, ".rpm"),
    entries: [],
    totalEntries: 0,
    metadata: { rpmVersion: `${major}.${minor}`, rpmType: type },
    evidence: {
      classification: "observation",
      summary: `Identified RedHat RPM package v${major}.${minor} (${type})`,
      source: { path: filePath },
    },
  });
}

/** macOS / iOS .pkg parser */
function parseXarPkg(filePath: string, buffer: Buffer): Result<UniversalPackageAnalysis> {
  const headerSize = buffer.readUInt16BE(4);
  const version = buffer.readUInt16BE(6);

  return success({
    targetPath: filePath,
    packageType: "pkg",
    packageName: path.basename(filePath, ".pkg"),
    entries: [],
    totalEntries: 0,
    metadata: { format: "XAR archive", version: String(version), headerSize: String(headerSize) },
    evidence: {
      classification: "observation",
      summary: `Identified Apple XAR package (.pkg) v${version}`,
      source: { path: filePath },
    },
  });
}

/** Windows .msi parser */
function parseMsiPackage(filePath: string): Result<UniversalPackageAnalysis> {
  return success({
    targetPath: filePath,
    packageType: "msi",
    packageName: path.basename(filePath, ".msi"),
    entries: [],
    totalEntries: 0,
    metadata: { format: "OLE2 Structured Storage (Compound File)" },
    evidence: {
      classification: "observation",
      summary: "Identified Windows Microsoft Installer (MSI) database",
      source: { path: filePath },
    },
  });
}

/** Windows .exe installer signature scanner (NSIS, Inno Setup, PyInstaller) */
function scanExeInstallerSignatures(filePath: string, buffer: Buffer, fileSize: number): Result<UniversalPackageAnalysis> {
  const text = buffer.toString("latin1");

  // 1. Check NSIS: "NullsoftInst" signature
  if (text.includes("NullsoftInst")) {
    return success({
      targetPath: filePath,
      packageType: "nsis-installer",
      installerType: "Nullsoft Scriptable Install System (NSIS)",
      packageName: path.basename(filePath),
      entries: [],
      totalEntries: 0,
      metadata: { installer: "NSIS", selfExtracting: "true", totalBytes: String(fileSize) },
      evidence: {
        classification: "observation",
        summary: "Identified NSIS (Nullsoft) self-extracting Windows installer executable",
        source: { path: filePath },
      },
    });
  }

  // 2. Check Inno Setup: "Inno Setup Setup Data"
  if (text.includes("Inno Setup Setup Data") || text.includes("Inno Setup")) {
    return success({
      targetPath: filePath,
      packageType: "inno-setup",
      installerType: "Inno Setup",
      packageName: path.basename(filePath),
      entries: [],
      totalEntries: 0,
      metadata: { installer: "Inno Setup", totalBytes: String(fileSize) },
      evidence: {
        classification: "observation",
        summary: "Identified Inno Setup Windows installer executable",
        source: { path: filePath },
      },
    });
  }

  // 3. Check PyInstaller: "MEIPASS" or "pyi-runtime"
  if (text.includes("MEIPASS") || text.includes("pyi-runtime") || text.includes("pydata")) {
    return success({
      targetPath: filePath,
      packageType: "pyinstaller",
      installerType: "PyInstaller Embedded Python Executable",
      packageName: path.basename(filePath),
      entries: [],
      totalEntries: 0,
      metadata: { runtime: "PyInstaller CArchive", totalBytes: String(fileSize) },
      evidence: {
        classification: "observation",
        summary: "Identified PyInstaller self-extracting Python application executable",
        source: { path: filePath },
      },
    });
  }

  // Fallback: Standard Windows Executable
  return success({
    targetPath: filePath,
    packageType: "unknown",
    installerType: "Standard PE Executable",
    packageName: path.basename(filePath),
    entries: [],
    totalEntries: 0,
    metadata: { totalBytes: String(fileSize) },
    evidence: {
      classification: "observation",
      summary: "Native PE executable (no standard NSIS/Inno/PyInstaller wrapper signatures detected)",
      source: { path: filePath },
    },
  });
}

/** macOS .app bundle directory parser */
async function parseMacOsAppBundle(appPath: string): Promise<Result<UniversalPackageAnalysis>> {
  const infoPlistPath = path.join(appPath, "Contents", "Info.plist");
  const metadata: Record<string, string> = {};

  try {
    const plistContent = await fs.readFile(infoPlistPath, "utf8");
    const getVal = (key: string) => {
      const match = plistContent.match(new RegExp(`<key>${key}<\\/key>\\s*<string>([^<]+)<\\/string>`));
      return match ? match[1] : undefined;
    };

    const bundleId = getVal("CFBundleIdentifier");
    const bundleName = getVal("CFBundleName") || path.basename(appPath, ".app");
    const bundleVersion = getVal("CFBundleShortVersionString") || getVal("CFBundleVersion");
    const executable = getVal("CFBundleExecutable");

    if (bundleId) metadata.bundleId = bundleId;
    if (executable) metadata.executable = executable;
    if (bundleVersion) metadata.version = bundleVersion;

    return success({
      targetPath: appPath,
      packageType: "macos-app",
      packageName: bundleName,
      version: bundleVersion,
      entries: executable ? [{ name: `Contents/MacOS/${executable}`, sizeBytes: 0 }] : [],
      totalEntries: 1,
      metadata,
      evidence: {
        classification: "observation",
        summary: `Parsed macOS application bundle '${bundleName}' (ID: ${bundleId ?? "none"}, Executable: ${executable ?? "none"})`,
        source: { path: infoPlistPath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to inspect macOS .app Info.plist: ${String(err)}`,
      path: appPath,
      cause: err,
    });
  }
}

async function fileExists(p: string): Promise<boolean> {
  try {
    await fs.access(p);
    return true;
  } catch {
    return false;
  }
}
