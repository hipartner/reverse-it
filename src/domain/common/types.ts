// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/domain/common/types.ts
// Description : Core domain types, evidence contracts and result algebra.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

/**
 * Tagged result type — every operation returns either a success with
 * evidence or a structured failure with a meaningful reason.
 */
export type Result<T, E = AnalysisError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };

export function success<T>(value: T): Result<T, never> {
  return { ok: true, value };
}

export function failure<E>(error: E): Result<never, E> {
  return { ok: false, error };
}

/** Categories of analysis failure. */
export type AnalysisErrorKind =
  | "parse_error"
  | "file_not_found"
  | "unsupported_format"
  | "timeout"
  | "capacity_exceeded"
  | "permission_denied"
  | "internal";

export interface AnalysisError {
  readonly kind: AnalysisErrorKind;
  readonly message: string;
  readonly path?: string;
  readonly cause?: unknown;
}

/**
 * Evidence — provenance tracking for every fact Reverse IT reports.
 * Each piece of evidence records what was observed, how it was derived,
 * and its known limitations.
 */
export interface Evidence {
  /** What kind of fact this is. */
  readonly classification: "observation" | "derivation" | "inference";
  /** Human-readable description of the fact. */
  readonly summary: string;
  /** Source file or location where this was observed. */
  readonly source?: EvidenceSource;
  /** Known limitations or caveats. */
  readonly limitations?: string[];
}

export interface EvidenceSource {
  readonly path: string;
  readonly line?: number;
  readonly column?: number;
}

/** File identity for analysis targets. */
export interface FileIdentity {
  readonly absolutePath: string;
  readonly relativePath: string;
  readonly sizeBytes: number;
  readonly sha256?: string;
}

/** Module classification within a JavaScript application. */
export type ModuleKind =
  | "esm"
  | "commonjs"
  | "json"
  | "css"
  | "asset"
  | "unknown";

/** An import relationship between two modules. */
export interface ImportRelationship {
  readonly source: string;
  readonly target: string;
  readonly specifier: string;
  readonly kind: "static" | "dynamic" | "require" | "reexport";
  readonly evidence: Evidence;
}

/** An export from a module. */
export interface ModuleExport {
  readonly name: string;
  readonly kind: "named" | "default" | "namespace" | "reexport";
  readonly line?: number;
  readonly evidence: Evidence;
}

/** Summary of a discovered JavaScript module. */
export interface ModuleInfo {
  readonly identity: FileIdentity;
  readonly kind: ModuleKind;
  readonly imports: ImportRelationship[];
  readonly exports: ModuleExport[];
  readonly evidence: Evidence;
}

/** Top-level analysis result for a JavaScript application. */
export interface ApplicationAnalysis {
  readonly targetPath: string;
  readonly modules: ModuleInfo[];
  readonly entryPoints: string[];
  readonly framework?: FrameworkDetection;
  readonly electron?: ElectronAnalysis;
  readonly sourceMapCount: number;
  readonly totalFiles: number;
  readonly analyzedFiles: number;
  readonly evidence: Evidence;
}

export interface FrameworkDetection {
  readonly name: string;
  readonly version?: string;
  readonly evidence: Evidence;
}

export interface ElectronAnalysis {
  readonly mainProcess?: string;
  readonly preloadScripts: string[];
  readonly ipcChannels: IpcChannel[];
  readonly browserWindows: BrowserWindowInfo[];
  readonly evidence: Evidence;
}

export interface IpcChannel {
  readonly name: string;
  readonly direction: "main-to-renderer" | "renderer-to-main" | "bidirectional";
  readonly handler?: string;
  readonly evidence: Evidence;
}

export interface BrowserWindowInfo {
  readonly createdIn: string;
  readonly line?: number;
  readonly preload?: string;
  readonly evidence: Evidence;
}
