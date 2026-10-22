// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/parser/javascript-parser.ts
// Description : JavaScript/TypeScript AST parser using Acorn. Extracts
//               imports, exports, require() calls, and module metadata.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as acorn from "acorn";
import * as walk from "acorn-walk";
import type {
  ImportRelationship,
  ModuleExport,
  ModuleKind,
  Evidence,
  Result,
} from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

/** Options for parsing a single JavaScript file. */
export interface ParseOptions {
  readonly filePath: string;
  readonly source: string;
  readonly isModule?: boolean;
}

/** Result of parsing a single JavaScript file. */
export interface ParseResult {
  readonly kind: ModuleKind;
  readonly imports: ImportRelationship[];
  readonly exports: ModuleExport[];
  readonly hasJsx: boolean;
  readonly evidence: Evidence;
}

/**
 * Parse a JavaScript source file and extract its module graph edges.
 * Uses Acorn for standards-compliant ECMAScript parsing. Does NOT execute
 * the target code — all analysis is purely static.
 */
export function parseJavaScriptFile(
  options: ParseOptions
): Result<ParseResult> {
  const { filePath, source } = options;

  try {
    const isModule = options.isModule ?? detectModuleKind(source);
    const ast = acorn.parse(source, {
      ecmaVersion: "latest",
      sourceType: isModule ? "module" : "script",
      locations: true,
      allowReturnOutsideFunction: !isModule,
      allowImportExportEverywhere: false,
    });

    const imports: ImportRelationship[] = [];
    const exports: ModuleExport[] = [];
    let hasJsx = false;

    // Walk the AST to collect import/export declarations and require() calls.
    walk.simple(ast, {
      ImportDeclaration(node: acorn.ImportDeclaration) {
        const specifier = (node.source as acorn.Literal).value as string;
        imports.push({
          source: filePath,
          target: specifier,
          specifier,
          kind: "static",
          evidence: {
            classification: "observation",
            summary: `Static ESM import of '${specifier}'`,
            source: {
              path: filePath,
              line: node.loc?.start.line,
              column: node.loc?.start.column,
            },
          },
        });
      },

      ImportExpression(node: acorn.ImportExpression) {
        if (node.source.type === "Literal") {
          const specifier = (node.source as acorn.Literal).value as string;
          imports.push({
            source: filePath,
            target: specifier,
            specifier,
            kind: "dynamic",
            evidence: {
              classification: "observation",
              summary: `Dynamic import() of '${specifier}'`,
              source: {
                path: filePath,
                line: node.loc?.start.line,
                column: node.loc?.start.column,
              },
            },
          });
        }
      },

      CallExpression(node: acorn.CallExpression) {
        // Detect require('...') calls for CommonJS modules.
        if (
          node.callee.type === "Identifier" &&
          (node.callee as acorn.Identifier).name === "require" &&
          node.arguments.length === 1 &&
          node.arguments[0].type === "Literal"
        ) {
          const specifier = (node.arguments[0] as acorn.Literal)
            .value as string;
          imports.push({
            source: filePath,
            target: specifier,
            specifier,
            kind: "require",
            evidence: {
              classification: "observation",
              summary: `CommonJS require() of '${specifier}'`,
              source: {
                path: filePath,
                line: node.loc?.start.line,
                column: node.loc?.start.column,
              },
            },
          });
        }
      },

      ExportNamedDeclaration(node: acorn.ExportNamedDeclaration) {
        if (node.source) {
          // Re-export: export { foo } from 'bar'
          const specifier = (node.source as acorn.Literal).value as string;
          imports.push({
            source: filePath,
            target: specifier,
            specifier,
            kind: "reexport",
            evidence: {
              classification: "observation",
              summary: `Re-export from '${specifier}'`,
              source: {
                path: filePath,
                line: node.loc?.start.line,
              },
            },
          });
        }

        for (const spec of node.specifiers) {
          exports.push({
            name:
              spec.exported.type === "Identifier"
                ? spec.exported.name
                : (spec.exported as acorn.Literal).value as string,
            kind: "named",
            line: spec.loc?.start.line,
            evidence: {
              classification: "observation",
              summary: `Named export '${spec.exported.type === "Identifier" ? spec.exported.name : (spec.exported as acorn.Literal).value}'`,
              source: { path: filePath, line: spec.loc?.start.line },
            },
          });
        }

        if (node.declaration) {
          const names = extractDeclarationNames(node.declaration);
          for (const name of names) {
            exports.push({
              name,
              kind: "named",
              line: node.loc?.start.line,
              evidence: {
                classification: "observation",
                summary: `Named export declaration '${name}'`,
                source: { path: filePath, line: node.loc?.start.line },
              },
            });
          }
        }
      },

      ExportDefaultDeclaration(node: acorn.ExportDefaultDeclaration) {
        exports.push({
          name: "default",
          kind: "default",
          line: node.loc?.start.line,
          evidence: {
            classification: "observation",
            summary: "Default export",
            source: { path: filePath, line: node.loc?.start.line },
          },
        });
      },

      ExportAllDeclaration(node: acorn.ExportAllDeclaration) {
        const specifier = (node.source as acorn.Literal).value as string;
        imports.push({
          source: filePath,
          target: specifier,
          specifier,
          kind: "reexport",
          evidence: {
            classification: "observation",
            summary: `Namespace re-export from '${specifier}'`,
            source: { path: filePath, line: node.loc?.start.line },
          },
        });
        exports.push({
          name: "*",
          kind: "namespace",
          line: node.loc?.start.line,
          evidence: {
            classification: "observation",
            summary: `Namespace re-export from '${specifier}'`,
            source: { path: filePath, line: node.loc?.start.line },
          },
        });
      },
    });

    // Detect JSX by scanning for <-prefixed identifiers in unrecognized tokens.
    if (source.includes("React") || source.includes("jsx")) {
      hasJsx = true;
    }

    const kind: ModuleKind = isModule ? "esm" : "commonjs";

    return success({
      kind,
      imports,
      exports,
      hasJsx,
      evidence: {
        classification: "observation",
        summary: `Parsed ${filePath} as ${kind} with ${imports.length} imports and ${exports.length} exports`,
        source: { path: filePath },
        limitations: [
          "Static analysis only — dynamic require() with variables are not resolved",
          "TypeScript type-only imports are not distinguished from value imports",
        ],
      },
    });
  } catch (err) {
    if (err instanceof SyntaxError) {
      return failure({
        kind: "parse_error" as const,
        message: `Syntax error in ${filePath}: ${err.message}`,
        path: filePath,
        cause: err,
      });
    }
    return failure({
      kind: "internal" as const,
      message: `Unexpected error parsing ${filePath}: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  }
}

/** Heuristic: does the source look like an ES module? */
function detectModuleKind(source: string): boolean {
  return (
    /\b(import|export)\s/.test(source) &&
    !/\bmodule\.exports\b/.test(source)
  );
}

/** Extract declared names from a declaration node. */
function extractDeclarationNames(node: acorn.Declaration): string[] {
  const names: string[] = [];
  if (node.type === "FunctionDeclaration" || node.type === "ClassDeclaration") {
    if (node.id) names.push(node.id.name);
  } else if (node.type === "VariableDeclaration") {
    for (const decl of node.declarations) {
      if (decl.id.type === "Identifier") {
        names.push(decl.id.name);
      }
    }
  }
  return names;
}
