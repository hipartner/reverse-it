// ============================================================================
// ChronoSpark Solutions — Where Time Meets Technology
// © 2026 ChronoSparkSolutions. All rights reserved.
//
// Project     : Reverse IT
// File        : src/analysis/network/har-analyzer.ts
// Description : HTTP Archive (.har) capture inspection. Identifies API endpoints,
//               sensitive authorization headers, response codes and timings.
// Author      : R Kiran Kumar — Fullstack Developer & System Engineer
// Website     : https://sadafiles.com/
// Repository  : https://github.com/hipartner/reverse-it
// ============================================================================

import * as fs from "node:fs/promises";
import type { Evidence, Result } from "../../domain/common/types.js";
import { success, failure } from "../../domain/common/types.js";

export interface HarRequestSummary {
  readonly method: string;
  readonly url: string;
  readonly status: number;
  readonly mimeType?: string;
  readonly hasAuthHeader: boolean;
  readonly responseBytes?: number;
}

export interface HarAnalysis {
  readonly filePath: string;
  readonly creator?: string;
  readonly totalRequests: number;
  readonly requests: HarRequestSummary[];
  readonly uniqueDomains: string[];
  readonly evidence: Evidence;
}

/** Analyze a captured HTTP Archive (.har) JSON file without exposing secrets. */
export async function analyzeHarCapture(filePath: string): Promise<Result<HarAnalysis>> {
  try {
    const rawContent = await fs.readFile(filePath, "utf8");
    const har = JSON.parse(rawContent);

    if (!har.log || !Array.isArray(har.log.entries)) {
      return failure({
        kind: "unsupported_format",
        message: "Not a valid HAR format (missing log.entries array).",
        path: filePath,
      });
    }

    const creator = har.log.creator?.name ? `${har.log.creator.name} ${har.log.creator.version ?? ""}`.trim() : undefined;
    const entries = har.log.entries;
    const requests: HarRequestSummary[] = [];
    const domains = new Set<string>();

    for (const entry of entries) {
      const req = entry.request;
      const res = entry.response;
      if (!req) continue;

      const urlStr = req.url || "";
      try {
        const parsedUrl = new URL(urlStr);
        domains.add(parsedUrl.hostname);
      } catch {
        // Continue
      }

      const hasAuth = Array.isArray(req.headers)
        ? req.headers.some((h: { name?: string }) =>
            h.name && /^(authorization|x-api-key|token|bearer)$/i.test(h.name)
          )
        : false;

      requests.push({
        method: req.method || "GET",
        url: urlStr,
        status: res?.status || 0,
        mimeType: res?.content?.mimeType,
        hasAuthHeader: hasAuth,
        responseBytes: res?.bodySize ?? res?.content?.size,
      });
    }

    return success({
      filePath,
      creator,
      totalRequests: requests.length,
      requests: requests.slice(0, 100), // First 100 entries for summary
      uniqueDomains: Array.from(domains),
      evidence: {
        classification: "observation",
        summary: `Parsed HAR capture with ${requests.length} requests across ${domains.size} domains`,
        source: { path: filePath },
      },
    });
  } catch (err) {
    return failure({
      kind: "internal",
      message: `Failed to analyze HAR file: ${String(err)}`,
      path: filePath,
      cause: err,
    });
  }
}
