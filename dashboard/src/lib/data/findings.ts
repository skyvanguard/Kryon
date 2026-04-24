import { DEMO_MODE } from "../config";
import { listFindings as apiListFindings } from "../api/kryon";
import { getFindings as mockFindings } from "../mocks/findings";
import type { Finding } from "../types";

/**
 * Data source for Finding records.
 *
 * Strategy: try the real backend first when configured; fall back to
 * deterministic mocks on any failure (no URL set, network error, 4xx/5xx,
 * timeout). The dashboard therefore renders *something credible* in every
 * scenario — a hard requirement for the BritImp demo where we cannot
 * guarantee the FastAPI service is running.
 *
 * Callers always get a `Finding[]` and a `source` flag they can surface
 * in the UI ("Conectado a Kryon backend" vs "Modo demo").
 */

export interface FindingsResult {
  items: Finding[];
  total: number;
  source: "api" | "mock";
  error?: string;
}

export async function loadFindings(): Promise<FindingsResult> {
  if (DEMO_MODE) {
    const items = mockFindings();
    return { items, total: items.length, source: "mock" };
  }

  try {
    const page = await apiListFindings({ limit: 200 });
    return { items: page.items, total: page.total, source: "api" };
  } catch (err) {
    const items = mockFindings();
    return {
      items,
      total: items.length,
      source: "mock",
      error: err instanceof Error ? err.message : "unknown",
    };
  }
}
