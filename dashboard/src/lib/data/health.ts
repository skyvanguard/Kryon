import { DEMO_MODE } from "../config";
import { getHealth as apiGetHealth, type HealthResponse } from "../api/kryon";

/**
 * Health probe with a synthetic demo-mode response so the UI can show
 * a consistent status pill without branching on config in components.
 */

export interface HealthResult {
  status: "ok" | "degraded" | "unhealthy" | "demo";
  version: string;
  agents: number;
  source: "api" | "mock";
}

export async function probeHealth(): Promise<HealthResult> {
  if (DEMO_MODE) {
    return {
      status: "demo",
      version: "2.1.0 (demo)",
      agents: 33,
      source: "mock",
    };
  }

  try {
    const h: HealthResponse = await apiGetHealth();
    return {
      status: h.status,
      version: h.version,
      agents: h.agents_count,
      source: "api",
    };
  } catch {
    return {
      status: "unhealthy",
      version: "—",
      agents: 0,
      source: "mock",
    };
  }
}
