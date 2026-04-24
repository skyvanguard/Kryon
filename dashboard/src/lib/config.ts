/**
 * Runtime configuration resolved from environment.
 *
 * NEXT_PUBLIC_KRYON_API_URL — base URL of the FastAPI backend. When unset,
 * the dashboard runs in demo mode using deterministic mock fixtures.
 *
 * NEXT_PUBLIC_KRYON_API_KEY — optional API key for the Kryon backend
 * require_api_key dependency. Use instead of JWT for simple setups.
 */

export const KRYON_API_URL =
  process.env.NEXT_PUBLIC_KRYON_API_URL?.replace(/\/+$/, "") ?? "";

export const KRYON_API_KEY = process.env.NEXT_PUBLIC_KRYON_API_KEY ?? "";

export const DEMO_MODE = KRYON_API_URL === "";

/**
 * Default request timeout in milliseconds. Short enough that when the
 * backend is down the UI falls back to mocks in under a second — the
 * demo must always feel snappy, never hung.
 */
export const API_TIMEOUT_MS = 3000;
