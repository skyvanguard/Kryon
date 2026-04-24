import { API_TIMEOUT_MS, KRYON_API_KEY, KRYON_API_URL } from "../config";

export class KryonApiError extends Error {
  constructor(
    message: string,
    public readonly status: number,
    public readonly cause?: unknown
  ) {
    super(message);
    this.name = "KryonApiError";
  }
}

export interface RequestOptions {
  method?: "GET" | "POST" | "PUT" | "DELETE";
  body?: unknown;
  query?: Record<string, string | number | boolean | undefined>;
  signal?: AbortSignal;
  timeoutMs?: number;
}

/**
 * Low-level fetch wrapper for the Kryon FastAPI backend.
 *
 * Design notes:
 * - ALWAYS throws KryonApiError on non-2xx or network failure so the caller
 *   can easily `try { ... } catch { return mock }`.
 * - Timeouts are enforced client-side — we never want the dashboard to hang
 *   because the backend is slow during a demo.
 * - Runs server-side only (import from server components / route handlers),
 *   so credentials stay off the wire to the browser.
 */
export async function kryonFetch<T>(
  path: string,
  options: RequestOptions = {}
): Promise<T> {
  if (!KRYON_API_URL) {
    throw new KryonApiError("Kryon API URL not configured", 0);
  }

  const url = new URL(`${KRYON_API_URL}${path.startsWith("/") ? path : `/${path}`}`);
  if (options.query) {
    for (const [k, v] of Object.entries(options.query)) {
      if (v !== undefined && v !== null) {
        url.searchParams.set(k, String(v));
      }
    }
  }

  const headers: Record<string, string> = {
    Accept: "application/json",
  };
  if (options.body !== undefined) {
    headers["Content-Type"] = "application/json";
  }
  if (KRYON_API_KEY) {
    headers["X-API-Key"] = KRYON_API_KEY;
  }

  const controller = new AbortController();
  const timeout = options.timeoutMs ?? API_TIMEOUT_MS;
  const timer = setTimeout(() => controller.abort(), timeout);
  const signal = options.signal ?? controller.signal;

  try {
    const res = await fetch(url, {
      method: options.method ?? "GET",
      headers,
      body: options.body !== undefined ? JSON.stringify(options.body) : undefined,
      signal,
      // Opt out of Next.js fetch caching so dashboard data stays fresh.
      cache: "no-store",
    });

    if (!res.ok) {
      let detail = res.statusText;
      try {
        const err = await res.json();
        if (err && typeof err === "object" && "detail" in err) {
          detail = String((err as { detail: unknown }).detail);
        }
      } catch {
        // non-JSON error body — keep statusText
      }
      throw new KryonApiError(detail, res.status);
    }

    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof KryonApiError) throw err;
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new KryonApiError(`Request timeout after ${timeout}ms`, 0, err);
    }
    throw new KryonApiError(
      err instanceof Error ? err.message : "Network error",
      0,
      err
    );
  } finally {
    clearTimeout(timer);
  }
}
