/**
 * Mock authentication for demo.
 * Real auth via FastAPI JWT comes in Day 7 integration.
 *
 * Strategy: a `kryon-auth` cookie holds a base64 blob with email + expiry.
 * Proxy reads the cookie to gate protected routes; client reads it to show
 * the current user. No secrets are embedded — this is a placeholder layer
 * swapped out when we wire the real /auth/login endpoint.
 */

export const AUTH_COOKIE = "kryon-auth";
export const AUTH_MAX_AGE_SECONDS = 60 * 60 * 12; // 12 hours

export interface AuthSession {
  email: string;
  name: string;
  role: "admin" | "analyst" | "viewer";
  expiresAt: number; // unix epoch ms
}

// Demo credentials — replaced by real backend call in Day 7.
const DEMO_USERS: Record<string, { password: string; session: Omit<AuthSession, "expiresAt"> }> = {
  "admin@kryon.py": {
    password: "kryon2026",
    session: {
      email: "admin@kryon.py",
      name: "Admin Kryon",
      role: "admin",
    },
  },
  "demo@britimp.com.py": {
    password: "demo2026",
    session: {
      email: "demo@britimp.com.py",
      name: "BritImp Demo",
      role: "analyst",
    },
  },
};

export type LoginResult =
  | { ok: true; session: AuthSession; cookieValue: string }
  | { ok: false; error: string };

export function tryLogin(email: string, password: string): LoginResult {
  const normalized = email.trim().toLowerCase();
  const entry = DEMO_USERS[normalized];
  if (!entry || entry.password !== password) {
    return { ok: false, error: "Credenciales inválidas" };
  }
  const session: AuthSession = {
    ...entry.session,
    expiresAt: Date.now() + AUTH_MAX_AGE_SECONDS * 1000,
  };
  const cookieValue = encodeCookie(session);
  return { ok: true, session, cookieValue };
}

function encodeCookie(session: AuthSession): string {
  // Base64 JSON — NOT cryptographically secure, only a demo marker.
  // Real impl: signed JWT from the backend.
  if (typeof btoa !== "undefined") {
    return btoa(JSON.stringify(session));
  }
  return Buffer.from(JSON.stringify(session)).toString("base64");
}

export function decodeCookie(raw: string | undefined): AuthSession | null {
  if (!raw) return null;
  try {
    const json =
      typeof atob !== "undefined"
        ? atob(raw)
        : Buffer.from(raw, "base64").toString("utf-8");
    const parsed = JSON.parse(json) as AuthSession;
    if (parsed.expiresAt < Date.now()) return null;
    return parsed;
  } catch {
    return null;
  }
}

export function isSessionValid(session: AuthSession | null): session is AuthSession {
  return session !== null && session.expiresAt > Date.now();
}
