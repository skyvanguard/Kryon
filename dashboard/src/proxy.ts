import { NextResponse, type NextRequest } from "next/server";
import { AUTH_COOKIE, decodeCookie, isSessionValid } from "@/lib/auth";

/**
 * Route guards for the dashboard.
 *
 * Any request to the protected routes below is redirected to /login
 * when the `kryon-auth` cookie is missing or expired. Already-logged-in
 * users visiting /login are bounced back to /overview so auth feels
 * like a real SPA.
 */

const PROTECTED_PREFIXES = [
  "/overview",
  "/findings",
  "/compliance",
  "/scans",
  "/reports",
  "/settings",
];

export function proxy(request: NextRequest) {
  const { pathname } = request.nextUrl;
  const cookie = request.cookies.get(AUTH_COOKIE)?.value;
  const session = decodeCookie(cookie);
  const authed = isSessionValid(session);

  const isProtected = PROTECTED_PREFIXES.some((prefix) =>
    pathname === prefix || pathname.startsWith(`${prefix}/`)
  );

  if (isProtected && !authed) {
    const loginUrl = new URL("/login", request.url);
    loginUrl.searchParams.set("next", pathname);
    return NextResponse.redirect(loginUrl);
  }

  if (pathname === "/login" && authed) {
    return NextResponse.redirect(new URL("/overview", request.url));
  }

  return NextResponse.next();
}

export const config = {
  // Run on everything except Next.js internals, static assets, and
  // the public favicon. Adjust if API routes need gating later.
  matcher: ["/((?!_next/static|_next/image|favicon.ico|.*\\.(?:svg|png|jpg|jpeg|gif|webp)$).*)"],
};
