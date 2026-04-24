"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { AUTH_COOKIE, AUTH_MAX_AGE_SECONDS, tryLogin } from "@/lib/auth";

export interface LoginFormState {
  error?: string;
  email?: string;
}

export async function loginAction(
  _prev: LoginFormState,
  formData: FormData
): Promise<LoginFormState> {
  const email = String(formData.get("email") ?? "").trim();
  const password = String(formData.get("password") ?? "");
  const next = String(formData.get("next") ?? "/overview");

  if (!email || !password) {
    return { error: "Email y contraseña son obligatorios", email };
  }

  const result = tryLogin(email, password);
  if (!result.ok) {
    return { error: result.error, email };
  }

  const store = await cookies();
  store.set(AUTH_COOKIE, result.cookieValue, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    maxAge: AUTH_MAX_AGE_SECONDS,
    // secure: true in production, dev over http needs false
    secure: process.env.NODE_ENV === "production",
  });

  // Only redirect to internal paths; prevents open-redirect on ?next=...
  const safeNext = next.startsWith("/") && !next.startsWith("//") ? next : "/overview";
  redirect(safeNext);
}

export async function logoutAction() {
  const store = await cookies();
  store.delete(AUTH_COOKIE);
  redirect("/");
}
