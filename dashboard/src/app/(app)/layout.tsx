import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { AUTH_COOKIE, decodeCookie, isSessionValid } from "@/lib/auth";
import { Sidebar } from "@/components/app/sidebar";
import { Topbar } from "@/components/app/topbar";
import { MotorStatus } from "@/components/app/motor-status";

/**
 * Authenticated shell for the dashboard.
 *
 * The proxy already gates these routes, but we double-check server-side
 * so that the Sidebar always receives a valid session object (avoids
 * null-check clutter in children). If the cookie is somehow missing
 * here we redirect as a belt-and-braces fallback.
 */
export default async function AppLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const cookieStore = await cookies();
  const raw = cookieStore.get(AUTH_COOKIE)?.value;
  const session = decodeCookie(raw);

  if (!isSessionValid(session)) {
    redirect("/login");
  }

  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar session={session} statusSlot={<MotorStatus />} />
      <div className="flex min-w-0 flex-1 flex-col">
        <Topbar />
        <main className="flex-1 overflow-y-auto">{children}</main>
      </div>
    </div>
  );
}
