import { Suspense } from "react";
import Link from "next/link";
import { Zap } from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { LoginForm } from "./login-form";

export const metadata = {
  title: "Ingresar",
};

export default async function LoginPage({
  searchParams,
}: {
  searchParams: Promise<{ next?: string }>;
}) {
  const params = await searchParams;
  const next = params?.next ?? "/overview";

  return (
    <div className="relative flex min-h-screen items-center justify-center bg-background p-6">
      {/* Subtle grid background for depth */}
      <div
        className="pointer-events-none absolute inset-0 opacity-[0.03]"
        style={{
          backgroundImage:
            "linear-gradient(var(--foreground) 1px, transparent 1px), linear-gradient(to right, var(--foreground) 1px, transparent 1px)",
          backgroundSize: "40px 40px",
        }}
        aria-hidden
      />

      {/* Ambient glow at the top */}
      <div
        className="pointer-events-none absolute -top-32 left-1/2 h-96 w-[40rem] -translate-x-1/2 rounded-full opacity-[0.15] blur-3xl"
        style={{ background: "var(--primary)" }}
        aria-hidden
      />

      <div className="relative z-10 w-full max-w-md space-y-6">
        <Link href="/" className="flex items-center justify-center gap-2">
          <div className="flex h-9 w-9 items-center justify-center rounded-md bg-primary text-primary-foreground">
            <Zap className="h-5 w-5" strokeWidth={2.5} />
          </div>
          <span className="font-sans text-xl font-semibold tracking-tight">
            Kryon
          </span>
          <Badge variant="outline" className="ml-1 font-mono text-[10px]">
            v2.1
          </Badge>
        </Link>

        <div className="rounded-xl border border-border/60 bg-card/80 p-6 shadow-2xl backdrop-blur-sm sm:p-8">
          <div className="mb-6 space-y-1">
            <h1 className="text-xl font-semibold tracking-tight">
              Ingresá a tu panel
            </h1>
            <p className="text-sm text-muted-foreground">
              Usá tus credenciales corporativas para continuar.
            </p>
          </div>

          <Suspense>
            <LoginForm next={next} />
          </Suspense>
        </div>

        <div className="space-y-2 rounded-lg border border-dashed border-border/50 bg-muted/30 p-4 text-xs text-muted-foreground">
          <p className="font-medium text-foreground">
            Credenciales de demostración
          </p>
          <div className="space-y-0.5 font-mono">
            <p>
              admin@kryon.py ·{" "}
              <span className="text-primary">kryon2026</span>
            </p>
            <p>
              demo@britimp.com.py ·{" "}
              <span className="text-primary">demo2026</span>
            </p>
          </div>
        </div>

        <p className="text-center text-xs text-muted-foreground">
          © 2026 Kryon · Hecho en Paraguay 🇵🇾
        </p>
      </div>
    </div>
  );
}
