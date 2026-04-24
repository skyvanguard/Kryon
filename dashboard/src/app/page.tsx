import Link from "next/link";
import { ArrowRight, ShieldCheck, Zap, Lock } from "lucide-react";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export default function HomePage() {
  return (
    <div className="flex min-h-screen flex-col">
      <header className="border-b border-border/60 bg-sidebar/40 backdrop-blur-sm">
        <div className="mx-auto flex h-16 w-full max-w-7xl items-center justify-between px-6">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-md bg-primary text-primary-foreground">
              <Zap className="h-4 w-4" strokeWidth={2.5} />
            </div>
            <span className="font-sans text-lg font-semibold tracking-tight">
              Kryon
            </span>
            <Badge variant="outline" className="ml-2 font-mono text-xs">
              v2.1 · Hydra
            </Badge>
          </div>
          <Link href="/login" className={buttonVariants({ size: "sm" })}>
            Ingresar <ArrowRight className="ml-1 h-4 w-4" />
          </Link>
        </div>
      </header>

      <main className="flex flex-1 flex-col items-center justify-center px-6 py-16">
        <div className="w-full max-w-4xl space-y-12 text-center">
          <div className="space-y-6">
            <Badge variant="secondary" className="font-mono text-xs">
              Hecho en Paraguay · Datos soberanos
            </Badge>
            <h1 className="text-balance font-sans text-5xl font-semibold tracking-tight sm:text-6xl">
              Operaciones de seguridad{" "}
              <span className="text-primary">autónomas</span>
            </h1>
            <p className="mx-auto max-w-2xl text-balance text-lg text-muted-foreground">
              Plataforma NOC + SOC impulsada por IA: pentest continuo,
              compliance multi-framework y remediación automática sobre tu
              propia infraestructura.
            </p>
            <div className="flex items-center justify-center gap-3 pt-2">
              <Link
                href="/login"
                className={buttonVariants({ size: "lg" })}
              >
                Comenzar
              </Link>
              <Link
                href="/overview"
                className={buttonVariants({ size: "lg", variant: "outline" })}
              >
                Ver demo
              </Link>
            </div>
          </div>

          <div className="grid grid-cols-1 gap-4 text-left sm:grid-cols-3">
            <Card>
              <CardHeader>
                <ShieldCheck className="h-5 w-5 text-primary" />
                <CardTitle className="mt-2 text-base">
                  9 frameworks en una pasada
                </CardTitle>
                <CardDescription>
                  PCI-DSS, ISO 27001, CIS, NIST, GDPR, SOC2, HIPAA, OWASP,
                  MITRE ATT&CK — evidencia reproducible con hash firmado.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <Zap className="h-5 w-5 text-primary" />
                <CardTitle className="mt-2 text-base">
                  Objetivos ilimitados
                </CardTitle>
                <CardDescription>
                  Sin cobro por activo. Escaneá 10 endpoints o 10.000 —
                  mismo precio, misma plataforma, sin fricción al crecer.
                </CardDescription>
              </CardHeader>
            </Card>

            <Card>
              <CardHeader>
                <Lock className="h-5 w-5 text-primary" />
                <CardTitle className="mt-2 text-base">
                  Soberanía total
                </CardTitle>
                <CardDescription>
                  LLM local, datos nunca salen de tu red. Apto banca
                  BCP-regulada, gobierno e infraestructura crítica.
                </CardDescription>
              </CardHeader>
            </Card>
          </div>

          <div className="pt-8">
            <p className="font-mono text-xs text-muted-foreground">
              Benchmarks: Juice Shop 85/111 · Juliet SAST 67.1% recall ·
              F48 pilot OK
            </p>
          </div>
        </div>
      </main>

      <footer className="border-t border-border/60 py-6">
        <div className="mx-auto flex w-full max-w-7xl items-center justify-between px-6 text-xs text-muted-foreground">
          <span>© 2026 Kryon · Hecho en Paraguay</span>
          <span className="font-mono">v2.1.0 "Hydra — Skillforge"</span>
        </div>
      </footer>
    </div>
  );
}
