"use client";

import { format, parseISO } from "date-fns";
import { es } from "date-fns/locale";
import {
  AlertTriangle,
  Bot,
  CheckCircle2,
  Clock,
  Cpu,
  ExternalLink,
  FileSignature,
  ShieldAlert,
  Wrench,
  Zap,
} from "lucide-react";
import {
  Sheet,
  SheetContent,
  SheetDescription,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { SeverityBadge } from "./severity-badge";
import { STATUS_LABELS, STATUS_TONES } from "@/lib/mocks/findings";
import { FRAMEWORK_CATALOG } from "@/lib/mocks/frameworks";
import { cn } from "@/lib/utils";
import type { Finding } from "@/lib/types";

interface Props {
  finding: Finding | null;
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export function FindingDetailSheet({ finding, open, onOpenChange }: Props) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="w-full max-w-2xl overflow-y-auto sm:w-[640px]">
        {finding ? (
          <FindingDetail finding={finding} />
        ) : (
          <div className="flex h-full items-center justify-center text-sm text-muted-foreground">
            Seleccioná un finding para ver su detalle.
          </div>
        )}
      </SheetContent>
    </Sheet>
  );
}

function FindingDetail({ finding }: { finding: Finding }) {
  return (
    <div className="flex flex-col gap-5">
      <SheetHeader className="gap-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex flex-wrap items-center gap-2">
            <SeverityBadge severity={finding.severity} />
            {finding.exploitable ? (
              <Badge
                variant="outline"
                className="border-[var(--critical)]/40 font-mono text-[10px] text-[var(--critical)]"
              >
                <Zap className="mr-1 h-3 w-3" />
                exploit disponible
              </Badge>
            ) : null}
            <span
              className={cn(
                "rounded-md border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
                STATUS_TONES[finding.status]
              )}
            >
              {STATUS_LABELS[finding.status]}
            </span>
          </div>
          <span className="font-mono text-xs text-muted-foreground">
            {finding.id}
          </span>
        </div>

        <SheetTitle className="text-left text-lg leading-snug tracking-tight">
          {finding.title}
        </SheetTitle>

        <div className="flex flex-wrap items-center gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1.5">
            <Cpu className="h-3.5 w-3.5" />
            <span className="font-mono">{finding.assetName}</span>
          </span>
          {finding.cve ? (
            <span className="flex items-center gap-1.5">
              <ShieldAlert className="h-3.5 w-3.5" />
              <span className="font-mono">{finding.cve}</span>
            </span>
          ) : null}
          {finding.cvss !== undefined ? (
            <span className="flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5" />
              <span className="font-mono">CVSS {finding.cvss.toFixed(1)}</span>
            </span>
          ) : null}
          <span className="flex items-center gap-1.5">
            <Clock className="h-3.5 w-3.5" />
            hace {finding.ageDays}d
          </span>
        </div>

        <SheetDescription className="sr-only">
          Detalle de la vulnerabilidad {finding.id}
        </SheetDescription>
      </SheetHeader>

      <Separator />

      <Tabs defaultValue="overview" className="flex flex-1 flex-col gap-4">
        <TabsList className="w-fit">
          <TabsTrigger value="overview">Resumen</TabsTrigger>
          <TabsTrigger value="technical">Técnico</TabsTrigger>
          <TabsTrigger value="remediation">Remediación</TabsTrigger>
          <TabsTrigger value="compliance">Compliance</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-4">
          <Section title="Descripción">
            <p className="text-sm leading-relaxed text-muted-foreground">
              {finding.description}
            </p>
          </Section>

          <Section title="Activo afectado">
            <div className="space-y-1 font-mono text-xs">
              <p>
                <span className="text-muted-foreground">Host:</span>{" "}
                {finding.assetName}
              </p>
              <p>
                <span className="text-muted-foreground">Asset ID:</span>{" "}
                {finding.assetId}
              </p>
              <p>
                <span className="text-muted-foreground">Detectado:</span>{" "}
                {format(parseISO(finding.detectedAt), "d MMM yyyy · HH:mm", {
                  locale: es,
                })}
              </p>
              <p>
                <span className="text-muted-foreground">Skill Kryon:</span>{" "}
                <span className="text-primary">{finding.kryonSkill}</span>
              </p>
            </div>
          </Section>
        </TabsContent>

        <TabsContent value="technical" className="space-y-4">
          <Section title="Identificadores">
            <dl className="grid grid-cols-2 gap-3 text-xs">
              {finding.cve ? (
                <div>
                  <dt className="mb-0.5 text-muted-foreground">CVE</dt>
                  <dd className="flex items-center gap-1 font-mono">
                    {finding.cve}
                    <ExternalLink className="h-3 w-3 text-muted-foreground" />
                  </dd>
                </div>
              ) : null}
              {finding.cwe ? (
                <div>
                  <dt className="mb-0.5 text-muted-foreground">CWE</dt>
                  <dd className="font-mono">{finding.cwe}</dd>
                </div>
              ) : null}
              {finding.cvss !== undefined ? (
                <div>
                  <dt className="mb-0.5 text-muted-foreground">CVSS 3.1</dt>
                  <dd className="font-mono">{finding.cvss.toFixed(1)} / 10</dd>
                </div>
              ) : null}
              <div>
                <dt className="mb-0.5 text-muted-foreground">Severidad</dt>
                <dd>
                  <SeverityBadge severity={finding.severity} />
                </dd>
              </div>
            </dl>
          </Section>

          <Section title="Evidencia">
            <pre className="max-h-64 overflow-auto rounded-md border border-border/60 bg-card/50 p-3 font-mono text-[11px] leading-relaxed text-muted-foreground">
              {`$ kryon scan --skill ${finding.kryonSkill} --target ${finding.assetName}
[+] Loaded skill: ${finding.kryonSkill}
[+] Connecting to target...
[+] ${finding.cve || "Misconfiguration check"} detected
[!] Severity: ${finding.severity.toUpperCase()} · CVSS ${finding.cvss ?? "—"}
[!] Exploitable: ${finding.exploitable ? "YES" : "NO"}
[+] Evidence captured in /workspace/evidence/${finding.id}/
[+] Finding persisted with hash signature`}
            </pre>
          </Section>
        </TabsContent>

        <TabsContent value="remediation" className="space-y-4">
          <Section title="Recomendación">
            <p className="text-sm leading-relaxed">
              {finding.remediation.summary}
            </p>
          </Section>

          <Section title="Esfuerzo estimado">
            <div className="flex items-center gap-2 text-sm">
              <Wrench className="h-4 w-4 text-muted-foreground" />
              <span className="font-mono">
                {finding.remediation.effortHours}h
              </span>
              <span className="text-muted-foreground">de trabajo técnico</span>
            </div>
          </Section>

          {finding.remediation.automated ? (
            <div className="rounded-lg border border-primary/30 bg-primary/10 p-4">
              <div className="mb-2 flex items-center gap-2 text-sm font-medium text-primary">
                <Bot className="h-4 w-4" />
                Remediación automática disponible
              </div>
              <p className="mb-3 text-xs text-muted-foreground">
                Kryon puede aplicar el parche con rollback automático usando el
                skill <span className="font-mono">safe-modification</span>.
                Requiere aprobación del operador.
              </p>
              <div className="flex gap-2">
                <Button size="sm">
                  <Zap className="h-3.5 w-3.5" />
                  Remediar ahora
                </Button>
                <Button size="sm" variant="outline">
                  Simular (dry-run)
                </Button>
              </div>
            </div>
          ) : (
            <div className="rounded-lg border border-border/60 bg-muted/30 p-4 text-xs text-muted-foreground">
              <div className="mb-1 flex items-center gap-2 font-medium text-foreground">
                <AlertTriangle className="h-4 w-4" />
                Remediación manual requerida
              </div>
              Este finding requiere intervención humana porque involucra
              cambios que podrían afectar disponibilidad.
            </div>
          )}
        </TabsContent>

        <TabsContent value="compliance" className="space-y-4">
          <Section title="Frameworks impactados">
            <div className="space-y-2">
              {finding.frameworks.map((fwId) => {
                const fw = FRAMEWORK_CATALOG[fwId];
                return (
                  <div
                    key={fwId}
                    className="flex items-center justify-between rounded-md border border-border/60 bg-card/40 p-2.5 text-xs"
                  >
                    <div className="flex items-center gap-2">
                      <FileSignature className="h-3.5 w-3.5 text-primary" />
                      <span className="font-medium">{fw.name}</span>
                    </div>
                    <Badge
                      variant="outline"
                      className="font-mono text-[10px] text-[var(--critical)]"
                    >
                      incumple
                    </Badge>
                  </div>
                );
              })}
            </div>
          </Section>

          <Section title="Evidencia auditable">
            <div className="flex items-start gap-2 rounded-md border border-border/60 bg-card/30 p-3 text-xs">
              <CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--success)]" />
              <div className="space-y-1">
                <p className="font-medium">Hash criptográfico firmado</p>
                <p className="font-mono text-[10px] text-muted-foreground">
                  sha256:9f2a8c73e4b1d5f6... (reproducibilidad verificable)
                </p>
              </div>
            </div>
          </Section>
        </TabsContent>
      </Tabs>
    </div>
  );
}

function Section({
  title,
  children,
}: {
  title: string;
  children: React.ReactNode;
}) {
  return (
    <section className="space-y-2">
      <h3 className="text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
        {title}
      </h3>
      {children}
    </section>
  );
}
