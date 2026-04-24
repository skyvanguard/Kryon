"use client";

import { useMemo, useState } from "react";
import { formatDistanceToNow, parseISO } from "date-fns";
import { es } from "date-fns/locale";
import {
  Loader2,
  CheckCircle2,
  XCircle,
  Clock,
  Globe,
  Code2,
  Server,
  Network,
  ChevronDown,
  ChevronRight,
  Search,
  Download,
} from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { cn } from "@/lib/utils";
import {
  SCAN_STATUS_LABELS,
  SCAN_STATUS_TONES,
  TARGET_TYPE_LABELS,
  type Scan,
} from "@/lib/mocks/scans";

const TYPE_ICONS = {
  network: Network,
  host: Server,
  web: Globe,
  code: Code2,
};

export function ScansList({ scans }: { scans: readonly Scan[] }) {
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(scans.find((s) => s.status === "running")?.id ?? null);

  const filtered = useMemo(() => {
    const needle = search.trim().toLowerCase();
    if (!needle) return scans;
    return scans.filter(
      (s) =>
        s.target.toLowerCase().includes(needle) ||
        s.id.toLowerCase().includes(needle) ||
        s.skills.some((sk) => sk.toLowerCase().includes(needle))
    );
  }, [scans, search]);

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-2">
        <div className="relative flex-1 max-w-md">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="Buscar por target, ID o skill…"
            className="h-8 pl-8 text-xs"
          />
        </div>
        <div className="ml-auto flex items-center gap-1.5 rounded-md border border-border/60 bg-card/40 px-2 py-1 font-mono text-[10px] text-muted-foreground">
          {filtered.length} escaneo{filtered.length === 1 ? "" : "s"}
        </div>
      </div>

      <div className="space-y-2">
        {filtered.map((scan) => (
          <ScanRow
            key={scan.id}
            scan={scan}
            expanded={expanded === scan.id}
            onToggle={() =>
              setExpanded((prev) => (prev === scan.id ? null : scan.id))
            }
          />
        ))}
      </div>
    </div>
  );
}

function ScanRow({
  scan,
  expanded,
  onToggle,
}: {
  scan: Scan;
  expanded: boolean;
  onToggle: () => void;
}) {
  const TypeIcon = TYPE_ICONS[scan.targetType];
  const totalFindings = scan.findingsCount
    ? Object.values(scan.findingsCount).reduce((a, b) => a + b, 0)
    : 0;

  return (
    <Card
      className={cn(
        "overflow-hidden transition-all",
        scan.status === "running" && "border-primary/40"
      )}
    >
      <button
        type="button"
        onClick={onToggle}
        className="flex w-full cursor-pointer items-center gap-3 p-4 text-left transition-colors hover:bg-muted/20"
      >
        <div className="flex h-9 w-9 shrink-0 items-center justify-center rounded-md border border-border/60 bg-card">
          <TypeIcon className="h-4 w-4 text-muted-foreground" />
        </div>

        <div className="min-w-0 flex-1 space-y-1">
          <div className="flex items-center gap-2">
            <p className="truncate text-sm font-medium">{scan.target}</p>
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[10px] uppercase tracking-wider",
                SCAN_STATUS_TONES[scan.status]
              )}
            >
              {scan.status === "running" ? (
                <Loader2 className="h-2.5 w-2.5 animate-spin" />
              ) : scan.status === "completed" ? (
                <CheckCircle2 className="h-2.5 w-2.5" />
              ) : scan.status === "failed" ? (
                <XCircle className="h-2.5 w-2.5" />
              ) : (
                <Clock className="h-2.5 w-2.5" />
              )}
              {SCAN_STATUS_LABELS[scan.status]}
            </span>
          </div>
          <div className="flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-muted-foreground">
            <span className="font-mono">{scan.id}</span>
            <span>·</span>
            <span>{TARGET_TYPE_LABELS[scan.targetType]}</span>
            <span>·</span>
            <span>
              {formatDistanceToNow(parseISO(scan.startedAt), {
                addSuffix: true,
                locale: es,
              })}
            </span>
            {scan.durationSeconds ? (
              <>
                <span>·</span>
                <span>
                  duró{" "}
                  {scan.durationSeconds < 60
                    ? `${scan.durationSeconds}s`
                    : `${Math.round(scan.durationSeconds / 60)}min`}
                </span>
              </>
            ) : null}
            <span>·</span>
            <span className="font-mono text-muted-foreground/80">
              por {scan.triggeredBy}
            </span>
          </div>
        </div>

        <div className="flex shrink-0 items-center gap-4">
          {scan.status === "completed" && scan.findingsCount ? (
            <div className="hidden items-center gap-1.5 sm:flex">
              {scan.findingsCount.critical > 0 ? (
                <Badge
                  variant="outline"
                  className="border-[var(--critical)]/40 bg-[var(--critical)]/10 font-mono text-[9px] text-[var(--critical)]"
                >
                  {scan.findingsCount.critical}C
                </Badge>
              ) : null}
              {scan.findingsCount.high > 0 ? (
                <Badge
                  variant="outline"
                  className="border-[oklch(0.68_0.2_45)]/40 bg-[oklch(0.68_0.2_45)]/10 font-mono text-[9px] text-[oklch(0.68_0.2_45)]"
                >
                  {scan.findingsCount.high}H
                </Badge>
              ) : null}
              <span className="font-mono text-[10px] text-muted-foreground">
                {totalFindings} total
              </span>
            </div>
          ) : null}

          <div className="flex h-6 w-6 items-center justify-center text-muted-foreground">
            {expanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </div>
        </div>
      </button>

      {expanded ? (
        <CardContent className="border-t border-border/40 bg-card/30 p-4">
          {scan.status === "running" ? (
            <RunningScanDetail scan={scan} />
          ) : (
            <CompletedScanDetail scan={scan} />
          )}
        </CardContent>
      ) : null}
    </Card>
  );
}

function RunningScanDetail({ scan }: { scan: Scan }) {
  const progress = scan.progressPercent ?? 0;
  return (
    <div className="space-y-4">
      <div>
        <div className="mb-1.5 flex items-center justify-between text-xs">
          <span className="text-muted-foreground">Progreso</span>
          <span className="font-mono tabular-nums">{progress}%</span>
        </div>
        <Progress value={progress} className="h-1.5" />
      </div>

      <div className="grid grid-cols-1 gap-2 text-xs md:grid-cols-2">
        <DetailRow label="Paso actual" value={scan.currentStep ?? "—"} mono />
        <DetailRow label="Skills activos" value={scan.skills.join(", ")} mono />
      </div>

      <div className="rounded-md border border-border/60 bg-background/50 p-3">
        <p className="mb-2 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
          Log en vivo
        </p>
        <pre className="max-h-40 overflow-auto font-mono text-[10px] leading-relaxed text-muted-foreground">
          {`[${shortTime(3)}] kryon-recon-scout → nmap sS -p- ${scan.target}
[${shortTime(2)}] kryon-recon-scout ← 2.847 hosts descubiertos
[${shortTime(2)}] kryon-vuln-hunter → lanzando nuclei contra hosts discovered
[${shortTime(1)}] kryon-vuln-hunter ← CVE-2024-6387 detectado en 4 hosts
[${shortTime(1)}] kryon-server-hardening → evaluando SSH config en 47 hosts
[${shortTime(0)}] kryon-server-hardening → nuclei_scan ejecutándose en 47 hosts`}
        </pre>
      </div>
    </div>
  );
}

function CompletedScanDetail({ scan }: { scan: Scan }) {
  return (
    <div className="grid grid-cols-1 gap-4 md:grid-cols-2">
      <div className="space-y-2 text-xs">
        <DetailRow label="Scan ID" value={scan.id} mono />
        <DetailRow
          label="Target"
          value={scan.target}
          mono
        />
        <DetailRow label="Tipo" value={TARGET_TYPE_LABELS[scan.targetType]} />
        <DetailRow label="Skills ejecutados" value={scan.skills.join(", ")} mono />
        <DetailRow
          label="Duración"
          value={
            scan.durationSeconds
              ? `${Math.round(scan.durationSeconds / 60)} min`
              : "—"
          }
        />
      </div>

      {scan.findingsCount ? (
        <div className="space-y-3">
          <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            Findings producidos
          </p>
          <FindingsSummary counts={scan.findingsCount} />
          <div className="flex gap-2">
            <Button size="sm" variant="outline" className="flex-1">
              Ver findings
            </Button>
            <Button size="sm" variant="outline">
              <Download className="h-3.5 w-3.5" />
              Reporte
            </Button>
          </div>
        </div>
      ) : (
        <div className="rounded-md border border-[var(--critical)]/40 bg-[var(--critical)]/10 p-3 text-xs text-[var(--critical)]">
          Escaneo fallido. Revisar logs del motor para más detalles.
        </div>
      )}
    </div>
  );
}

function FindingsSummary({
  counts,
}: {
  counts: NonNullable<Scan["findingsCount"]>;
}) {
  const rows = [
    { key: "critical", label: "Crítica", value: counts.critical, color: "var(--critical)" },
    { key: "high", label: "Alta", value: counts.high, color: "oklch(0.68 0.2 45)" },
    { key: "medium", label: "Media", value: counts.medium, color: "var(--warning)" },
    { key: "low", label: "Baja", value: counts.low, color: "var(--chart-5)" },
    { key: "info", label: "Info", value: counts.info, color: "var(--primary)" },
  ];
  const total = rows.reduce((a, b) => a + b.value, 0);

  return (
    <div className="space-y-1.5 text-xs">
      {rows.map((row) => (
        <div key={row.key} className="flex items-center gap-3">
          <span
            className="h-2 w-2 rounded-sm"
            style={{ background: row.color }}
          />
          <span className="flex-1 text-muted-foreground">{row.label}</span>
          <span className="font-mono tabular-nums">{row.value}</span>
        </div>
      ))}
      <div className="mt-1 flex items-center justify-between border-t border-border/40 pt-1.5">
        <span className="text-muted-foreground">Total</span>
        <span className="font-mono font-medium tabular-nums">{total}</span>
      </div>
    </div>
  );
}

function DetailRow({
  label,
  value,
  mono,
}: {
  label: string;
  value: string;
  mono?: boolean;
}) {
  return (
    <div>
      <p className="text-muted-foreground">{label}</p>
      <p className={cn("mt-0.5 break-all text-foreground", mono && "font-mono")}>
        {value}
      </p>
    </div>
  );
}

function shortTime(minutesAgo: number): string {
  const d = new Date();
  d.setMinutes(d.getMinutes() - minutesAgo);
  return d.toISOString().slice(11, 19);
}
