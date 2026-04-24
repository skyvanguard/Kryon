import { Plus, Activity, CheckCircle2, XCircle } from "lucide-react";
import { PageHeader } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
} from "@/components/ui/card";
import { ScansList } from "@/components/scans/scans-list";
import { getScans } from "@/lib/mocks/scans";

export const metadata = { title: "Escaneos" };

export default function ScansPage() {
  const scans = getScans();
  const running = scans.filter((s) => s.status === "running").length;
  const completed24h = scans.filter(
    (s) =>
      s.status === "completed" &&
      Date.now() - new Date(s.startedAt).getTime() < 1000 * 60 * 60 * 24
  ).length;
  const failed24h = scans.filter(
    (s) =>
      s.status === "failed" &&
      Date.now() - new Date(s.startedAt).getTime() < 1000 * 60 * 60 * 24
  ).length;

  return (
    <div>
      <PageHeader
        title="Escaneos"
        description="Historial y escaneos en ejecución. Click en una fila para ver logs en vivo, findings producidos y descargar el reporte generado."
        actions={
          <Button size="sm">
            <Plus className="h-3.5 w-3.5" />
            Nuevo escaneo
          </Button>
        }
      />

      <div className="space-y-6 px-6 py-6">
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <MetricCard
            label="En ejecución"
            value={running}
            icon={<Activity className="h-4 w-4 text-primary" />}
            tone="primary"
          />
          <MetricCard
            label="Completados (24h)"
            value={completed24h}
            icon={<CheckCircle2 className="h-4 w-4 text-[var(--success)]" />}
            tone="success"
          />
          <MetricCard
            label="Fallidos (24h)"
            value={failed24h}
            icon={<XCircle className="h-4 w-4 text-[var(--critical)]" />}
            tone="critical"
          />
        </div>

        <ScansList scans={scans} />
      </div>
    </div>
  );
}

function MetricCard({
  label,
  value,
  icon,
  tone,
}: {
  label: string;
  value: number;
  icon: React.ReactNode;
  tone: "primary" | "success" | "critical";
}) {
  const bg =
    tone === "primary"
      ? "bg-primary/10"
      : tone === "success"
        ? "bg-[var(--success)]/10"
        : "bg-[var(--critical)]/10";

  return (
    <Card>
      <CardContent className="flex items-center gap-4 p-5">
        <div
          className={`flex h-9 w-9 items-center justify-center rounded-lg ${bg}`}
        >
          {icon}
        </div>
        <div>
          <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
            {label}
          </p>
          <p className="mt-0.5 font-mono text-2xl font-semibold tabular-nums">
            {value}
          </p>
        </div>
      </CardContent>
    </Card>
  );
}
