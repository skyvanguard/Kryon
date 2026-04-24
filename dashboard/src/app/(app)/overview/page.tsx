import Link from "next/link";
import {
  Activity,
  FileText,
  Plus,
  Server,
  ShieldAlert,
  Target,
} from "lucide-react";
import { PageHeader } from "@/components/app/page-header";
import { buttonVariants } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { KpiCard } from "@/components/overview/kpi-card";
import { SecurityScoreCard } from "@/components/overview/security-score";
import { ActivityFeed } from "@/components/overview/activity-feed";
import { FindingsOverTime } from "@/components/charts/findings-over-time";
import { FindingsBySeverity } from "@/components/charts/findings-by-severity";
import { ComplianceByFramework } from "@/components/charts/compliance-by-framework";
import { getOverviewKpis, getFindingsTimeseries } from "@/lib/mocks/overview";
import { getFrameworks } from "@/lib/mocks/frameworks";
import { getRecentActivity } from "@/lib/mocks/activity";
import { cn } from "@/lib/utils";

export const metadata = { title: "Overview" };

export default function OverviewPage() {
  const kpis = getOverviewKpis();
  const timeseries = getFindingsTimeseries(30);
  const frameworks = getFrameworks();
  const activity = getRecentActivity();

  return (
    <div>
      <PageHeader
        title="Overview"
        description="Estado general de seguridad, cumplimiento y actividad reciente en tiempo real."
        actions={
          <>
            <Link
              href="/reports"
              className={cn(
                buttonVariants({ size: "sm", variant: "outline" })
              )}
            >
              <FileText className="h-3.5 w-3.5" />
              Generar reporte
            </Link>
            <Link
              href="/scans?new=1"
              className={cn(buttonVariants({ size: "sm" }))}
            >
              <Plus className="h-3.5 w-3.5" />
              Nuevo escaneo
            </Link>
          </>
        }
      />

      <div className="space-y-5 px-6 py-6">
        {/* Row 1: Hero security score + 3 KPI cards */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-4">
          <SecurityScoreCard score={kpis.securityScore} />
          <KpiCard
            label="Activos monitoreados"
            value={kpis.assets.total}
            icon={Server}
            trend={kpis.assets.trend}
            hint={`${kpis.assets.tier1} de criticidad tier-1`}
          />
          <KpiCard
            label="Findings abiertos"
            value={kpis.findings.openTotal}
            icon={ShieldAlert}
            trend={kpis.findings.trend}
            inverseTrend
            hint={`${kpis.findings.bySeverity.critical} críticos · ${kpis.findings.bySeverity.high} altos`}
          />
          <KpiCard
            label="Compliance promedio"
            value={kpis.compliance.averagePercent}
            unit="%"
            icon={Target}
            trend={kpis.compliance.trend}
            hint={`${kpis.compliance.frameworksCovered} frameworks activos`}
          />
        </div>

        {/* Row 2: Findings trend + severity donut */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
          <Card className="lg:col-span-2">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">
                    Findings en el tiempo
                  </CardTitle>
                  <CardDescription>
                    Últimos 30 días apilados por severidad
                  </CardDescription>
                </div>
                <Activity className="h-4 w-4 text-muted-foreground" />
              </div>
            </CardHeader>
            <CardContent className="pt-2">
              <FindingsOverTime data={timeseries} />
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">Por severidad</CardTitle>
              <CardDescription>Distribución actual de abiertos</CardDescription>
            </CardHeader>
            <CardContent>
              <FindingsBySeverity bySeverity={kpis.findings.bySeverity} />
            </CardContent>
          </Card>
        </div>

        {/* Row 3: Compliance by framework + activity feed */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-5">
          <Card className="lg:col-span-3">
            <CardHeader>
              <CardTitle className="text-base">
                Cumplimiento por framework
              </CardTitle>
              <CardDescription>
                9 frameworks evaluados · evidencia con hash firmado
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ComplianceByFramework frameworks={frameworks} />
            </CardContent>
          </Card>

          <Card className="lg:col-span-2">
            <CardHeader>
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-base">Actividad reciente</CardTitle>
                  <CardDescription>
                    Eventos del motor en tiempo real
                  </CardDescription>
                </div>
                <span className="relative flex h-2 w-2">
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-[var(--success)] opacity-75" />
                  <span className="relative inline-flex h-2 w-2 rounded-full bg-[var(--success)]" />
                </span>
              </div>
            </CardHeader>
            <CardContent className="pt-0">
              <ActivityFeed events={activity} />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
