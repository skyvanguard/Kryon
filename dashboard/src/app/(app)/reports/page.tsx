import { Plus, FileText } from "lucide-react";
import { PageHeader } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";
import { Card, CardContent } from "@/components/ui/card";
import { ReportCard } from "@/components/reports/report-card";
import { getReports, REPORT_KIND_LABELS } from "@/lib/mocks/reports";

export const metadata = { title: "Reportes" };

export default function ReportsPage() {
  const reports = getReports();

  // Kind tallies for the summary row
  const byKind = reports.reduce<Record<string, number>>((acc, r) => {
    acc[r.kind] = (acc[r.kind] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div>
      <PageHeader
        title="Reportes"
        description="Documentos ejecutivos, técnicos y de compliance. Cada reporte incluye firma criptográfica para evidencia reproducible ante auditores."
        actions={
          <Button size="sm">
            <Plus className="h-3.5 w-3.5" />
            Generar reporte
          </Button>
        }
      />

      <div className="space-y-6 px-6 py-6">
        {/* Summary */}
        <Card>
          <CardContent className="flex flex-wrap items-center gap-x-8 gap-y-3 p-5">
            <div className="flex items-center gap-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                <FileText className="h-4 w-4" />
              </div>
              <div>
                <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                  Reportes disponibles
                </p>
                <p className="font-mono text-2xl font-semibold tabular-nums">
                  {reports.length}
                </p>
              </div>
            </div>

            <div className="flex flex-wrap gap-x-5 gap-y-2 text-xs">
              {Object.entries(byKind).map(([kind, count]) => (
                <div key={kind} className="space-y-0.5">
                  <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    {REPORT_KIND_LABELS[kind as keyof typeof REPORT_KIND_LABELS]}
                  </p>
                  <p className="font-mono text-sm tabular-nums">{count}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Grid */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4">
          {reports.map((report) => (
            <ReportCard key={report.id} report={report} />
          ))}
        </div>
      </div>
    </div>
  );
}
