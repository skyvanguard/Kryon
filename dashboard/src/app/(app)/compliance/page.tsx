import { Download, FileCheck2, Hash, ShieldCheck } from "lucide-react";
import { PageHeader } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { FrameworkCard } from "@/components/compliance/framework-card";
import { ComplianceByFramework } from "@/components/charts/compliance-by-framework";
import { getFrameworks } from "@/lib/mocks/frameworks";

export const metadata = { title: "Compliance" };

export default function CompliancePage() {
  const frameworks = getFrameworks();
  const sorted = [...frameworks].sort(
    (a, b) => b.compliancePercent - a.compliancePercent
  );

  const totalControls = frameworks.reduce(
    (sum, f) => sum + f.totalControls,
    0
  );
  const passedControls = frameworks.reduce(
    (sum, f) => sum + f.passedControls,
    0
  );
  const avgPercent = Math.round(
    frameworks.reduce((sum, f) => sum + f.compliancePercent, 0) /
      frameworks.length
  );

  return (
    <div>
      <PageHeader
        title="Compliance"
        description="9 frameworks evaluados en paralelo. Evidencia criptográficamente firmada, apta para auditores externos y reguladores (SIB, BCP, Contraloría)."
        actions={
          <Button size="sm">
            <Download className="h-3.5 w-3.5" />
            Reporte multi-framework
          </Button>
        }
      />

      <div className="space-y-6 px-6 py-6">
        {/* Summary row */}
        <div className="grid grid-cols-1 gap-4 md:grid-cols-3">
          <Card>
            <CardContent className="p-5">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    Cumplimiento promedio
                  </p>
                  <p className="mt-1 font-mono text-3xl font-semibold tabular-nums">
                    {avgPercent}%
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Ponderado sobre 9 frameworks
                  </p>
                </div>
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <ShieldCheck className="h-4 w-4" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-5">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    Controles aprobados
                  </p>
                  <p className="mt-1 font-mono text-3xl font-semibold tabular-nums">
                    {passedControls.toLocaleString("es-PY")}
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    de {totalControls.toLocaleString("es-PY")} controles
                    evaluados
                  </p>
                </div>
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <FileCheck2 className="h-4 w-4" />
                </div>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardContent className="p-5">
              <div className="flex items-start justify-between">
                <div>
                  <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
                    Reproducibilidad
                  </p>
                  <p className="mt-1 font-mono text-sm font-semibold">
                    sha256:9f2a8c73…
                  </p>
                  <p className="mt-1 text-xs text-muted-foreground">
                    Hash firmado · evidencia verificable
                  </p>
                </div>
                <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
                  <Hash className="h-4 w-4" />
                </div>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Framework comparison chart */}
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Comparativa global</CardTitle>
            <CardDescription>
              % de cumplimiento por framework, ordenado descendente
            </CardDescription>
          </CardHeader>
          <CardContent>
            <ComplianceByFramework frameworks={frameworks} />
          </CardContent>
        </Card>

        {/* Framework grid */}
        <div>
          <h2 className="mb-3 text-sm font-semibold tracking-tight">
            Frameworks activos
          </h2>
          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {sorted.map((framework) => (
              <FrameworkCard key={framework.id} framework={framework} />
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
