import Link from "next/link";
import { Plus, Download, Database, FlaskConical } from "lucide-react";
import { PageHeader } from "@/components/app/page-header";
import { buttonVariants } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { FindingsTable } from "@/components/findings/findings-table";
import { loadFindings } from "@/lib/data/findings";
import { cn } from "@/lib/utils";

export const metadata = { title: "Findings" };

export default async function FindingsPage() {
  const { items: findings, source } = await loadFindings();
  const open = findings.filter((f) => f.status === "open" || f.status === "confirmed").length;
  const critical = findings.filter((f) => f.severity === "critical").length;

  return (
    <div>
      <PageHeader
        title="Findings"
        description={`${findings.length} vulnerabilidades detectadas · ${open} abiertas · ${critical} críticas. Click en cualquier fila para ver detalle, evidencia y remediación.`}
        actions={
          <>
            <Badge
              variant="outline"
              className={cn(
                "gap-1 font-mono text-[10px]",
                source === "api"
                  ? "border-[var(--success)]/40 bg-[var(--success)]/10 text-[var(--success)]"
                  : "border-border/60 bg-muted/40 text-muted-foreground"
              )}
              title={
                source === "api"
                  ? "Datos cargados desde el backend Kryon en vivo"
                  : "Backend no alcanzable — usando fixtures de demo"
              }
            >
              {source === "api" ? (
                <>
                  <Database className="h-3 w-3" />
                  live
                </>
              ) : (
                <>
                  <FlaskConical className="h-3 w-3" />
                  demo
                </>
              )}
            </Badge>
            <button
              className={cn(
                buttonVariants({ size: "sm", variant: "outline" })
              )}
            >
              <Download className="h-3.5 w-3.5" />
              Exportar CSV
            </button>
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
      <div className="px-6 py-6">
        <FindingsTable findings={findings} />
      </div>
    </div>
  );
}
