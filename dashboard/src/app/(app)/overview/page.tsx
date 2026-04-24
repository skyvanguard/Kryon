import { LayoutDashboard, Sparkles } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/app/page-header";

export const metadata = { title: "Overview" };

export default function OverviewPage() {
  return (
    <div>
      <PageHeader
        title="Overview"
        description="Estado general de seguridad, cumplimiento y actividad reciente."
      />
      <EmptyState
        icon={<LayoutDashboard className="h-5 w-5" />}
        title="Construcción en curso — Day 3"
        description="Acá irán los KPI principales: security score, assets monitoreados, findings por severidad, compliance por framework y feed de actividad en tiempo real."
        action={
          <span className="inline-flex items-center gap-1.5 rounded-md border border-primary/30 bg-primary/10 px-2.5 py-1 font-mono text-xs text-primary">
            <Sparkles className="h-3 w-3" />
            próximo paso
          </span>
        }
      />
    </div>
  );
}
