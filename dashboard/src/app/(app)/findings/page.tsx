import Link from "next/link";
import { ShieldAlert, Plus } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/app/page-header";
import { buttonVariants } from "@/components/ui/button";

export const metadata = { title: "Findings" };

export default function FindingsPage() {
  return (
    <div>
      <PageHeader
        title="Findings"
        description="Vulnerabilidades detectadas con severidad, framework afectado y estado de remediación."
        actions={
          <Link
            href="/scans?new=1"
            className={buttonVariants({ size: "sm" })}
          >
            <Plus className="h-3.5 w-3.5" />
            Nuevo escaneo
          </Link>
        }
      />
      <EmptyState
        icon={<ShieldAlert className="h-5 w-5" />}
        title="Construcción en curso — Day 4"
        description="Acá irá la tabla de findings con 150+ vulnerabilidades de demo, filtros por severidad, framework y asset, y drawer de detalle con steps to reproduce y remediation recommendations."
      />
    </div>
  );
}
