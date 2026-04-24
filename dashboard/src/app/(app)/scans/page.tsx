import Link from "next/link";
import { Radar, Plus } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/app/page-header";
import { buttonVariants } from "@/components/ui/button";

export const metadata = { title: "Escaneos" };

export default function ScansPage() {
  return (
    <div>
      <PageHeader
        title="Escaneos"
        description="Historial completo y escaneos en ejecución. Podés lanzar nuevos escaneos con targets específicos, skills activas y programación."
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
        icon={<Radar className="h-5 w-5" />}
        title="Construcción en curso — Day 5"
        description="Acá irá la lista de escaneos con estado, duración, # de findings producidos, logs en vivo para los que corran y el modal de configuración para lanzar nuevos."
      />
    </div>
  );
}
