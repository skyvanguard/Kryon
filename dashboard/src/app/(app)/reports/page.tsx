import { FileText, Plus } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/app/page-header";
import { Button } from "@/components/ui/button";

export const metadata = { title: "Reportes" };

export default function ReportsPage() {
  return (
    <div>
      <PageHeader
        title="Reportes"
        description="Documentos ejecutivos y técnicos generados. Todos los reportes incluyen hash criptográfico de reproducibilidad."
        actions={
          <Button size="sm">
            <Plus className="h-3.5 w-3.5" />
            Generar reporte
          </Button>
        }
      />
      <EmptyState
        icon={<FileText className="h-5 w-5" />}
        title="Construcción en curso — Day 6"
        description="Acá irá la grilla de reportes con thumbnails, filtros por framework y asset, y el modal de generación con selección de template, formato (PDF/HTML/JSON) y alcance."
      />
    </div>
  );
}
