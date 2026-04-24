import { FileCheck2 } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/app/page-header";

export const metadata = { title: "Compliance" };

export default function CompliancePage() {
  return (
    <div>
      <PageHeader
        title="Compliance"
        description="9 frameworks evaluados en paralelo: PCI-DSS, ISO 27001, CIS, NIST 800-53, GDPR, SOC 2, HIPAA, OWASP y MITRE ATT&CK."
      />
      <EmptyState
        icon={<FileCheck2 className="h-5 w-5" />}
        title="Construcción en curso — Day 5"
        description="Acá irá la grilla de 9 frameworks con % de cumplimiento, controles passed/failed, detalle por control y el botón para descargar el reporte multi-framework con hash de reproducibilidad."
      />
    </div>
  );
}
