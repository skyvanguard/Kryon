import { Settings } from "lucide-react";
import { PageHeader, EmptyState } from "@/components/app/page-header";

export const metadata = { title: "Ajustes" };

export default function SettingsPage() {
  return (
    <div>
      <PageHeader
        title="Ajustes"
        description="Configuración de la plataforma, usuarios, integraciones, API keys y preferencias de notificación."
      />
      <EmptyState
        icon={<Settings className="h-5 w-5" />}
        title="Construcción en curso — Day 6"
        description="Acá irán los tabs de General, Usuarios, Integraciones y API Keys. Para el MVP el foco estará en General; el resto queda marcado como 'próximamente'."
      />
    </div>
  );
}
