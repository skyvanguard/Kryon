import type { LucideIcon } from "lucide-react";
import {
  LayoutDashboard,
  ShieldAlert,
  FileCheck2,
  Radar,
  FileText,
  Settings,
} from "lucide-react";

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  description: string;
}

export const NAV_ITEMS: readonly NavItem[] = [
  {
    href: "/overview",
    label: "Overview",
    icon: LayoutDashboard,
    description: "Vista general del estado de seguridad",
  },
  {
    href: "/findings",
    label: "Findings",
    icon: ShieldAlert,
    description: "Vulnerabilidades detectadas",
  },
  {
    href: "/compliance",
    label: "Compliance",
    icon: FileCheck2,
    description: "9 frameworks de cumplimiento",
  },
  {
    href: "/scans",
    label: "Escaneos",
    icon: Radar,
    description: "Historial y escaneos en curso",
  },
  {
    href: "/reports",
    label: "Reportes",
    icon: FileText,
    description: "Documentos ejecutivos y técnicos",
  },
  {
    href: "/settings",
    label: "Ajustes",
    icon: Settings,
    description: "Configuración y usuarios",
  },
] as const;

export function resolveActiveNav(pathname: string): NavItem | undefined {
  return NAV_ITEMS.find(
    (item) => pathname === item.href || pathname.startsWith(`${item.href}/`)
  );
}
