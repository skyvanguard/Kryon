"use client";

import { usePathname } from "next/navigation";
import { Bell, Search, ChevronRight } from "lucide-react";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { resolveActiveNav } from "./nav-items";

export function Topbar() {
  const pathname = usePathname();
  const active = resolveActiveNav(pathname);

  return (
    <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-border/60 bg-background/80 px-5 backdrop-blur-md">
      {/* Breadcrumb */}
      <nav
        className="flex items-center gap-1.5 text-sm text-muted-foreground"
        aria-label="Breadcrumb"
      >
        <span className="font-medium text-foreground">Kryon</span>
        <ChevronRight className="h-3.5 w-3.5" />
        <span className="text-foreground">{active?.label ?? "Dashboard"}</span>
      </nav>

      <div className="ml-auto flex items-center gap-2">
        {/* Global search — decorative for MVP */}
        <div className="relative hidden w-72 sm:block">
          <Search className="pointer-events-none absolute left-2.5 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-muted-foreground" />
          <Input
            type="search"
            placeholder="Buscar finding, asset, reporte…"
            className="h-8 pl-8 text-xs"
            aria-label="Buscar"
          />
          <kbd className="pointer-events-none absolute right-2 top-1/2 hidden -translate-y-1/2 select-none rounded border border-border/60 bg-muted px-1 font-mono text-[9px] text-muted-foreground sm:inline-flex">
            ⌘K
          </kbd>
        </div>

        {/* Notifications */}
        <Button variant="ghost" size="icon" aria-label="Notificaciones">
          <Bell className="h-4 w-4" />
          <Badge
            variant="destructive"
            className="absolute -right-0.5 -top-0.5 h-3 min-w-3 border-background p-0 font-mono text-[9px]"
          >
            3
          </Badge>
        </Button>
      </div>
    </header>
  );
}
