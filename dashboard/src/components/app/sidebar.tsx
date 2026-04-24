"use client";

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useTransition } from "react";
import { Zap, LogOut, Plus, ChevronsUpDown } from "lucide-react";
import { cn } from "@/lib/utils";
import { Badge } from "@/components/ui/badge";
import { Separator } from "@/components/ui/separator";
import { buttonVariants } from "@/components/ui/button";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuLabel,
  DropdownMenuSeparator,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import { NAV_ITEMS } from "./nav-items";
import type { AuthSession } from "@/lib/auth";
import { logoutAction } from "@/app/login/actions";

export interface SidebarProps {
  session: AuthSession;
  /** Server-rendered status pill (e.g. backend health). Optional. */
  statusSlot?: React.ReactNode;
}

export function Sidebar({ session, statusSlot }: SidebarProps) {
  const pathname = usePathname();
  const router = useRouter();
  const [, startTransition] = useTransition();

  return (
    <aside className="hidden h-screen w-64 shrink-0 flex-col border-r border-sidebar-border bg-sidebar md:flex">
      {/* Brand */}
      <div className="flex h-14 items-center gap-2 px-4">
        <div className="flex h-7 w-7 items-center justify-center rounded-md bg-primary text-primary-foreground">
          <Zap className="h-4 w-4" strokeWidth={2.5} />
        </div>
        <div className="flex flex-1 items-center gap-1.5">
          <span className="font-sans text-sm font-semibold tracking-tight text-sidebar-foreground">
            Kryon
          </span>
          <Badge
            variant="outline"
            className="h-4 border-sidebar-border px-1 font-mono text-[9px] text-muted-foreground"
          >
            v2.1
          </Badge>
        </div>
      </div>

      <Separator className="bg-sidebar-border" />

      {/* Primary CTA */}
      <div className="p-3">
        <Link
          href="/scans?new=1"
          className={cn(
            buttonVariants({ size: "sm" }),
            "w-full justify-center gap-1.5"
          )}
        >
          <Plus className="h-3.5 w-3.5" />
          Nuevo escaneo
        </Link>
      </div>

      {/* Primary nav */}
      <nav className="flex-1 space-y-0.5 overflow-y-auto px-2 pb-3">
        <p className="mb-2 px-2 text-[10px] font-semibold uppercase tracking-wider text-muted-foreground">
          Plataforma
        </p>
        {NAV_ITEMS.map((item) => {
          const active =
            pathname === item.href || pathname.startsWith(`${item.href}/`);
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              aria-current={active ? "page" : undefined}
              className={cn(
                "group/nav flex items-center gap-2.5 rounded-md px-2.5 py-1.5 text-sm transition-colors",
                active
                  ? "bg-sidebar-accent text-sidebar-accent-foreground"
                  : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-sidebar-accent-foreground"
              )}
            >
              <Icon
                className={cn(
                  "h-4 w-4 shrink-0 transition-colors",
                  active
                    ? "text-primary"
                    : "text-muted-foreground group-hover/nav:text-foreground"
                )}
                strokeWidth={active ? 2.2 : 2}
              />
              <span className={cn(active && "font-medium")}>{item.label}</span>
            </Link>
          );
        })}
      </nav>

      <Separator className="bg-sidebar-border" />

      {/* Status pill — server-rendered in layout when provided */}
      {statusSlot ? <div className="px-3 py-3">{statusSlot}</div> : null}

      {/* User menu */}
      <div className="p-2">
        <DropdownMenu>
          <DropdownMenuTrigger
            className={cn(
              "flex w-full items-center gap-2 rounded-md px-2 py-1.5 text-left text-sm transition-colors",
              "hover:bg-sidebar-accent"
            )}
          >
            <Avatar className="h-7 w-7">
              <AvatarFallback className="bg-primary/10 text-[10px] font-semibold text-primary">
                {getInitials(session.name)}
              </AvatarFallback>
            </Avatar>
            <div className="flex-1 truncate">
              <p className="truncate text-xs font-medium">{session.name}</p>
              <p className="truncate text-[10px] text-muted-foreground">
                {session.email}
              </p>
            </div>
            <ChevronsUpDown className="h-3.5 w-3.5 text-muted-foreground" />
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end" side="top" className="w-56">
            <DropdownMenuLabel>
              <div className="flex flex-col gap-0.5">
                <span className="text-xs font-medium">{session.name}</span>
                <span className="text-[10px] font-normal text-muted-foreground">
                  {session.role}
                </span>
              </div>
            </DropdownMenuLabel>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => startTransition(() => router.push("/settings"))}
              className="cursor-pointer"
            >
              Ajustes
            </DropdownMenuItem>
            <DropdownMenuSeparator />
            <DropdownMenuItem
              variant="destructive"
              onClick={() => startTransition(() => logoutAction())}
              className="cursor-pointer"
            >
              <LogOut className="mr-2 h-3.5 w-3.5" />
              Cerrar sesión
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </aside>
  );
}

function getInitials(name: string): string {
  return name
    .split(" ")
    .map((part) => part[0]?.toUpperCase() ?? "")
    .slice(0, 2)
    .join("");
}
