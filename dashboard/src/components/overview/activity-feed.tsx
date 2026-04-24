"use client";

import { formatDistanceToNow, parseISO } from "date-fns";
import { es } from "date-fns/locale";
import {
  AlertTriangle,
  CheckCircle2,
  FileSignature,
  FileText,
  Loader2,
  Plug,
  Radar,
  ShieldAlert,
  User,
  XCircle,
  type LucideIcon,
} from "lucide-react";
import { cn } from "@/lib/utils";
import type { ActivityEvent } from "@/lib/types";

const ICONS: Record<ActivityEvent["type"], { icon: LucideIcon; tone: string }> = {
  scan_started: { icon: Loader2, tone: "text-primary" },
  scan_completed: { icon: Radar, tone: "text-primary" },
  scan_failed: { icon: XCircle, tone: "text-[var(--critical)]" },
  finding_detected: { icon: ShieldAlert, tone: "text-[var(--warning)]" },
  finding_remediated: { icon: CheckCircle2, tone: "text-[var(--success)]" },
  report_generated: { icon: FileText, tone: "text-muted-foreground" },
  compliance_evaluated: { icon: FileSignature, tone: "text-primary" },
  skill_loaded: { icon: Plug, tone: "text-muted-foreground" },
  user_action: { icon: User, tone: "text-muted-foreground" },
};

export function ActivityFeed({ events }: { events: readonly ActivityEvent[] }) {
  return (
    <ol className="space-y-0.5">
      {events.map((event) => (
        <ActivityItem key={event.id} event={event} />
      ))}
    </ol>
  );
}

function ActivityItem({ event }: { event: ActivityEvent }) {
  const meta = ICONS[event.type] ?? { icon: AlertTriangle, tone: "text-muted-foreground" };
  const Icon = meta.icon;
  const spin = event.type === "scan_started";

  return (
    <li className="group/item relative flex gap-3 rounded-lg px-2 py-2 transition-colors hover:bg-muted/40">
      <div
        className={cn(
          "mt-0.5 flex h-7 w-7 shrink-0 items-center justify-center rounded-md border border-border/60 bg-card",
          meta.tone
        )}
      >
        <Icon className={cn("h-3.5 w-3.5", spin && "animate-spin")} />
      </div>

      <div className="min-w-0 flex-1">
        <div className="flex items-baseline justify-between gap-3">
          <p className="truncate text-sm font-medium text-foreground">
            {event.title}
          </p>
          <span
            className="shrink-0 font-mono text-[10px] text-muted-foreground"
            title={event.timestamp}
          >
            {formatDistanceToNow(parseISO(event.timestamp), {
              addSuffix: true,
              locale: es,
            })}
          </span>
        </div>
        {event.description ? (
          <p className="mt-0.5 truncate text-xs text-muted-foreground">
            {event.description}
          </p>
        ) : null}
        {event.actor ? (
          <p className="mt-1 font-mono text-[10px] uppercase tracking-wider text-muted-foreground/80">
            {event.actor}
          </p>
        ) : null}
      </div>
    </li>
  );
}
