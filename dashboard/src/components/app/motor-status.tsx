import { Clock } from "lucide-react";
import { probeHealth } from "@/lib/data/health";
import { cn } from "@/lib/utils";

/**
 * Server component that probes the real backend once per request and
 * renders a colored pill: green when /health returns ok, amber for
 * degraded, red for unhealthy, muted when running in demo mode (no URL).
 *
 * Used inside the sidebar so the operator always sees at a glance whether
 * the product is talking to a real engine or showing mock data.
 */
export async function MotorStatus() {
  const health = await probeHealth();

  const tone =
    health.status === "ok"
      ? "text-[var(--success)]"
      : health.status === "degraded"
        ? "text-[var(--warning)]"
        : health.status === "demo"
          ? "text-muted-foreground"
          : "text-[var(--critical)]";

  const label =
    health.status === "ok"
      ? "Motor activo"
      : health.status === "degraded"
        ? "Motor degradado"
        : health.status === "demo"
          ? "Modo demo"
          : "Motor offline";

  const dotColor =
    health.status === "ok"
      ? "var(--success)"
      : health.status === "degraded"
        ? "var(--warning)"
        : health.status === "demo"
          ? "var(--muted-foreground)"
          : "var(--critical)";

  return (
    <div className="flex items-center gap-2 rounded-md border border-sidebar-border bg-card/50 px-2.5 py-1.5 text-xs">
      <span className="relative flex h-2 w-2">
        {health.status === "ok" ? (
          <span
            className="absolute inline-flex h-full w-full animate-ping rounded-full opacity-75"
            style={{ background: dotColor }}
          />
        ) : null}
        <span
          className="relative inline-flex h-2 w-2 rounded-full"
          style={{ background: dotColor }}
        />
      </span>
      <span className={cn("truncate", tone)} title={`v${health.version}`}>
        {label}
      </span>
      <Clock className="ml-auto h-3 w-3 text-muted-foreground" />
      <span className="font-mono text-[10px] text-muted-foreground">24/7</span>
    </div>
  );
}
