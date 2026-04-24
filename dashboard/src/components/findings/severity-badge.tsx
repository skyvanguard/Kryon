import { cn } from "@/lib/utils";
import { SEVERITY_LABELS } from "@/lib/mocks/overview";
import type { Severity } from "@/lib/types";

const STYLES: Record<Severity, string> = {
  critical:
    "bg-[var(--critical)]/15 text-[var(--critical)] border-[var(--critical)]/40",
  high: "bg-[oklch(0.68_0.2_45)]/15 text-[oklch(0.68_0.2_45)] border-[oklch(0.68_0.2_45)]/40",
  medium:
    "bg-[var(--warning)]/15 text-[var(--warning)] border-[var(--warning)]/40",
  low: "bg-[var(--chart-5)]/15 text-[var(--chart-5)] border-[var(--chart-5)]/40",
  info: "bg-primary/15 text-primary border-primary/40",
};

export function SeverityBadge({
  severity,
  className,
}: {
  severity: Severity;
  className?: string;
}) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 font-mono text-[10px] font-medium uppercase tracking-wider",
        STYLES[severity],
        className
      )}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: "currentColor" }}
      />
      {SEVERITY_LABELS[severity]}
    </span>
  );
}
