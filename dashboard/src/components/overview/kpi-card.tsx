import type { LucideIcon } from "lucide-react";
import { ArrowDownRight, ArrowUpRight, Minus } from "lucide-react";
import { cn } from "@/lib/utils";
import { Card, CardContent } from "@/components/ui/card";
import type { KpiTrend } from "@/lib/types";

export interface KpiCardProps {
  label: string;
  value: string | number;
  unit?: string;
  icon: LucideIcon;
  trend?: KpiTrend;
  // "inverse" metrics where lower is better (e.g., open findings)
  inverseTrend?: boolean;
  hint?: string;
  className?: string;
}

export function KpiCard({
  label,
  value,
  unit,
  icon: Icon,
  trend,
  inverseTrend = false,
  hint,
  className,
}: KpiCardProps) {
  return (
    <Card className={cn("relative overflow-hidden", className)}>
      <CardContent className="p-5">
        <div className="flex items-start justify-between gap-3">
          <div className="space-y-1">
            <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
              {label}
            </p>
            <div className="flex items-baseline gap-1">
              <p className="font-mono text-3xl font-semibold tabular-nums">
                {value}
              </p>
              {unit ? (
                <span className="text-sm font-medium text-muted-foreground">
                  {unit}
                </span>
              ) : null}
            </div>
          </div>
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-primary/10 text-primary">
            <Icon className="h-4 w-4" />
          </div>
        </div>

        {trend ? (
          <div className="mt-3 flex items-center gap-2 text-xs">
            <TrendPill trend={trend} inverse={inverseTrend} />
            {hint ? (
              <span className="text-muted-foreground">{hint}</span>
            ) : null}
          </div>
        ) : hint ? (
          <p className="mt-3 text-xs text-muted-foreground">{hint}</p>
        ) : null}
      </CardContent>
    </Card>
  );
}

function TrendPill({ trend, inverse }: { trend: KpiTrend; inverse: boolean }) {
  const Icon =
    trend.direction === "up"
      ? ArrowUpRight
      : trend.direction === "down"
        ? ArrowDownRight
        : Minus;

  // Semantic tint — "up" means good unless the metric is inverse (then "down" is good).
  const isGood = inverse
    ? trend.direction === "down"
    : trend.direction === "up";

  const tone =
    trend.direction === "flat"
      ? "text-muted-foreground"
      : isGood
        ? "text-[var(--success)]"
        : "text-[var(--critical)]";

  const bg =
    trend.direction === "flat"
      ? "bg-muted"
      : isGood
        ? "bg-[var(--success)]/10"
        : "bg-[var(--critical)]/10";

  return (
    <span
      className={cn(
        "inline-flex items-center gap-0.5 rounded-md px-1.5 py-0.5 font-mono text-[10px] font-medium tabular-nums",
        tone,
        bg
      )}
    >
      <Icon className="h-3 w-3" />
      {trend.percentChange > 0 ? "+" : ""}
      {trend.percentChange}%
    </span>
  );
}
