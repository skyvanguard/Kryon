import { formatDistanceToNow, parseISO } from "date-fns";
import { es } from "date-fns/locale";
import { ChevronRight, CheckCircle2, XCircle, Clock } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";
import type { Framework } from "@/lib/types";

function toneForPercent(percent: number): {
  bar: string;
  badge: string;
  label: string;
} {
  if (percent >= 90)
    return {
      bar: "[&>div]:bg-[var(--success)]",
      badge:
        "border-[var(--success)]/40 bg-[var(--success)]/10 text-[var(--success)]",
      label: "Conforme",
    };
  if (percent >= 75)
    return {
      bar: "[&>div]:bg-primary",
      badge: "border-primary/40 bg-primary/10 text-primary",
      label: "Parcial",
    };
  if (percent >= 60)
    return {
      bar: "[&>div]:bg-[var(--warning)]",
      badge:
        "border-[var(--warning)]/40 bg-[var(--warning)]/10 text-[var(--warning)]",
      label: "Atención",
    };
  return {
    bar: "[&>div]:bg-[var(--critical)]",
    badge:
      "border-[var(--critical)]/40 bg-[var(--critical)]/10 text-[var(--critical)]",
    label: "No conforme",
  };
}

export function FrameworkCard({ framework }: { framework: Framework }) {
  const tone = toneForPercent(framework.compliancePercent);

  return (
    <Card className="group/framework relative cursor-pointer overflow-hidden transition-all hover:border-primary/40 hover:shadow-lg">
      <CardContent className="p-5">
        <div className="mb-3 flex items-start justify-between gap-3">
          <div className="min-w-0 space-y-1">
            <p className="font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              {framework.shortName}
            </p>
            <h3 className="truncate text-sm font-semibold tracking-tight">
              {framework.name}
            </h3>
          </div>
          <Badge
            variant="outline"
            className={cn("shrink-0 font-mono text-[10px]", tone.badge)}
          >
            {tone.label}
          </Badge>
        </div>

        <div className="mb-2 flex items-baseline gap-1">
          <span className="font-mono text-3xl font-semibold tabular-nums">
            {framework.compliancePercent}
          </span>
          <span className="text-sm text-muted-foreground">%</span>
        </div>

        <Progress
          value={framework.compliancePercent}
          className={cn("h-1.5", tone.bar)}
        />

        <div className="mt-3 flex items-center justify-between gap-2 text-[10px]">
          <div className="flex items-center gap-3 text-muted-foreground">
            <span className="flex items-center gap-1">
              <CheckCircle2 className="h-3 w-3 text-[var(--success)]" />
              <span className="font-mono tabular-nums">
                {framework.passedControls}
              </span>
            </span>
            <span className="flex items-center gap-1">
              <XCircle className="h-3 w-3 text-[var(--critical)]" />
              <span className="font-mono tabular-nums">
                {framework.failedControls}
              </span>
            </span>
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              <span>
                {formatDistanceToNow(parseISO(framework.lastEvaluatedAt), {
                  addSuffix: true,
                  locale: es,
                })}
              </span>
            </span>
          </div>
          <ChevronRight className="h-3.5 w-3.5 text-muted-foreground transition-transform group-hover/framework:translate-x-0.5 group-hover/framework:text-primary" />
        </div>

        <p className="mt-3 line-clamp-1 text-[11px] text-muted-foreground">
          {framework.description}
        </p>
      </CardContent>
    </Card>
  );
}
