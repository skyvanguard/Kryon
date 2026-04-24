import { ShieldCheck, TrendingUp } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import type { OverviewKpis } from "@/lib/types";

/**
 * Hero card with the composite security score.
 * Renders a large circular progress ring around the score number, which
 * visually dominates the overview and anchors the whole page.
 */
export function SecurityScoreCard({
  score,
}: {
  score: OverviewKpis["securityScore"];
}) {
  const radius = 72;
  const circumference = 2 * Math.PI * radius;
  const progress = (score.value / 100) * circumference;

  const gradeTone =
    score.value >= 88
      ? "var(--success)"
      : score.value >= 68
        ? "var(--primary)"
        : score.value >= 55
          ? "var(--warning)"
          : "var(--critical)";

  return (
    <Card className="relative overflow-hidden lg:col-span-2">
      {/* subtle gradient accent */}
      <div
        className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full opacity-20 blur-3xl"
        style={{ background: gradeTone }}
        aria-hidden
      />

      <CardContent className="relative flex items-center gap-6 p-6">
        <div className="relative flex h-44 w-44 shrink-0 items-center justify-center">
          <svg className="h-full w-full -rotate-90" viewBox="0 0 180 180">
            <circle
              cx="90"
              cy="90"
              r={radius}
              fill="none"
              stroke="var(--border)"
              strokeWidth="10"
            />
            <circle
              cx="90"
              cy="90"
              r={radius}
              fill="none"
              stroke={gradeTone}
              strokeWidth="10"
              strokeLinecap="round"
              strokeDasharray={circumference}
              strokeDashoffset={circumference - progress}
              style={{
                transition: "stroke-dashoffset 1.2s cubic-bezier(0.65,0,0.35,1)",
              }}
            />
          </svg>
          <div className="absolute inset-0 flex flex-col items-center justify-center">
            <span className="font-mono text-5xl font-semibold tabular-nums">
              {score.value}
            </span>
            <span className="mt-0.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
              de 100
            </span>
          </div>
        </div>

        <div className="min-w-0 space-y-3">
          <div className="space-y-1">
            <div className="flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" />
              <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">
                Security score
              </p>
              <Badge
                variant="outline"
                className="border-primary/40 font-mono text-[10px] text-primary"
              >
                {score.grade}
              </Badge>
            </div>
            <h2 className="text-xl font-semibold tracking-tight">
              Tu postura de seguridad es{" "}
              {score.value >= 88
                ? "excelente"
                : score.value >= 68
                  ? "sólida"
                  : score.value >= 55
                    ? "mejorable"
                    : "crítica"}
            </h2>
          </div>

          <p className="text-sm text-muted-foreground">
            Promedio ponderado de compliance multi-framework, tasa de
            remediación, cobertura de activos y exposición crítica.
          </p>

          <div className="flex items-center gap-2 text-xs">
            <TrendingUp className="h-3.5 w-3.5 text-[var(--success)]" />
            <span className="font-mono tabular-nums text-[var(--success)]">
              +{score.trend.percentChange} pts
            </span>
            <span className="text-muted-foreground">vs. semana anterior</span>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}
