"use client";

import { Cell, Pie, PieChart, ResponsiveContainer } from "recharts";
import { SEVERITIES, SEVERITY_COLORS, SEVERITY_LABELS } from "@/lib/mocks/overview";
import type { Severity } from "@/lib/types";

interface Props {
  bySeverity: Record<Severity, number>;
}

export function FindingsBySeverity({ bySeverity }: Props) {
  const data = SEVERITIES.map((sev) => ({
    id: sev,
    label: SEVERITY_LABELS[sev],
    value: bySeverity[sev],
    color: SEVERITY_COLORS[sev],
  })).filter((item) => item.value > 0);

  const total = data.reduce((sum, d) => sum + d.value, 0);

  return (
    <div className="flex h-full flex-col">
      <div className="relative flex flex-1 items-center justify-center">
        <ResponsiveContainer width="100%" height={180}>
          <PieChart>
            <Pie
              data={data}
              dataKey="value"
              innerRadius={58}
              outerRadius={82}
              paddingAngle={2}
              startAngle={90}
              endAngle={-270}
              stroke="var(--card)"
              strokeWidth={2}
            >
              {data.map((entry) => (
                <Cell key={entry.id} fill={entry.color} />
              ))}
            </Pie>
          </PieChart>
        </ResponsiveContainer>
        <div className="pointer-events-none absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-2xl font-semibold tabular-nums">
            {total}
          </span>
          <span className="mt-0.5 text-[10px] font-medium uppercase tracking-wider text-muted-foreground">
            abiertos
          </span>
        </div>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-1.5">
        {data.map((entry) => {
          const percent = Math.round((entry.value / total) * 100);
          return (
            <div
              key={entry.id}
              className="flex items-center justify-between gap-3 text-xs"
            >
              <div className="flex min-w-0 items-center gap-2">
                <span
                  className="h-2 w-2 shrink-0 rounded-sm"
                  style={{ background: entry.color }}
                />
                <span className="truncate text-muted-foreground">
                  {entry.label}
                </span>
              </div>
              <div className="flex shrink-0 items-center gap-2 font-mono tabular-nums">
                <span className="text-foreground">{entry.value}</span>
                <span className="w-9 text-right text-[10px] text-muted-foreground">
                  {percent}%
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
