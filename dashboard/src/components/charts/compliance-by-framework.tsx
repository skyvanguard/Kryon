"use client";

import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import type { Framework } from "@/lib/types";

interface Props {
  frameworks: readonly Framework[];
}

function colorForPercent(percent: number): string {
  if (percent >= 90) return "var(--success)";
  if (percent >= 75) return "var(--primary)";
  if (percent >= 60) return "var(--warning)";
  return "var(--critical)";
}

export function ComplianceByFramework({ frameworks }: Props) {
  const data = [...frameworks]
    .sort((a, b) => b.compliancePercent - a.compliancePercent)
    .map((f) => ({
      name: f.shortName,
      value: f.compliancePercent,
      passed: f.passedControls,
      total: f.totalControls,
      color: colorForPercent(f.compliancePercent),
    }));

  return (
    <ResponsiveContainer width="100%" height={260}>
      <BarChart
        data={data}
        layout="vertical"
        margin={{ top: 5, right: 40, bottom: 0, left: 0 }}
        barCategoryGap={6}
      >
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="var(--border)"
          horizontal={false}
        />
        <XAxis
          type="number"
          domain={[0, 100]}
          tick={{ fill: "var(--muted-foreground)", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          tickFormatter={(v: number) => `${v}%`}
        />
        <YAxis
          type="category"
          dataKey="name"
          tick={{ fill: "var(--foreground)", fontSize: 11 }}
          axisLine={false}
          tickLine={false}
          width={80}
        />
        <Tooltip content={<CustomTooltip />} cursor={{ fill: "var(--accent)" }} />
        <Bar dataKey="value" radius={[0, 6, 6, 0]}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}

interface TooltipPayload {
  payload: {
    name: string;
    value: number;
    passed: number;
    total: number;
    color: string;
  };
}

function CustomTooltip({
  active,
  payload,
}: {
  active?: boolean;
  payload?: TooltipPayload[];
}) {
  if (!active || !payload?.length) return null;
  const d = payload[0].payload;
  return (
    <div className="rounded-md border border-border/80 bg-popover/95 px-3 py-2 text-xs shadow-xl backdrop-blur-sm">
      <p className="mb-1 font-medium text-foreground">{d.name}</p>
      <div className="flex items-center gap-2">
        <span
          className="h-2 w-2 rounded-sm"
          style={{ background: d.color }}
        />
        <span className="font-mono text-foreground">
          {d.value}% · {d.passed}/{d.total} controles
        </span>
      </div>
    </div>
  );
}
