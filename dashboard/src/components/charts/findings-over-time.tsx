"use client";

import {
  Area,
  AreaChart,
  CartesianGrid,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { format, parseISO } from "date-fns";
import { es } from "date-fns/locale";
import { SEVERITIES, SEVERITY_COLORS, SEVERITY_LABELS } from "@/lib/mocks/overview";
import type { TimeseriesPoint } from "@/lib/types";

interface Props {
  data: readonly TimeseriesPoint[];
}

export function FindingsOverTime({ data }: Props) {
  return (
    <ResponsiveContainer width="100%" height={240}>
      <AreaChart
        data={[...data]}
        margin={{ top: 5, right: 10, bottom: 0, left: -20 }}
      >
        <defs>
          {SEVERITIES.map((sev) => (
            <linearGradient
              key={sev}
              id={`gradient-${sev}`}
              x1="0"
              y1="0"
              x2="0"
              y2="1"
            >
              <stop
                offset="0%"
                stopColor={SEVERITY_COLORS[sev]}
                stopOpacity={0.55}
              />
              <stop
                offset="100%"
                stopColor={SEVERITY_COLORS[sev]}
                stopOpacity={0.02}
              />
            </linearGradient>
          ))}
        </defs>
        <CartesianGrid
          strokeDasharray="3 3"
          stroke="var(--border)"
          vertical={false}
        />
        <XAxis
          dataKey="date"
          tick={{ fill: "var(--muted-foreground)", fontSize: 10 }}
          tickFormatter={(value: string) =>
            format(parseISO(value), "d MMM", { locale: es })
          }
          axisLine={false}
          tickLine={false}
          interval="preserveStartEnd"
          minTickGap={32}
        />
        <YAxis
          tick={{ fill: "var(--muted-foreground)", fontSize: 10 }}
          axisLine={false}
          tickLine={false}
          width={40}
        />
        <Tooltip
          content={<CustomTooltip />}
          cursor={{ stroke: "var(--border)", strokeWidth: 1 }}
        />
        {SEVERITIES.map((sev) => (
          <Area
            key={sev}
            type="monotone"
            dataKey={sev}
            stackId="1"
            stroke={SEVERITY_COLORS[sev]}
            strokeWidth={1.5}
            fill={`url(#gradient-${sev})`}
            name={SEVERITY_LABELS[sev]}
          />
        ))}
      </AreaChart>
    </ResponsiveContainer>
  );
}

interface TooltipPayload {
  value: number;
  dataKey: string;
  color: string;
  name: string;
}

function CustomTooltip({
  active,
  payload,
  label,
}: {
  active?: boolean;
  payload?: TooltipPayload[];
  label?: string;
}) {
  if (!active || !payload?.length || !label) return null;
  const total = payload.reduce((sum, p) => sum + p.value, 0);

  return (
    <div className="rounded-md border border-border/80 bg-popover/95 px-3 py-2 text-xs shadow-xl backdrop-blur-sm">
      <p className="mb-1.5 font-mono text-[10px] uppercase tracking-wider text-muted-foreground">
        {format(parseISO(label), "d MMM yyyy", { locale: es })}
      </p>
      <div className="space-y-0.5">
        {[...payload].reverse().map((entry) => (
          <div
            key={entry.dataKey}
            className="flex items-center justify-between gap-4"
          >
            <div className="flex items-center gap-1.5">
              <span
                className="h-2 w-2 rounded-sm"
                style={{ background: entry.color }}
              />
              <span className="text-foreground">{entry.name}</span>
            </div>
            <span className="font-mono tabular-nums text-foreground">
              {entry.value}
            </span>
          </div>
        ))}
      </div>
      <div className="mt-1.5 flex items-center justify-between border-t border-border/60 pt-1.5">
        <span className="text-muted-foreground">Total</span>
        <span className="font-mono font-medium tabular-nums">{total}</span>
      </div>
    </div>
  );
}
