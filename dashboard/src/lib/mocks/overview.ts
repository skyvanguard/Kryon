import type { OverviewKpis, TimeseriesPoint, Severity } from "../types";

// Deterministic pseudo-random so the dashboard looks stable across refreshes
// (no point in showing users a different score every time they F5).
function mulberry32(seed: number): () => number {
  let a = seed;
  return () => {
    a |= 0;
    a = (a + 0x6d2b79f5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

function scoreToGrade(value: number): OverviewKpis["securityScore"]["grade"] {
  if (value >= 95) return "A+";
  if (value >= 88) return "A";
  if (value >= 78) return "B";
  if (value >= 68) return "C";
  if (value >= 55) return "D";
  return "F";
}

export function getOverviewKpis(): OverviewKpis {
  const securityScore = 82;
  return {
    securityScore: {
      value: securityScore,
      grade: scoreToGrade(securityScore),
      trend: { direction: "up", percentChange: 3, weekOverWeek: 3 },
    },
    assets: {
      total: 347,
      tier1: 42,
      monitored: 347,
      trend: { direction: "up", percentChange: 3.5, weekOverWeek: 12 },
    },
    findings: {
      openTotal: 28,
      bySeverity: {
        critical: 2,
        high: 7,
        medium: 11,
        low: 6,
        info: 2,
      },
      trend: { direction: "down", percentChange: -15, weekOverWeek: -5 },
    },
    compliance: {
      averagePercent: 82,
      frameworksCovered: 9,
      trend: { direction: "up", percentChange: 4, weekOverWeek: 3 },
    },
  };
}

const SEVERITIES: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
  "info",
] as const;

/**
 * 30-day findings timeseries. The curve tells a story: a bump around day 18
 * where a new scan caught a wave of findings, then a steady downward trend
 * as remediation kicks in — exactly the narrative we want in the demo.
 */
export function getFindingsTimeseries(days = 30): TimeseriesPoint[] {
  const rng = mulberry32(42);
  const points: TimeseriesPoint[] = [];
  const today = new Date();
  today.setHours(0, 0, 0, 0);

  for (let i = days - 1; i >= 0; i--) {
    const date = new Date(today);
    date.setDate(date.getDate() - i);

    const dayFromStart = days - 1 - i;
    // Base level that declines over time
    const baseline = 18 - (dayFromStart / days) * 6;
    // Bump around day 10 (when the scan cycle kicked in)
    const bump = Math.max(0, 6 - Math.abs(dayFromStart - 10)) * 1.5;
    const noise = (rng() - 0.5) * 3;
    const total = Math.max(5, Math.round(baseline + bump + noise));

    // Distribute across severities with natural proportions
    const critical = Math.max(0, Math.round(total * 0.08 + (rng() - 0.5) * 1.5));
    const high = Math.max(0, Math.round(total * 0.22 + (rng() - 0.5) * 2));
    const medium = Math.max(0, Math.round(total * 0.38 + (rng() - 0.5) * 2));
    const low = Math.max(0, Math.round(total * 0.22 + (rng() - 0.5) * 2));
    const info = Math.max(0, total - critical - high - medium - low);

    points.push({
      date: date.toISOString().slice(0, 10),
      critical,
      high,
      medium,
      low,
      info,
    });
  }

  return points;
}

export const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "var(--critical)",
  high: "oklch(0.68 0.2 45)", // orange
  medium: "var(--warning)",
  low: "var(--chart-5)", // violet
  info: "var(--primary)", // cyan
};

export const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "Crítica",
  high: "Alta",
  medium: "Media",
  low: "Baja",
  info: "Info",
};

export { SEVERITIES };
