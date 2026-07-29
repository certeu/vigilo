// Severity ramp (spec §16) — desaturated, used ONLY for severity data viz.
export const SEVERITY_ORDER = [
  "critical",
  "high",
  "medium",
  "low",
  "informational",
] as const;

export const SEVERITY_COLORS: Record<string, string> = {
  critical: "#B4232C",
  high: "#C2410C",
  medium: "#B45309",
  low: "#4B5563",
  informational: "#8A93A3",
};

export const ACCENT = "#3B5BDB";

export function severityData(counts: Record<string, number>) {
  return SEVERITY_ORDER.map((s) => ({
    name: s[0].toUpperCase() + s.slice(1),
    key: s,
    value: counts[s] ?? 0,
    color: SEVERITY_COLORS[s],
  })).filter((d) => d.value > 0);
}
