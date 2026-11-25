// Presentation data for the Findings column of the analyses list: one entry per
// severity with a non-zero count, in severity order, with colour classes from the
// shared severity tokens (same colours as the SeverityChip used elsewhere).
import type { Severity } from "../../features/greybox/types";

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_NAME: Record<Severity, string> = {
  critical: "Critical", high: "High", medium: "Medium", low: "Low", info: "Info",
};

// Literal class names so the Tailwind JIT keeps them.
export const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "text-severity-critical",
  high: "text-severity-high",
  medium: "text-severity-medium",
  low: "text-severity-low",
  info: "text-severity-info",
};
export const SEVERITY_BG: Record<Severity, string> = {
  critical: "bg-severity-critical",
  high: "bg-severity-high",
  medium: "bg-severity-medium",
  low: "bg-severity-low",
  info: "bg-severity-info",
};

export interface FindingPart {
  severity: Severity;
  count: number;
  textClass: string;
  dotClass: string;
  title: string;
}

export function findingParts(bySeverity: Partial<Record<Severity, number>>): FindingPart[] {
  return SEVERITY_ORDER.filter((s) => (bySeverity[s] ?? 0) > 0).map((s) => {
    const count = bySeverity[s] ?? 0;
    return {
      severity: s,
      count,
      textClass: SEVERITY_TEXT[s],
      dotClass: SEVERITY_BG[s],
      title: `${count} ${SEVERITY_NAME[s].toLowerCase()}`,
    };
  });
}

/** Legend sentence for the column header tooltip. */
export const FINDINGS_LEGEND = "Total findings, then counts per severity: critical, high, medium, low, info (in that order, zero counts hidden).";
