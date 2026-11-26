import type { Severity } from "../../features/greybox/types";

// The ONE severity chip (Findings table, finding detail, Defenses, Overview counts).
// Colour is paired with the text label, never colour alone.
const TONE: Record<Severity, { chip: string; dot: string }> = {
  critical: { chip: "border-severity-critical/40 text-severity-critical", dot: "bg-severity-critical" },
  high: { chip: "border-severity-high/40 text-severity-high", dot: "bg-severity-high" },
  medium: { chip: "border-severity-medium/40 text-severity-medium", dot: "bg-severity-medium" },
  low: { chip: "border-severity-low/40 text-severity-low", dot: "bg-severity-low" },
  info: { chip: "border-severity-info/40 text-severity-info", dot: "bg-slate/50" },
};

export function SeverityChip({ severity, className = "" }: { severity: Severity | string; className?: string }) {
  const t = TONE[severity as Severity] ?? TONE.info;
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 text-[11px] font-semibold uppercase leading-5 ${t.chip} ${className}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${t.dot}`} aria-hidden="true" />
      {severity}
    </span>
  );
}
