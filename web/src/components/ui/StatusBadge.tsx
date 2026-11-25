import { StatusDot } from "../StatusDot";
import { statusLabel } from "../../lib/status";

// Run status as dot + text (the text carries the meaning; the dot is decoration).
// The text comes from the shared label map; `label` overrides it when needed.
export function StatusBadge({ status, label }: { status: string; label?: string }) {
  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap">
      <StatusDot status={status} />
      <span className="text-slate">{label ?? statusLabel(status)}</span>
    </span>
  );
}
