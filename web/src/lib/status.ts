// One sentence-case label map for every run / analysis status (white-box and
// grey-box). StatusBadge, StatusDot and the filters all read from here.
export const STATUS_LABEL: Record<string, string> = {
  queued: "Queued",
  preparing: "Preparing",
  running: "Running",
  cancelling: "Cancelling",
  succeeded: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function statusLabel(status: string | null | undefined): string {
  if (!status) return "—";
  const known = STATUS_LABEL[status];
  if (known) return known;
  const s = status.replace(/[_-]+/g, " ").trim();
  return s.charAt(0).toUpperCase() + s.slice(1).toLowerCase();
}
