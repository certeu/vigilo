// A small status indicator. Quiet by default; the one live signal is the pulsing
// accent dot for a running job.
const MAP: Record<string, string> = {
  queued: "bg-slate/40",
  preparing: "bg-accent/60",
  running: "bg-accent",
  succeeded: "bg-emerald-600",
  failed: "bg-severity-critical",
  cancelled: "bg-slate/50",
};

export function StatusDot({ status }: { status: string }) {
  const color = MAP[status] ?? "bg-slate/40";
  const pulse = status === "running" || status === "preparing";
  return (
    <span className="relative inline-flex h-2.5 w-2.5" title={status}>
      {pulse && (
        <span
          className={`absolute inline-flex h-full w-full animate-ping rounded-full ${color} opacity-60`}
        />
      )}
      <span className={`relative inline-flex h-2.5 w-2.5 rounded-full ${color}`} />
    </span>
  );
}
