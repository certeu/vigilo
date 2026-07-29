// The signature element (spec §16.5). A vertical spine of pipeline phases:
// completed nodes filled, the active node pulses in accent, pending nodes are
// outlined, and a failed run marks the active node in the critical severity hue.
//
// Steps and the phase→step mapping are NOT hardcoded here — they come from the
// backend (`GET /pipeline/trace-rail`, see src/webapi/trace_rail.py) so this stays
// in lockstep with the pipeline's real phase/agent identifiers.

export interface RailPhase {
  key: string;
  label: string;
}

export function TraceRail({
  steps,
  activeKey,
  status,
  selected,
  onSelect,
}: {
  steps: RailPhase[];
  activeKey: string | null;
  status: string;
  selected?: string | null;
  onSelect?: (key: string | null) => void;
}) {
  const terminalDone = status === "succeeded";
  let activeIdx = steps.findIndex((p) => p.key === activeKey);
  if (terminalDone) activeIdx = steps.length; // all complete
  const failed = status === "failed";

  return (
    <ol className="relative flex flex-col gap-1 pl-1">
      {steps.map((p, i) => {
        const done = i < activeIdx;
        const active = i === activeIdx && !terminalDone;
        const isFailedNode = active && failed;
        const isSelected = selected === p.key;
        return (
          <li key={p.key} className="relative">
            <button
              type="button"
              onClick={() => onSelect?.(isSelected ? null : p.key)}
              className={[
                "flex w-full items-center gap-3 rounded-md px-2 py-2 text-left transition",
                isSelected ? "bg-canvas" : "hover:bg-canvas",
              ].join(" ")}
              title="Show logs for this step"
            >
              <span className="relative inline-flex h-4 w-4 items-center justify-center">
                {i < steps.length - 1 && (
                  <span
                    className={`absolute left-[7px] top-5 h-5 w-px ${done ? "bg-accent" : "bg-line"}`}
                  />
                )}
                {active && !failed && (
                  <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-accent opacity-50" />
                )}
                <span
                  className={[
                    "relative h-3.5 w-3.5 rounded-full border",
                    isFailedNode
                      ? "border-severity-critical bg-severity-critical"
                      : done || active
                        ? "border-accent bg-accent"
                        : "border-line bg-surface",
                  ].join(" ")}
                />
              </span>
              <span
                className={[
                  "text-sm",
                  isSelected ? "text-accent font-medium" : done || active ? "text-ink font-medium" : "text-slate",
                ].join(" ")}
              >
                {p.label}
              </span>
            </button>
          </li>
        );
      })}
    </ol>
  );
}
