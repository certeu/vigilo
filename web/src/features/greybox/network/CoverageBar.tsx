import { coverageSummary, type AssetGraphState } from "./model";

/** Tested / in-scope endpoints. The definition is shown on hover and to screen readers. */
export function CoverageBar({ graph }: { graph: Pick<AssetGraphState, "coverage" | "nodes"> }) {
  const c = coverageSummary(graph);
  return (
    <div className="flex min-w-[220px] flex-1 items-center gap-2 text-[13px]" title={c.definition}>
      <span className="shrink-0 font-medium text-ink">Coverage</span>
      <span
        className="h-2 min-w-[80px] flex-1 overflow-hidden rounded-full bg-line"
        role="progressbar"
        aria-label="Endpoint coverage"
        aria-valuemin={0}
        aria-valuemax={100}
        aria-valuenow={c.percent ?? 0}
        aria-valuetext={c.percent === null ? "No in-scope endpoints yet" : `${c.tested} of ${c.inScope} in-scope endpoints tested (${c.percent}%)`}
      >
        <span className="block h-full bg-emerald-600 transition-[width] duration-500" style={{ width: `${c.percent ?? 0}%` }} />
      </span>
      <span className="shrink-0 tabular-nums text-slate">
        {c.inScope === 0 ? "no in-scope endpoints yet" : `${c.tested}/${c.inScope} endpoints tested (${c.percent}%)`}
      </span>
      <span className="sr-only">{c.definition}</span>
    </div>
  );
}
