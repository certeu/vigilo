import { useState } from "react";
import { CATEGORY_STYLE, KIND_STYLE, STATUS_CATEGORIES } from "./encoding";
import { KindIcon } from "./KindIcon";
import { NODE_KINDS } from "./types";

/** Collapsible legend: kind (icon + outline), status (glyph + label + colour), link style. */
export function GraphLegend({ defaultOpen = false }: { defaultOpen?: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  return (
    <div className="max-w-[min(560px,calc(100vw-2rem))] rounded-lg border border-line bg-surface/95 px-3 py-2 text-[11px] text-slate shadow-card">
      <button
        type="button"
        className="flex w-full items-center justify-between gap-2 text-[11px] font-semibold text-ink"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
      >
        Legend
        <span aria-hidden="true">{open ? "▾" : "▸"}</span>
      </button>
      {open && (
        <div className="mt-1.5 space-y-1.5">
          <ul className="flex flex-wrap gap-x-3 gap-y-1" aria-label="Node kinds">
            {NODE_KINDS.map((k) => (
              <li key={k} className="inline-flex items-center gap-1" title={KIND_STYLE[k].description}>
                <KindIcon kind={k} size={15} />
                <span className="text-ink/80">{KIND_STYLE[k].label}</span>
              </li>
            ))}
          </ul>
          <ul className="flex flex-wrap gap-x-3 gap-y-1 border-t border-line pt-1.5" aria-label="Live state">
            <li className="inline-flex items-center gap-1" title="Running: pulsing blue ring, spinner, animated edge flowing into it (only while the run is live).">
              <span className="gx-state-running inline-block h-3.5 w-5 rounded-sm border border-accent bg-surface" aria-hidden="true" /> Running
            </li>
            <li className="inline-flex items-center gap-1" title="Pending: decided but not started.">
              <span className="inline-block h-3.5 w-5 rounded-sm border border-dashed border-slate/70 bg-surface" aria-hidden="true" /> Pending
            </li>
            <li className="inline-flex items-center gap-1" title="Done: solid outline.">
              <span className="inline-block h-3.5 w-5 rounded-sm border border-ink/40 bg-surface" aria-hidden="true" /> Done
            </li>
            <li className="inline-flex items-center gap-1" title="Failed or blocked.">
              <span className="inline-block h-3.5 w-5 rounded-sm border border-severity-critical bg-red-50" aria-hidden="true" /> Failed
            </li>
            <li className="inline-flex items-center gap-1" title="Superseded, refuted, skipped: muted but still readable.">
              <span className="inline-block h-3.5 w-5 rounded-sm border border-dashed border-slate/60 bg-canvas" aria-hidden="true" /> Superseded / refuted
            </li>
            <li className="inline-flex items-center gap-1" title="The agent's current reasoning cycle. Pulses indigo while it waits for the model.">
              <span className="gx-state-current inline-block h-3.5 w-5 rounded-sm border border-indigo-700 bg-surface" aria-hidden="true" /> Current cycle / thinking
            </li>
          </ul>
          <ul className="flex flex-wrap gap-x-2 gap-y-1 border-t border-line pt-1.5" aria-label="Statuses">
            {STATUS_CATEGORIES.map((c) => (
              <li key={c} title={CATEGORY_STYLE[c].description}>
                <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-px ${CATEGORY_STYLE[c].chip}`}>
                  <span aria-hidden="true">{CATEGORY_STYLE[c].glyph}</span>
                  {CATEGORY_STYLE[c].label}
                </span>
              </li>
            ))}
          </ul>
          <ul className="flex flex-wrap gap-x-3 gap-y-1 border-t border-line pt-1.5" aria-label="Links">
            <li className="inline-flex items-center gap-1" title="Spine: spawned, executed, observed, verified. One edge per pair of nodes; hover it for every relation it stands for.">
              <svg width="22" height="6" aria-hidden="true"><line x1="0" y1="3" x2="22" y2="3" stroke="#606A7B" strokeWidth="1.8" /></svg>
              Flow (hover for detail)
            </li>
            <li className="inline-flex items-center gap-1" title="An edge flowing into a node means that node is running now.">
              <svg width="22" height="6" aria-hidden="true"><line x1="0" y1="3" x2="22" y2="3" stroke="#3b5bdb" strokeWidth="2.2" strokeDasharray="5 3" /></svg>
              Into a running node
            </li>
            <li className="inline-flex items-center gap-1" title="Consecutive reasoning cycles.">
              <svg width="22" height="6" aria-hidden="true"><line x1="0" y1="3" x2="22" y2="3" stroke="#4338ca" strokeWidth="2.2" /></svg>
              Next cycle
            </li>
            <li className="inline-flex items-center gap-1" title="Evidence links: investigates, supports, contradicts. Shown around the selected node, or everywhere with the Evidence links toggle.">
              <svg width="22" height="6" aria-hidden="true"><line x1="0" y1="3" x2="22" y2="3" stroke="#B4232C" strokeWidth="1.4" strokeDasharray="2 3" /></svg>
              Evidence (on selection)
            </li>
            <li className="inline-flex items-center gap-1">
              <span className="rounded bg-accent px-1 text-[11px] font-semibold uppercase text-white">new</span>
              arrived in the last seconds
            </li>
          </ul>
        </div>
      )}
    </div>
  );
}
