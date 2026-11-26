// Windowed exchange list (fixed row height, reuses computeWindow from the Activity tab).
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import { computeWindow } from "../run/activityModel";
import { formatClock } from "../format";
import { ChevronDownIcon, ChevronRightIcon } from "@heroicons/react/20/solid";
import { blockSentence, errorSentence, formatMs, formatSize, hostPort, rowFlags, statusColor, type TrafficItem } from "./trafficModel";

export const TRAFFIC_ROW_H = 32;
export const GRID = "grid grid-cols-[4.5rem_3.5rem_3.5rem_minmax(14rem,1fr)_4.5rem_4.5rem_9rem_9rem] items-center gap-x-3 px-3";

export function TrafficList({
  rows, selectedId, hasMore, loadingMore, onSelect, onLoadMore, onToggleGroup, height = 520,
}: {
  rows: readonly TrafficItem[];
  selectedId: number | null;
  hasMore: boolean;
  loadingMore: boolean;
  onSelect: (id: number) => void;
  onLoadMore: () => void;
  onToggleGroup: (key: string) => void;
  height?: number;
}) {
  const ref = useRef<HTMLDivElement>(null);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(height);
  useLayoutEffect(() => {
    if (ref.current) setViewportH(ref.current.clientHeight || height);
  }, [height]);

  const w = computeWindow({ count: rows.length, expanded: [], scrollTop, viewportH, rowH: TRAFFIC_ROW_H, overscan: 6 });
  const nearEnd = w.end >= rows.length - 15;
  const underfilled = rows.length * TRAFFIC_ROW_H < viewportH;
  useEffect(() => {
    if (hasMore && !loadingMore && (nearEnd || underfilled)) onLoadMore();
  }, [hasMore, loadingMore, nearEnd, underfilled, rows.length, onLoadMore]);

  return (
    <div className="card overflow-x-auto">
      <div className="min-w-[60rem]">
        <div className={`${GRID} border-b border-line py-1.5 text-[11px] uppercase tracking-wide text-slate`} role="row">
          <span>Time</span><span>Method</span><span>Status</span><span>Host and path</span><span className="text-right">Size</span><span className="text-right">Time taken</span><span>Tool / agent</span><span>Flags</span>
        </div>
        <div ref={ref} className="overflow-y-auto" style={{ height }} onScroll={(e) => setScrollTop(e.currentTarget.scrollTop)} role="list" aria-label="HTTP exchanges" tabIndex={0}>
          <div style={{ paddingTop: w.padTop, paddingBottom: w.padBottom }}>
            {rows.slice(w.start, w.end).map((item) => {
              if (item.type === "group") {
                return (
                  <button
                    key={`g:${item.key}`}
                    type="button"
                    role="listitem"
                    aria-expanded={item.expanded}
                    onClick={() => onToggleGroup(item.key)}
                    style={{ height: TRAFFIC_ROW_H }}
                    className="flex w-full items-center gap-2 border-b border-line/60 bg-canvas px-3 text-left text-xs text-slate hover:text-ink"
                    title={`${item.label}. Static assets are folded; ${item.expanded ? "collapse" : "expand"} to list the requests.`}
                  >
                    {item.expanded ? <ChevronDownIcon className="h-4 w-4 shrink-0" aria-hidden="true" /> : <ChevronRightIcon className="h-4 w-4 shrink-0" aria-hidden="true" />}
                    <span className="mono truncate font-semibold">{item.label}</span>
                    <span className="shrink-0">static</span>
                  </button>
                );
              }
              const x = item.x;
              const f = rowFlags(x);
              const sel = x.id === selectedId;
              return (
                <button
                  key={x.id}
                  type="button"
                  role="listitem"
                  onClick={() => onSelect(x.id)}
                  aria-current={sel}
                  style={{ height: TRAFFIC_ROW_H }}
                  className={`${GRID} w-full border-b border-line/60 text-left text-xs hover:bg-canvas ${sel ? "bg-accent/5" : ""}`}
                >
                  <span className="mono tabular-nums text-slate" title={x.ts}>{formatClock(x.ts)}</span>
                  <span className="mono font-semibold">{x.method}</span>
                  <span className={`mono tabular-nums font-semibold ${statusColor(x.status_code)}`}>{x.status_code ?? "—"}</span>
                  <span className={`mono truncate ${item.nested ? "pl-4" : ""}`} title={`${x.scheme ?? ""}://${hostPort(x)}${x.path ?? ""}`}>
                    <span className="text-slate">{hostPort(x)}</span>{x.path ?? ""}
                  </span>
                  <span className="text-right tabular-nums text-slate">{formatSize(x.response_size)}</span>
                  <span className="text-right tabular-nums text-slate">{formatMs(x.duration_ms)}</span>
                  <span className="truncate text-slate" title={`${x.tool}${x.agent_name ? ` · ${x.agent_name}` : ""}`}>{x.tool}{x.agent_name ? ` · ${x.agent_name}` : ""}</span>
                  <span className="flex min-w-0 items-center gap-1.5 truncate">
                    {f.blocked && <span className="rounded border border-severity-critical/30 bg-red-50 px-1 text-severity-critical" title={blockSentence(x.block_reason)}>blocked</span>}
                    {f.error && <span className="rounded border border-severity-medium/30 bg-amber-50 px-1" title={errorSentence(x.error ?? "")}>error</span>}
                    {f.hop > 0 && <span className="text-slate" title={`Redirect hop ${f.hop}`}>hop {f.hop}</span>}
                    {f.findings > 0 && <span className="rounded border border-accent/30 bg-accent/5 px-1 text-accent" title={`${f.findings} linked finding(s)`}>{f.findings} finding{f.findings === 1 ? "" : "s"}</span>}
                  </span>
                </button>
              );
            })}
          </div>
          {loadingMore && <p className="px-3 py-2 text-xs text-slate" role="status">Loading more…</p>}
        </div>
      </div>
    </div>
  );
}
