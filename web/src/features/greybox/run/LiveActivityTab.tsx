// Live Activity tab: the run's event timeline, fed by the shared
// RunLiveContext stream. The list is windowed (fixed row heights, see activityModel),
// so 5k+ events keep ~40 DOM rows. Event text is rendered as React text only.
//
// URL: ?tab=activity&seq=<n> expands and scrolls to that event (graph nodes carry
// event_seq / last_event_seq); older history is fetched on demand to reach it.
import { Fragment, useCallback, useEffect, useLayoutEffect as useLayoutEffectDom, useMemo, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowDownIcon, MagnifyingGlassIcon } from "@heroicons/react/20/solid";
import { EmptyState } from "../../../components/ui";
import { EVENT_LEVELS, type GreyboxEvent, type StreamState } from "../events";
import {
  DEFAULT_FILTERS, DETAIL_H, ROW_H, computeWindow, distinctAgents, distinctGroups, eventFields, eventJson,
  eventTitle, filterEvents, findingEventInfo, graphNodeSearch, indexOfSeq, isHintKind, kindStyle, LEVEL_DOT, parseSeqParam, rowTop, type ActivityFilters,
} from "./activityModel";
import { explorerDetail, isLlmKind, llmMeta, TODO_LABEL } from "../explorerView";
import { formatClock, formatDateMs } from "../format";
import { useRunLive } from "./RunLiveContext";
import { describeEvent, indexByWorkOrder, taskOutput, TASK_OUTPUT_KINDS, type TaskOutput } from "./eventView";

const NO_EVENTS: readonly GreyboxEvent[] = [];
const useLayoutEffect = typeof window === "undefined" ? useEffect : useLayoutEffectDom;

export const STREAM_BADGE: Record<StreamState, { label: string; dot: string }> = {
  connecting: { label: "Connecting…", dot: "bg-severity-medium" },
  live: { label: "Live", dot: "bg-emerald-600" },
  reconnecting: { label: "Reconnecting…", dot: "bg-severity-medium" },
  disconnected: { label: "Disconnected, retrying", dot: "bg-severity-critical" },
  finished: { label: "Stream ended (run finished)", dot: "bg-slate/50" },
};

export function ConnectionBadge({ state }: { state: StreamState }) {
  const b = STREAM_BADGE[state];
  const pulse = state === "live" ? "motion-safe:animate-pulse" : "";
  return (
    <span className="inline-flex items-center gap-1.5 rounded-full border border-line bg-surface px-2 py-0.5 text-xs" role="status">
      <span className={`h-2 w-2 rounded-full ${b.dot} ${pulse}`} aria-hidden="true" />
      {b.label}
    </span>
  );
}


function CopyButton({ label, text }: { label: string; text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="rounded border border-line bg-surface px-2 py-0.5 font-medium text-ink hover:bg-canvas"
      onClick={() => {
        void Promise.resolve(navigator.clipboard?.writeText(text)).then(() => setDone(true)).catch(() => {});
        setTimeout(() => setDone(false), 1500);
      }}
    >
      {done ? "Copied" : label}
    </button>
  );
}

function ExplorerSection({ e }: { e: GreyboxEvent }) {
  const d = explorerDetail(e.data);
  const meta = llmMeta(e.data);
  if (!d.reasoning && d.todolist.length === 0 && !meta) return null;
  return (
    <div className="mb-2 space-y-2" data-testid="explorer-detail">
      {meta && <p className="text-slate">{meta}</p>}
      {d.reasoning && (
        <div>
          <p className="font-semibold text-slate">Reasoning</p>
          <p className="whitespace-pre-wrap break-words text-ink">{d.reasoning}</p>
        </div>
      )}
      {d.todolist.length > 0 && (
        <div>
          <p className="font-semibold text-slate">Todo list</p>
          <ul className="space-y-0.5">
            {d.todolist.map((t, i) => (
              <li key={i} className={`flex gap-2 ${t.status === "done" ? "text-slate line-through" : "text-ink"}`}>
                <span className="w-16 shrink-0 text-[11px] uppercase tracking-wide text-slate no-underline">{TODO_LABEL[t.status]}</span>
                <span className="min-w-0 break-words">{t.step}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}

const SEV_TEXT: Record<string, string> = { critical: "critical", high: "high", medium: "medium", low: "low", info: "info" };

function TaskOutputSection({ out }: { out: TaskOutput }) {
  return (
    <div className="mb-2 space-y-2 rounded border border-line bg-surface px-2 py-1.5" data-testid="task-output">
      <p className="font-semibold text-slate">Task output{out.tool ? <span className="mono ml-1 font-normal text-ink">{out.tool}</span> : null}</p>
      {out.error && <p className="break-words text-severity-critical">Error: {out.error}</p>}
      {out.resultSummary && <p className="break-words text-ink">{out.resultSummary}</p>}
      {out.args.length > 0 && (
        <p className="break-all text-slate">
          Input: {out.args.map((a, i) => (<span key={i}>{i > 0 ? " · " : ""}{a.label} <span className="mono text-ink">{a.value}</span></span>))}
        </p>
      )}
      {out.result.length > 0 && (
        <p className="text-slate">Tool result: <span className="text-ink">{out.result.map((r) => `${r.label} ${r.value}`).join(", ")}</span></p>
      )}
      {out.requests.length > 0 && (
        <div>
          <p className="text-slate">Requests sent ({out.requests.length + out.requestsMore})</p>
          <ul className="mono max-h-24 overflow-y-auto break-all">
            {out.requests.map((r, i) => (<li key={i}>{r.method} {r.url} → {r.status ?? "?"}</li>))}
            {out.requestsMore > 0 && <li className="text-slate">… {out.requestsMore} more</li>}
          </ul>
        </div>
      )}
      {out.observations.length > 0 && (
        <div>
          <p className="text-slate">Observed</p>
          <ul className="mono max-h-24 overflow-y-auto break-all">
            {out.observations.map((o, i) => (<li key={i}>{o}</li>))}
            {out.observationsMore > 0 && <li className="text-slate">… {out.observationsMore} more</li>}
          </ul>
        </div>
      )}
      {(out.findings.length > 0 || out.assets > 0) && (
        <p className="text-slate">
          {out.assets > 0 && <span>{out.assets} new asset{out.assets === 1 ? "" : "s"}. </span>}
          {out.findings.length > 0 && <span>Findings: </span>}
          {out.findings.map((f, i) => (
            <span key={i} className="text-ink">{i > 0 ? "; " : ""}{f.title}{f.severity ? ` (${SEV_TEXT[f.severity] ?? f.severity}, ${f.status})` : ` (${f.status})`}</span>
          ))}
        </p>
      )}
    </div>
  );
}

function EventDetail({ e, related }: { e: GreyboxEvent; related: readonly GreyboxEvent[] }) {
  const [raw, setRaw] = useState(false);
  const view = useMemo(() => describeEvent(e), [e]);
  const output = useMemo(() => (TASK_OUTPUT_KINDS.has(e.kind) ? taskOutput(related) : null), [e.kind, related]);
  const refs = e.refs ?? {};
  const link = typeof window !== "undefined" ? `${window.location.origin}${window.location.pathname}?tab=activity&seq=${e.seq}` : "";
  const { fields, hidden } = eventFields(e.data);
  const finding = findingEventInfo(e);
  return (
    <div className="overflow-y-auto border-t border-line bg-canvas/60 px-3 py-2 text-xs" style={{ height: DETAIL_H }}>
      {finding && (
        <p className="mb-2 flex flex-wrap items-center gap-x-3 gap-y-1">
          <span className="font-medium text-ink">{finding.title}</span>
          {finding.nodeId && <Link className="text-accent hover:underline" to={graphNodeSearch(finding.nodeId)}>Show in graph</Link>}
          <Link className="text-accent hover:underline" to="?tab=findings">Open Findings tab</Link>
        </p>
      )}
      <p className="mb-2 whitespace-pre-wrap break-words text-ink">{eventTitle(e)}</p>
      {isLlmKind(e.kind) && <ExplorerSection e={e} />}
      {!raw && output && <TaskOutputSection out={output} />}
      {!raw && view.lines.length > 0 && (
        <dl className="mb-2 grid grid-cols-[7rem_1fr] gap-x-2 gap-y-0.5" data-testid="event-lines">
          {view.lines.map((l, i) => (
            <Fragment key={i}><dt className="text-slate">{l.label}</dt><dd className={`break-words ${l.mono ? "mono" : ""}`}>{l.value}</dd></Fragment>
          ))}
        </dl>
      )}
      <dl className="mb-2 grid grid-cols-[7rem_1fr] gap-x-2 gap-y-0.5">
        <dt className="text-slate">Time</dt><dd className="mono">{formatDateMs(e.ts)}</dd>
        <dt className="text-slate">Source</dt><dd>{e.source}{e.agent_name ? ` · ${e.agent_name}` : ""}</dd>
        {e.work_order_id && (<><dt className="text-slate">Work order</dt><dd className="mono break-all">{e.work_order_id}</dd></>)}
        {e.tool_call_id && (<><dt className="text-slate">Tool call</dt><dd className="mono break-all">{e.tool_call_id}</dd></>)}
        {e.duration_ms != null && (<><dt className="text-slate">Duration</dt><dd>{e.duration_ms} ms</dd></>)}
        {!!refs.node_ids?.length && (<><dt className="text-slate">Nodes</dt><dd className="mono break-all">{refs.node_ids.join(", ")}</dd></>)}
        {!!refs.exchange_ids?.length && (<><dt className="text-slate">Exchanges</dt><dd className="mono">{refs.exchange_ids.join(", ")}</dd></>)}
        {refs.finding_id && (<><dt className="text-slate">Finding</dt><dd className="mono break-all">{refs.finding_id}</dd></>)}
        {raw && fields.map((f) => (
          <Fragment key={f.key}><dt className="text-slate">{f.key}</dt><dd className="mono break-words">{f.value}</dd></Fragment>
        ))}
      </dl>
      {raw && hidden > 0 && <p className="mb-2 text-slate">{hidden} more fields: use Copy JSON for the full payload.</p>}
      <div className="flex flex-wrap items-center gap-2">
        <button type="button" aria-pressed={raw} className="rounded border border-line bg-surface px-2 py-0.5 font-medium text-ink hover:bg-canvas" onClick={() => setRaw((v) => !v)}>
          {raw ? "Readable view" : "Raw data"}
        </button>
        <CopyButton label="Copy JSON" text={eventJson(e)} />
        {link && <CopyButton label={`Copy link to event #${e.seq}`} text={link} />}
      </div>
    </div>
  );
}

function Row({ e, open, flash, onToggle, pos, size, related }: { e: GreyboxEvent; open: boolean; flash: boolean; onToggle: (seq: number) => void; pos: number; size: number; related: readonly GreyboxEvent[] }) {
  const ks = kindStyle(e.kind);
  const hint = isHintKind(e.kind);
  return (
    <li
      aria-posinset={pos}
      aria-setsize={size}
      data-seq={e.seq}
      className={`border-b border-line/60 ${hint ? "bg-hint-soft/60" : ""} ${flash ? "ring-2 ring-inset ring-accent" : ""}`}
      style={{ height: ROW_H + (open ? DETAIL_H : 0) }}
    >
      <button
        type="button"
        onClick={() => onToggle(e.seq)}
        aria-expanded={open}
        className="flex w-full items-center gap-2 px-3 text-left text-xs hover:bg-canvas focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
        style={{ height: ROW_H }}
      >
        <span className="w-12 shrink-0 text-right tabular-nums text-slate">#{e.seq}</span>
        <span className="mono w-[5rem] shrink-0 tabular-nums text-slate" title={formatDateMs(e.ts)}>{formatClock(e.ts)}</span>
        <span className={`h-2 w-2 shrink-0 rounded-full ${LEVEL_DOT[e.level] ?? LEVEL_DOT.info}`} title={`Level: ${e.level}`} />
        <span className="sr-only">{e.level}</span>
        <span className={`shrink-0 rounded border px-1.5 py-px text-[11px] font-semibold ${ks.chip}`}>{ks.label}</span>
        {e.agent_name && <span className="hidden shrink-0 text-slate md:inline">{e.agent_name}</span>}
        <span className="min-w-0 flex-1 truncate text-ink">{eventTitle(e)}</span>
        {isLlmKind(e.kind) && llmMeta(e.data) && <span className="hidden shrink-0 text-[11px] text-slate lg:inline">{llmMeta(e.data)}</span>}
        {e.status && <span className="shrink-0 text-[11px] font-semibold uppercase tracking-wide text-slate">{e.status}</span>}
      </button>
      {open && <EventDetail e={e} related={related} />}
    </li>
  );
}

export function LiveActivityTab() {
  const live = useRunLive();
  const { events, state, hasMoreBefore, loadOlder, reconnect, error } = live;
  const [params] = useSearchParams();
  const seqParam = parseSeqParam(params.get("seq"));

  const [filters, setFilters] = useState<ActivityFilters>(DEFAULT_FILTERS);
  const [expanded, setExpanded] = useState<ReadonlySet<number>>(() => new Set());
  const [follow, setFollow] = useState(true);
  const [scrollTop, setScrollTop] = useState(0);
  const [viewportH, setViewportH] = useState(600);
  const [flash, setFlash] = useState<number | null>(null);
  const [target, setTarget] = useState<number | null>(null);
  const [missing, setMissing] = useState<number | null>(null);
  const [loadingOlder, setLoadingOlder] = useState(false);
  const box = useRef<HTMLDivElement>(null);
  const seenLen = useRef(0);
  const eventsRef = useRef(events);
  eventsRef.current = events;
  const handledSeq = useRef<number | null>(null);

  const historyReady = !(state === "connecting" && events.length === 0);
  const filtered = useMemo(() => filterEvents(events, filters), [events, filters]);
  const groups = useMemo(() => distinctGroups(events), [events]);
  const byWorkOrder = useMemo(() => indexByWorkOrder(events), [events]);
  const agents = useMemo(() => distinctAgents(events), [events]);
  const expandedIdx = useMemo(
    () => [...expanded].map((s) => indexOfSeq(filtered, s)).filter((i) => i >= 0).sort((a, b) => a - b),
    [expanded, filtered],
  );
  const win = computeWindow({ count: filtered.length, expanded: expandedIdx, scrollTop, viewportH });

  // Track viewport height.
  useEffect(() => {
    const el = box.current;
    if (!el) return;
    setViewportH(el.clientHeight || 600);
    if (typeof ResizeObserver === "undefined") return;
    const ro = new ResizeObserver(() => setViewportH(el.clientHeight || 600));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  // Auto-follow: stick to the bottom while the user has not scrolled up.
  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    if (follow) {
      el.scrollTop = el.scrollHeight;
      seenLen.current = filtered.length;
    }
  }, [follow, filtered.length, win.total]);

  const onScroll = useCallback(() => {
    const el = box.current;
    if (!el) return;
    setScrollTop(el.scrollTop);
    setFollow(el.scrollHeight - el.scrollTop - el.clientHeight < 48);
  }, []);

  const jumpToLatest = () => {
    setFollow(true);
    const el = box.current;
    if (el) el.scrollTop = el.scrollHeight;
  };

  const toggle = useCallback((seq: number) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(seq)) next.delete(seq);
      else next.add(seq);
      return next;
    });
  }, []);

  // Deep link: ?seq=N loads older history if needed, clears hiding filters, expands and scrolls.
  useEffect(() => {
    if (seqParam === null || handledSeq.current === seqParam) return;
    if (!historyReady) return; // wait for the history tail
    let cancelled = false;
    void (async () => {
      setLoadingOlder(true);
      for (let i = 0; i < 40 && !cancelled; i++) {
        const first = eventsRef.current[0]?.seq ?? Infinity;
        if (first <= seqParam) break;
        if (!(await loadOlder())) break;
        await new Promise((r) => setTimeout(r, 0));
      }
      if (cancelled) return;
      setLoadingOlder(false);
      handledSeq.current = seqParam;
      if (indexOfSeq(eventsRef.current, seqParam) < 0) {
        setMissing(seqParam);
        return;
      }
      setMissing(null);
      setFilters({ ...DEFAULT_FILTERS, level: "debug" });
      setExpanded((p) => new Set(p).add(seqParam));
      setFollow(false);
      setTarget(seqParam);
      setFlash(seqParam);
    })();
    return () => {
      cancelled = true;
    };
  }, [seqParam, historyReady, loadOlder]);

  useLayoutEffect(() => {
    if (target === null) return;
    const el = box.current;
    const idx = indexOfSeq(filtered, target);
    if (!el || idx < 0) return;
    const top = Math.max(0, rowTop(idx, expandedIdx) - 2 * ROW_H);
    el.scrollTop = top;
    setScrollTop(top);
    setTarget(null);
  }, [target, filtered, expandedIdx]);

  useEffect(() => {
    if (flash === null) return;
    const t = setTimeout(() => setFlash(null), 4000);
    return () => clearTimeout(t);
  }, [flash]);

  const newCount = follow ? 0 : Math.max(0, filtered.length - seenLen.current);
  const set = <K extends keyof ActivityFilters>(k: K, v: ActivityFilters[K]) => setFilters((f) => ({ ...f, [k]: v }));
  const filtersActive = JSON.stringify(filters) !== JSON.stringify(DEFAULT_FILTERS);

  return (
    <div className="card overflow-hidden p-0">
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2 text-xs">
        <ConnectionBadge state={state} />
        <label className="relative min-w-[10rem] flex-1 sm:max-w-xs">
          <span className="sr-only">Search events</span>
          <MagnifyingGlassIcon className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate" aria-hidden="true" />
          <input type="search" className="field !py-1 pl-7 text-xs" placeholder="Search summary, kind, agent…" value={filters.q} onChange={(e) => set("q", e.target.value)} />
        </label>
        <label className="flex items-center gap-1">
          <span className="text-slate">Level</span>
          <select className="field !w-auto !py-1 text-xs" value={filters.level} onChange={(e) => set("level", e.target.value)}>
            {EVENT_LEVELS.map((l) => (
              <option key={l} value={l}>{l === "debug" ? "all (debug+)" : `${l}+`}</option>
            ))}
          </select>
        </label>
        <label className="flex items-center gap-1">
          <span className="text-slate">Kind</span>
          <select className="field !w-auto !py-1 text-xs" value={filters.group} onChange={(e) => set("group", e.target.value)}>
            <option value="*">all</option>
            {groups.map((g) => (<option key={g} value={g}>{g}.*</option>))}
          </select>
        </label>
        <label className="flex items-center gap-1">
          <span className="text-slate">Agent</span>
          <select className="field !w-auto !py-1 text-xs" value={filters.agent} onChange={(e) => set("agent", e.target.value)}>
            <option value="*">all</option>
            <option value="-">none (system)</option>
            {agents.map((a) => (<option key={a.id} value={a.id}>{a.name}</option>))}
          </select>
        </label>
        {filtersActive && (
          <button type="button" className="text-accent hover:underline" onClick={() => setFilters(DEFAULT_FILTERS)}>Reset</button>
        )}
        <span className="ml-auto tabular-nums text-slate" aria-live="off">
          {filtered.length.toLocaleString()}{filtered.length !== events.length ? ` of ${events.length.toLocaleString()}` : ""} events
        </span>
      </div>

      {state === "disconnected" && (
        <div role="alert" className="flex flex-wrap items-center gap-2 border-b border-severity-medium/30 bg-amber-50 px-3 py-1.5 text-xs text-severity-medium">
          The live stream is unavailable{error ? ` (${error})` : ""}. The rest of the page keeps polling.
          <button type="button" className="font-medium text-accent hover:underline" onClick={reconnect}>Retry now</button>
        </div>
      )}
      {missing !== null && (
        <div role="status" className="border-b border-line bg-canvas px-3 py-1.5 text-xs text-slate">
          Event #{missing} is not available for this run.
        </div>
      )}
      {loadingOlder && <div role="status" className="border-b border-line px-3 py-1.5 text-xs text-slate">Loading earlier events…</div>}

      <div className="relative">
        {hasMoreBefore && filtered.length > 0 && (
          <div className="border-b border-line px-3 py-1.5 text-center text-xs">
            <button
              type="button"
              className="text-accent hover:underline disabled:opacity-50"
              disabled={loadingOlder}
              onClick={() => {
                setLoadingOlder(true);
                void loadOlder().finally(() => setLoadingOlder(false));
              }}
            >
              Load earlier events
            </button>
          </div>
        )}
        <div
          ref={box}
          onScroll={onScroll}
          tabIndex={0}
          role="region"
          aria-label="Run events"
          className="h-[60vh] min-h-[320px] overflow-y-auto"
        >
          {filtered.length === 0 ? (
            <EmptyState title={events.length === 0 ? (state === "connecting" ? "Loading events…" : "No events yet") : "No events match the filters"}>
              {events.length === 0
                ? "Worker actions, planner decisions and tool calls appear here as they happen."
                : "Try a lower level, another kind or a different search."}
            </EmptyState>
          ) : (
            <ul role="list" style={{ paddingTop: win.padTop, paddingBottom: win.padBottom }}>
              {filtered.slice(win.start, win.end).map((e, i) => (
                <Row key={e.seq} e={e} open={expanded.has(e.seq)} flash={flash === e.seq} onToggle={toggle} pos={win.start + i + 1} size={filtered.length} related={(e.work_order_id && byWorkOrder.get(e.work_order_id)) || NO_EVENTS} />
              ))}
            </ul>
          )}
        </div>
        {!follow && filtered.length > 0 && (
          <button
            type="button"
            onClick={jumpToLatest}
            className="absolute bottom-3 left-1/2 z-10 inline-flex -translate-x-1/2 items-center gap-1 rounded-full border border-line bg-ink px-3 py-1 text-xs font-medium text-white shadow-card"
          >
            <ArrowDownIcon className="h-3.5 w-3.5" aria-hidden="true" />
            Jump to latest{newCount > 0 ? ` (${newCount.toLocaleString()} new)` : ""}
          </button>
        )}
      </div>
    </div>
  );
}

export default LiveActivityTab;
