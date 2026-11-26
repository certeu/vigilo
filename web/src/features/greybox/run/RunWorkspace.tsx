import { EgressFailureNote, ViaProxyChip } from "../egressProxyUi";
import { Suspense, lazy, useEffect, useId, useMemo, useRef, useState, type ComponentProps, type ReactNode } from "react";
import { Link, useLocation, useParams, useSearchParams } from "react-router-dom";
import { ArrowDownTrayIcon, ChatBubbleLeftEllipsisIcon, StopCircleIcon } from "@heroicons/react/24/outline";
import { api, ApiError } from "../../../api/client";
import { useAuth } from "../../../auth/AuthContext";
import { ConfirmDialog } from "../../../components/ConfirmDialog";
import { Breadcrumb, EmptyState, ErrorBoundary, ErrorState, ModeBadge, Skeleton, SkeletonCard, StatusBadge, TabPanel, Tabs, type TabItem } from "../../../components/ui";
import { StatusDot } from "../../../components/StatusDot";
import { greyboxApi } from "../api";
import { formatDate, formatDuration, shortId } from "../format";
import { statusLabel } from "../../../lib/status";
import { RUN_TERMINAL, type RunRead, type RunStatus } from "../types";
import { RunChatProvider, useRunChatContext } from "./RunChatContext";
import { RunChatDock } from "./RunChatDock";
import { OverviewTab } from "./OverviewTab";
import { ReportTab } from "./ReportTab";
import { FindingsTab } from "./FindingsTab";
import { defaultTab, errorHead, outcomeParts, type TabKey } from "./runHeaderModel";
import { AgentReasoningPanel } from "./AgentReasoningPanel";
import { DefensesTab } from "./DefensesTab";
import { LiveActivityTab, STREAM_BADGE } from "./LiveActivityTab";
import { skippedDetail } from "../checksAvailability";
import { NetworkTab } from "../network";
import { TrafficTab } from "./TrafficTab";
import { RunLiveProvider, useRunLive, useRunLiveStatusOptional } from "./RunLiveContext";
import { explorerLive } from "../explorerView";
import { useRun, type RunConnection } from "./useRun";

// Grey-box run workspace, /greybox/runs/:id?tab=….
// Live data: one SSE stream per workspace (RunLiveContext) drives the header, graph and
// Live Activity; GET /greybox/runs/{id} polls every 3 s only while the stream is not live.

const ExplorationTab = lazy(() => import("./ExplorationTabSlot").then((m) => ({ default: m.ExplorationTab })));

// Order: what the analyst wants first. Assets/Traffic placeholders are hidden until they exist.
// The graph keeps the URL key "exploration" (existing links); only the label is "Graph".
const TABS: TabItem<TabKey>[] = [
  { key: "findings", label: "Findings" },
  { key: "activity", label: "Activity" },
  { key: "exploration", label: "Graph" },
  { key: "network", label: "Network" },
  { key: "traffic", label: "Traffic" },
  { key: "defenses", label: "Defenses" },
  { key: "report", label: "Report" },
  { key: "overview", label: "Overview" },
];
const isTab = (v: string | null): v is TabKey => TABS.some((t) => t.key === v);
/** `?tab=graph` is accepted as an alias of the Graph tab (URL key "exploration"). */
const parseTab = (v: string | null): TabKey | null => (v === "graph" ? "exploration" : isTab(v) ? v : null);

const NOTICE_MS = 8000;
const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);
const ACTIVE_CLOCK: ReadonlySet<RunStatus> = new Set(["preparing", "running", "cancelling"]);

/** Seconds since start; ticks once per second only while the run is actually running. */
function useElapsed(run: RunRead | null): number | null {
  const ticking = !!run?.started_at && !run.finished_at && ACTIVE_CLOCK.has(run.status);
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!ticking) return;
    setNow(Date.now());
    const t = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(t);
  }, [ticking]);
  if (!run?.started_at) return null;
  const end = run.finished_at ? Date.parse(run.finished_at) : ticking ? now : Date.parse(run.started_at);
  return Math.max(0, (end - Date.parse(run.started_at)) / 1000);
}

function formatClock(s: number | null): string {
  if (s == null) return "—";
  const t = Math.floor(s);
  const hh = String(Math.floor(t / 3600)).padStart(2, "0");
  const mm = String(Math.floor((t % 3600) / 60)).padStart(2, "0");
  const ss = String(t % 60).padStart(2, "0");
  return `${hh}:${mm}:${ss}`;
}

const CONNECTION: Record<RunConnection, { label: string; dot: string }> = {
  live: { label: "Live (updates every 3 s)", dot: "bg-emerald-600" },
  reconnecting: { label: "Reconnecting…", dot: "bg-severity-medium" },
  disconnected: { label: "Disconnected, retrying", dot: "bg-severity-critical" },
  finished: { label: "Run finished", dot: "bg-slate/50" },
};

function Stat({ label, children, sub }: { label: string; children: ReactNode; sub?: ReactNode }) {
  return (
    <div className="min-w-0 sm:min-w-[6.5rem] sm:px-3 sm:py-1.5 sm:first:pl-0">
      <dt className="text-[11px] uppercase tracking-wide text-slate">{label}</dt>
      <dd className="font-display text-base font-semibold tabular-nums">
        {children}
        {sub && <span className="ml-1 text-xs font-normal text-slate">{sub}</span>}
      </dd>
    </div>
  );
}

/** Only counters the API actually returned are shown; nothing is estimated client-side. */
function CountsStrip({ run }: { run: RunRead }) {
  const c = run.counters ?? {};
  const wo = c.work_orders;
  const woTotal = wo ? Object.values(wo).reduce((a, b) => a + (isNum(b) ? b : 0), 0) : null;
  const events = isNum(c.events) ? c.events : isNum(run.last_seq) ? run.last_seq : null;
  return (
    <dl className="grid grid-cols-2 gap-x-4 gap-y-2 sm:flex sm:flex-wrap sm:gap-0 sm:divide-x sm:divide-line" aria-label="Run counters">
      {isNum(c.assets) && <Stat label="Assets">{c.assets.toLocaleString()}</Stat>}
      {isNum(c.endpoints) && <Stat label="Endpoints">{c.endpoints.toLocaleString()}</Stat>}
      {run.findings && (
        <Stat label="Findings" sub={`verified · ${run.findings.candidate} candidate`}>
          {run.findings.verified}
        </Stat>
      )}
      {isNum(c.agents_active) && <Stat label="Workers">{c.agents_active}<span className="ml-1 text-xs font-normal text-slate">active</span></Stat>}
      {wo && woTotal !== null && (
        <Stat label="Work orders done" sub={`of ${woTotal}`}>{isNum(wo.done) ? wo.done : 0}</Stat>
      )}
      {isNum(c.requests) && (
        <Stat label="Requests" sub={`/ ${run.limits.max_requests.toLocaleString()}`}>{c.requests.toLocaleString()}</Stat>
      )}
      {isNum(c.requests_blocked) && c.requests_blocked > 0 && (
        <Stat label="Blocked">{c.requests_blocked.toLocaleString()}</Stat>
      )}
      {events !== null && <Stat label="Events">{events.toLocaleString()}</Stat>}
    </dl>
  );
}

/** Header toggle for the run chat dock, with a badge counting agent replies not yet seen. */
function ChatToggle() {
  const { open, toggle, accepting, unread, chat } = useRunChatContext();
  // A finished run without messages has no history to show.
  if (!accepting && chat.hints.length === 0) return null;
  const n = chat.hints.length;
  return (
    <button
      type="button"
      className={`inline-flex items-center gap-2 rounded-md border border-hint-line px-3 py-1.5 text-sm font-medium text-hint-ink transition hover:brightness-95 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-hint/40 ${open ? "bg-hint-line/40" : "bg-hint-soft"}`}
      onClick={toggle}
      aria-expanded={open}
      aria-label={unread > 0 ? `Chat, ${unread} new ${unread === 1 ? "reply" : "replies"}` : "Chat"}
      title={accepting ? "Message the exploration agent while it runs" : `Messages sent during this run (${n})`}
    >
      <ChatBubbleLeftEllipsisIcon className="h-4 w-4 text-hint" aria-hidden="true" />
      Chat
      {unread > 0 && (
        <span className="rounded-full bg-hint px-1.5 text-[11px] font-semibold leading-4 text-white" aria-hidden="true">
          {unread}
        </span>
      )}
    </button>
  );
}

/** Owns the single live event stream of this run (RunLiveContext) for everything below. */
export function RunWorkspace() {
  const { id = "" } = useParams();
  return (
    <RunLiveProvider runId={id}>
      <RunWorkspaceBody />
    </RunLiveProvider>
  );
}

type ExplorationTabProps = ComponentProps<typeof ExplorationTab>;

/** Wraps the graph tab so only it (not the whole workspace) re-renders per event; tells it whether a model call is outstanding. */
function ExplorationTabLive(props: ExplorationTabProps) {
  const { events } = useRunLive();
  const llmOutstanding = useMemo(() => explorerLive(events).phase === "thinking", [events]);
  return <ExplorationTab {...props} llmOutstanding={llmOutstanding} />;
}

function RunWorkspaceBody() {
  const { id = "" } = useParams();
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  // Default tab is pinned when the run first loads (Findings if finished, Activity if active),
  // so a run finishing while you watch does not switch tabs under you.
  const pinnedDefault = useRef<TabKey | null>(null);
  const tabsId = useId();
  const { user } = useAuth();
  const { run, loadError, notFound, fails, connection, transport, lastUpdated, refresh, setRun } = useRun(id);
  const liveStatus = useRunLiveStatusOptional();
  const elapsed = useElapsed(run);
  if (run && !pinnedDefault.current) pinnedDefault.current = defaultTab(run.status);
  const tab: TabKey = parseTab(params.get("tab")) ?? pinnedDefault.current ?? "findings";

  const [confirmCancel, setConfirmCancel] = useState(false);
  const [notice, setNotice] = useState<string | null>(
    ((location.state ?? null) as { notice?: string } | null)?.notice ?? null,
  );
  // Transient notices (e.g. "Analysis started.") clear themselves so they never linger over the canvas.
  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(null), NOTICE_MS);
    return () => clearTimeout(t);
  }, [notice]);
  const [announce, setAnnounce] = useState("");
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [owners, setOwners] = useState<Record<string, string>>({});

  // Announce status transitions (incl. the terminal acknowledgement after a cancel).
  const prevStatus = useRef<RunStatus | null>(null);
  useEffect(() => {
    if (!run) return;
    const prev = prevStatus.current;
    prevStatus.current = run.status;
    if (prev === null || prev === run.status) return;
    if (run.status === "cancelled" && (prev === "cancelling" || run.cancel_requested)) {
      setNotice("Cancellation acknowledged: the engine stopped all work for this run.");
      setAnnounce("Run cancelled. Cancellation acknowledged by the engine.");
    } else {
      setAnnounce(`Run status: ${statusLabel(run.status)}.`);
    }
  }, [run]);

  useEffect(() => {
    if (user?.role !== "admin") return;
    api.users().then((us) => setOwners(Object.fromEntries(us.map((u) => [u.id, u.email])))).catch(() => {});
  }, [user?.role]);

  const setTab = (t: TabKey) => {
    const next = new URLSearchParams(params);
    next.set("tab", t);
    next.delete("open");
    setParams(next, { replace: true });
  };

  /** Graph nodes carry event seqs: open Live Activity scrolled to that event. */
  const openEvent = (seq: number) => {
    const next = new URLSearchParams(params);
    next.set("tab", "activity");
    next.set("seq", String(seq));
    setParams(next);
  };

  async function cancel() {
    if (!run) return;
    try {
      const r = await greyboxApi.cancelRun(run.id);
      setRun(r);
      setConfirmCancel(false);
      setNotice(
        r.status === "cancelled"
          ? "The run was cancelled before it started."
          : "Cancellation requested. In-flight requests finish (bounded by the request timeout), then the engine confirms.",
      );
    } catch (e) {
      if (e instanceof ApiError && e.status === 409) {
        setConfirmCancel(false);
        setNotice("The run had already finished, so there was nothing to cancel.");
        await refresh();
        return;
      }
      throw e; // ConfirmDialog shows the message
    }
  }

  async function resume() {
    if (!run) return;
    try {
      const r = await greyboxApi.resumeRun(run.id);
      setRun(r);
      setNotice("The run was resumed: it continues from its recorded knowledge, evidence and tools without repeating finished work.");
    } catch (e) {
      setNotice(e instanceof ApiError ? `Could not resume: ${e.message}` : "Could not resume the run.");
    }
  }

  async function download() {
    if (!run) return;
    setDownloading(true);
    setDownloadError(null);
    try {
      await greyboxApi.downloadReport(run.id);
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : "Download failed");
    } finally {
      setDownloading(false);
    }
  }

  const crumbsBase = [{ label: "Vigilo", to: "/" }, { label: "Grey-box", to: "/greybox" }];

  if (!run) {
    if (notFound || fails >= 3) {
      return (
        <div>
          <Breadcrumb items={[...crumbsBase, { label: "Run" }]} />
          {notFound ? (
            <div className="card">
              <EmptyState title="Run not found">
                It does not exist, you do not have access to it, or grey-box analysis is disabled on this server.
              </EmptyState>
            </div>
          ) : (
            <ErrorState title="Could not load this run" error={loadError} what="this run" onRetry={() => void refresh()} />
          )}
        </div>
      );
    }
    return (
      <div role="status" aria-label="Loading run">
        <Breadcrumb items={[...crumbsBase, { label: "Run" }]} />
        <Skeleton className="mb-3 h-7 w-64" />
        <Skeleton className="mb-5 h-4 w-96 max-w-full" />
        <div className="grid gap-4 sm:grid-cols-2"><SkeletonCard /><SkeletonCard /></div>
      </div>
    );
  }

  const terminal = RUN_TERMINAL.has(run.status);
  const cancelling = run.status === "cancelling" || (run.cancel_requested && !terminal);
  const initiator = run.owner_id === user?.id ? "You" : owners[run.owner_id] ?? `user ${shortId(run.owner_id)}`;
  const who = (id: string) => (id === user?.id ? "you" : owners[id] ?? `user ${shortId(id)}`);
  const outcomeP = outcomeParts(run, who);
  const outcome = outcomeP?.text ?? null;
  const err = run.status === "failed" && run.error_summary ? errorHead(run.error_summary) : null;
  // Same source as the Live Activity chip: the RunLiveContext stream state (poll state only without a provider).
  const conn = liveStatus
    ? STREAM_BADGE[liveStatus.state]
    : connection === "live" && transport === "stream" ? { label: "Live (streaming)", dot: "bg-emerald-600" } : CONNECTION[connection];
  const [firstScope, ...moreScope] = run.scope_summary;

  return (
    <RunChatProvider runId={run.id} accepting={!terminal} checks={run.checks}>
      <div>
        <p className="sr-only" role="status" aria-live="polite">{announce}</p>

        <header className="z-20 -mx-4 -mt-4 mb-4 border-b border-line bg-canvas/95 px-4 pb-3 pt-4 backdrop-blur sm:-mx-8 sm:-mt-8 sm:px-8 sm:pt-6 md:sticky md:top-0">
          <Breadcrumb
            items={[
              ...crumbsBase,
              { label: run.target.name, to: `/greybox/targets/${run.target.id}` },
              { label: `Run · ${formatDate(run.started_at ?? run.created_at)}` },
            ]}
          />
          <div className="flex flex-wrap items-start justify-between gap-3">
            <div className="min-w-0">
              <div className="flex flex-wrap items-center gap-x-3 gap-y-1">
                <h1 className="text-xl font-semibold">{run.target.name}</h1>
                <ModeBadge mode="greybox" />
                {run.egress_proxy && <ViaProxyChip name={run.egress_proxy.name} />}
              </div>
              <div className="mt-1 flex flex-wrap items-center gap-x-3 gap-y-1 text-sm">
                {outcome ? (
                  <span className="inline-flex min-w-0 items-center gap-2 font-medium" title={outcomeP?.note ? `${outcome}\n${skippedDetail(run.skipped_checks)}` : outcome ?? undefined}>
                    <StatusDot status={run.status} />
                    <span className={`break-words ${outcomeP?.tone === "warn" ? "text-severity-medium" : ""}`}>{outcome}</span>
                  </span>
                ) : (
                  <>
                    <span className="rounded-full border border-line bg-surface px-2 py-0.5">
                      <StatusBadge status={run.status} label={statusLabel(run.status)} />
                    </span>
                    <span
                      className="flex items-center gap-1.5 text-xs text-slate"
                      title={loadError && connection !== "live" ? loadError.message : undefined}
                    >
                      <span className={`h-2 w-2 rounded-full ${conn.dot}`} aria-hidden="true" />
                      {conn.label}
                      {lastUpdated && <span> · updated {new Date(lastUpdated).toLocaleTimeString()}</span>}
                    </span>
                  </>
                )}
                <span className="mono tabular-nums text-slate" title="Duration" aria-label={`Duration ${formatDuration(elapsed)}`}>
                  {run.started_at ? formatClock(elapsed) : "Not started"}
                </span>
              </div>
              <p className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-xs text-slate">
                <span className="mono break-all">{run.target.base_url}</span>
                {firstScope && (
                  <span title={run.scope_summary.join("\n")}>
                    Scope: {firstScope}
                    {moreScope.length > 0 && ` · +${moreScope.length} more`}
                  </span>
                )}
                <span>Started by {initiator}</span>
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              {run.report_status === "ready" && (
                <button type="button" className="btn-ghost py-1.5" onClick={download} disabled={downloading}>
                  <ArrowDownTrayIcon className="h-4 w-4" /> {downloading ? "Downloading…" : "Download report"}
                </button>
              )}
              <ChatToggle />
              {terminal && run.resumable && (
                <button type="button" className="btn-ghost py-1.5" onClick={() => void resume()}>
                  Resume run
                </button>
              )}
              {!terminal && (
                <button
                  type="button"
                  className="btn-ghost py-1.5 text-severity-critical disabled:opacity-60"
                  onClick={() => setConfirmCancel(true)}
                  disabled={cancelling}
                >
                  <StopCircleIcon className="h-4 w-4" /> {cancelling ? "Cancelling…" : "Cancel run"}
                </button>
              )}
            </div>
          </div>
          <div className="mt-3">
            <CountsStrip run={run} />
          </div>
          {downloadError && <p role="alert" className="mt-2 text-xs text-severity-critical">{downloadError}</p>}
        </header>

        {notice && (
          <div role="status" className="pointer-events-none mb-4 flex items-start justify-between gap-3 rounded-md border border-line bg-surface p-3 text-sm">
            <span>{notice}</span>
            <button type="button" className="pointer-events-auto text-xs text-slate hover:text-ink" onClick={() => setNotice(null)} aria-label="Dismiss message">
              Dismiss
            </button>
          </div>
        )}

        {run.status === "failed" && (
          <EgressFailureNote
            text={`${run.error_summary ?? ""} ${run.end_reason ?? ""}`}
            viaProxy={!!run.egress_proxy}
            proxyName={run.egress_proxy?.name}
            className="mb-4 rounded-md border border-severity-critical/30 bg-red-50 p-3"
          />
        )}

        {err?.truncated && (
          <div role="alert" className="mb-4 rounded-md border border-severity-critical/30 bg-red-50 p-3 text-sm">
            <p className="font-medium text-severity-critical">The run failed with this error</p>
            <p className="mt-1 whitespace-pre-wrap break-words">{run.error_summary}</p>
          </div>
        )}

        <AgentReasoningPanel active={!RUN_TERMINAL.has(run.status)} />

        <Tabs items={TABS} value={tab} onChange={setTab} label="Run sections" idBase={tabsId} />
        <ErrorBoundary key={tab} label="this tab">
          <TabPanel idBase={tabsId} tabKey={tab} className="pt-5">
            {tab === "overview" && <OverviewTab run={run} elapsedS={elapsed} />}
            {tab === "activity" && <LiveActivityTab />}
            {tab === "exploration" && (
              <Suspense fallback={<div role="status" aria-label="Loading graph"><Skeleton className="h-[28rem] w-full" /></div>}>
                <ExplorationTabLive
                  runId={run.id}
                  runStatus={run.status}
                  graphVersion={run.graph_version}
                  onOpenEvent={(seq) => openEvent(seq)}
                />
              </Suspense>
            )}
            {tab === "traffic" && <TrafficTab runId={run.id} viaProxy={!!run.egress_proxy} />}
            {tab === "network" && <NetworkTab runId={run.id} runStatus={run.status} />}
            {tab === "findings" && <FindingsTab runId={run.id} runStatus={run.status} />}
            {tab === "defenses" && (
              <DefensesTab
                runId={run.id}
                runStatus={run.status}
                findingCount={run.findings ? run.findings.verified + run.findings.candidate : null}
              />
            )}
            {tab === "report" && <ReportTab runId={run.id} runStatus={run.status} reportStatus={run.report_status} />}
          </TabPanel>
        </ErrorBoundary>

        <p className="mt-6 text-xs text-slate">
          <Link to={`/greybox/targets/${run.target.id}?tab=runs`} className="hover:text-ink hover:underline">
            ← All runs of {run.target.name}
          </Link>
        </p>

        {confirmCancel && (
          <ConfirmDialog
            title="Cancel this run?"
            confirmLabel="Cancel run"
            cancelLabel="Keep running"
            body={
              run.status === "queued"
                ? "The run has not started yet, so it is cancelled immediately."
                : "The engine stops scheduling new work, lets in-flight requests finish (bounded by the request timeout) and then confirms the cancellation. Results gathered so far are kept."
            }
            onConfirm={cancel}
            onCancel={() => setConfirmCancel(false)}
          />
        )}
      </div>
      <RunChatDock />
    </RunChatProvider>
  );
}
