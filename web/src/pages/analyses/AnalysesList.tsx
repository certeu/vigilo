import { useCallback, useEffect, useRef, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowPathIcon, PlusIcon, Squares2X2Icon } from "@heroicons/react/24/outline";
import { api, ApiError } from "../../api/client";
import { listAnalyses, type AnalysisItem, type AnalysisModeFilter } from "../../api/analyses";
import { useAuth } from "../../auth/AuthContext";
import { Breadcrumb, EmptyState, ModeBadge, StatusBadge } from "../../components/ui";
import { formatDuration } from "../../features/greybox/format";
import { RelativeTime } from "../../features/greybox/RelativeTime";
import { statusLabel } from "../../lib/status";
import { FINDINGS_LEGEND, SEVERITY_BG, SEVERITY_NAME, SEVERITY_ORDER, findingParts } from "./findingsModel";
import { greyboxEnabled, useGreyboxConfig } from "../../features/greybox/useGreyboxConfig";

const MODES: { key: AnalysisModeFilter; label: string }[] = [
  { key: "all", label: "All" },
  { key: "whitebox", label: "White-box" },
  { key: "greybox", label: "Grey-box" },
];
const STATUSES = ["queued", "preparing", "running", "cancelling", "succeeded", "failed", "cancelled"];
// `status` accepts a comma-separated list, so "active" is one server-side filter.
const ACTIVE_FILTER = "queued,preparing,running,cancelling";
const TERMINAL = new Set(["succeeded", "failed", "cancelled"]);

function parseMode(v: string | null): AnalysisModeFilter {
  return v === "whitebox" || v === "greybox" ? v : "all";
}

// The API's `href` is the canonical link: /runs/<id> (white-box) or /greybox/runs/<id>.
function rowHref(a: AnalysisItem): string {
  if (a.mode === "greybox") return `/greybox/runs/${a.id}`;
  return a.href;
}

function Findings({ f }: { f: AnalysisItem["findings"] }) {
  if (!f) return <span className="text-slate" title="No metrics recorded for this analysis">—</span>;
  const parts = findingParts(f.by_severity);
  return (
    <span className="inline-flex items-center gap-2 whitespace-nowrap">
      <span className="font-medium">{f.total}</span>
      {parts.map((p) => (
        <span key={p.severity} className={`inline-flex items-center gap-1 text-xs font-semibold ${p.textClass}`} title={p.title}>
          <span className={`h-1.5 w-1.5 rounded-full ${p.dotClass}`} aria-hidden="true" />
          {p.count}
          <span className="sr-only"> {p.severity}</span>
        </span>
      ))}
    </span>
  );
}

export function AnalysesList() {
  const { user } = useAuth();
  const [params, setParams] = useSearchParams();
  const mode = parseMode(params.get("mode"));
  const status = params.get("status") ?? "";
  const q = params.get("q") ?? "";
  const cfg = useGreyboxConfig();

  const [qDraft, setQDraft] = useState(q);
  const [items, setItems] = useState<AnalysisItem[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [owners, setOwners] = useState<Record<string, string>>({});
  const pages = useRef(1);

  function update(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value && !(key === "mode" && value === "all")) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  // Debounce the search box into the URL.
  useEffect(() => setQDraft(q), [q]);
  useEffect(() => {
    if (qDraft === q) return;
    const t = setTimeout(() => update("q", qDraft.trim()), 350);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qDraft]);

  const load = useCallback(async () => {
    try {
      const page = await listAnalyses({ mode, status: status || undefined, q: q || undefined, limit: 50 });
      setItems(page.items);
      setCursor(page.next_cursor);
      pages.current = 1;
      setError(null);
    } catch (e) {
      setError(
        e instanceof ApiError && e.status === 404
          ? "The unified analyses list is not available on this server yet. White-box runs are still listed under White-box."
          : e instanceof Error ? e.message : "Failed to load analyses",
      );
    }
  }, [mode, status, q]);

  useEffect(() => {
    setItems(null);
    void load();
  }, [load]);

  // Refresh the first page while something is still running (like the Runs board),
  // but never clobber extra pages the user loaded.
  const hasActive = !!items?.some((a) => !TERMINAL.has(a.status));
  useEffect(() => {
    if (!hasActive) return;
    const t = setInterval(() => pages.current === 1 && void load(), 5000);
    return () => clearInterval(t);
  }, [hasActive, load]);

  // Admins can see other users' analyses; resolve owner ids to emails for them.
  useEffect(() => {
    if (user?.role !== "admin") return;
    api.users().then((us) => setOwners(Object.fromEntries(us.map((u) => [u.id, u.email])))).catch(() => {});
  }, [user?.role]);

  async function loadMore() {
    if (!cursor) return;
    setLoadingMore(true);
    try {
      const page = await listAnalyses({ mode, status: status || undefined, q: q || undefined, limit: 50, cursor });
      setItems((cur) => [...(cur ?? []), ...page.items]);
      setCursor(page.next_cursor);
      pages.current += 1;
    } catch (e) {
      // 422 "Invalid cursor": the cursor went stale; start again from page 1.
      if (e instanceof ApiError && e.status === 422) {
        setCursor(null);
        void load();
      } else {
        setError(e instanceof Error ? e.message : "Failed to load more");
      }
    } finally {
      setLoadingMore(false);
    }
  }

  const owner = (id: string) => (id === user?.id ? "You" : owners[id] ?? id.slice(0, 8));
  const title = mode === "all" ? "All analyses" : `${mode === "whitebox" ? "White-box" : "Grey-box"} analyses`;
  const gbOn = greyboxEnabled(cfg);

  return (
    <div>
      <Breadcrumb
        items={[
          { label: "Analyses", to: mode === "all" ? undefined : "/analyses" },
          ...(mode === "all" ? [] : [{ label: mode === "whitebox" ? "White-box" : "Grey-box" }]),
        ]}
      />
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">{title}</h1>
        <Link to={mode === "all" ? "/analyses/new" : `/analyses/new?mode=${mode}`} className="btn-primary">
          <PlusIcon className="h-4 w-4" /> New analysis
        </Link>
      </div>

      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div role="group" aria-label="Mode" className="inline-flex rounded-md border border-line bg-surface p-0.5">
          {MODES.map((m) => (
            <button
              key={m.key}
              type="button"
              aria-pressed={mode === m.key}
              onClick={() => update("mode", m.key)}
              className={`rounded px-3 py-1.5 text-sm transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
                mode === m.key ? "bg-canvas font-medium text-ink ring-1 ring-line" : "text-slate hover:text-ink"
              }`}
            >
              {m.label}
            </button>
          ))}
        </div>
        <div>
          <label htmlFor="an-status" className="sr-only">Status</label>
          <select id="an-status" className="field w-40 py-1.5" value={status} onChange={(e) => update("status", e.target.value)}>
            <option value="">Any status</option>
            <option value={ACTIVE_FILTER}>Active (not finished)</option>
            {STATUSES.map((s) => <option key={s} value={s}>{statusLabel(s)}</option>)}
          </select>
        </div>
        <div className="min-w-[12rem] flex-1 sm:max-w-xs">
          <label htmlFor="an-q" className="sr-only">Search</label>
          <input
            id="an-q"
            type="search"
            className="field py-1.5"
            placeholder="Search name, repository or target"
            value={qDraft}
            onChange={(e) => setQDraft(e.target.value)}
          />
        </div>
        <button type="button" className="btn-ghost py-1.5" onClick={() => void load()} aria-label="Refresh">
          <ArrowPathIcon className="h-4 w-4" />
        </button>
      </div>

      {mode === "greybox" && cfg.status !== "loading" && !gbOn && (
        <p className="mb-4 rounded-md border border-line bg-surface p-3 text-sm text-slate">
          {cfg.status === "unavailable" ? cfg.reason : "Grey-box analysis is disabled on this server."}
        </p>
      )}
      {mode === "whitebox" && (
        <p className="mb-4 text-xs text-slate">
          The full white-box tools are unchanged: <Link to="/runs" className="text-accent hover:underline">Runs</Link>,{" "}
          <Link to="/jobs" className="text-accent hover:underline">Jobs</Link> and{" "}
          <Link to="/schedules" className="text-accent hover:underline">Schedules</Link>.
        </p>
      )}
      {error && <p role="alert" className="mb-4 text-sm text-severity-critical">{error}</p>}

      <div className="card overflow-x-auto">
        {items === null && !error ? (
          <p className="p-4 text-sm text-slate">Loading analyses…</p>
        ) : items && items.length === 0 ? (
          <EmptyState
            icon={Squares2X2Icon}
            title={q || status ? "No analyses match these filters" : "No analyses yet"}
            action={
              !q && !status ? (
                <Link to={mode === "all" ? "/analyses/new" : `/analyses/new?mode=${mode}`} className="btn-primary">
                  <PlusIcon className="h-4 w-4" /> New analysis
                </Link>
              ) : undefined
            }
          >
            {q || status ? "Try clearing the search or status filter." : "Start a white-box or grey-box analysis to see it here."}
          </EmptyState>
        ) : items ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-slate">
                <th className="px-4 py-3 font-medium">Mode</th>
                <th className="px-4 py-3 font-medium">Name</th>
                <th className="px-4 py-3 font-medium">Repository / target</th>
                <th className="px-4 py-3 font-medium">Status</th>
                <th className="whitespace-nowrap px-4 py-3 font-medium">Started</th>
                <th className="whitespace-nowrap px-4 py-3 font-medium">Duration</th>
                <th className="px-4 py-3 font-medium" title={FINDINGS_LEGEND}>Findings</th>
                <th className="px-4 py-3 font-medium">Owner</th>
              </tr>
            </thead>
            <tbody>
              {items.map((a) => (
                <tr key={`${a.mode}:${a.id}`} className="border-b border-line/60 hover:bg-canvas">
                  <td className="px-4 py-3"><ModeBadge mode={a.mode} /></td>
                  <td className="px-4 py-3">
                    <Link to={rowHref(a)} className="font-medium hover:text-accent">{a.name}</Link>
                  </td>
                  <td className="px-4 py-3 text-slate">
                    {a.subject.type === "repository" ? (
                      <Link to={`/repos/${a.subject.id}`} className="hover:text-ink">{a.subject.name}</Link>
                    ) : (
                      <span className="mono text-xs" title={a.subject.name}>{a.subject.base_url}</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <StatusBadge status={a.status} />
                    {a.phase && !TERMINAL.has(a.status) && <span className="mono ml-2 text-xs text-slate">{a.phase}</span>}
                  </td>
                  <td className="whitespace-nowrap px-4 py-3 text-slate"><RelativeTime iso={a.started_at ?? a.created_at} /></td>
                  <td className="mono px-4 py-3 text-slate">{formatDuration(a.duration_s)}</td>
                  <td className="px-4 py-3"><Findings f={a.findings} /></td>
                  <td className="px-4 py-3 text-slate">{owner(a.owner_id)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>
      {items && items.length > 0 && (
        <p className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-xs text-slate" title={FINDINGS_LEGEND}>
          Findings: total, then by severity
          {SEVERITY_ORDER.map((s) => (
            <span key={s} className="inline-flex items-center gap-1">
              <span className={`h-1.5 w-1.5 rounded-full ${SEVERITY_BG[s]}`} aria-hidden="true" />
              {SEVERITY_NAME[s]}
            </span>
          ))}
        </p>
      )}
      {cursor && (
        <div className="mt-4 flex justify-center">
          <button type="button" className="btn-ghost" disabled={loadingMore} onClick={loadMore}>
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        </div>
      )}
    </div>
  );
}
