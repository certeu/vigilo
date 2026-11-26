import { useCallback, useEffect, useId, useRef, useState } from "react";
import { Link, useLocation, useNavigate, useParams, useSearchParams } from "react-router-dom";
import { ArchiveBoxIcon, ArrowUturnLeftIcon, PlayIcon, TrashIcon, ExclamationTriangleIcon } from "@heroicons/react/24/outline";
import { ApiError } from "../../api/client";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Badge, Breadcrumb, EmptyState, ErrorBoundary, ModeBadge, StatusBadge, TabPanel, Tabs } from "../../components/ui";
import { greyboxApi } from "./api";
import { NewGreyboxForm } from "./NewGreyboxForm";
import { formatDuration, newIdempotencyKey, shortId } from "./format";
import { RelativeTime } from "./RelativeTime";
import { RUN_TERMINAL, type RunSummary, type TargetRead } from "./types";
import { NoModelNotice } from "./NewGreyboxForm";
import { useStartRun } from "./useStartRun";
import { useGreyboxConfig } from "./useGreyboxConfig";
import { EgressFailureNote, useAvailableProxies } from "./egressProxyUi";
import type { PreflightResult } from "./types";
import { willBeSkipped } from "./checksAvailability";

type Tab = "overview" | "runs" | "edit";
const TABS: { key: Tab; label: string }[] = [
  { key: "overview", label: "Overview" },
  { key: "runs", label: "Runs" },
  { key: "edit", label: "Edit" },
];

const LIMIT_LABELS: Record<string, (v: number) => string> = {
  max_requests: (v) => `${v} requests`,
  max_duration_s: (v) => `${formatDuration(v)} duration`,
  max_concurrency: (v) => `${v} concurrent`,
  rate_limit_rps: (v) => `${v} req/s`,
  request_timeout_s: (v) => `${v}s request timeout`,
  max_pages: (v) => `${v} pages`,
};

export function TargetDetail() {
  const { id = "" } = useParams();
  const navigate = useNavigate();
  const location = useLocation();
  const [params, setParams] = useSearchParams();
  const tab = (TABS.some((t) => t.key === params.get("tab")) ? params.get("tab") : "overview") as Tab;
  const tabsId = useId();
  const cfg = useGreyboxConfig();

  const flash = (location.state ?? null) as { notice?: string; noticeError?: boolean } | null;
  const [target, setTarget] = useState<TargetRead | null>(null);
  const [loadError, setLoadError] = useState<{ status: number; message: string } | null>(null);
  const [runs, setRuns] = useState<RunSummary[] | null>(null);
  const [runsError, setRunsError] = useState<string | null>(null);

  const [authorized, setAuthorized] = useState(false);
  const [starting, setStarting] = useState(false);
  const [startError, setStartError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [archiving, setArchiving] = useState(false);
  const [archiveError, setArchiveError] = useState<string | null>(null);
  const proxies = useAvailableProxies();
  const [pf, setPf] = useState<PreflightResult | null>(null);
  const [pfBusy, setPfBusy] = useState(false);
  const [pfError, setPfError] = useState<string | null>(null);
  const startRun = useStartRun();
  // One idempotency key per start intent: a retry after a network error reuses it.
  const startKey = useRef(newIdempotencyKey());

  const load = useCallback(async () => {
    try {
      setTarget(await greyboxApi.target(id));
      setLoadError(null);
    } catch (e) {
      setLoadError({
        status: e instanceof ApiError ? e.status : 0,
        message: e instanceof Error ? e.message : "Failed to load",
      });
    }
    try {
      setRuns((await greyboxApi.runs({ target_id: id, limit: 50 })).items);
      setRunsError(null);
    } catch (e) {
      setRuns(null);
      setRunsError(
        e instanceof ApiError && e.status === 404
          ? "Run history is not available on this server yet."
          : e instanceof Error ? e.message : "Failed to load runs",
      );
    }
  }, [id]);

  // location.key changes after the Edit tab saves and navigates back here.
  useEffect(() => {
    void load();
  }, [load, location.key]);

  const setTab = (t: Tab) => {
    const next = new URLSearchParams(params);
    if (t === "overview") next.delete("tab");
    else next.set("tab", t);
    setParams(next, { replace: true });
  };

  async function start() {
    if (!target || !authorized) return;
    setStarting(true);
    setStartError(null);
    try {
      await startRun(target.id, startKey.current); // navigates to the new run
    } catch (e) {
      setStartError(e instanceof Error ? e.message : "The analysis did not start.");
      // The server answered, so the next attempt is a new intent.
      startKey.current = newIdempotencyKey();
      setStarting(false);
    }
  }

  async function checkConnection() {
    if (!target) return;
    setPfBusy(true);
    setPfError(null);
    setPf(null);
    try {
      setPf(await greyboxApi.preflight(target.id));
    } catch (e) {
      setPfError(e instanceof ApiError && e.status === 429 ? "Wait a few seconds before checking again." : e instanceof Error ? e.message : "Connection check failed");
    } finally {
      setPfBusy(false);
    }
  }

  async function toggleArchived() {
    if (!target) return;
    setArchiving(true);
    setArchiveError(null);
    try {
      setTarget(await greyboxApi.updateTarget(target.id, { archived: !target.archived }));
    } catch (e) {
      setArchiveError(e instanceof Error ? e.message : "Update failed");
    } finally {
      setArchiving(false);
    }
  }

  async function remove() {
    if (!target) return;
    await greyboxApi.deleteTarget(target.id);
    navigate("/greybox", { replace: true });
  }

  if (loadError) {
    return (
      <div>
        <Breadcrumb items={[{ label: "Vigilo", to: "/" }, { label: "Grey-box", to: "/greybox" }, { label: "Target" }]} />
        <div className="card">
          <EmptyState title={loadError.status === 404 ? "Target not found" : "Could not load this target"}>
            {loadError.status === 404
              ? "It does not exist, you do not have access to it, or grey-box analysis is disabled on this server."
              : loadError.message}
          </EmptyState>
        </div>
      </div>
    );
  }
  if (!target) return <p className="text-sm text-slate">Loading target…</p>;

  const active = target.last_run && !RUN_TERMINAL.has(target.last_run.status);
  const configDisabled = cfg.status === "ok" && !cfg.config.enabled;
  const noModel = cfg.status === "ok" && cfg.config.agent?.available === false;

  return (
    <div>
      <Breadcrumb
        items={[
          { label: "Vigilo", to: "/" },
          { label: "Grey-box", to: "/greybox" },
          { label: target.name },
        ]}
      />
      <div className="mb-4 flex flex-wrap items-start justify-between gap-3">
        <div className="min-w-0">
          <div className="flex flex-wrap items-center gap-2">
            <h1 className="text-xl font-semibold">{target.name}</h1>
            <ModeBadge mode="greybox" />
            {target.archived && <Badge>Archived</Badge>}
          </div>
          <p className="mono mt-1 break-all text-sm text-slate">{target.base_url}</p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <button type="button" className="btn-ghost" onClick={toggleArchived} disabled={archiving}>
            {target.archived ? <ArrowUturnLeftIcon className="h-4 w-4" /> : <ArchiveBoxIcon className="h-4 w-4" />}
            {archiving ? "Saving…" : target.archived ? "Unarchive" : "Archive"}
          </button>
          <span className="mx-1 hidden h-6 w-px bg-line sm:block" aria-hidden="true" />
          <button
            type="button"
            className="inline-flex items-center gap-2 rounded-md border border-severity-critical/40 px-3 py-2 text-sm font-medium text-severity-critical transition hover:bg-red-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-severity-critical/30"
            onClick={() => setConfirmDelete(true)}
          >
            <TrashIcon className="h-4 w-4" /> Delete target
          </button>
        </div>
      </div>
      {archiveError && <p role="alert" className="mb-4 text-sm text-severity-critical">{archiveError}</p>}

      {flash?.notice && (
        <p role="status" className={`mb-4 rounded-md border p-3 text-sm ${flash.noticeError ? "border-severity-medium/30 bg-amber-50" : "border-line bg-surface"}`}>
          {flash.notice}
        </p>
      )}

      <Tabs items={TABS} value={tab} onChange={setTab} label="Target sections" idBase={tabsId} />
      <ErrorBoundary key={tab} label="this tab">
        <TabPanel idBase={tabsId} tabKey={tab} className="pt-5">
          {tab === "overview" && (
            <div className="grid gap-5 lg:grid-cols-3">
              <section className="card p-5 lg:col-span-2" aria-labelledby={`${tabsId}-scope`}>
                <h2 id={`${tabsId}-scope`} className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">Authorised scope</h2>
                <ul className="list-disc space-y-0.5 pl-5 text-sm">
                  {target.scope_summary.map((l, i) => <li key={i}>{l}</li>)}
                </ul>
                {target.description && (
                  <>
                    <h2 className="mb-1 mt-4 text-xs font-semibold uppercase tracking-wide text-slate">Objective and context</h2>
                    <p className="whitespace-pre-wrap text-sm">{target.description}</p>
                  </>
                )}
                <dl className="mt-4 grid gap-x-6 gap-y-2 text-sm sm:grid-cols-2">
                  <div>
                    <dt className="text-xs text-slate">Authentication</dt>
                    <dd>{target.credential ? `Cookie: ${target.credential.label}` : "None (unauthenticated)"}</dd>
                  </div>
                  {proxies && proxies.length > 0 && (
                    <div>
                      <dt className="text-xs text-slate">Network path</dt>
                      <dd>
                        {target.egress_proxy_id
                          ? `Via egress proxy: ${proxies.find((p) => p.id === target.egress_proxy_id)?.name ?? "configured proxy"}`
                          : "Direct"}
                      </dd>
                    </div>
                  )}
                  <div>
                    <dt className="text-xs text-slate">Checks</dt>
                    <dd className="mono text-xs">{target.checks.length ? target.checks.join(", ") : "None enabled"}</dd>
                    {cfg.status === "ok" && willBeSkipped(target.checks, cfg.config.checks).length > 0 && (
                      <dd className="mt-1 text-xs text-severity-medium">
                        Will be skipped (not available in this build): {willBeSkipped(target.checks, cfg.config.checks).join(", ")}
                      </dd>
                    )}
                  </div>
                  <div className="sm:col-span-2">
                    <dt className="text-xs text-slate">Limits (enforced)</dt>
                    <dd>
                      {Object.entries(target.limits)
                        .map(([k, v]) => (LIMIT_LABELS[k] ? LIMIT_LABELS[k](v) : `${k} ${v}`))
                        .join(" · ")}
                    </dd>
                  </div>
                  <div>
                    <dt className="text-xs text-slate">Created</dt>
                    <dd><RelativeTime iso={target.created_at} /></dd>
                  </div>
                  <div>
                    <dt className="text-xs text-slate">Updated</dt>
                    <dd><RelativeTime iso={target.updated_at} /></dd>
                  </div>
                </dl>
              </section>

              <section className="card p-5" aria-labelledby={`${tabsId}-start`}>
                <h2 id={`${tabsId}-start`} className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">Start an analysis</h2>
                {target.last_run && (
                  <p className="mb-3 flex items-center gap-2 text-sm">
                    Last run:{" "}
                    <Link to={`/greybox/runs/${target.last_run.id}`} className="hover:underline">
                      <StatusBadge status={target.last_run.status} />
                    </Link>
                    <RelativeTime iso={target.last_run.created_at} className="text-xs text-slate" />
                  </p>
                )}
                {configDisabled ? (
                  <p className="text-sm text-slate">Grey-box analysis is disabled on this server, so runs cannot be started.</p>
                ) : target.archived ? (
                  <p className="text-sm text-slate">This target is archived. Unarchive it to start a run.</p>
                ) : (
                  <>
                    {noModel && <div className="mb-3"><NoModelNotice /></div>}
                    <p className="mb-3 flex items-start gap-2 text-xs text-slate">
                      <ExclamationTriangleIcon className="h-4 w-4 shrink-0 text-severity-medium" aria-hidden="true" />
                      This sends real HTTP requests to {target.base_url}, limited to the scope shown.
                    </p>
                    <label className="mb-3 flex items-start gap-2 text-sm">
                      <input
                        type="checkbox"
                        className="mt-1"
                        checked={authorized}
                        onChange={(e) => setAuthorized(e.target.checked)}
                      />
                      <span>I confirm I am authorised to test this target within this scope.</span>
                    </label>
                    <button
                      type="button"
                      className="btn-primary disabled:opacity-60"
                      disabled={!authorized || starting || !!active || noModel}
                      aria-describedby={!active && !authorized ? `${tabsId}-why` : undefined}
                      onClick={start}
                    >
                      <PlayIcon className="h-4 w-4" />
                      {starting ? "Starting…" : "Start analysis"}
                    </button>
                    {!active && !authorized && !starting && (
                      <p id={`${tabsId}-why`} className="mt-2 text-xs text-slate">Confirm authorisation to start.</p>
                    )}
                    {active && target.last_run && (
                      <p className="mt-2 text-xs text-slate">
                        A run is already active for this target.{" "}
                        <Link to={`/greybox/runs/${target.last_run.id}`} className="text-accent hover:underline">Open it</Link>
                      </p>
                    )}
                  </>
                )}
                {!configDisabled && !target.archived && (
                  <div className="mt-3 border-t border-line pt-3">
                    <button type="button" className="btn-ghost py-1 text-xs" onClick={checkConnection} disabled={pfBusy}>
                      {pfBusy ? "Checking…" : "Check connection"}
                    </button>
                    {pfError && <p role="alert" className="mt-2 text-sm text-severity-critical">{pfError}</p>}
                    {pf && (
                      <div role="status" className="mt-2 text-sm">
                        {pf.ok ? (
                          <p className="text-emerald-700">Reachable{pf.status_code ? ` (HTTP ${pf.status_code})` : ""}{target.egress_proxy_id ? " via the egress proxy" : ""}.</p>
                        ) : (
                          <>
                            <p className="text-severity-critical">Not reachable{pf.blocked_reason ? `: ${pf.blocked_reason}` : "."}</p>
                            <EgressFailureNote
                              text={pf.blocked_reason}
                              viaProxy={!!target.egress_proxy_id}
                              proxyName={proxies?.find((p) => p.id === target.egress_proxy_id)?.name}
                              className="mt-1 text-slate"
                            />
                          </>
                        )}
                      </div>
                    )}
                  </div>
                )}
                {startError && (
                  <>
                    <p role="alert" className="mt-3 text-sm text-severity-critical">{startError}</p>
                    <EgressFailureNote text={startError} viaProxy={!!target.egress_proxy_id} proxyName={proxies?.find((p) => p.id === target.egress_proxy_id)?.name} className="mt-1 text-slate" />
                  </>
                )}
              </section>
            </div>
          )}

          {tab === "runs" && (
            <div className="card overflow-x-auto">
              {runsError ? (
                <EmptyState title="Runs unavailable">{runsError}</EmptyState>
              ) : runs === null ? (
                <p className="p-4 text-sm text-slate">Loading runs…</p>
              ) : runs.length === 0 ? (
                <EmptyState title="No runs yet">Start an analysis from the Overview tab.</EmptyState>
              ) : (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-line text-left text-slate">
                      <th className="px-4 py-3 font-medium">Run</th>
                      <th className="px-4 py-3 font-medium">Status</th>
                      <th className="px-4 py-3 font-medium">Findings</th>
                      <th className="px-4 py-3 font-medium">Started</th>
                      <th className="px-4 py-3 font-medium">Finished</th>
                    </tr>
                  </thead>
                  <tbody>
                    {runs.map((r) => (
                      <tr key={r.id} className="border-b border-line/60">
                        <td className="mono px-4 py-3 text-xs">
                          <Link to={`/greybox/runs/${r.id}`} className="text-accent hover:underline" aria-label={`Open run ${shortId(r.id)}`}>
                            {shortId(r.id)}
                          </Link>
                        </td>
                        <td className="px-4 py-3"><StatusBadge status={r.status} /></td>
                        <td className="px-4 py-3 text-slate">
                          {r.findings.verified} verified · {r.findings.candidate} candidate
                        </td>
                        <td className="px-4 py-3 text-slate"><RelativeTime iso={r.started_at} /></td>
                        <td className="px-4 py-3 text-slate"><RelativeTime iso={r.finished_at} /></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          )}

          {tab === "edit" &&
            (cfg.status === "ok" ? (
              <NewGreyboxForm config={cfg.config} initial={target} />
            ) : cfg.status === "loading" ? (
              <p className="text-sm text-slate">Loading…</p>
            ) : (
              <div className="card"><EmptyState title="Editing unavailable">{cfg.reason}</EmptyState></div>
            ))}
        </TabPanel>
      </ErrorBoundary>

      <p className="mt-6 text-xs text-slate">
        <Link to="/greybox" className="hover:text-ink hover:underline">← All grey-box targets</Link>
      </p>

      {confirmDelete && (
        <ConfirmDialog
          title="Delete target"
          body={<>Delete “{target.name}” and all of its runs? This cannot be undone. Targets with an active run cannot be deleted.</>}
          onConfirm={remove}
          onCancel={() => setConfirmDelete(false)}
        />
      )}
    </div>
  );
}
