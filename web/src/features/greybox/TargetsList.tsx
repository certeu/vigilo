import { useCallback, useEffect, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { ArrowPathIcon, GlobeAltIcon, PlayIcon, PlusIcon } from "@heroicons/react/24/outline";
import { ApiError } from "../../api/client";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Badge, Breadcrumb, EmptyState, StatusBadge } from "../../components/ui";
import { greyboxApi } from "./api";
import { statusLabel } from "../../lib/status";
import { newIdempotencyKey } from "./format";
import { RelativeTime } from "./RelativeTime";
import { RUN_TERMINAL, type TargetRead } from "./types";
import { greyboxEnabled, useGreyboxConfig } from "./useGreyboxConfig";
import { NoModelNotice } from "./NewGreyboxForm";
import { useStartRun } from "./useStartRun";

// Target-centric grey-box landing page (sidebar "Grey-box"): GET /greybox/targets.
// Filters (archived, q) live in the URL.

function ScopeSummary({ lines }: { lines: string[] }) {
  if (lines.length === 0) return <span className="text-slate">—</span>;
  const [first, ...rest] = lines;
  return (
    <span title={lines.join("\n")}>
      {first}
      {rest.length > 0 && <span className="text-slate"> · +{rest.length} more</span>}
    </span>
  );
}

function LastRun({ t }: { t: TargetRead }) {
  if (!t.last_run) return <span className="text-slate">Never run</span>;
  return (
    <span className="inline-flex flex-wrap items-center gap-x-2">
      <Link to={`/greybox/runs/${t.last_run.id}`} className="hover:underline" aria-label={`Last run: ${statusLabel(t.last_run.status)}, open run`}>
        <StatusBadge status={t.last_run.status} />
      </Link>
      <RelativeTime iso={t.last_run.created_at} className="text-xs text-slate" />
    </span>
  );
}

function Actions({ t, canStart, onStart }: { t: TargetRead; canStart: boolean; onStart: (t: TargetRead) => void }) {
  const active = t.last_run && !RUN_TERMINAL.has(t.last_run.status) ? t.last_run : null;
  return (
    <div className="flex flex-wrap justify-end gap-2">
      {active ? (
        <Link to={`/greybox/runs/${active.id}`} className="btn-ghost py-1">View active run</Link>
      ) : (
        <button
          type="button"
          className="btn-ghost py-1 disabled:opacity-50"
          disabled={!canStart || t.archived}
          title={t.archived ? "Unarchive the target to start a run" : !canStart ? "Grey-box analysis is unavailable on this server" : undefined}
          onClick={() => onStart(t)}
          aria-label={`Start analysis of ${t.name}`}
        >
          <PlayIcon className="h-4 w-4" /> Start
        </button>
      )}
      <Link to={`/greybox/targets/${t.id}`} className="btn-ghost py-1" aria-label={`Open target ${t.name}`}>Open</Link>
    </div>
  );
}

export function TargetsList() {
  const [params, setParams] = useSearchParams();
  const archived = params.get("archived") === "true";
  const q = params.get("q") ?? "";
  const cfg = useGreyboxConfig();
  const noModel = cfg.status === "ok" && cfg.config.agent?.available === false;
  const canStart = greyboxEnabled(cfg) && !noModel;

  const [qDraft, setQDraft] = useState(q);
  const [items, setItems] = useState<TargetRead[] | null>(null);
  const [cursor, setCursor] = useState<string | null>(null);
  const [error, setError] = useState<{ status: number; message: string } | null>(null);
  const [loadingMore, setLoadingMore] = useState(false);
  const [startFor, setStartFor] = useState<{ target: TargetRead; key: string } | null>(null);
  const startRun = useStartRun();
  const openStart = useCallback((t: TargetRead) => setStartFor({ target: t, key: newIdempotencyKey() }), []);

  function update(key: string, value: string) {
    const next = new URLSearchParams(params);
    if (value) next.set(key, value);
    else next.delete(key);
    setParams(next, { replace: true });
  }

  useEffect(() => setQDraft(q), [q]);
  useEffect(() => {
    if (qDraft === q) return;
    const t = setTimeout(() => update("q", qDraft.trim()), 350);
    return () => clearTimeout(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qDraft]);

  const load = useCallback(async () => {
    try {
      const page = await greyboxApi.targets({ archived, q: q || undefined, limit: 50 });
      setItems(page.items);
      setCursor(page.next_cursor);
      setError(null);
    } catch (e) {
      setItems(null);
      setError({ status: e instanceof ApiError ? e.status : 0, message: e instanceof Error ? e.message : "Failed to load targets" });
    }
  }, [archived, q]);

  useEffect(() => {
    setItems(null);
    void load();
  }, [load]);

  async function loadMore() {
    if (!cursor) return;
    setLoadingMore(true);
    try {
      const page = await greyboxApi.targets({ archived, q: q || undefined, limit: 50, cursor });
      setItems((cur) => [...(cur ?? []), ...page.items]);
      setCursor(page.next_cursor);
    } catch (e) {
      // 422 "Invalid cursor" (e.g. stale after a filter change): reload from page 1.
      if (e instanceof ApiError && e.status === 422) void load();
      else setError({ status: 0, message: e instanceof Error ? e.message : "Failed to load more" });
    } finally {
      setLoadingMore(false);
    }
  }

  return (
    <div>
      <Breadcrumb items={[{ label: "Vigilo", to: "/" }, { label: "Grey-box" }]} />
      <div className="mb-5 flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="text-xl font-semibold">Grey-box targets</h1>
          <p className="text-sm text-slate">
            Running applications you are authorised to test. All runs are listed under{" "}
            <Link to="/analyses?mode=greybox" className="text-accent hover:underline">Analyses</Link>.
          </p>
        </div>
        <Link to="/analyses/new?mode=greybox" className="btn-primary">
          <PlusIcon className="h-4 w-4" /> New target
        </Link>
      </div>

      <div className="mb-4 flex flex-wrap items-end gap-3">
        <div role="group" aria-label="Archived filter" className="inline-flex rounded-md border border-line bg-surface p-0.5">
          {[
            { v: false, label: "Active targets" },
            { v: true, label: "Archived" },
          ].map((o) => (
            <button
              key={o.label}
              type="button"
              aria-pressed={archived === o.v}
              onClick={() => update("archived", o.v ? "true" : "")}
              className={`rounded px-3 py-1.5 text-sm transition focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
                archived === o.v ? "bg-canvas font-medium text-ink ring-1 ring-line" : "text-slate hover:text-ink"
              }`}
            >
              {o.label}
            </button>
          ))}
        </div>
        <div className="min-w-[12rem] flex-1 sm:max-w-xs">
          <label htmlFor="gbt-q" className="sr-only">Search targets</label>
          <input
            id="gbt-q"
            type="search"
            className="field py-1.5"
            placeholder="Search name or URL"
            value={qDraft}
            onChange={(e) => setQDraft(e.target.value)}
          />
        </div>
        <button type="button" className="btn-ghost py-1.5" onClick={() => void load()} aria-label="Refresh">
          <ArrowPathIcon className="h-4 w-4" />
        </button>
      </div>

      {noModel && <div className="mb-4"><NoModelNotice /></div>}
      {cfg.status !== "loading" && !canStart && !noModel && (
        <p className="mb-4 rounded-md border border-line bg-surface p-3 text-sm text-slate">
          {cfg.status === "unavailable" ? cfg.reason : "Grey-box analysis is disabled on this server, so runs cannot be started."}
        </p>
      )}

      <div className="card">
        {error ? (
          <EmptyState icon={GlobeAltIcon} title={error.status === 404 ? "Grey-box targets are not available" : "Could not load targets"}>
            {error.status === 404
              ? "This server does not provide grey-box analysis, or it is disabled."
              : error.message}
          </EmptyState>
        ) : items === null ? (
          <p className="p-4 text-sm text-slate" role="status">Loading targets…</p>
        ) : items.length === 0 ? (
          <EmptyState
            icon={GlobeAltIcon}
            title={q ? "No targets match this search" : archived ? "No archived targets" : "No grey-box targets yet"}
            action={!q && !archived ? (
              <Link to="/analyses/new?mode=greybox" className="btn-primary"><PlusIcon className="h-4 w-4" /> New target</Link>
            ) : undefined}
          >
            {q ? "Try a different search." : archived ? "Archived targets appear here." : "Define a target URL and its authorised scope to start testing."}
          </EmptyState>
        ) : (
          <>
            {/* Desktop table */}
            <table className="hidden w-full text-sm md:table">
              <thead>
                <tr className="border-b border-line text-left text-slate">
                  <th className="px-4 py-3 font-medium">Name</th>
                  <th className="px-4 py-3 font-medium">Base URL</th>
                  <th className="px-4 py-3 font-medium">Scope</th>
                  <th className="px-4 py-3 font-medium">Last run</th>
                  <th className="px-4 py-3 font-medium"><span className="sr-only">Actions</span></th>
                </tr>
              </thead>
              <tbody>
                {items.map((t) => (
                  <tr key={t.id} className="border-b border-line/60 hover:bg-canvas">
                    <td className="px-4 py-3">
                      <Link to={`/greybox/targets/${t.id}`} className="font-medium hover:text-accent">{t.name}</Link>
                      {t.archived && <Badge className="ml-2">Archived</Badge>}
                    </td>
                    <td className="mono max-w-[16rem] break-all px-4 py-3 text-xs text-slate">{t.base_url}</td>
                    <td className="max-w-[20rem] px-4 py-3 text-xs"><ScopeSummary lines={t.scope_summary} /></td>
                    <td className="px-4 py-3"><LastRun t={t} /></td>
                    <td className="px-4 py-3"><Actions t={t} canStart={canStart} onStart={openStart} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
            {/* Mobile cards */}
            <ul className="divide-y divide-line md:hidden">
              {items.map((t) => (
                <li key={t.id} className="space-y-1.5 p-4">
                  <div className="flex flex-wrap items-center gap-2">
                    <Link to={`/greybox/targets/${t.id}`} className="font-medium hover:text-accent">{t.name}</Link>
                    {t.archived && <Badge>Archived</Badge>}
                  </div>
                  <p className="mono break-all text-xs text-slate">{t.base_url}</p>
                  <p className="text-xs"><ScopeSummary lines={t.scope_summary} /></p>
                  <div className="text-sm"><LastRun t={t} /></div>
                  <Actions t={t} canStart={canStart} onStart={openStart} />
                </li>
              ))}
            </ul>
          </>
        )}
      </div>
      {cursor && !error && (
        <div className="mt-4 flex justify-center">
          <button type="button" className="btn-ghost" disabled={loadingMore} onClick={loadMore}>
            {loadingMore ? "Loading…" : "Load more"}
          </button>
        </div>
      )}

      {startFor && (
        <ConfirmDialog
          title="Start grey-box analysis"
          danger={false}
          confirmLabel="I am authorised, start"
          body={
            <div className="space-y-2">
              <p>
                This sends real HTTP requests to <span className="mono break-all text-ink">{startFor.target.base_url}</span>,
                limited to this scope:
              </p>
              <ul className="list-disc pl-5 text-ink">
                {startFor.target.scope_summary.map((l, i) => <li key={i}>{l}</li>)}
              </ul>
              <p>By starting, you confirm you are authorised to test this target within this scope.</p>
            </div>
          }
          onConfirm={() => startRun(startFor.target.id, startFor.key)}
          onCancel={() => setStartFor(null)}
        />
      )}
    </div>
  );
}
