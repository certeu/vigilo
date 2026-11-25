import { useMemo, type ReactNode } from "react";
import { Link } from "react-router-dom";
import { skippedDetail, skippedSummary } from "../checksAvailability";
import { ChevronDownIcon } from "@heroicons/react/24/outline";
import { endReasonLabel, formatDate, formatDuration } from "../format";
import { statusLabel } from "../../../lib/status";
import { RUN_TERMINAL, type RunRead, type Severity } from "../types";
import { SeverityChip, StatusBadge } from "../../../components/ui";
import { TODO_LABEL } from "../explorerView";
import { useRunLive } from "./RunLiveContext";
import { buildCycles, explorationCounts, latestTodolist, schedulerNotes, type Cycle } from "./explorationModel";
import { CoverageVerdictPanel } from "./CoverageVerdictPanel";
import { SecurityModelPanel } from "./SecurityModelPanel";

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];

const isNum = (v: unknown): v is number => typeof v === "number" && Number.isFinite(v);

function Section({ title, children, className = "" }: { title: string; children: ReactNode; className?: string }) {
  return (
    <section className={`card p-5 ${className}`}>
      <h2 className="mb-3 text-xs font-semibold uppercase tracking-wide text-slate">{title}</h2>
      {children}
    </section>
  );
}

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div>
      <dt className="text-xs text-slate">{label}</dt>
      <dd className="text-sm">{children}</dd>
    </div>
  );
}

/** "used / max" with a thin bar. Only rendered when both numbers come from the API. */
function Budget({ label, used, max, format }: { label: string; used: number; max: number; format: (v: number) => string }) {
  const pct = max > 0 ? Math.min(100, Math.round((used / max) * 100)) : 0;
  return (
    <div>
      <div className="flex items-baseline justify-between gap-3 text-sm">
        <span>{label}</span>
        <span className="mono text-xs text-slate">
          {format(used)} / {format(max)}
        </span>
      </div>
      <div className="mt-1 h-1.5 overflow-hidden rounded-full bg-line" aria-hidden="true">
        <div className="h-full rounded-full bg-accent/70" style={{ width: `${pct}%` }} />
      </div>
    </div>
  );
}

const CYCLE_STATE: Record<Cycle["state"], string> = { thinking: "thinking…", done: "", failed: "model call failed" };

/** Reasoning cycles of the exploration agent, newest last. Plain text only. */
export function CycleTimeline({ cycles, active }: { cycles: readonly Cycle[]; active: boolean }) {
  if (cycles.length === 0) {
    return <p className="text-sm text-slate">{active ? "Waiting for the exploration agent's first reasoning cycle…" : "No reasoning cycle was recorded."}</p>;
  }
  return (
    <ol className="space-y-3" aria-label="Exploration cycles">
      {cycles.map((c) => (
        <li key={c.cycle} className="border-l-2 border-line pl-3" data-testid="cycle">
          <p className="flex flex-wrap items-baseline gap-x-2 text-sm">
            <Link to={`?tab=activity&seq=${c.seq}`} className="font-medium text-accent hover:underline">Cycle {c.cycle}</Link>
            {c.trigger && <span className="text-xs text-slate">after {c.trigger}</span>}
            {c.assessment && <span className="text-xs font-medium">assessment: {c.assessment}</span>}
            {c.state !== "done" && (
              <span className={`text-xs font-medium ${c.state === "failed" ? "text-severity-critical" : "text-indigo-800"}`}>{CYCLE_STATE[c.state]}</span>
            )}
          </p>
          {(c.hypotheses !== null || c.actions !== null) && (
            <p className="text-xs text-slate">
              {c.hypotheses !== null && `${c.hypotheses} hypothes${c.hypotheses === 1 ? "is" : "es"}`}
              {c.hypotheses !== null && c.actions !== null && ", "}
              {c.actions !== null && `${c.actions} action${c.actions === 1 ? "" : "s"}`}
              {c.tools.length > 0 && <span className="mono"> · {[...new Set(c.tools)].join(", ")}</span>}
            </p>
          )}
          {c.reasoning && <p className="line-clamp-3 break-words text-[13px] text-ink" title={c.reasoning}>{c.reasoning}</p>}
          {c.error && <p className="break-words text-xs text-severity-critical">{c.error}</p>}
          {c.failures > 0 && c.state === "done" && <p className="text-xs text-slate">{c.failures} model call{c.failures === 1 ? "" : "s"} failed and were retried.</p>}
        </li>
      ))}
    </ol>
  );
}

export function OverviewTab({ run, elapsedS }: { run: RunRead; elapsedS: number | null }) {
  const terminal = RUN_TERMINAL.has(run.status);
  const c = run.counters ?? null;
  const wo = c?.work_orders;
  const f = run.findings;
  const { events } = useRunLive();
  const cycles = useMemo(() => buildCycles(events), [events]);
  const todo = useMemo(() => latestTodolist(events), [events]);
  const notes = useMemo(() => schedulerNotes(events), [events]);
  const counts = useMemo(() => explorationCounts(events), [events]);
  const l = run.limits;

  return (
    <div className="grid items-start gap-5 lg:grid-cols-3">
      {run.coverage_verdict && (
        <div className="lg:col-span-3">
          <CoverageVerdictPanel verdict={run.coverage_verdict} authStates={run.auth_states} />
        </div>
      )}
      <div className="lg:col-span-3">
        <SecurityModelPanel runId={run.id} runStatus={run.status} />
      </div>
      <Section title="Status" className="lg:col-span-2">
        <dl className="grid gap-x-6 gap-y-3 sm:grid-cols-2">
          <Row label="Status">
            <StatusBadge status={run.status} label={statusLabel(run.status)} />
            {run.cancel_requested && run.status !== "cancelled" && (
              <span className="ml-2 text-xs text-slate">(cancellation requested)</span>
            )}
          </Row>
          <Row label="Outcome">{terminal ? endReasonLabel(run.end_reason) : "Not finished"}</Row>
          <Row label="Created">{formatDate(run.created_at)}</Row>
          <Row label="Started">{run.started_at ? formatDate(run.started_at) : "Not started yet"}</Row>
          <Row label="Finished">{run.finished_at ? formatDate(run.finished_at) : "—"}</Row>
          <Row label="Duration">{run.started_at ? formatDuration(elapsedS) : "—"}</Row>
          {run.last_event_at !== undefined && <Row label="Last event">{formatDate(run.last_event_at)}</Row>}
          {run.heartbeat_at !== undefined && !terminal && <Row label="Worker heartbeat">{formatDate(run.heartbeat_at)}</Row>}
        </dl>
      </Section>

      <Section title="Findings">
        {f ? (
          <>
            <ul className="space-y-1.5" aria-label="Findings by severity (candidate and verified)">
              {SEVERITIES.map((s) => (
                <li key={s} className="flex items-center justify-between text-sm">
                  <SeverityChip severity={s} />
                  <span className="mono">{f.by_severity?.[s] ?? 0}</span>
                </li>
              ))}
            </ul>
            <p className="mt-3 border-t border-line pt-3 text-sm">
              <span className="font-medium">{f.verified}</span> verified ·{" "}
              <span className="font-medium">{f.candidate}</span> candidate ·{" "}
              <span className="text-slate">{f.rejected} rejected</span>
            </p>
            <p className="mt-1 text-xs text-slate">Severity counts include candidate and verified findings only.</p>
          </>
        ) : (
          <p className="text-sm text-slate">No finding counts were returned.</p>
        )}
      </Section>

      <Section title="Exploration (decided by the AI model)" className="lg:col-span-2">
        <CycleTimeline cycles={cycles} active={!terminal} />
        {notes.length > 0 && (
          <div className="mt-4 border-t border-line pt-3">
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate">Recent scheduler notes</h3>
            <ul className="space-y-1 text-xs">
              {notes.map((n) => (
                <li key={n.seq} className="break-words">
                  <Link to={`?tab=activity&seq=${n.seq}`} className="text-accent hover:underline">#{n.seq}</Link> {n.text}
                </li>
              ))}
            </ul>
          </div>
        )}
        <p className="mt-3 text-xs text-slate">
          The model decides every step, so there is no fixed list of phases and no completion percentage: the amount of work is discovered as the run goes.
        </p>
      </Section>

      <Section title="Todo list and progress">
        {todo.length === 0 ? (
          <p className="text-sm text-slate">The agent has not published a todo list yet.</p>
        ) : (
          <ul className="space-y-1" aria-label="Agent todo list">
            {todo.map((t, i) => (
              <li key={i} className="flex gap-2 text-[13px]">
                <span className="w-16 shrink-0 text-[11px] uppercase tracking-wide text-slate">{TODO_LABEL[t.status]}</span>
                <span className={`min-w-0 break-words ${t.status === "done" ? "text-slate line-through" : ""}`}>{t.step}</span>
              </li>
            ))}
          </ul>
        )}
        <dl className="mt-4 grid grid-cols-2 gap-x-4 gap-y-2 border-t border-line pt-3" aria-label="Progress counters">
          <Row label="Requests">{isNum(c?.requests) ? c!.requests!.toLocaleString() : "—"}</Row>
          <Row label="Reasoning cycles">{counts.cycles}</Row>
          <Row label="Work orders">
            {wo
              ? (["pending", "running", "done", "failed", "skipped", "cancelled"] as const)
                  .filter((k) => isNum(wo[k]) && (wo[k] as number) > 0)
                  .map((k) => `${wo[k]} ${k}`)
                  .join(" · ") || "none"
              : `${counts.workOrdersQueued} queued`}
          </Row>
          <Row label="Findings">{f ? `${f.verified} verified, ${f.candidate} candidate` : `${counts.findingsVerified} verified`}</Row>
        </dl>
      </Section>

      {(isNum(c?.requests) || (isNum(elapsedS) && run.started_at)) && (
        <Section title="Budgets (enforced)">
          <div className="space-y-3">
            {isNum(c?.requests) && (
              <Budget label="Requests" used={c!.requests!} max={l.max_requests} format={(v) => v.toLocaleString()} />
            )}
            {isNum(elapsedS) && run.started_at && (
              <Budget label="Duration" used={elapsedS} max={l.max_duration_s} format={formatDuration} />
            )}
            {isNum(c?.requests_blocked) && (
              <p className="text-xs text-slate">
                {c!.requests_blocked!.toLocaleString()} request{c!.requests_blocked === 1 ? "" : "s"} blocked by the scope policy.
              </p>
            )}
          </div>
        </Section>
      )}

      <details className="card group p-5 lg:col-span-3">
        <summary className="flex cursor-pointer list-none items-center justify-between gap-3 text-xs font-semibold uppercase tracking-wide text-slate [&::-webkit-details-marker]:hidden">
          <span>
            Configuration and budgets
            {skippedSummary(run.skipped_checks) && (
              <span
                className="ml-2 font-normal normal-case text-severity-medium"
                title={skippedDetail(run.skipped_checks)}
              >
                · {skippedSummary(run.skipped_checks)}
              </span>
            )}
          </span>
          <span className="flex items-center gap-1 font-normal normal-case">
            <span className="group-open:hidden">Show scope, limits, work orders</span>
            <span className="hidden group-open:inline">Hide</span>
            <ChevronDownIcon className="h-4 w-4 transition group-open:rotate-180" aria-hidden="true" />
          </span>
        </summary>
        <div className="mt-4 grid gap-6 md:grid-cols-3">
          <div>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate">Scope</h3>
            <ul className="list-disc space-y-0.5 pl-5 text-sm">
              {run.scope_summary.map((s, i) => <li key={i} className="break-words">{s}</li>)}
            </ul>
            <dl className="mt-3 space-y-2">
              <Row label="Authentication">{run.credential ? `Cookie: ${run.credential.label}` : "None (unauthenticated)"}</Row>
              <Row label="Network path">
                {run.egress_proxy ? `Via egress proxy: ${run.egress_proxy.name}` : "Direct"}
              </Row>
              {run.model && (
                <Row label="AI model">{run.model_backend ? `${run.model_backend} · ${run.model}` : run.model}</Row>
              )}
              <Row label="Checks">
                <span className="mono text-xs">{run.checks.length ? run.checks.join(", ") : "None"}</span>
              </Row>
              {skippedSummary(run.skipped_checks) && (
                <Row label="Not available in this build">
                  <ul className="space-y-0.5 text-xs">
                    {run.skipped_checks!.map((c) => (
                      <li key={c.id} title={c.reason}>
                        <span className="mono">{c.id}</span> <span className="text-slate">· {c.reason}</span>
                      </li>
                    ))}
                  </ul>
                </Row>
              )}
            </dl>
            <p className="mt-2 text-xs text-slate">The snapshot the run started with; later target edits do not change it.</p>
          </div>
          <div>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate">Limits</h3>
            <dl className="grid grid-cols-2 gap-x-4 gap-y-2">
              <Row label="Max requests">{l.max_requests.toLocaleString()}</Row>
              <Row label="Max duration">{formatDuration(l.max_duration_s)}</Row>
              <Row label="Concurrency">{l.max_concurrency}</Row>
              <Row label="Rate limit">{l.rate_limit_rps} req/s</Row>
              <Row label="Request timeout">{l.request_timeout_s}s</Row>
              <Row label="Max pages">{l.max_pages.toLocaleString()}</Row>
            </dl>
          </div>
          <div>
            <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate">Work orders</h3>
            {wo ? (
              <dl className="grid grid-cols-3 gap-3 text-sm">
                {(["pending", "running", "done", "failed", "skipped", "cancelled"] as const).map((k) =>
                  isNum(wo[k]) ? (
                    <div key={k}>
                      <dt className="text-xs capitalize text-slate">{k}</dt>
                      <dd className="mono">{wo[k]}</dd>
                    </div>
                  ) : null,
                )}
              </dl>
            ) : (
              <p className="text-sm text-slate">No work order counts were returned.</p>
            )}
          </div>
        </div>
      </details>
    </div>
  );
}
