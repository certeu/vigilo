// "Agent reasoning": the latest exploration-agent cycle, live from the run's event stream
// (llm.request / llm.response / llm.failed, planner.decision). Plain text only.
import { useMemo } from "react";
import { Link } from "react-router-dom";
import { useRunLive } from "./RunLiveContext";
import { explorerLive, llmMeta, TODO_LABEL, type ExplorerLive } from "../explorerView";

const plural = (n: number, w: string) => `${n} ${n === 1 ? w : w === "hypothesis" ? "hypotheses" : `${w}s`}`;

export function AgentReasoningView({ live, active }: { live: ExplorerLive; active: boolean }) {
  const { phase, cycle, last, error, decision } = live;
  const status =
    phase === "thinking" ? `Thinking… (cycle ${cycle ?? "?"})`
    : phase === "failed" ? `Model call failed${cycle ? ` (cycle ${cycle})` : ""}`
    : last ? `Cycle ${last.cycle ?? "?"}` : active ? "Waiting for the first reasoning cycle…" : "No reasoning recorded";
  const counts = last ? [last.hypotheses !== null ? plural(last.hypotheses, "hypothesis") : null, last.actions !== null ? plural(last.actions, "action") : null].filter(Boolean) : [];
  const meta = last ? llmMeta({ model: last.model, tokens: last.tokens, trigger: last.trigger }) : null;
  return (
    <section className="card mb-4 p-4" aria-label="Agent reasoning" data-testid="agent-reasoning">
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
        <h2 className="text-xs font-semibold uppercase tracking-wide text-slate">Agent reasoning</h2>
        <p className="flex flex-wrap items-center gap-x-3 text-xs text-slate" role="status" aria-live="polite">
          <span className={phase === "failed" ? "font-medium text-severity-critical" : phase === "thinking" ? "font-medium text-indigo-800" : ""}>{status}</span>
          {last && phase !== "responded" && <span>last completed: cycle {last.cycle ?? "?"}</span>}
          {meta && <span>{meta}</span>}
        </p>
      </div>
      {phase === "failed" && error && <p className="mt-2 break-words text-sm text-severity-critical">{error}</p>}
      {decision && active && <p className="mt-2 text-xs text-slate">{decision}</p>}
      {last && (
        <div className="mt-3 grid gap-4 lg:grid-cols-3">
          <div className="lg:col-span-2">
            {last.assessment && (
              <p className="mb-1 text-sm">
                <span className="text-slate">Assessment: </span>
                <span className="font-medium">{last.assessment}</span>
                {counts.length > 0 && <span className="text-slate"> — {counts.join(", ")} proposed</span>}
              </p>
            )}
            <p className="max-h-40 overflow-y-auto whitespace-pre-wrap break-words text-[13px] text-ink">{last.reasoning ?? "No reasoning text recorded."}</p>
          </div>
          <div>
            <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Todo list</h3>
            {last.todolist.length === 0 ? (
              <p className="text-xs text-slate">None.</p>
            ) : (
              <ul className="max-h-40 space-y-1 overflow-y-auto">
                {last.todolist.map((t, i) => (
                  <li key={i} className="flex gap-2 text-[13px]">
                    <span className="w-16 shrink-0 text-[11px] uppercase tracking-wide text-slate">{TODO_LABEL[t.status]}</span>
                    <span className={`min-w-0 break-words ${t.status === "done" ? "text-slate line-through" : ""}`}>{t.step}</span>
                  </li>
                ))}
              </ul>
            )}
            <p className="mt-2 text-xs text-slate">
              <Link to={`?tab=activity&seq=${last.seq}`} className="text-accent hover:underline">Open event</Link>
              {" · "}
              <Link to="?tab=exploration" className="text-accent hover:underline">See in graph</Link>
            </p>
          </div>
        </div>
      )}
    </section>
  );
}

/** Reads the run's live stream (RunLiveProvider) and renders the latest explorer cycle. */
export function AgentReasoningPanel({ active }: { active: boolean }) {
  const { events } = useRunLive();
  const live = useMemo(() => explorerLive(events), [events]);
  if (live.phase === "idle" && !active) return null;
  return <AgentReasoningView live={live} active={active} />;
}
