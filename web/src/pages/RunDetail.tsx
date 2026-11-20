import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, getToken, type Job, type Run, type TraceRailConfig } from "../api/client";
import { TraceRail, type RailPhase } from "../components/TraceRail";
import { StatusDot } from "../components/StatusDot";
import { ConfirmDialog } from "../components/ConfirmDialog";

const TERMINAL = new Set(["succeeded", "failed", "cancelled"]);

// One log entry as served by /runs/{id}/logs/stream. Runs with a structured
// event log carry their trace-rail `step` and `level`; runs recorded before the
// event log existed only have the raw text `line`.
interface LogEntry {
  line: string;
  step?: string | null;
  level?: string;
  kind?: string;
  actor?: string | null;
  // agent.retrying only
  data?: {
    attempt?: number;
    max_attempts?: number | null;
    error_type?: string;
    reason?: string;
    next_attempt_at?: string | null;
    retry_in_s?: number | null;
  };
}

// Agents whose latest failed attempt is waiting for a retry: an agent.retrying
// event stands until that agent starts again or finishes.
function pendingRetries(entries: LogEntry[]): LogEntry[] {
  const pending = new Map<string, LogEntry>();
  for (const e of entries) {
    const actor = e.actor ?? "";
    if (e.kind === "agent.retrying") pending.set(actor, e);
    else if (e.kind === "agent.started" || e.kind === "agent.finished") pending.delete(actor);
  }
  return [...pending.values()];
}

function retryWhen(d: NonNullable<LogEntry["data"]>, now: number): string {
  const at = d.next_attempt_at ? Date.parse(d.next_attempt_at) : NaN;
  if (Number.isNaN(at)) return "retrying";
  const secs = Math.round((at - now) / 1000);
  if (secs <= 5) return "retrying now";
  if (secs < 90) return `retrying in ~${secs}s`;
  return `retrying in ~${Math.round(secs / 60)} min`;
}

function parseEntry(text: string): LogEntry {
  if (text.startsWith("{")) {
    try {
      const obj = JSON.parse(text);
      if (obj && typeof obj.line === "string") return obj as LogEntry;
    } catch {
      /* not JSON — fall through */
    }
  }
  return { line: text };
}

// Attribute each entry to a rail step. Structured entries say so directly;
// legacy text lines are attributed via their "[PHASE] …" / "[AGENT] name:"
// markers (mapped through the backend config), each line belonging to the most
// recent step seen.
function withSteps(entries: LogEntry[], rail: TraceRailConfig | null): LogEntry[] {
  if (!rail) return entries;
  const stepFor = (name: string): string | null =>
    rail.phase_to_step[name] ?? rail.agent_to_step[name] ?? null;
  let current: string | null = null;
  return entries.map((e) => {
    if (e.step !== undefined) {
      current = e.step ?? current;
      return e;
    }
    const pm = e.line.match(/\[PHASE\]\s*\w+\s*:\s*(.+?)\s*$/);
    const am = e.line.match(/\[AGENT\]\s*([\w-]+)\s*:/);
    if (pm) current = stepFor(pm[1]);
    else if (am) current = stepFor(am[1]);
    return { ...e, step: current };
  });
}

const LEVEL_CLASS: Record<string, string> = {
  error: "text-severity-critical",
  warn: "text-severity-medium",
  debug: "text-slate",
};

export function RunDetail() {
  const { id } = useParams<{ id: string }>();
  const [run, setRun] = useState<Run | null>(null);
  const [confirmStop, setConfirmStop] = useState(false);
  const [job, setJob] = useState<Job | null>(null);
  const [entries, setEntries] = useState<LogEntry[]>([]);
  const [showAgentOutput, setShowAgentOutput] = useState(false);
  const [selectedPhase, setSelectedPhase] = useState<string | null>(null);
  const [report, setReport] = useState<string | null>(null);
  const [artifacts, setArtifacts] = useState<string[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [rail, setRail] = useState<TraceRailConfig | null>(null);
  const logScroll = useRef<HTMLDivElement>(null);
  const [now, setNow] = useState(() => Date.now());
  const retries = useMemo(() => pendingRetries(entries), [entries]);

  // Tick so the "retrying in ..." countdown stays current while a retry is pending.
  useEffect(() => {
    if (!retries.length) return;
    const t = setInterval(() => setNow(Date.now()), 5000);
    return () => clearInterval(t);
  }, [retries.length]);

  // Fetch the canonical rail steps + phase/agent → step map once (static config).
  useEffect(() => {
    api.traceRail().then(setRail).catch(() => {});
  }, []);

  useEffect(() => {
    if (!id) return;
    let active = true;
    let fails = 0;
    async function tick() {
      try {
        const r = await api.run(id!);
        if (!active) return;
        setRun(r);
        setError(null);
        fails = 0;
        if (!job) {
          const jobs = await api.jobs();
          setJob(jobs.find((j) => j.id === r.job_id) ?? null);
        }
      } catch (e) {
        fails += 1;
        // Surface a persistent failure instead of an infinite "Loading…".
        if (fails >= 3) setError(e instanceof Error ? e.message : "Failed to load run");
      }
    }
    void tick();
    const t = setInterval(tick, 3000);
    return () => { active = false; clearInterval(t); };
  }, [id, job]);

  useEffect(() => {
    if (!id) return;
    const controller = new AbortController();
    (async () => {
      const resp = await fetch(`/api/runs/${id}/logs/stream`, {
        headers: { Authorization: `Bearer ${getToken()}` },
        signal: controller.signal,
      });
      if (!resp.body) return;
      const reader = resp.body.getReader();
      const decoder = new TextDecoder();
      let buf = "";
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        buf += decoder.decode(value, { stream: true });
        const events = buf.split("\n\n");
        buf = events.pop() ?? "";
        for (const ev of events) {
          const dataLine = ev.split("\n").find((l) => l.startsWith("data:"));
          if (dataLine) {
            const text = dataLine.slice(5).trim();
            if (text && text !== "{}") setEntries((prev) => [...prev, parseEntry(text)]);
          }
        }
      }
    })().catch(() => {});
    return () => controller.abort();
  }, [id]);

  const isTerminal = run ? TERMINAL.has(run.status) : false;
  useEffect(() => {
    if (!id || !isTerminal) return;
    fetch(`/api/runs/${id}/report`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then((r) => r.json())
      .then((d) => setReport(d.exists ? d.markdown : null))
      .catch(() => {});
    fetch(`/api/runs/${id}/artifacts`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then((r) => r.json())
      .then((d) => setArtifacts(Array.isArray(d.artifacts) ? d.artifacts : []))
      .catch(() => {});
  }, [id, isTerminal]);

  const shownLines = useMemo(
    () =>
      withSteps(entries, rail).filter(
        (e) =>
          (!selectedPhase || e.step === selectedPhase) &&
          (showAgentOutput || e.kind !== "agent.turn"),
      ),
    [entries, selectedPhase, rail, showAgentOutput],
  );

  // Auto-scroll the log container to the bottom on new lines, but only if the user
  // is already near the bottom (don't yank them up while they scroll back).
  useEffect(() => {
    const el = logScroll.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [shownLines]);

  async function downloadArtifact(kind: string, filename: string) {
    const resp = await fetch(`/api/runs/${id}/artifacts/${kind}`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    if (!resp.ok) {
      setDownloadError(`Download failed (${resp.status})`);
      return;
    }
    setDownloadError(null);
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  if (error && !run) return <p className="text-sm text-severity-critical">Could not load run: {error}</p>;
  if (!run) return <p className="text-slate">Loading…</p>;

  // Resolve the rail steps for this preset and the active step from current_phase,
  // both via the backend config (no hardcoded phase list or name guessing).
  const preset = job?.stage_preset ?? "full";
  const railSteps: RailPhase[] = rail
    ? (rail.presets[preset] ?? rail.presets.full ?? []).map((k) => ({
        key: k,
        label: rail.steps.find((s) => s.key === k)?.label ?? k,
      }))
    : [];
  const activeKey = rail && run.current_phase ? rail.phase_to_step[run.current_phase] ?? null : null;

  return (
    <div>
      <div className="mb-6 flex items-center gap-3">
        <StatusDot status={run.status} />
        <h1 className="text-xl font-semibold">Run {run.id.slice(0, 8)}</h1>
        <span className="mono text-sm text-slate">
          {job?.stage_preset} · {run.status}
          {run.total_cost_usd != null ? ` · $${run.total_cost_usd.toFixed(2)}` : ""}
          {run.commit_sha ? ` · commit ${run.commit_sha.slice(0, 8)}` : ""}
        </span>
        {!TERMINAL.has(run.status) && (
          <button className="btn-ghost ml-auto" onClick={() => setConfirmStop(true)}>
            Stop
          </button>
        )}
      </div>

      {confirmStop && (
        <ConfirmDialog
          title="Stop run"
          confirmLabel="Stop"
          body={
            <>
              This stops the scan; the run and its results so far are kept. A
              cancelled scan cannot be restarted.
            </>
          }
          onConfirm={async () => {
            if (!id) return;
            setRun(await api.cancelRun(id));
            setConfirmStop(false);
          }}
          onCancel={() => setConfirmStop(false)}
        />
      )}

      {!TERMINAL.has(run.status) &&
        retries.map((e) => {
          const d = e.data ?? {};
          return (
            <div
              key={e.actor ?? ""}
              className="card mb-4 border-severity-medium/40 bg-severity-medium/5 p-3 text-sm"
            >
              <div className="font-semibold text-severity-medium">
                {e.actor ?? "agent"} failed (attempt {d.attempt ?? "?"}
                {d.max_attempts ? ` of ${d.max_attempts}` : ""}) — {retryWhen(d, now)}
              </div>
              <div className="mono mt-1 whitespace-pre-wrap break-words text-slate">
                {d.reason}
              </div>
            </div>
          );
        })}

      {(run.error_summary || run.status === "failed") && (
        <div className="card mb-4 border-severity-critical/30 bg-severity-critical/5 p-3 text-sm">
          <div className="mb-1 font-semibold text-severity-critical">
            Run failed{run.current_phase ? ` during ${run.current_phase}` : ""}
          </div>
          <div className="mono whitespace-pre-wrap break-words text-severity-critical/90">
            {run.error_summary || "No failure detail was captured for this run."}
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[220px_minmax(0,1fr)] lg:gap-8">
        <aside className="card min-w-0 self-start p-4">
          <h2 className="mb-3 px-2 text-xs font-semibold uppercase tracking-wide text-slate">
            Trace Rail
          </h2>
          <TraceRail
            steps={railSteps}
            activeKey={activeKey}
            status={run.status}
            selected={selectedPhase}
            onSelect={setSelectedPhase}
          />
          <p className="mt-3 px-2 text-xs text-slate">Click a step to filter its logs.</p>
        </aside>

        <section className="card flex h-[70vh] min-w-0 flex-col overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-4 py-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate">
              Evidence / logs
              {selectedPhase ? ` · ${railSteps.find((s) => s.key === selectedPhase)?.label ?? selectedPhase}` : ""}
            </span>
            <div className="flex items-center gap-4">
              <label className="flex items-center gap-1.5 text-xs text-slate">
                <input
                  type="checkbox"
                  checked={showAgentOutput}
                  onChange={(e) => setShowAgentOutput(e.target.checked)}
                />
                Agent output
              </label>
              {selectedPhase && (
                <button className="text-xs text-accent hover:underline" onClick={() => setSelectedPhase(null)}>
                  Show all
                </button>
              )}
            </div>
          </div>
          <div ref={logScroll} className="min-h-0 flex-1 overflow-auto bg-ink/[0.015] p-4">
            <pre className="mono whitespace-pre-wrap break-all text-xs leading-relaxed text-ink">
              {shownLines.length
                ? shownLines.map((e, i) => (
                    <div key={i} className={LEVEL_CLASS[e.level ?? ""] ?? ""}>
                      {e.line}
                    </div>
                  ))
                : selectedPhase
                  ? "No log lines for this step yet."
                  : "Waiting for output…"}
            </pre>
          </div>
        </section>
      </div>

      {report !== null && (
        <section className="card mt-8 overflow-hidden">
          <div className="flex items-center justify-between border-b border-line px-4 py-2">
            <span className="text-xs font-semibold uppercase tracking-wide text-slate">Report</span>
            <div className="flex items-center gap-2">
              {downloadError && <span className="text-xs text-severity-critical">{downloadError}</span>}
              {artifacts.includes("bundle") && (
                <button
                  className="btn-ghost py-1"
                  onClick={() => downloadArtifact("bundle", `vigilo-deliverables-${id?.slice(0, 8)}.zip`)}
                >
                  Download all (.zip)
                </button>
              )}
              {artifacts.includes("patches") && (
                <button
                  className="btn-ghost py-1"
                  onClick={() => downloadArtifact("patches", `vigilo-patches-${id?.slice(0, 8)}.zip`)}
                >
                  Download patches (.zip)
                </button>
              )}
              <button
                className="btn-ghost py-1"
                onClick={() => downloadArtifact("report_md", `vigilo-report-${id?.slice(0, 8)}.md`)}
              >
                Download
              </button>
            </div>
          </div>
          <div className="markdown max-h-[640px] overflow-auto break-words p-6">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{report}</ReactMarkdown>
          </div>
        </section>
      )}
    </div>
  );
}
