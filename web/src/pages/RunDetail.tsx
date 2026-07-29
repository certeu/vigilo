import { useEffect, useMemo, useRef, useState } from "react";
import { useParams } from "react-router-dom";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { api, getToken, type Job, type Run, type TraceRailConfig } from "../api/client";
import { TraceRail, type RailPhase } from "../components/TraceRail";
import { StatusDot } from "../components/StatusDot";

const TERMINAL = new Set(["succeeded", "failed", "cancelled"]);

// Slice a text workflow.log by rail step using the pipeline's own markers
// ("[PHASE] Starting: <name>" / "[AGENT] <name>: ...") — the log is human-readable
// text, not JSON. Each marker's raw phase/agent identifier is mapped to a rail step
// via the backend-provided config (no name guessing); each line is attributed to
// the most recent step seen.
function linesForPhase(
  lines: string[],
  selected: string | null,
  rail: TraceRailConfig | null,
): string[] {
  if (!selected || !rail) return lines;
  const stepFor = (name: string): string | null =>
    rail.phase_to_step[name] ?? rail.agent_to_step[name] ?? null;
  const out: string[] = [];
  let current: string | null = null;
  for (const ln of lines) {
    const pm = ln.match(/\[PHASE\]\s*\w+\s*:\s*(.+?)\s*$/);
    const am = ln.match(/\[AGENT\]\s*([\w-]+)\s*:/);
    if (pm) current = stepFor(pm[1]);
    else if (am) current = stepFor(am[1]);
    if (current === selected) out.push(ln);
  }
  return out;
}

export function RunDetail() {
  const { id } = useParams<{ id: string }>();
  const [run, setRun] = useState<Run | null>(null);
  const [job, setJob] = useState<Job | null>(null);
  const [lines, setLines] = useState<string[]>([]);
  const [selectedPhase, setSelectedPhase] = useState<string | null>(null);
  const [report, setReport] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [rail, setRail] = useState<TraceRailConfig | null>(null);
  const logScroll = useRef<HTMLDivElement>(null);

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
            if (text && text !== "{}") setLines((prev) => [...prev, text]);
          }
        }
      }
    })().catch(() => {});
    return () => controller.abort();
  }, [id]);

  useEffect(() => {
    if (!id || !run) return;
    if (!TERMINAL.has(run.status)) return;
    fetch(`/api/runs/${id}/report`, { headers: { Authorization: `Bearer ${getToken()}` } })
      .then((r) => r.json())
      .then((d) => setReport(d.exists ? d.markdown : null))
      .catch(() => {});
  }, [id, run]);

  const shownLines = useMemo(
    () => linesForPhase(lines, selectedPhase, rail),
    [lines, selectedPhase, rail],
  );

  // Auto-scroll the log container to the bottom on new lines, but only if the user
  // is already near the bottom (don't yank them up while they scroll back).
  useEffect(() => {
    const el = logScroll.current;
    if (!el) return;
    const nearBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 60;
    if (nearBottom) el.scrollTop = el.scrollHeight;
  }, [shownLines]);

  async function downloadReport() {
    const resp = await fetch(`/api/runs/${id}/artifacts/report_md`, {
      headers: { Authorization: `Bearer ${getToken()}` },
    });
    if (!resp.ok) return;
    const blob = await resp.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `vigilo-report-${id?.slice(0, 8)}.md`;
    a.click();
    URL.revokeObjectURL(url);
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
          <button className="btn-ghost ml-auto" onClick={() => id && api.cancelRun(id).then(setRun)}>
            Cancel
          </button>
        )}
      </div>

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
            {selectedPhase && (
              <button className="text-xs text-accent hover:underline" onClick={() => setSelectedPhase(null)}>
                Show all
              </button>
            )}
          </div>
          <div ref={logScroll} className="min-h-0 flex-1 overflow-auto bg-ink/[0.015] p-4">
            <pre className="mono whitespace-pre-wrap break-all text-xs leading-relaxed text-ink">
              {shownLines.length
                ? shownLines.join("\n")
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
            <button className="btn-ghost py-1" onClick={downloadReport}>Download</button>
          </div>
          <div className="markdown max-h-[640px] overflow-auto break-words p-6">
            <ReactMarkdown remarkPlugins={[remarkGfm]}>{report}</ReactMarkdown>
          </div>
        </section>
      )}
    </div>
  );
}
