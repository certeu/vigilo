// Human view of a run event: a one-line headline plus the meaningful fields only.
// Pure and defensive (event data is untrusted JSON); every value is plain text.
// "Task output" gathers what a work order's tool actually observed (requests, result,
// observations, findings) from the events that share its work_order_id.
import type { GreyboxEvent } from "../events";

export interface ViewLine {
  label: string;
  value: string;
  /** Monospace values (URLs, ids, tool names). */
  mono?: boolean;
}

export interface EventView {
  headline: string;
  lines: ViewLine[];
}

type Data = Record<string, unknown>;

const VALUE_MAX = 400;
const clip = (t: string, n = VALUE_MAX) => (t.length > n ? `${t.slice(0, n)}…` : t);
const isObj = (v: unknown): v is Data => !!v && typeof v === "object" && !Array.isArray(v);
const str = (v: unknown): string | null => (typeof v === "string" && v.trim() ? v.trim() : null);
const num = (v: unknown): number | null => (typeof v === "number" && Number.isFinite(v) ? v : null);
const strList = (v: unknown): string[] => (Array.isArray(v) ? v.filter((x): x is string => typeof x === "string" && !!x.trim()) : []);
const plural = (n: number, w: string, pl = `${w}s`) => `${n} ${n === 1 ? w : pl}`;

/** "ruled_out" -> "ruled out". */
export const humanize = (s: string): string => s.replace(/[_-]+/g, " ").trim();

/** Empty values carry no information: null, "", [], {}, and objects whose values are all empty. */
export function isEmptyValue(v: unknown): boolean {
  if (v === null || v === undefined) return true;
  if (typeof v === "string") return v.trim() === "";
  if (Array.isArray(v)) return v.length === 0;
  if (isObj(v)) return Object.values(v).every(isEmptyValue);
  return false;
}

export function scalarText(v: unknown): string {
  if (v === null || v === undefined) return "—";
  if (typeof v === "string") return clip(v);
  if (typeof v === "number" || typeof v === "boolean") return String(v);
  if (Array.isArray(v) && v.every((x) => typeof x === "string" || typeof x === "number")) return clip(v.join(", "));
  try {
    return clip(JSON.stringify(v) ?? String(v));
  } catch {
    return String(v);
  }
}

/** Key/value rows from a payload, hiding empty values and any key in `skip`. */
export function dataLines(data: Data | null | undefined, skip: readonly string[] = []): ViewLine[] {
  const out: ViewLine[] = [];
  for (const [k, v] of Object.entries(data ?? {})) {
    if (skip.includes(k) || isEmptyValue(v)) continue;
    out.push({ label: humanize(k), value: scalarText(v) });
  }
  return out;
}

const line = (label: string, value: string | number | null | undefined, mono = false): ViewLine[] =>
  value === null || value === undefined || value === "" ? [] : [{ label, value: String(value), mono }];

// ---- planner trigger ----

const TRIGGER_TEXT: Record<string, string> = {
  start: "run start",
  idle: "nothing left queued",
  delta: "new results since the last cycle",
  wo_terminal: "work orders finished",
  agent: "the exploration agent's proposal",
  finding: "new finding",
  asset: "newly discovered assets",
  lead: "an open lead",
  hint: "an analyst hint",
  admission: "admission check",
  run: "run start",
};

export function triggerText(trigger: unknown): string | null {
  if (typeof trigger === "string") return TRIGGER_TEXT[trigger] ?? humanize(trigger);
  if (!isObj(trigger)) return null;
  const kind = str(trigger.kind);
  if (!kind) return null;
  const base = TRIGGER_TEXT[kind] ?? humanize(kind);
  const n = Array.isArray(trigger.node_ids) ? trigger.node_ids.length : 0;
  return n > 1 ? `${base} (${n} nodes)` : base;
}

// ---- planner.decision ----

function settleOutcome(reason: string): { lead: string; outcome: string } | null {
  const m = /^lead '(.+)' (\w+)(?: \((\w+)\))?$/.exec(reason);
  return m ? { lead: m[1], outcome: `${m[2]}${m[3] ? ` (${humanize(m[3])})` : ""}` } : null;
}

function plannerView(e: GreyboxEvent): EventView {
  const d = e.data ?? {};
  const decision = str(d.decision) ?? "";
  const reason = str(d.reason) ?? "";
  const trig = triggerText(d.trigger);
  const woIds = Array.isArray(d.work_order_ids) ? d.work_order_ids.length : 0;
  const triggerLine = line("Triggered by", trig);

  switch (decision) {
    case "waiting_for_explorer": {
      const grace = num(d.grace_s) ?? (/up to (\d+)s/.exec(reason)?.[1] ? Number(/up to (\d+)s/.exec(reason)![1]) : null);
      const why = /\):\s*(.+)$/.exec(reason)?.[1] ?? null;
      return {
        headline: `Waiting for the exploration agent${grace ? ` (up to ${grace}s)` : ""}${why ? `: ${why}` : ""}`,
        lines: [...line("Why", why), ...line("Waits at most", grace ? `${grace} s` : null)],
      };
    }
    case "dispatch": {
      const byAgent = reason.startsWith("explorer:");
      const text = byAgent ? reason.slice("explorer:".length).trim() : reason;
      const headline = byAgent
        ? `Explorer's plan queued${woIds ? ` ${plural(woIds, "work order")}` : ""}`
        : `Queued${woIds ? ` ${plural(woIds, "work order")}` : ""}: ${text}`;
      return {
        headline,
        lines: [
          ...line(byAgent ? "Explorer's reasoning" : "Why", text),
          ...line("Work orders queued", woIds || null),
          ...triggerLine,
        ],
      };
    }
    case "settle_lead": {
      const s = settleOutcome(reason);
      return {
        headline: s ? `Lead '${s.lead}' settled: ${s.outcome}` : reason || "Lead settled",
        lines: [...(s ? [...line("Lead", s.lead), ...line("Outcome", s.outcome)] : line("Why", reason)), ...triggerLine],
      };
    }
    case "open_lead":
      return { headline: reason || "Lead opened", lines: triggerLine };
    case "rejected": {
      const tool = str(d.tool);
      return {
        headline: `Rejected${tool ? ` ${tool}` : ""}: ${str(d.detail) ?? humanize(reason)}`,
        lines: [...line("Tool", tool, true), ...line("Why", humanize(reason)), ...line("Detail", str(d.detail))],
      };
    }
    case "model_retry":
      return {
        headline: reason || "Model call failed, retrying",
        lines: [...line("Attempt", num(d.attempt)), ...line("Error", str(d.error))],
      };
    case "explorer_adequate":
      return { headline: "The exploration agent judged the assessment adequate", lines: line("Details", reason) };
    case "explorer_no_work":
    case "explorer_exhausted": {
      const why = str(d.why);
      const round = num(d.empty_rounds);
      const max = num(d.max_empty_rounds);
      const rounds = round !== null && max !== null ? `${round} of ${max}` : null;
      const head =
        decision === "explorer_exhausted"
          ? "The exploration agent found no new avenues: completing"
          : `The exploration agent proposed no new work${why ? ` (${humanize(why)})` : ""}`;
      return {
        headline: rounds ? `${head} (empty round ${rounds})` : head,
        lines: [...line("Why", why ? humanize(why) : null), ...line("Assessment", str(d.assessment)), ...line("Empty rounds", rounds)],
      };
    }
    case "explorer_ask_again":
      return { headline: "Asking the exploration agent again", lines: line("Details", reason) };
    default:
      return {
        headline: reason ? `${humanize(decision || "decision")}: ${reason}` : e.summary,
        lines: [...line("Reason", reason), ...triggerLine, ...dataLines(d, ["decision", "reason", "trigger", "work_order_ids", "considered"])],
      };
  }
}

// ---- tool args / results ----

const ARG_LABEL: Record<string, string> = { url: "URL", path: "Path", header: "Header", expect: "Expected", finding_id: "Finding" };

export function toolArgLines(args: unknown): ViewLine[] {
  if (!isObj(args)) return [];
  return Object.entries(args)
    .filter(([, v]) => !isEmptyValue(v))
    .map(([k, v]) => ({ label: ARG_LABEL[k] ?? humanize(k), value: scalarText(v), mono: k !== "expect" }));
}

export function toolResultLines(result: unknown): ViewLine[] {
  if (!isObj(result)) return [];
  return Object.entries(result)
    .filter(([, v]) => !isEmptyValue(v))
    .map(([k, v]) => ({ label: humanize(k), value: scalarText(v) }));
}

/** "status 200, 25 links" style one-liner for a tool result. */
export function toolResultBrief(result: unknown): string {
  return toolResultLines(result).map((l) => `${l.label} ${l.value}`).join(", ");
}

const TRIGGER_REASON: Record<string, string> = TRIGGER_TEXT;

// ---- per-kind view ----

export function describeEvent(e: Pick<GreyboxEvent, "kind" | "summary" | "data"> & Partial<GreyboxEvent>): EventView {
  const d: Data = e.data ?? {};
  const full = e as GreyboxEvent;
  switch (e.kind) {
    case "planner.decision":
      return plannerView(full);
    case "work_order.created": {
      const tool = str(d.tool);
      return {
        headline: str(d.title) ?? e.summary,
        lines: [
          ...line("Tool", tool, true),
          ...line("Kind", str(d.kind)),
          ...line("Why", str(d.reason)),
          ...line("Priority", num(d.priority)),
        ],
      };
    }
    case "work_order.claimed": {
      const attempt = num(d.attempt);
      return { headline: e.summary, lines: attempt && attempt > 1 ? line("Attempt", attempt) : [] };
    }
    case "work_order.completed": {
      const tool = e.summary.replace(/ done:.*$/, "");
      const res = str(d.result_summary);
      return {
        headline: res ? `${tool} done: ${res}` : `${tool} done (no result summary recorded)`,
        lines: [...line("Result", res ?? "no summary recorded")],
      };
    }
    case "work_order.failed": {
      const retry = d.will_retry === true;
      return {
        headline: e.summary,
        lines: [...line("Error", str(d.error)), ...line("Attempt", num(d.attempt)), ...line("Will retry", retry ? "yes" : "no")],
      };
    }
    case "tool.started": {
      const tool = str(d.tool) ?? "tool";
      const args = toolArgLines(d.args);
      const url = args.find((a) => a.label === "URL")?.value;
      return { headline: url ? `${tool} started on ${url}` : e.summary, lines: [...line("Tool", tool, true), ...args] };
    }
    case "tool.succeeded": {
      const tool = str(d.tool) ?? "tool";
      const brief = toolResultBrief(d.result);
      return {
        headline: brief ? `${tool} succeeded: ${brief}` : `${tool} succeeded (no result details recorded)`,
        lines: [...line("Tool", tool, true), ...toolResultLines(d.result)],
      };
    }
    case "tool.failed":
      return { headline: e.summary, lines: [...line("Tool", str(d.tool), true), ...line("Error", str(d.error))] };
    case "http.exchange": {
      const hop = num(d.redirect_hop);
      return {
        headline: e.summary,
        lines: [
          ...line("Request", [str(d.method), str(d.url)].filter(Boolean).join(" "), true),
          ...line("Status", num(d.status_code)),
          ...line("Took", num(d.duration_ms) !== null ? `${num(d.duration_ms)} ms` : null),
          ...line("Redirect hop", hop && hop > 0 ? hop : null),
          ...line("Exchange", num(d.exchange_id) !== null ? `#${num(d.exchange_id)}` : null),
        ],
      };
    }
    case "scope.blocked":
      return { headline: e.summary, lines: [...line("URL", str(d.url), true), ...line("Why", str(d.reason) ? humanize(String(d.reason)) : null)] };
    case "finding.created":
      return {
        headline: e.summary,
        lines: [...line("Finding", str(d.title)), ...line("Severity", str(d.severity)), ...line("Found by", str(d.check_id), true), ...line("Status", str(d.status))],
      };
    case "finding.verified":
      return {
        headline: e.summary,
        lines: [...line("Verification", str(d.method)), ...line("Evidence", Array.isArray(d.exchange_ids) && d.exchange_ids.length ? `exchange ${d.exchange_ids.map((x) => `#${x}`).join(", ")}` : null)],
      };
    case "finding.rejected":
      return { headline: e.summary, lines: dataLines(d, ["finding_id"]) };
    case "observation.recorded": {
      const f = isObj(d.facts) ? d.facts : {};
      const params = strList(f.params);
      const links = num(f.links);
      const forms = num(f.forms);
      return {
        headline: e.summary,
        lines: [
          ...line("Status", num(f.status)),
          ...line("Links", links && links > 0 ? links : null),
          ...line("Parameters", params.length ? params.join(", ") : null),
          ...line("Forms", forms && forms > 0 ? forms : null),
          ...line("Redirects to", str(f.redirect_to), true),
        ],
      };
    }
    case "asset.discovered":
      return { headline: e.summary, lines: [...line("Kind", str(d.kind)), ...line("Key", str(d.key), true), ...line("In scope", typeof d.in_scope === "boolean" ? (d.in_scope ? "yes" : "no") : null)] };
    case "surface.updated":
      return {
        headline: e.summary,
        lines: [...line("Kind", str(d.kind)), ...line("Risk score", num(d.risk_score)), ...line("Changed", strList(d.changed).map(humanize).join(", "))],
      };
    case "defense.proposed":
      return {
        headline: e.summary,
        lines: [...line("Title", str(d.title)), ...line("Kind", str(d.kind) ? humanize(String(d.kind)) : null), ...line("Format", str(d.format)), ...line("Scope", str(d.scope))],
      };
    case "graph.updated":
      return {
        headline: `Graph v${num(d.version) ?? "?"}: ${num(d.nodes) ?? 0} nodes, ${num(d.assets) ?? 0} assets`,
        lines: dataLines(d, ["max_created_version"]),
      };
    case "llm.request": {
      const r = str(d.reason);
      return {
        headline: e.summary,
        lines: [...line("Cycle", num(d.cycle)), ...line("Triggered by", r ? (TRIGGER_REASON[r] ?? humanize(r)) : null), ...line("Prompt size", num(d.prompt_chars) !== null ? `${num(d.prompt_chars)!.toLocaleString()} characters` : null)],
      };
    }
    case "llm.response": {
      const labels = strList(d.hypothesis_labels);
      const tools = strList(d.action_tools);
      const trig = str(d.trigger);
      return {
        headline: e.summary,
        lines: [
          ...line("Assessment", str(d.assessment)),
          ...line("Triggered by", trig ? (TRIGGER_REASON[trig] ?? humanize(trig)) : null),
          ...line("Hypotheses", labels.length ? labels.join(", ") : num(d.hypotheses)),
          ...line("Tools requested", tools.length ? tools.join(", ") : null, true),
        ],
      };
    }
    case "llm.failed":
      return { headline: e.summary, lines: [...line("Error", str(d.error))] };
    case "run.phase":
      return { headline: e.summary, lines: [] };
    case "run.completed": {
      const f = isObj(d.findings) ? d.findings : {};
      const ms = num(d.duration_ms);
      return {
        headline: e.summary,
        lines: [
          ...line("Requests", num(d.requests_made)),
          ...line("Duration", ms !== null ? `${(ms / 1000).toFixed(1)} s` : null),
          ...line("Findings", `${num(f.verified) ?? 0} verified, ${num(f.candidate) ?? 0} candidate, ${num(f.rejected) ?? 0} rejected`),
        ],
      };
    }
    case "run.failed":
      return { headline: e.summary, lines: [...line("Error", str(d.error))] };
    case "agent.started":
      return { headline: e.summary, lines: [] };
    case "agent.finished":
      return { headline: e.summary, lines: [] };
    case "agent.failed":
      return { headline: e.summary, lines: line("Error", str(d.error)) };
    case "report.ready":
      return { headline: e.summary, lines: [] };
    default:
      return { headline: e.summary, lines: dataLines(d) };
  }
}

// ---- task output ----

export interface TaskRequest {
  method: string;
  url: string;
  status: number | null;
}

export interface TaskOutput {
  tool: string | null;
  args: ViewLine[];
  result: ViewLine[];
  resultSummary: string | null;
  error: string | null;
  requests: TaskRequest[];
  requestsMore: number;
  observations: string[];
  observationsMore: number;
  findings: { title: string; severity: string | null; status: "candidate" | "verified" | "rejected" }[];
  assets: number;
}

const REQ_MAX = 30;
const OBS_MAX = 15;

/** What the work order's tool did and observed, from the events sharing its work_order_id. */
export function taskOutput(related: readonly GreyboxEvent[]): TaskOutput | null {
  if (related.length === 0) return null;
  const out: TaskOutput = {
    tool: null, args: [], result: [], resultSummary: null, error: null,
    requests: [], requestsMore: 0, observations: [], observationsMore: 0, findings: [], assets: 0,
  };
  const reqs: TaskRequest[] = [];
  const obs: string[] = [];
  const byFinding = new Map<string, TaskOutput["findings"][number]>();
  for (const e of related) {
    const d: Data = e.data ?? {};
    switch (e.kind) {
      case "tool.started":
        out.tool = str(d.tool) ?? out.tool;
        out.args = toolArgLines(d.args);
        break;
      case "tool.succeeded":
        out.tool = str(d.tool) ?? out.tool;
        out.result = toolResultLines(d.result);
        break;
      case "tool.failed":
      case "work_order.failed":
        out.error = str(d.error) ?? out.error;
        break;
      case "work_order.completed":
        out.resultSummary = str(d.result_summary);
        break;
      case "http.exchange":
        reqs.push({ method: str(d.method) ?? "GET", url: str(d.url) ?? "", status: num(d.status_code) });
        break;
      case "observation.recorded":
        obs.push(e.summary);
        break;
      case "asset.discovered":
        out.assets++;
        break;
      case "finding.created":
        byFinding.set(str(d.finding_id) ?? e.summary, { title: str(d.title) ?? e.summary, severity: str(d.severity), status: "candidate" });
        break;
      case "finding.verified": {
        const id = str(d.finding_id) ?? e.summary;
        const prev = byFinding.get(id);
        byFinding.set(id, { title: prev?.title ?? e.summary.replace(/^verified:\s*/i, ""), severity: prev?.severity ?? null, status: "verified" });
        break;
      }
    }
  }
  out.requests = reqs.slice(0, REQ_MAX);
  out.requestsMore = Math.max(0, reqs.length - REQ_MAX);
  out.observations = [...new Set(obs)].slice(0, OBS_MAX);
  out.observationsMore = Math.max(0, new Set(obs).size - OBS_MAX);
  out.findings = [...byFinding.values()];
  const empty = !out.tool && !out.error && !out.requests.length && !out.observations.length && !out.findings.length && !out.assets && !out.resultSummary;
  return empty ? null : out;
}

/** Index of events by work_order_id (ascending seq preserved). */
export function indexByWorkOrder(events: readonly GreyboxEvent[]): Map<string, GreyboxEvent[]> {
  const m = new Map<string, GreyboxEvent[]>();
  for (const e of events) {
    if (!e.work_order_id) continue;
    const l = m.get(e.work_order_id);
    if (l) l.push(e);
    else m.set(e.work_order_id, [e]);
  }
  return m;
}

/** Kinds whose detail pane shows the task output. */
export const TASK_OUTPUT_KINDS: ReadonlySet<string> = new Set(["work_order.completed", "work_order.failed", "tool.succeeded", "tool.failed"]);
