// DEV ONLY. Synthetic, made-up exploration graph used by the graph preview route to
// exercise snapshot + delta merging. Not telemetry; the target is a reserved
// `.invalid` hostname. Never imported by production code paths.
import type { ExplorationEdge, ExplorationEdgeRel, ExplorationGraphResponse, ExplorationNode, ExplorationNodeKind, ExplorationNodeStatus } from "../types";

const BASE = Date.parse("2026-01-01T10:00:00Z");
const HOST = "http://demo.invalid";

export const SYNTH_AGENTS = [
  { id: "agent-discovery-1", name: "discovery-1", role: "discovery" },
  { id: "agent-checker-1", name: "checker-1", role: "checker" },
  { id: "agent-checker-2", name: "checker-2", role: "checker" },
  { id: "agent-verifier-1", name: "verifier-1", role: "verifier" },
];
const AGENT_NAME = new Map(SYNTH_AGENTS.map((a) => [a.id, a.name]));

export class SyntheticRun {
  /** Current graph version (one per tick). */
  v = 0;
  private hist = new Map<string, ExplorationNode[]>();
  private edgeList: ExplorationEdge[] = [];
  private seq = 0;
  private created = new Map<string, number>();

  tick(): number {
    this.v += 1;
    return this.v;
  }

  private ts(): string {
    return new Date(BASE + this.v * 2300).toISOString();
  }

  node(
    id: string,
    kind: ExplorationNodeKind,
    label: string,
    status: ExplorationNodeStatus,
    extra: Partial<ExplorationNode> = {},
  ): string {
    this.seq += 3;
    this.created.set(id, this.v);
    const n: ExplorationNode = {
      id,
      kind,
      key: extra.key ?? `${kind}:${id}`,
      label,
      status,
      agent_id: null,
      work_order_id: null,
      finding_id: null,
      asset_id: null,
      event_seq: this.seq,
      data: {},
      version: this.v,
      created_version: this.v,
      created_at: this.ts(),
      updated_at: this.ts(),
      ...extra,
    };
    if (n.agent_id) n.agent_name = AGENT_NAME.get(n.agent_id) ?? null;
    this.hist.set(id, [n]);
    return id;
  }

  set(id: string, status: ExplorationNodeStatus, patch: Partial<ExplorationNode> = {}): void {
    const h = this.hist.get(id);
    if (!h) throw new Error(`unknown synthetic node ${id}`);
    const prev = h[h.length - 1];
    this.seq += 2;
    const next = { ...prev, ...patch, status, version: this.v, updated_at: this.ts(), last_event_seq: this.seq };
    if (next.agent_id) next.agent_name = AGENT_NAME.get(next.agent_id) ?? null;
    h.push(next);
  }

  edge(src: string, dst: string, rel: ExplorationEdgeRel): void {
    this.edgeList.push({ id: `e-${src}-${rel}-${dst}`, src, dst, rel, version: this.v });
  }

  /** What the endpoint would answer at graph version `at`, for `since_version`, capped at `limit`. */
  respond(at: number, since: number, limit: number): ExplorationGraphResponse {
    const nodes: ExplorationNode[] = [];
    let total = 0;
    for (const h of this.hist.values()) {
      let cur: ExplorationNode | undefined;
      for (const n of h) if (n.version <= at) cur = n;
      if (!cur) continue;
      total++;
      if (cur.version > since) nodes.push(cur);
    }
    nodes.sort((a, b) => a.version - b.version || a.id.localeCompare(b.id));
    const truncated = nodes.length > limit;
    const out = truncated ? nodes.slice(0, limit) : nodes;
    const ids = new Set(out.map((n) => n.id));
    const known = (id: string) => ids.has(id) || (since > 0 && (this.created.get(id) ?? Infinity) <= since);
    const liveEdges = this.edgeList.filter((e) => e.version <= at);
    const edges = liveEdges.filter((e) => e.version > since && known(e.src) && known(e.dst));
    return {
      version: at,
      since_version: since,
      full: since === 0,
      truncated,
      total_nodes: total,
      total_edges: liveEdges.length,
      nodes: out,
      edges,
      agents: SYNTH_AGENTS,
    };
  }
}

/** A small, readable run that grows over ~40 versions (one step per delta). */
export function buildStoryRun(): SyntheticRun {
  const s = new SyntheticRun();
  const [disc, chk1, chk2, ver] = SYNTH_AGENTS.map((a) => a.id);

  s.tick();
  s.node("obj", "objective", `Assess ${HOST}/ within scope`, "active", { key: "objective" });
  s.node("wo-crawl", "work_order", "crawl.site /", "pending", { work_order_id: "wo-crawl" });
  s.edge("obj", "wo-crawl", "spawned");
  s.node("wo-fp", "work_order", "fingerprint.service demo.invalid:80", "pending", { work_order_id: "wo-fp" });
  s.edge("obj", "wo-fp", "spawned");

  s.tick();
  s.set("wo-crawl", "running", { agent_id: disc });
  s.node("act-crawl", "action", "crawl.site → GET /", "running", { agent_id: disc, work_order_id: "wo-crawl", data: { tool: "crawl.site" } });
  s.edge("wo-crawl", "act-crawl", "executed");

  s.tick();
  s.set("act-crawl", "succeeded", { exchange_ids: [1, 2, 3, 4], data: { tool: "crawl.site", pages: 9 } });
  s.node("obs-search", "observation", "/search reflects parameter q", "recorded", { agent_id: disc, exchange_ids: [3], data: { endpoint: "/search", parameter: "q" } });
  s.edge("act-crawl", "obs-search", "observed");
  s.node("obs-login", "observation", "Form with password field on /login", "recorded", { agent_id: disc, exchange_ids: [4] });
  s.edge("act-crawl", "obs-login", "observed");

  s.tick();
  s.set("wo-crawl", "done", { asset_ids: ["asset-root", "asset-search", "asset-login"], asset_id: "asset-root" });
  s.set("wo-fp", "running", { agent_id: disc });
  s.node("act-fp", "action", "fingerprint.service → HEAD /", "running", { agent_id: disc, work_order_id: "wo-fp" });
  s.edge("wo-fp", "act-fp", "executed");

  s.tick();
  s.set("act-fp", "succeeded", { exchange_ids: [5] });
  s.node("obs-hdr", "observation", "Missing Content-Security-Policy on /", "recorded", { agent_id: disc, exchange_ids: [5], data: { header: "content-security-policy" } });
  s.edge("act-fp", "obs-hdr", "observed");
  s.node("obs-git", "observation", "/.git/ path referenced in HTML comment", "recorded", { agent_id: disc, exchange_ids: [2] });
  s.edge("act-crawl", "obs-git", "observed");
  s.set("wo-fp", "done");

  s.tick();
  s.node("lead-q", "lead", "Parameter q is reflected: test for XSS", "open");
  s.edge("obs-search", "lead-q", "spawned");
  s.node("lead-git", "lead", "/.git/ may be exposed", "open");
  s.edge("obs-git", "lead-git", "spawned");
  s.node("lead-cookie", "lead", "Session cookie flags on /login", "open");
  s.edge("obs-login", "lead-cookie", "spawned");

  s.tick();
  s.node("wo-xss", "work_order", "injection.reflected /search?q", "pending", { work_order_id: "wo-xss" });
  s.edge("lead-q", "wo-xss", "spawned");
  s.node("wo-git", "work_order", "exposure.vcs /.git/HEAD", "pending", { work_order_id: "wo-git" });
  s.edge("lead-git", "wo-git", "spawned");
  s.node("wo-hdr", "work_order", "headers.security /", "pending", { work_order_id: "wo-hdr" });
  s.edge("obj", "wo-hdr", "spawned");
  s.node("wo-cookie", "work_order", "cookies.flags /login", "pending", { work_order_id: "wo-cookie" });
  s.edge("lead-cookie", "wo-cookie", "spawned");

  s.tick();
  s.set("wo-xss", "running", { agent_id: chk1 });
  s.edge("wo-xss", "lead-q", "investigated");
  s.set("lead-q", "investigating");
  s.node("act-xss", "action", "injection.reflected → GET /search?q=<marker>", "running", { agent_id: chk1, work_order_id: "wo-xss" });
  s.edge("wo-xss", "act-xss", "executed");
  s.set("wo-hdr", "running", { agent_id: chk2 });
  s.node("act-hdr", "action", "headers.security → GET /", "running", { agent_id: chk2, work_order_id: "wo-hdr" });
  s.edge("wo-hdr", "act-hdr", "executed");

  s.tick();
  s.set("act-xss", "succeeded", { exchange_ids: [11, 12] });
  s.node("obs-xss", "observation", "Marker reflected unencoded in HTML body", "recorded", { agent_id: chk1, exchange_ids: [12] });
  s.edge("act-xss", "obs-xss", "observed");
  s.set("act-hdr", "succeeded", { exchange_ids: [13] });
  s.node("obs-hdr2", "observation", "4 security headers missing on /", "recorded", { agent_id: chk2, exchange_ids: [13] });
  s.edge("act-hdr", "obs-hdr2", "observed");

  s.tick();
  s.node("f-xss", "finding", "Reflected XSS in /search (q)", "candidate", { agent_id: chk1, finding_id: "f-xss", severity: "high", exchange_ids: [12] });
  s.edge("obs-xss", "f-xss", "supports");
  s.node("f-hdr", "finding", "Missing security headers on /", "candidate", { agent_id: chk2, finding_id: "f-hdr", severity: "low", exchange_ids: [13] });
  s.edge("obs-hdr2", "f-hdr", "supports");
  s.edge("obs-hdr", "f-hdr", "supports");
  s.set("wo-xss", "done", { outcome: "reported" });
  s.set("wo-hdr", "done", { outcome: "reported" });

  s.tick();
  s.set("wo-git", "running", { agent_id: chk2 });
  s.edge("wo-git", "lead-git", "investigated");
  s.set("lead-git", "investigating");
  s.node("act-git", "action", "exposure.vcs → GET /.git/HEAD", "running", { agent_id: chk2, work_order_id: "wo-git" });
  s.edge("wo-git", "act-git", "executed");
  s.node("wo-vxss", "work_order", "verify reflected XSS /search?q", "pending", { work_order_id: "wo-vxss" });
  s.edge("f-xss", "wo-vxss", "spawned");

  s.tick();
  s.set("act-git", "succeeded", { exchange_ids: [14] });
  s.node("obs-git2", "observation", "/.git/HEAD answers 404", "recorded", { agent_id: chk2, exchange_ids: [14] });
  s.edge("act-git", "obs-git2", "observed");
  s.set("wo-git", "done", { outcome: "ruled_out" });
  s.set("lead-git", "refuted");
  s.set("wo-vxss", "running", { agent_id: ver });
  s.node("act-vxss", "action", "verify.reflected → GET /search?q=<marker2>", "running", { agent_id: ver, work_order_id: "wo-vxss" });
  s.edge("wo-vxss", "act-vxss", "executed");

  s.tick();
  s.set("act-vxss", "succeeded", { exchange_ids: [15, 16] });
  s.edge("act-vxss", "f-xss", "verified");
  s.set("f-xss", "verified");
  s.set("lead-q", "confirmed");
  s.set("wo-vxss", "done");
  s.node("wo-vhdr", "work_order", "verify missing headers /", "pending", { work_order_id: "wo-vhdr" });
  s.edge("f-hdr", "wo-vhdr", "spawned");

  s.tick();
  s.set("wo-cookie", "running", { agent_id: chk1 });
  s.edge("wo-cookie", "lead-cookie", "investigated");
  s.set("lead-cookie", "investigating");
  s.node("act-cookie", "action", "cookies.flags → POST /login", "blocked", { agent_id: chk1, work_order_id: "wo-cookie", data: { reason: "auth testing disabled" } });
  s.edge("wo-cookie", "act-cookie", "executed");
  s.set("wo-vhdr", "running", { agent_id: ver });
  s.node("act-vhdr", "action", "verify.headers → GET / (no CDN)", "running", { agent_id: ver, work_order_id: "wo-vhdr" });
  s.edge("wo-vhdr", "act-vhdr", "executed");

  s.tick();
  s.set("wo-cookie", "failed", { data: { error: "blocked by scope policy" } });
  s.set("lead-cookie", "inconclusive");
  s.set("act-vhdr", "succeeded", { exchange_ids: [17] });
  s.edge("act-vhdr", "f-hdr", "refuted");
  s.set("f-hdr", "rejected");
  s.set("wo-vhdr", "done");

  s.tick();
  s.node("wo-dir", "work_order", "discovery.paths common files", "skipped", { work_order_id: "wo-dir", data: { reason: "budget" } });
  s.edge("obj", "wo-dir", "spawned");
  s.node("wo-cors", "work_order", "cors.policy /api", "pending", { work_order_id: "wo-cors" });
  s.edge("obj", "wo-cors", "spawned");

  s.tick();
  s.set("wo-cors", "running", { agent_id: chk2 });
  s.node("act-cors", "action", "cors.policy → OPTIONS /api", "running", { agent_id: chk2, work_order_id: "wo-cors" });
  s.edge("wo-cors", "act-cors", "executed");

  s.tick();
  s.node("hint-api", "hint", "Focus /api/v2: the mobile app talks to it", "open", {
    key: "hint:api", data: { action: "focus", target: "/api/v2", created_by_name: "Analyst" },
  });
  s.edge("hint-api", "wo-cors", "guides");
  s.edge("hint-api", "obj", "guides");

  s.tick();
  s.node("def-xss", "defense", "ModSecurity rule for reflected XSS in /search", "proposed", {
    key: "defense:f-xss:modsecurity", finding_id: "f-xss", data: { kind: "waf_rule", format: "modsecurity" },
  });
  s.edge("def-xss", "f-xss", "mitigates");
  s.node("def-hdr", "defense", "nginx headers for missing security headers", "unverified", {
    key: "defense:f-hdr:nginx", finding_id: "f-hdr", data: { kind: "config", format: "nginx" },
  });
  s.edge("def-hdr", "f-hdr", "mitigates");
  return s;
}

/** A large synthetic run (about `n` nodes) to exercise the render cap and folding. */
export function buildLargeRun(n = 3000): SyntheticRun {
  const s = new SyntheticRun();
  s.tick();
  s.node("obj", "objective", `Assess ${HOST}/ within scope`, "active", { key: "objective" });
  let count = 1;
  let i = 0;
  while (count < n) {
    if (i % 40 === 0) s.tick();
    const agent = SYNTH_AGENTS[1 + (i % 3)].id;
    const wo = `wo-${i}`;
    s.node(wo, "work_order", `check.synthetic /path-${i}`, i % 11 === 0 ? "failed" : "done", { agent_id: agent, work_order_id: wo });
    s.edge("obj", wo, "spawned");
    const act = `act-${i}`;
    s.node(act, "action", `tool.synthetic → GET /path-${i}`, i % 11 === 0 ? "failed" : "succeeded", { agent_id: agent, work_order_id: wo });
    s.edge(wo, act, "executed");
    count += 2;
    if (i % 11 !== 0) {
      const obs = `obs-${i}`;
      s.node(obs, "observation", `synthetic fact ${i}`, "recorded", { agent_id: agent });
      s.edge(act, obs, "observed");
      count += 1;
      if (i % 37 === 1) {
        const f = `f-${i}`;
        s.node(f, "finding", `Synthetic finding ${i}`, i % 2 ? "verified" : "candidate", { agent_id: agent, finding_id: f, severity: "medium" });
        s.edge(obs, f, "supports");
        count += 1;
      }
    }
    i++;
  }
  return s;
}
