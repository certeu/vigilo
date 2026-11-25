import { useMemo, useState } from "react";
import type { ExplorationEdge, ExplorationNode } from "./types";
import { KIND_STYLE, REL_STYLE } from "./encoding";
import { KindIcon } from "./KindIcon";
import { StatusChip } from "./GraphNodeCard";

const PAGE = 200;

/**
 * Accessible alternative to the canvas: the same (filtered) nodes and links as
 * tables. Searching here filters rows; the toolbar filters apply too.
 */
export function GraphTable({
  nodes,
  edges,
  byId,
  agents,
  matches,
  query,
  onOpen,
}: {
  nodes: readonly ExplorationNode[];
  edges: readonly ExplorationEdge[];
  byId: ReadonlyMap<string, ExplorationNode>;
  agents: ReadonlyMap<string, string>;
  /** Search matches (ids) when a query is set. */
  matches: ReadonlySet<string> | null;
  query: string;
  onOpen: (id: string) => void;
}) {
  const [tab, setTab] = useState<"nodes" | "edges">("nodes");
  const [limit, setLimit] = useState(PAGE);
  const rows = useMemo(() => {
    const list = matches ? nodes.filter((n) => matches.has(n.id)) : [...nodes];
    return list.sort((a, b) => b.version - a.version || a.id.localeCompare(b.id));
  }, [nodes, matches]);
  const keep = useMemo(() => new Set(nodes.map((n) => n.id)), [nodes]);
  const edgeRows = useMemo(
    () =>
      edges.filter(
        (e) => keep.has(e.src) && keep.has(e.dst) && (!matches || matches.has(e.src) || matches.has(e.dst)),
      ),
    [edges, keep, matches],
  );

  const degree = useMemo(() => {
    const m = new Map<string, number>();
    for (const e of edges) {
      m.set(e.src, (m.get(e.src) ?? 0) + 1);
      m.set(e.dst, (m.get(e.dst) ?? 0) + 1);
    }
    return m;
  }, [edges]);
  const agentOf = (n: ExplorationNode) => (n.agent_id ? (agents.get(n.agent_id) ?? n.agent_name ?? n.agent_id.slice(0, 8)) : "planner / system");

  return (
    <div className="flex h-full min-h-0 flex-col">
      <div className="flex items-center gap-2 border-b border-line px-3 py-2" role="group" aria-label="Table">
        {(["nodes", "edges"] as const).map((t) => (
          <button
            key={t}
            type="button"
            aria-pressed={tab === t}
            onClick={() => {
              setTab(t);
              setLimit(PAGE);
            }}
            className={`rounded-md px-2.5 py-1 text-xs font-medium ${tab === t ? "bg-ink text-white" : "text-slate hover:bg-canvas"}`}
          >
            {t === "nodes" ? `Nodes (${rows.length})` : `Links (${edgeRows.length})`}
          </button>
        ))}
        {query && <span className="text-xs text-slate">Filtered by “{query}”</span>}
      </div>
      <div className="min-h-0 flex-1 overflow-auto">
        {tab === "nodes" ? (
          <table className="w-full text-left text-[13px]">
            <caption className="sr-only">Exploration graph nodes, newest first</caption>
            <thead className="sticky top-0 bg-canvas text-xs text-slate">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">Kind</th>
                <th scope="col" className="px-3 py-2 font-medium">Label</th>
                <th scope="col" className="px-3 py-2 font-medium">Status</th>
                <th scope="col" className="px-3 py-2 font-medium">Agent</th>
                <th scope="col" className="px-3 py-2 font-medium">Links</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Version</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {rows.slice(0, limit).map((n) => {
                const deg = degree.get(n.id) ?? 0;
                return (
                  <tr key={n.id} className="hover:bg-canvas">
                    <td className="whitespace-nowrap px-3 py-1.5">
                      <span className="inline-flex items-center gap-1.5">
                        <KindIcon kind={n.kind} size={15} />
                        {KIND_STYLE[n.kind].label}
                      </span>
                    </td>
                    <td className="max-w-[28rem] px-3 py-1.5">
                      <button type="button" className="text-left text-accent hover:underline" onClick={() => onOpen(n.id)}>
                        {n.label}
                      </button>
                    </td>
                    <td className="px-3 py-1.5"><StatusChip node={n} /></td>
                    <td className="whitespace-nowrap px-3 py-1.5 text-slate">{agentOf(n)}</td>
                    <td className="px-3 py-1.5 tabular-nums text-slate">{deg}</td>
                    <td className="px-3 py-1.5 text-right tabular-nums text-slate">{n.version}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        ) : (
          <table className="w-full text-left text-[13px]">
            <caption className="sr-only">Exploration graph links</caption>
            <thead className="sticky top-0 bg-canvas text-xs text-slate">
              <tr>
                <th scope="col" className="px-3 py-2 font-medium">From</th>
                <th scope="col" className="px-3 py-2 font-medium">Link</th>
                <th scope="col" className="px-3 py-2 font-medium">To</th>
                <th scope="col" className="px-3 py-2 text-right font-medium">Version</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-line">
              {edgeRows.slice(0, limit).map((e) => {
                const s = byId.get(e.src);
                const d = byId.get(e.dst);
                return (
                  <tr key={e.id} className="hover:bg-canvas">
                    <td className="max-w-[22rem] px-3 py-1.5">
                      {s && (
                        <button type="button" className="text-left text-accent hover:underline" onClick={() => onOpen(s.id)}>
                          {KIND_STYLE[s.kind].label}: {s.label}
                        </button>
                      )}
                    </td>
                    <td className="whitespace-nowrap px-3 py-1.5" style={{ color: REL_STYLE[e.rel].color }}>{REL_STYLE[e.rel].label}</td>
                    <td className="max-w-[22rem] px-3 py-1.5">
                      {d && (
                        <button type="button" className="text-left text-accent hover:underline" onClick={() => onOpen(d.id)}>
                          {KIND_STYLE[d.kind].label}: {d.label}
                        </button>
                      )}
                    </td>
                    <td className="px-3 py-1.5 text-right tabular-nums text-slate">{e.version}</td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
        {(tab === "nodes" ? rows.length : edgeRows.length) > limit && (
          <div className="p-3 text-center">
            <button type="button" className="btn-ghost" onClick={() => setLimit((l) => l + PAGE)}>
              Show {PAGE} more
            </button>
          </div>
        )}
        {(tab === "nodes" ? rows.length : edgeRows.length) === 0 && (
          <p className="p-6 text-center text-sm text-slate">Nothing matches the current filters.</p>
        )}
      </div>
    </div>
  );
}
