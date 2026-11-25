// Exploration graph view (lazy chunk: React Flow + dagre live here only).
// Design: card nodes with
// kind icon + status chip, left-to-right layered layout, positions kept while the
// graph grows, selection dims everything but the neighbourhood, a details drawer
// with typed links that navigate the graph, minimap, legend, table alternative.
import "@xyflow/react/dist/style.css";
import "./graph.css";
import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import {
  Background, BackgroundVariant, MarkerType, MiniMap, ReactFlow, ReactFlowProvider, useReactFlow,
  type Edge, type EdgeTypes, type NodeChange, type NodeTypes,
} from "@xyflow/react";
import {
  ArrowPathIcon, ArrowsPointingOutIcon, MagnifyingGlassIcon, MinusIcon, PlusIcon, Squares2X2Icon, TableCellsIcon,
} from "@heroicons/react/20/solid";
import { Drawer, EmptyState } from "../../../components/ui";
import type { ExplorationGraphController } from "./useExplorationGraph";
import { adjacency, defaultViewFor, deriveView, findingsCentred, LARGE_GRAPH_NODES, neighbourhood, searchNodes } from "./model";
import { useNodeParam } from "./useNodeParam";
import { CATEGORY_STYLE, KIND_STYLE, REL_STYLE, STATUS_CATEGORIES, statusCategory, type StatusCategory } from "./encoding";
import { GraphNodeCard, type CardNode } from "./GraphNodeCard";
import { GroupNodeCard, type GroupNode } from "./GroupNodeCard";
import { GraphLegend } from "./GraphLegend";
import { GraphEdge, type MergedFlowEdge } from "./GraphEdge";
import { edgeLabel, edgeTooltip, edgeVisible, isLiveStatus, mergeEdges, withTimeline } from "./edges";
import { currentReasoning, isThinking, nodeVisual } from "./nodeState";
import { GraphTable } from "./GraphTable";
import { NodeDetails, type GraphDeepLinks } from "./NodeDetails";
import { computeFit, incrementalLayout, layeredLayout, NODE_H, NODE_W, type Positions } from "./layout";
import { NODE_KINDS, type ExplorationNodeKind } from "./types";
import type { StreamState } from "../events";

/** Above this many nodes: actions fold into work orders and the view centres on findings (user can override). */
export const FOLD_THRESHOLD = LARGE_GRAPH_NODES;
/** Never render more nodes than this on the canvas; the table still lists everything. */
export const RENDER_CAP = 1500;
/** Children of one kind shown per parent before "+N more" (sibling fold). */
export const SIBLING_LIMIT = 25;

export interface ExplorationGraphProps extends GraphDeepLinks {
  controller: ExplorationGraphController;
  /** The run is still producing events (shows the live marker). */
  runActive?: boolean;
  /** Event-stream state (RunLiveContext); null/undefined when there is no stream (polling only). */
  liveState?: StreamState | null;
  renderCap?: number;
  foldThreshold?: number;
  /** An llm.request is outstanding (the current reasoning cycle shows "thinking"). Inferred from the graph when omitted. */
  llmOutstanding?: boolean;
  /** Fill the parent (dev preview) instead of sizing to the viewport. */
  fill?: boolean;
}

const NODE_TYPES: NodeTypes = { card: GraphNodeCard, group: GroupNodeCard };
const EDGE_TYPES: EdgeTypes = { merged: GraphEdge };
type AnyNode = CardNode | GroupNode;

function usePrefersReducedMotion(): boolean {
  const q = "(prefers-reduced-motion: reduce)";
  const [v, setV] = useState(() => typeof window !== "undefined" && !!window.matchMedia?.(q).matches);
  useEffect(() => {
    const m = window.matchMedia?.(q);
    if (!m) return;
    const on = () => setV(m.matches);
    m.addEventListener("change", on);
    return () => m.removeEventListener("change", on);
  }, []);
  return v;
}

function useViewportWidth(): number {
  const [w, setW] = useState(() => (typeof window === "undefined" ? 1440 : window.innerWidth));
  useEffect(() => {
    const on = () => setW(window.innerWidth);
    window.addEventListener("resize", on);
    return () => window.removeEventListener("resize", on);
  }, []);
  return w;
}

/** Below this viewport width the minimap is hidden (it only gets in the way). */
export const MINIMAP_MIN_WIDTH = 1200;

function Toggle({ pressed, onClick, children, title }: { pressed: boolean; onClick: () => void; children: ReactNode; title?: string }) {
  return (
    <button
      type="button"
      aria-pressed={pressed}
      title={title}
      onClick={onClick}
      className={`inline-flex items-center gap-1 rounded-md border px-2 py-1 text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
        pressed ? "border-accent/40 bg-accent/10 text-accent" : "border-line bg-surface text-slate hover:text-ink"
      }`}
    >
      {children}
    </button>
  );
}

function Notice({ tone = "info", children }: { tone?: "info" | "warn"; children: ReactNode }) {
  return (
    <div
      role="status"
      className={`flex flex-wrap items-center gap-2 border-b px-3 py-1.5 text-xs ${
        tone === "warn" ? "border-severity-medium/30 bg-amber-50 text-severity-medium" : "border-accent/20 bg-accent/5 text-ink"
      }`}
    >
      {children}
    </div>
  );
}

const LIVE_INDICATOR: Record<StreamState, { label: string; dot: string; title: string }> = {
  live: { label: "Live", dot: "bg-emerald-600", title: "Updates arrive as events; a delta is fetched within about 1 s." },
  connecting: { label: "Connecting…", dot: "bg-severity-medium", title: "Opening the live stream. Polling meanwhile." },
  reconnecting: { label: "Reconnecting…", dot: "bg-severity-medium", title: "The live stream dropped. Polling every few seconds meanwhile." },
  disconnected: { label: "Polling", dot: "bg-severity-critical", title: "The live stream is unavailable. Refreshing by polling." },
  finished: { label: "Run finished", dot: "bg-slate/50", title: "The run has ended." },
};

/** Connection indicator for the graph: stream state when known, otherwise plain "Live" (polling). */
export function LiveIndicator({ liveState, time, reduced }: { liveState: StreamState | null; time: string | null; reduced: boolean }) {
  const s = liveState ? LIVE_INDICATOR[liveState] : { label: "Live", dot: "bg-emerald-600", title: "Refreshing by polling." };
  const pulse = liveState === "live" && !reduced ? "gx-live-dot" : "";
  return (
    <span className="inline-flex items-center gap-1" role="status" title={`${s.title}${time ? ` Last update ${time}Z.` : ""}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot} ${pulse}`} aria-hidden="true" /> {s.label}{time ? ` · ${time}Z` : ""}
    </span>
  );
}

export default function ExplorationGraph(props: ExplorationGraphProps) {
  return (
    <ReactFlowProvider>
      <ExplorationGraphInner {...props} />
    </ReactFlowProvider>
  );
}

function ExplorationGraphInner({
  controller,
  runActive = false,
  liveState = null,
  renderCap = RENDER_CAP,
  foldThreshold = FOLD_THRESHOLD,
  fill = false,
  llmOutstanding,
  ...links
}: ExplorationGraphProps) {
  const { graph, status, error, updatedAt, refresh } = controller;
  const rf = useReactFlow();
  const reduced = usePrefersReducedMotion();

  const [mode, setMode] = useState<"graph" | "table">("graph");
  const [kinds, setKinds] = useState<Set<ExplorationNodeKind>>(() => new Set(NODE_KINDS));
  const [cats, setCats] = useState<Set<StatusCategory>>(() => new Set(STATUS_CATEGORIES));
  const [agent, setAgent] = useState<string>("*");
  const [collapsed, setCollapsed] = useState<Set<string>>(() => new Set());
  const [foldPref, setFoldPref] = useState<boolean | null>(null);
  /** null = automatic by node count; true = findings-centred; false = show all. */
  const [centredPref, setCentredPref] = useState<boolean | null>(null);
  const [focus, setFocus] = useState<{ id: string; hops: number } | null>(null);
  const [hops, setHops] = useState(1);
  const [selected, setSelected] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [matchIdx, setMatchIdx] = useState(-1);
  const [filtersOpen, setFiltersOpen] = useState(false);
  const [posTick, setPosTick] = useState(0);
  const [expandedGroups, setExpandedGroups] = useState<Map<string, number>>(() => new Map());
  const posRef = useRef<Positions>(new Map());
  const pendingCenter = useRef<string | null>(null);
  const [followActivity, setFollowActivity] = useState(false);
  /** Draw investigates / supports / contradicts links always (default: only around the selected node). */
  const [showEvidence, setShowEvidence] = useState(false);
  const canvasRef = useRef<HTMLDivElement>(null);
  const fitted = useRef(false);
  const fitPending = useRef(false);
  const viewportW = useViewportWidth();
  const [nodeParam, setNodeParam] = useNodeParam();
  const handledParam = useRef<string | null>(null);

  const auto = defaultViewFor(graph.nodes.size, foldThreshold);
  const autoFold = auto.foldActions;
  const foldActions = foldPref ?? autoFold;
  const centreSet = useMemo(() => findingsCentred(graph.nodes, graph.edges.values(), 1), [graph]);
  const centred = (centredPref ?? auto.centred) && !!centreSet;
  const agentSet = useMemo(() => (agent === "*" ? new Set<string>() : new Set([agent])), [agent]);

  const view = useMemo(
    () =>
      deriveView(graph, {
        kinds, categories: cats, agents: agentSet, collapsed, foldActions, focus, cap: renderCap,
        siblingLimit: SIBLING_LIMIT, expandedGroups, only: centred ? centreSet : null,
      }),
    [graph, kinds, cats, agentSet, collapsed, foldActions, focus, renderCap, expandedGroups, centred, centreSet],
  );
  const visible = useMemo(() => new Set(view.nodes.map((n) => n.id)), [view]);

  // One edge per node pair, plus the reasoning-cycle timeline. The spine (non-secondary) drives the layout.
  const merged = useMemo(() => mergeEdges(withTimeline(view.edges, view.nodes)), [view]);
  const spine = useMemo(() => merged.filter((e) => !e.secondary), [merged]);

  // Positions: existing ones never move; only nodes without one are placed.
  const positions = useMemo(() => {
    const ids = [...view.nodes.map((n) => n.id), ...view.groups.map((g) => g.id)];
    const edges = [...spine, ...view.groups.map((g) => ({ src: g.parent, dst: g.id, rel: "spawned" as const }))];
    const next = incrementalLayout(ids, edges, posRef.current);
    posRef.current = next;
    return next;
    // posTick: manual drags and re-layout write posRef directly.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [view, spine, posTick]);

  const viewAdj = useMemo(
    () => adjacency(view.edges.map((e) => ({ ...e, version: 0 })), (id) => visible.has(id)),
    [view, visible],
  );
  const near = useMemo(
    () => (selected && visible.has(selected) ? neighbourhood(viewAdj, selected, 1) : null),
    [selected, visible, viewAdj],
  );

  // Search: over everything loaded; canvas highlights the visible matches.
  const allMatches = useMemo(() => searchNodes(graph.nodes.values(), query, graph.agents), [graph, query]);
  const matchSet = useMemo(() => (query.trim() ? new Set(allMatches) : null), [allMatches, query]);
  const visibleMatches = useMemo(() => allMatches.filter((id) => visible.has(id)), [allMatches, visible]);

  const agentOptions = useMemo(() => {
    const ids = new Set<string>();
    let none = false;
    for (const n of graph.nodes.values()) {
      if (n.agent_id) ids.add(n.agent_id);
      else none = true;
    }
    return { none, list: [...ids].map((id) => ({ id, name: graph.agents.get(id) ?? id.slice(0, 8) })).sort((a, b) => a.name.localeCompare(b.name)) };
  }, [graph]);

  const centerOn = useCallback(
    (id: string) => {
      const p = posRef.current.get(id);
      if (!p) return;
      rf.setCenter(p.x + NODE_W / 2, p.y + NODE_H / 2, { zoom: Math.max(rf.getZoom(), 0.9), duration: reduced ? 0 : 300 });
    },
    [rf, reduced],
  );

  const viewIds = useRef<string[]>([]);
  viewIds.current = view.nodes.map((n) => n.id);
  /** Fit the whole view at a readable zoom; pans instead of shrinking when it does not fit. */
  const fit = useCallback(
    (animate = true) => {
      const el = canvasRef.current;
      if (!el) return;
      const f = computeFit(viewIds.current, posRef.current, { width: el.clientWidth, height: el.clientHeight });
      if (f) void rf.setViewport({ x: f.x, y: f.y, zoom: f.zoom }, { duration: reduced || !animate ? 0 : 300 });
    },
    [rf, reduced],
  );
  // Fit once when the canvas first has nodes (and on request); never on growth, so streaming
  // nodes do not move the user's viewport.
  useEffect(() => {
    if (mode !== "graph") {
      fitted.current = false;
      return;
    }
    if (!view.nodes.length) return;
    if (fitted.current && !fitPending.current) return;
    fitted.current = true;
    fitPending.current = false;
    requestAnimationFrame(() => fit(false));
  }, [mode, view, fit]);

  /** Make a node visible (drop focus, expand, re-enable its kind/status), then centre on it. */
  const reveal = useCallback(
    (id: string) => {
      setMode("graph");
      setSelected(id);
      if (visible.has(id)) {
        centerOn(id);
        return;
      }
      const n = graph.nodes.get(id);
      if (!n) return;
      setFocus(null);
      setCentredPref(false);
      setCollapsed(new Set());
      setExpandedGroups(new Map(view.groups.map((g) => [g.key, Number.MAX_SAFE_INTEGER])));
      setAgent("*");
      setKinds((k) => (k.has(n.kind) ? k : new Set([...k, n.kind])));
      const c = statusCategory(n.kind, n.status);
      setCats((s) => (s.has(c) ? s : new Set([...s, c])));
      if (n.kind === "action") setFoldPref(false);
      pendingCenter.current = id;
    },
    [visible, graph, centerOn, view],
  );
  useEffect(() => {
    const id = pendingCenter.current;
    if (id && visible.has(id) && positions.has(id)) {
      pendingCenter.current = null;
      // Wait one frame so React Flow has the node.
      requestAnimationFrame(() => centerOn(id));
    }
  }, [visible, positions, centerOn]);

  // ?node=<id>: select, centre and open the drawer (once per id, when the node is loaded).
  useEffect(() => {
    if (!nodeParam || nodeParam === handledParam.current || !graph.loaded) return;
    if (!graph.nodes.has(nodeParam)) return;
    handledParam.current = nodeParam;
    reveal(nodeParam);
    setDrawerOpen(true);
  }, [nodeParam, graph.loaded, graph.nodes, reveal]);

  // Follow activity: pan to the newest node whenever a delta adds nodes.
  useEffect(() => {
    if (!followActivity || mode !== "graph" || !graph.fresh.size) return;
    let best: string | null = null;
    let bestKey = -Infinity;
    for (const [id, t] of graph.fresh) {
      if (!visible.has(id) || !positions.has(id)) continue;
      const key = t * 1e6 + (graph.nodes.get(id)?.created_version ?? 0);
      if (key > bestKey) {
        bestKey = key;
        best = id;
      }
    }
    if (best) {
      const id = best;
      requestAnimationFrame(() => centerOn(id));
    }
    // Only react to new marks, not to every view change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph.fresh, followActivity]);

  const openNode = useCallback(
    (id: string) => {
      setSelected(id);
      setDrawerOpen(true);
      handledParam.current = id;
      setNodeParam(id);
    },
    [setNodeParam],
  );
  const closeDrawer = useCallback(() => {
    setDrawerOpen(false);
    handledParam.current = null;
    setNodeParam(null);
  }, [setNodeParam]);
  const toggleBranch = useCallback((id: string) => {
    setCollapsed((c) => {
      const next = new Set(c);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }, []);

  const showMore = useCallback((key: string, by: number | "all") => {
    setExpandedGroups((m) => {
      const next = new Map(m);
      next.set(key, by === "all" ? Number.MAX_SAFE_INTEGER : (m.get(key) ?? SIBLING_LIMIT) + by);
      return next;
    });
  }, []);

  const current = useMemo(() => currentReasoning(graph.nodes.values()), [graph]);
  const thinking = useMemo(() => isThinking(graph.nodes.values(), runActive, llmOutstanding), [graph, runActive, llmOutstanding]);

  const rfNodes: AnyNode[] = useMemo(
    () =>
      view.nodes.map((n) => ({
        id: n.id,
        type: "card" as const,
        position: positions.get(n.id) ?? { x: 0, y: 0 },
        width: NODE_W,
        height: NODE_H,
        selectable: false,
        focusable: true,
        ariaRole: "button" as const,
        ariaLabel: `${KIND_STYLE[n.kind].label}: ${n.label}. Status ${n.status}${n.agent_id ? `. Agent ${graph.agents.get(n.agent_id) ?? n.agent_name ?? ""}` : ""}. Press Enter to open details`,
        data: {
          node: n,
          agentName: n.agent_id ? (graph.agents.get(n.agent_id) ?? n.agent_name ?? null) : null,
          childCount: view.childCount.get(n.id) ?? 0,
          hiddenBelow: view.hiddenBelow.get(n.id) ?? 0,
          collapsed: collapsed.has(n.id),
          folded: view.foldedActions.get(n.id) ?? null,
          visual: nodeVisual(n, { runActive, currentReasoningId: current?.id ?? null, thinking }),
          fresh: graph.fresh.has(n.id),
          changed: graph.changed.has(n.id),
          selected: selected === n.id,
          dim: (!!near && !near.has(n.id)) || (!!matchSet && !matchSet.has(n.id)),
          match: !!matchSet && matchSet.has(n.id),
          onOpen: openNode,
          onToggle: toggleBranch,
        },
      }) as AnyNode).concat(
        view.groups.map((g) => ({
          id: g.id,
          type: "group" as const,
          position: positions.get(g.id) ?? { x: 0, y: 0 },
          width: NODE_W,
          height: Math.round(NODE_H * 0.7),
          selectable: false,
          focusable: false,
          data: { group: g, step: SIBLING_LIMIT, onMore: showMore },
        })),
      ),
    [view, positions, graph, collapsed, selected, near, matchSet, openNode, toggleBranch, showMore, runActive, current, thinking],
  );

  // Edges into in-progress nodes animate (marching dashes) unless the user prefers reduced motion.
  const runningIds = useMemo(() => {
    const ids = new Set<string>();
    // A finished run animates nothing, whatever a node's persisted status says.
    if (reduced || !runActive) return ids;
    for (const n of view.nodes) if (isLiveStatus(n.status) || (statusCategory(n.kind, n.status) === "running" && n.kind !== "objective")) ids.add(n.id);
    if (thinking && current) ids.add(current.id);
    return ids;
  }, [view, reduced, runActive, thinking, current]);

  const rfEdges: Edge[] = useMemo(() => {
    const labelOf = (id: string) => view.nodes.find((n) => n.id === id)?.label ?? id.slice(0, 8);
    const drawn = merged.filter((e) => edgeVisible(e, showEvidence, selected));
    const groupEdges: Edge[] = view.groups.map((g) => ({
      id: `${g.id}:edge`,
      source: g.parent,
      target: g.id,
      selectable: false,
      focusable: false,
      style: { stroke: "#9aa3b2", strokeWidth: 1.2, strokeDasharray: "4 4", opacity: near ? 0.12 : 0.8 },
    }));
    return groupEdges.concat(drawn.map((e): MergedFlowEdge => {
      const st = REL_STYLE[e.rel];
      const touches = !!selected && (e.src === selected || e.dst === selected);
      const faded = (!!near && !(near.has(e.src) && near.has(e.dst))) || (!!matchSet && !matchSet.has(e.src) && !matchSet.has(e.dst));
      // `mitigates` points defense → finding, but defenses are laid out to the right
      // of their finding: draw it finding → defense with the arrowhead at the start so
      // the curve stays forward and still points at the finding.
      const reversed = e.rel === "mitigates";
      const target = reversed ? e.src : e.dst;
      const live = !e.secondary && runningIds.has(target);
      const color = live ? "#3b5bdb" : e.synthetic ? "#4338ca" : st.color;
      const marker = { type: MarkerType.ArrowClosed, color, width: 14, height: 14 };
      return {
        id: e.id,
        type: "merged",
        source: reversed ? e.dst : e.src,
        target,
        selectable: false,
        focusable: false,
        animated: live,
        className: live ? "gx-edge-live" : undefined,
        data: {
          label: e.synthetic ? "next cycle" : edgeLabel(e),
          tooltip: e.synthetic ? "Reasoning cycles, in order" : edgeTooltip(e, labelOf),
          color,
          touches,
          edgeCount: drawn.length,
          secondary: e.secondary,
        },
        style: {
          stroke: color,
          strokeWidth: (touches ? st.width + 1 : st.width) + (live || e.synthetic ? 0.8 : 0),
          strokeDasharray: e.secondary ? (st.dash ?? "2 4") : e.folded ? "1 3" : undefined,
          opacity: faded ? 0.12 : e.secondary ? 0.75 : 0.9,
        },
        ...(reversed ? { markerStart: marker } : { markerEnd: marker }),
      };
    }));
  }, [view, merged, selected, near, matchSet, runningIds, showEvidence]);

  const onNodesChange = useCallback((changes: NodeChange<AnyNode>[]) => {
    let moved = false;
    for (const c of changes) {
      if (c.type === "position" && c.position) {
        if (!moved) posRef.current = new Map(posRef.current);
        posRef.current.set(c.id, c.position);
        moved = true;
      }
    }
    if (moved) setPosTick((t) => t + 1);
  }, []);

  const relayout = useCallback(() => {
    const fresh = layeredLayout(view.nodes.map((n) => n.id), spine);
    posRef.current = new Map([...posRef.current, ...fresh]);
    setPosTick((t) => t + 1);
    requestAnimationFrame(() => fit());
  }, [view, spine, fit]);

  const gotoMatch = useCallback(
    (dir: 1 | -1) => {
      if (!visibleMatches.length) return;
      const i = (matchIdx + dir + visibleMatches.length) % visibleMatches.length;
      setMatchIdx(i);
      setSelected(visibleMatches[i]);
      centerOn(visibleMatches[i]);
    },
    [visibleMatches, matchIdx, centerOn],
  );

  // Esc leaves focus mode / clears the selection (the drawer handles its own Esc).
  useEffect(() => {
    if (drawerOpen) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== "Escape") return;
      const t = e.target as HTMLElement | null;
      if (t && (t.tagName === "INPUT" || t.tagName === "SELECT" || t.tagName === "TEXTAREA")) return;
      if (focus) setFocus(null);
      else setSelected(null);
    };
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [drawerOpen, focus]);

  // Enter / Space on a focused node wrapper (React Flow's own focus target) opens its drawer.
  const onCanvasKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    if (e.key !== "Enter" && e.key !== " ") return;
    const t = e.target as HTMLElement;
    if (!t.classList?.contains("react-flow__node")) return;
    const id = t.getAttribute("data-id");
    if (id && !id.startsWith("group:")) {
      e.preventDefault();
      openNode(id);
    }
  };

  const toggleIn = <T,>(set: Set<T>, v: T, all: readonly T[]): Set<T> => {
    const next = new Set(set);
    if (next.has(v)) next.delete(v);
    else next.add(v);
    return next.size ? next : new Set(all);
  };
  const filtersActive =
    (kinds.size !== NODE_KINDS.length ? 1 : 0) + (cats.size !== STATUS_CATEGORIES.length ? 1 : 0) + (agent !== "*" ? 1 : 0);
  const resetFilters = () => {
    setKinds(new Set(NODE_KINDS));
    setCats(new Set(STATUS_CATEGORIES));
    setAgent("*");
    setFocus(null);
    setCollapsed(new Set());
    setExpandedGroups(new Map());
    setCentredPref(false);
  };

  const selectedNode = selected ? (graph.nodes.get(selected) ?? null) : null;
  const allEdges = useMemo(() => [...graph.edges.values()], [graph]);
  const tableNodes = useMemo(
    () =>
      [...graph.nodes.values()].filter(
        (n) =>
          kinds.has(n.kind) &&
          cats.has(statusCategory(n.kind, n.status)) &&
          (agent === "*" || (n.agent_id ?? "") === agent),
      ),
    [graph, kinds, cats, agent],
  );

  // ---------------------------------------------------------------- states
  if (!graph.loaded) {
    if (status === "error") {
      return (
        <EmptyState
          title="The exploration graph could not be loaded"
          action={
            <button type="button" className="btn-ghost" onClick={() => void refresh()}>
              Retry
            </button>
          }
        >
          <span className="mono break-words">{error}</span>
        </EmptyState>
      );
    }
    return (
      <div role="status" aria-live="polite" className="flex h-full min-h-[320px] items-center justify-center text-sm text-slate">
        Loading the exploration graph…
      </div>
    );
  }
  if (graph.nodes.size === 0) {
    return (
      <EmptyState title="No graph data yet">
        {runActive ? "Nothing has been recorded for this run yet. " : "No graph data was recorded for this run. "}
        When the run starts, its objective, the planner’s work orders, the actions the workers run, what they observe and the
        findings they verify appear here as they happen.
      </EmptyState>
    );
  }

  const truncatedKinds = Object.entries(graph.truncatedByKind)
    .filter(([, n]) => (n ?? 0) > 0)
    .map(([k, n]) => `${(n ?? 0).toLocaleString()} ${k.replace("_", " ")}${n === 1 ? "" : "s"}`)
    .join(", ");
  const time = updatedAt ? new Date(updatedAt).toISOString().slice(11, 19) : null;

  return (
    <div className={`flex w-full flex-col overflow-hidden rounded-lg border border-line bg-surface ${fill ? "h-full min-h-[440px]" : "h-[max(560px,calc(100vh-19rem))]"}`}>
      {/* Toolbar */}
      <div className="flex flex-wrap items-center gap-2 border-b border-line px-3 py-2">
        <div className="flex gap-1" role="group" aria-label="View">
          <Toggle pressed={mode === "graph"} onClick={() => setMode("graph")}>
            <Squares2X2Icon className="h-3.5 w-3.5" aria-hidden="true" /> Graph
          </Toggle>
          <Toggle pressed={mode === "table"} onClick={() => setMode("table")}>
            <TableCellsIcon className="h-3.5 w-3.5" aria-hidden="true" /> Table
          </Toggle>
        </div>
        <form
          role="search"
          className="flex min-w-[12rem] flex-1 items-center gap-1 sm:max-w-xs"
          onSubmit={(e) => {
            e.preventDefault();
            gotoMatch(1);
          }}
        >
          <label className="relative flex-1">
            <span className="sr-only">Search nodes</span>
            <MagnifyingGlassIcon className="pointer-events-none absolute left-2 top-1/2 h-3.5 w-3.5 -translate-y-1/2 text-slate" aria-hidden="true" />
            <input
              type="search"
              className="field !py-1 pl-7 text-xs"
              placeholder="Search label, key, status, agent…"
              value={query}
              onChange={(e) => {
                setQuery(e.target.value);
                setMatchIdx(-1);
              }}
            />
          </label>
          {query.trim() && (
            <span className="whitespace-nowrap text-[11px] text-slate" aria-live="polite">
              {visibleMatches.length ? `${matchIdx + 1 > 0 ? matchIdx + 1 : 0}/${visibleMatches.length}` : "0"}
              {allMatches.length > visibleMatches.length ? ` (+${allMatches.length - visibleMatches.length} hidden)` : ""}
            </span>
          )}
          {query.trim() && visibleMatches.length > 0 && mode === "graph" && (
            <>
              <button type="button" className="rounded border border-line px-1.5 text-xs" onClick={() => gotoMatch(-1)} aria-label="Previous match">
                ↑
              </button>
              <button type="submit" className="rounded border border-line px-1.5 text-xs" aria-label="Next match">
                ↓
              </button>
            </>
          )}
        </form>
        <button
          type="button"
          className={`inline-flex items-center gap-1.5 rounded-md border px-2 py-1 text-xs font-medium focus:outline-none focus-visible:ring-2 focus-visible:ring-accent ${
            filtersOpen || filtersActive ? "border-accent/40 bg-accent/10 text-accent" : "border-line bg-surface text-slate hover:text-ink"
          }`}
          aria-expanded={filtersOpen}
          aria-controls="gx-filters"
          onClick={() => setFiltersOpen((v) => !v)}
        >
          Filters
          {filtersActive > 0 && (
            <span
              className="grid h-4 min-w-4 place-items-center rounded-full bg-accent px-1 text-[11px] font-semibold leading-none text-white"
              aria-label={`${filtersActive} active`}
            >
              {filtersActive}
            </span>
          )}
          <span aria-hidden="true">{filtersOpen ? "▾" : "▸"}</span>
        </button>
        {mode === "graph" && (
          <Toggle
            pressed={showEvidence}
            onClick={() => setShowEvidence((v) => !v)}
            title="Draw evidence links (investigates, supports, contradicts) everywhere. Otherwise they appear around the selected node."
          >
            Evidence links
          </Toggle>
        )}
        <div className="ml-auto flex items-center gap-2 text-[11px] text-slate">
          <span className="hidden sm:inline">
            {view.nodes.length} of {graph.nodes.size} nodes · v{graph.version}
          </span>
          {runActive && (
            <>
              <Toggle
                pressed={followActivity}
                onClick={() => setFollowActivity((v) => !v)}
                title="Pan to the newest node as the run discovers things"
              >
                Follow activity
              </Toggle>
              <LiveIndicator liveState={liveState} time={time} reduced={reduced} />
            </>
          )}
          <button
            type="button"
            className="rounded p-1 hover:bg-canvas hover:text-ink"
            onClick={() => void refresh()}
            aria-label="Refresh the graph"
            title="Refresh"
          >
            <ArrowPathIcon className="h-4 w-4" aria-hidden="true" />
          </button>
        </div>
      </div>

      {filtersOpen && (
        <div id="gx-filters" className="flex flex-col gap-2 border-b border-line bg-canvas/60 px-3 py-2 text-xs">
          <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Filter by kind">
            <span className="mr-1 w-12 text-slate">Kind</span>
            {NODE_KINDS.map((k) => (
              <Toggle key={k} pressed={kinds.has(k)} onClick={() => setKinds((s) => toggleIn(s, k, NODE_KINDS))}>
                {KIND_STYLE[k].label}
              </Toggle>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-1" role="group" aria-label="Filter by status">
            <span className="mr-1 w-12 text-slate">Status</span>
            {STATUS_CATEGORIES.map((c) => (
              <Toggle key={c} pressed={cats.has(c)} onClick={() => setCats((s) => toggleIn(s, c, STATUS_CATEGORIES))} title={CATEGORY_STYLE[c].description}>
                <span aria-hidden="true">{CATEGORY_STYLE[c].glyph}</span> {CATEGORY_STYLE[c].label}
              </Toggle>
            ))}
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <label className="flex items-center gap-1">
              <span className="w-12 text-slate">Agent</span>
              <select className="field !w-auto !py-1 text-xs" value={agent} onChange={(e) => setAgent(e.target.value)}>
                <option value="*">All agents</option>
                {agentOptions.none && <option value="">Planner / system</option>}
                {agentOptions.list.map((a) => (
                  <option key={a.id} value={a.id}>
                    {a.name}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-1.5">
              <input type="checkbox" checked={foldActions} onChange={(e) => setFoldPref(e.target.checked)} />
              Fold actions into work orders
            </label>
            <label className="flex items-center gap-1">
              Focus depth
              <select className="field !w-auto !py-1 text-xs" value={hops} onChange={(e) => {
                const h = Number(e.target.value);
                setHops(h);
                setFocus((f) => (f ? { ...f, hops: h } : f));
              }}>
                {[1, 2, 3].map((h) => (
                  <option key={h} value={h}>
                    {h} hop{h > 1 ? "s" : ""}
                  </option>
                ))}
              </select>
            </label>
            {collapsed.size > 0 && (
              <button type="button" className="text-accent hover:underline" onClick={() => setCollapsed(new Set())}>
                Expand all ({collapsed.size})
              </button>
            )}
            {(filtersActive > 0 || focus || collapsed.size > 0) && (
              <button type="button" className="text-accent hover:underline" onClick={resetFilters}>
                Reset
              </button>
            )}
          </div>
        </div>
      )}

      {focus && (
        <Notice>
          Focus: {hops} hop{hops > 1 ? "s" : ""} around “{graph.nodes.get(focus.id)?.label ?? "node"}” ({view.nodes.length} nodes).
          <button type="button" className="font-medium text-accent hover:underline" onClick={() => setFocus(null)}>
            Show everything
          </button>
        </Notice>
      )}
      {view.capped > 0 && (
        <Notice tone="warn">
          Large graph: showing {view.nodes.length.toLocaleString()} of {(view.nodes.length + view.capped).toLocaleString()} nodes
          (objective, findings, leads and work orders first). Narrow the filters, collapse branches, focus on a node, or use the
          table for the full list.
        </Notice>
      )}
      {mode === "graph" && graph.nodes.size > foldThreshold && centreSet && (
        <Notice>
          {centred ? (
            <>
              Large run: showing findings, leads, hints and defenses plus their neighbours ({view.nodes.length} of {graph.nodes.size} nodes
              {foldActions ? ", actions folded into work orders" : ""}).
              <button type="button" className="font-medium text-accent hover:underline" onClick={() => { fitPending.current = true; setCentredPref(false); }}>
                Show all
              </button>
            </>
          ) : (
            <>
              Showing all {graph.nodes.size} nodes.
              <button type="button" className="font-medium text-accent hover:underline" onClick={() => { fitPending.current = true; setCentredPref(true); }}>
                Back to findings view
              </button>
            </>
          )}
          <button type="button" className="font-medium text-accent hover:underline" onClick={() => setMode("table")}>
            Open the table (easier to scan at this size)
          </button>
        </Notice>
      )}
      {mode === "graph" && graph.nodes.size > foldThreshold && !centreSet && (
        <Notice>
          Large run: the table lists every node and is easier to scan than the graph.
          <button type="button" className="font-medium text-accent hover:underline" onClick={() => setMode("table")}>
            Open the table
          </button>
        </Notice>
      )}
      {graph.truncated && (
        <Notice tone="warn">
          The server returned {graph.nodes.size.toLocaleString()} of {graph.totalNodes.toLocaleString()} nodes (response limit).
          {truncatedKinds && <> Not shown: {truncatedKinds}.</>} New changes still arrive.
        </Notice>
      )}
      {error && (
        <Notice tone="warn">
          Could not refresh the graph: {error}. Showing the last loaded version.
          <button type="button" className="font-medium text-accent hover:underline" onClick={() => void refresh()}>
            Retry
          </button>
        </Notice>
      )}

      <div className="relative min-h-0 flex-1">
        {mode === "table" ? (
          <GraphTable
            nodes={tableNodes}
            edges={allEdges}
            byId={graph.nodes}
            agents={graph.agents}
            matches={matchSet}
            query={query.trim()}
            onOpen={openNode}
          />
        ) : view.nodes.length === 0 ? (
          <EmptyState
            title="No nodes match the filters"
            action={
              <button type="button" className="btn-ghost" onClick={resetFilters}>
                Reset filters
              </button>
            }
          />
        ) : (
          <div ref={canvasRef} onKeyDown={onCanvasKeyDown} className="gx-canvas absolute inset-0" aria-label="Exploration graph canvas. Use the Table view for an accessible list." role="region">
            <ReactFlow<AnyNode, Edge>
              nodes={rfNodes}
              edges={rfEdges}
              nodeTypes={NODE_TYPES}
              edgeTypes={EDGE_TYPES}
              onNodesChange={onNodesChange}
              onPaneClick={() => setSelected(null)}
              onNodeClick={(_e, n) => {
                if (n.type === "card") openNode(n.id);
              }}
              autoPanOnNodeFocus
              nodesConnectable={false}
              elementsSelectable={false}
              nodesFocusable
              edgesFocusable={false}
              deleteKeyCode={null}
              selectionKeyCode={null}
              multiSelectionKeyCode={null}
              nodeDragThreshold={4}
              minZoom={0.08}
              maxZoom={1.75}
              onlyRenderVisibleElements={view.nodes.length > 250}
              proOptions={{ hideAttribution: false }}
            >
              <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#d5d9e2" />
              {viewportW >= MINIMAP_MIN_WIDTH && (
                <MiniMap
                  pannable
                  zoomable
                  ariaLabel="Minimap (node colour shows kind)"
                  nodeColor={(n) => (n.type === "group" ? "#c9ced8" : KIND_STYLE[(n.data as CardNode["data"]).node.kind].fill)}
                  nodeStrokeColor="#ffffff"
                  nodeStrokeWidth={2}
                  nodeBorderRadius={2}
                  maskColor="rgba(59, 91, 219, 0.08)"
                  maskStrokeColor="#3B5BDB"
                  maskStrokeWidth={1.5}
                  style={{ width: 168, height: 112 }}
                  className="!border !border-line"
                />
              )}
            </ReactFlow>
            <div className="pointer-events-none absolute left-3 top-3 z-10">
              <div className="pointer-events-auto">
                <GraphLegend />
              </div>
            </div>
            <div className="absolute bottom-3 left-3 z-10 flex flex-col overflow-hidden rounded-md border border-line bg-surface shadow-card" role="group" aria-label="Zoom">
              {[
                { label: "Zoom in", Icon: PlusIcon, on: () => rf.zoomIn({ duration: reduced ? 0 : 200 }) },
                { label: "Zoom out", Icon: MinusIcon, on: () => rf.zoomOut({ duration: reduced ? 0 : 200 }) },
                { label: "Fit to view", Icon: ArrowsPointingOutIcon, on: () => fit() },
              ].map(({ label, Icon, on }, i) => (
                <button
                  key={label}
                  type="button"
                  onClick={on}
                  aria-label={label}
                  title={label}
                  className={`grid h-8 w-8 place-items-center text-slate hover:bg-canvas hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${i ? "border-t border-line" : ""}`}
                >
                  <Icon className="h-4 w-4" aria-hidden="true" />
                </button>
              ))}
              <button
                type="button"
                onClick={relayout}
                title="Re-layout (moves every node)"
                className="border-t border-line px-1 py-1 text-[11px] font-semibold text-slate hover:bg-canvas hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent"
              >
                Re-layout
              </button>
            </div>
            {selected && visible.has(selected) && !drawerOpen && (
              <div className="absolute bottom-3 left-1/2 z-10 flex -translate-x-1/2 items-center gap-2 rounded-md border border-line bg-surface px-2 py-1 text-xs shadow-card">
                <span className="max-w-[14rem] truncate">{graph.nodes.get(selected)?.label}</span>
                <button type="button" className="text-accent hover:underline" onClick={() => setDrawerOpen(true)}>
                  Details
                </button>
                <button type="button" className="text-accent hover:underline" onClick={() => setFocus({ id: selected, hops })}>
                  Focus
                </button>
              </div>
            )}
          </div>
        )}
      </div>

      {drawerOpen && selectedNode && (
        <Drawer
          title={`${KIND_STYLE[selectedNode.kind].label} details`}
          onClose={closeDrawer}
          widthClass="max-w-md"
        >
          <NodeDetails
            node={selectedNode}
            nodes={graph.nodes}
            edges={allEdges}
            agentName={selectedNode.agent_id ? (graph.agents.get(selectedNode.agent_id) ?? selectedNode.agent_name ?? null) : null}
            fresh={graph.fresh.has(selectedNode.id)}
            folded={foldActions ? (view.foldedActions.get(selectedNode.id) ?? null) : null}
            collapsed={collapsed.has(selectedNode.id)}
            hasChildren={(view.childCount.get(selectedNode.id) ?? 0) > 0 || collapsed.has(selectedNode.id)}
            links={links}
            onSelect={(id) => setSelected(id)}
            onFocus={() => {
              setFocus({ id: selectedNode.id, hops });
              setMode("graph");
              setDrawerOpen(false);
            }}
            onToggle={() => toggleBranch(selectedNode.id)}
            onClose={closeDrawer}
            onCenter={() => {
              setDrawerOpen(false);
              reveal(selectedNode.id);
            }}
          />
        </Drawer>
      )}
    </div>
  );
}
