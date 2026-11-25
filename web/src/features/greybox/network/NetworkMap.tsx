// Network map canvas (lazy chunk: React Flow lives here only). Layout is deterministic
// and top-aligned (layout.ts), the viewport is fitted ONCE when the first nodes appear
// (and on request), never on growth, so live updates do not move what you are reading.
import "@xyflow/react/dist/style.css";
import "./network.css";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { Background, BackgroundVariant, MarkerType, MiniMap, ReactFlow, ReactFlowProvider, useReactFlow, type Edge, type NodeTypes } from "@xyflow/react";
import { ArrowsPointingOutIcon, MinusIcon, PlusIcon } from "@heroicons/react/20/solid";
import { EmptyState } from "../../../components/ui";
import type { AssetEdgeRel } from "../types";
import { assetVisual, deriveNetworkView, VISUAL_STYLE, type AssetGraphState } from "./model";
import { fitRects, layoutNetwork } from "./layout";
import { NetCard, type NetCardNode } from "./NetworkCards";

export interface NetworkMapProps {
  graph: AssetGraphState;
  selected: string | null;
  onOpen: (id: string) => void;
  showSecondary: boolean;
  /** Expand the static-asset groups (default: one collapsed group per prefix). */
  showStatic?: boolean;
  followActivity: boolean;
  /** Ask the map to centre on an asset (deep link, table row). `nonce` re-triggers the same id. */
  centerOn: { id: string; nonce: number } | null;
  /** Bump to refit the whole map. */
  fitNonce: number;
  /** Viewport-sized panel (default) or fill the parent. */
  className?: string;
}

const NODE_TYPES: NodeTypes = { net: NetCard };
const REL: Record<AssetEdgeRel, { color: string; width: number; dash?: string; label: string }> = {
  contains: { color: "#9aa3b2", width: 1.4, label: "contains" },
  has_param: { color: "#c4cad6", width: 1.2, label: "has parameter" },
  links_to: { color: "#3B5BDB", width: 1.2, dash: "4 4", label: "links to" },
  redirects_to: { color: "#B45309", width: 1.4, dash: "2 4", label: "redirects to" },
  protects: { color: "#0d9488", width: 1.8, label: "protects" },
};

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

export default function NetworkMap(props: NetworkMapProps) {
  return (
    <ReactFlowProvider>
      <NetworkMapInner {...props} />
    </ReactFlowProvider>
  );
}

function NetworkMapInner({ graph, selected, onOpen, showSecondary, showStatic = false, followActivity, centerOn, fitNonce, className }: NetworkMapProps) {
  const rf = useReactFlow();
  const reduced = usePrefersReducedMotion();
  const canvasRef = useRef<HTMLDivElement>(null);
  const [clusterOverrides, setClusterOverrides] = useState<Map<string, boolean>>(() => new Map());
  const [expandedParams, setExpandedParams] = useState<Set<string>>(() => new Set());
  const reveal = useMemo(() => (selected ? new Set([selected]) : undefined), [selected]);

  const view = useMemo(
    () => deriveNetworkView(graph, { showSecondary, showStatic, clusterOverrides, expandedParams, showDefenses: true, reveal }),
    [graph, showSecondary, showStatic, clusterOverrides, expandedParams, reveal],
  );
  useEffect(() => {
    setClusterOverrides((m) => {
      const n = new Map([...m].filter(([k]) => !k.includes("|static:")));
      return n.size === m.size ? m : n;
    });
  }, [showStatic]);
  const layout = useMemo(() => layoutNetwork(view), [view]);
  const layoutRef = useRef(layout);
  layoutRef.current = layout;

  const toggleCluster = useCallback((id: string, expanded: boolean) => setClusterOverrides((m) => new Map(m).set(id, expanded)), []);
  const toggleParams = useCallback(
    (id: string) =>
      setExpandedParams((s) => {
        const n = new Set(s);
        if (!n.delete(id)) n.add(id);
        return n;
      }),
    [],
  );

  const rfNodes = useMemo<NetCardNode[]>(() => {
    const out: NetCardNode[] = [];
    for (const v of view.nodes) {
      const r = layout.rects.get(v.id);
      if (!r) continue;
      out.push({
        id: v.id,
        type: "net",
        position: { x: r.x, y: r.y },
        width: r.w,
        height: r.h,
        draggable: false,
        selectable: false,
        focusable: false,
        data: {
          v,
          fresh: graph.fresh.has(v.id),
          changed: graph.changed.has(v.id),
          selected: selected === v.id,
          dim: false,
          onOpen,
          onToggleCluster: toggleCluster,
          onToggleParams: toggleParams,
        },
      });
    }
    return out;
  }, [view, layout, graph.fresh, graph.changed, selected, onOpen, toggleCluster, toggleParams]);

  const rfEdges = useMemo<Edge[]>(() => {
    const byId = new Map(view.nodes.map((v) => [v.id, v]));
    const out: Edge[] = [];
    for (const e of view.edges) {
      const a = layout.rects.get(e.src);
      const b = layout.rects.get(e.dst);
      if (!a || !b) continue;
      const sv = byId.get(e.src);
      // Cluster -> member is shown by indentation, not by a line.
      if (sv?.kind === "cluster" && e.rel === "contains") continue;
      const st = REL[e.rel];
      const marker = { type: MarkerType.ArrowClosed, color: st.color, width: 14, height: 14 };
      let source = e.src;
      let target = e.dst;
      let sourceHandle = "r";
      let targetHandle = "l";
      let markerEnd: typeof marker | undefined = marker;
      let markerStart: typeof marker | undefined;
      if (e.rel === "protects") {
        // Drawn from the protected asset to its shield; the arrow points back at the asset.
        source = e.dst;
        target = e.src;
        markerEnd = undefined;
        markerStart = marker;
        if (Math.abs(a.x - b.x) < 8) {
          sourceHandle = "b";
          targetHandle = "t";
        }
      } else if (Math.abs(a.x - b.x) < 8 && b.y > a.y) {
        sourceHandle = "b";
        targetHandle = "t";
      }
      out.push({
        id: e.id,
        source,
        target,
        sourceHandle,
        targetHandle,
        type: "smoothstep",
        markerEnd,
        markerStart,
        style: { stroke: st.color, strokeWidth: st.width, strokeDasharray: st.dash },
        label: e.secondary ? st.label : undefined,
        labelStyle: { fill: st.color, fontSize: 11, fontWeight: 500 },
        labelBgStyle: { fill: "#FBFBFD" },
        selectable: false,
        focusable: false,
        zIndex: e.secondary ? 0 : -1,
      });
    }
    return out;
  }, [view, layout]);

  const fit = useCallback(
    (animate = true) => {
      const el = canvasRef.current;
      if (!el) return;
      const f = fitRects(layoutRef.current.rects.values(), { width: el.clientWidth, height: el.clientHeight });
      if (f) void rf.setViewport({ x: f.x, y: f.y, zoom: f.zoom }, { duration: reduced || !animate ? 0 : 300 });
    },
    [rf, reduced],
  );

  // Fit once when the canvas first has nodes; never on growth.
  const fitted = useRef(false);
  useEffect(() => {
    if (fitted.current || !rfNodes.length) return;
    fitted.current = true;
    requestAnimationFrame(() => fit(false));
  }, [rfNodes.length, fit]);
  const lastFit = useRef(fitNonce);
  useEffect(() => {
    if (fitNonce !== lastFit.current) {
      lastFit.current = fitNonce;
      fit();
    }
  }, [fitNonce, fit]);

  const centre = useCallback(
    (id: string) => {
      const r = layoutRef.current.rects.get(id);
      if (!r) return false;
      void rf.setCenter(r.x + r.w / 2, r.y + r.h / 2, { zoom: Math.max(rf.getZoom(), 0.95), duration: reduced ? 0 : 300 });
      return true;
    },
    [rf, reduced],
  );

  // Explicit centre requests (deep link, table row): retried until the node has a position.
  const handled = useRef<number>(0);
  useEffect(() => {
    if (!centerOn || centerOn.nonce === handled.current) return;
    if (!layout.rects.has(centerOn.id)) return;
    handled.current = centerOn.nonce;
    requestAnimationFrame(() => centre(centerOn.id));
  }, [centerOn, layout, centre]);

  // Follow activity: pan to the newest asset when a delta adds some.
  useEffect(() => {
    if (!followActivity || !graph.fresh.size) return;
    let best: string | null = null;
    let bestT = -Infinity;
    for (const [id, t] of graph.fresh) {
      if (!layoutRef.current.rects.has(id)) continue;
      const key = t * 1e6 + (graph.nodes.get(id)?.version ?? 0);
      if (key > bestT) (bestT = key, (best = id));
    }
    if (best) {
      const id = best;
      requestAnimationFrame(() => centre(id));
    }
    // Only react to new marks, not to every layout change.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [graph.fresh, followActivity]);

  if (graph.nodes.size === 0) {
    return <EmptyState title="No assets discovered yet">The network picture builds up as the run explores the target.</EmptyState>;
  }

  return (
    <div ref={canvasRef} className={`nm-canvas absolute inset-0 ${className ?? ""}`} role="region" aria-label="Network map canvas. Use the Table view for an accessible list.">
      <ReactFlow<NetCardNode, Edge>
        nodes={rfNodes}
        edges={rfEdges}
        nodeTypes={NODE_TYPES}
        nodesConnectable={false}
        nodesDraggable={false}
        elementsSelectable={false}
        nodesFocusable={false}
        edgesFocusable={false}
        deleteKeyCode={null}
        selectionKeyCode={null}
        multiSelectionKeyCode={null}
        minZoom={0.1}
        maxZoom={1.75}
        onlyRenderVisibleElements={rfNodes.length > 250}
        proOptions={{ hideAttribution: false }}
      >
        <Background variant={BackgroundVariant.Dots} gap={18} size={1} color="#d5d9e2" />
        <MiniMap
          pannable
          zoomable
          ariaLabel="Minimap (ring colour shows state)"
          nodeColor={(n) => {
            const v = (n.data as NetCardNode["data"]).v;
            if (v.kind === "defense") return "#0d9488";
            if (v.kind === "cluster") return "#c9ced8";
            return v.asset ? VISUAL_STYLE[assetVisual(v.asset)].fill : "#c9ced8";
          }}
          nodeStrokeColor="#ffffff"
          nodeStrokeWidth={2}
          maskColor="rgba(59, 91, 219, 0.08)"
          maskStrokeColor="#3B5BDB"
          style={{ width: 168, height: 112 }}
          className="!hidden !border !border-line min-[1200px]:!block"
        />
      </ReactFlow>
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
            className={`p-1.5 text-slate hover:bg-canvas hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-inset focus-visible:ring-accent ${i ? "border-t border-line" : ""}`}
          >
            <Icon className="h-4 w-4" aria-hidden="true" />
          </button>
        ))}
      </div>
    </div>
  );
}
