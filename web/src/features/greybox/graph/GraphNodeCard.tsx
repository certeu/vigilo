import { memo } from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { OUTCOME_LABEL, type ExplorationNode } from "./types";
import { CATEGORY_STYLE, KIND_STYLE, SEVERITY_CHIP, STATUS_LABEL, statusCategory } from "./encoding";
import { KindIcon } from "./KindIcon";
import { NODE_H, NODE_W } from "./layout";
import type { NodeVisual } from "./nodeState";

export interface CardData extends Record<string, unknown> {
  node: ExplorationNode;
  agentName: string | null;
  childCount: number;
  hiddenBelow: number;
  collapsed: boolean;
  folded: Record<string, number> | null;
  /** Live-state styling (pulse, current cycle, thinking, muted / failed). */
  visual: NodeVisual;
  fresh: boolean;
  changed: boolean;
  selected: boolean;
  dim: boolean;
  match: boolean;
  onOpen: (id: string) => void;
  onToggle: (id: string) => void;
}

export type CardNode = Node<CardData, "card">;

function shortTime(iso: string | undefined): string {
  if (!iso) return "";
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? "" : d.toISOString().slice(11, 19);
}

export function StatusChip({ node, className = "", spinner = false }: { node: ExplorationNode; className?: string; spinner?: boolean }) {
  const cat = CATEGORY_STYLE[statusCategory(node.kind, node.status)];
  return (
    <span
      className={`inline-flex h-[18px] shrink-0 items-center gap-1 rounded border px-1.5 text-[11px] font-semibold leading-none ${cat.chip} ${className}`}
      title={`${cat.label}: ${cat.description}`}
    >
      {spinner ? <span className="gx-spinner" aria-hidden="true" /> : <span aria-hidden="true">{cat.glyph}</span>}
      {STATUS_LABEL[node.status] ?? node.status}
    </span>
  );
}

function foldedSummary(f: Record<string, number>): string {
  const total = Object.values(f).reduce((a, b) => a + b, 0);
  const bad = (f.failed ?? 0) + (f.blocked ?? 0);
  return `${total} action${total === 1 ? "" : "s"}${bad ? ` · ${bad} failed/blocked` : ""}`;
}

function GraphNodeCardImpl({ data }: NodeProps<CardNode>) {
  const { visual, node, agentName, childCount, hiddenBelow, collapsed, folded, fresh, changed, selected, dim, match } = data;
  const kind = KIND_STYLE[node.kind];
  const cat = CATEGORY_STYLE[statusCategory(node.kind, node.status)];
  const sev = node.kind === "finding" ? (node.severity ?? (node.data?.severity as string | undefined)) : undefined;
  const ring = selected
    ? "ring-2 ring-accent ring-offset-2"
    : match
      ? "ring-2 ring-amber-400 ring-offset-1"
      : "";
  return (
    <div
      className={`gx-card group relative flex flex-col border bg-surface px-2.5 pb-1.5 pt-2 text-left shadow-card transition-opacity duration-200 ${kind.shape} ${cat.border} ${cat.body} ${visual.className} ${ring} ${dim ? "!opacity-30" : ""} ${fresh ? "gx-fresh" : ""} ${changed ? "gx-changed" : ""}`}
      style={{ width: NODE_W, height: NODE_H }}
      data-kind={node.kind}
    >
      {visual.pulse && <span className="gx-running-dot" aria-hidden="true" />}
      <Handle type="target" position={Position.Left} isConnectable={false} className="gx-handle" />
      <Handle type="source" position={Position.Right} isConnectable={false} className="gx-handle" />
      {/* The whole card opens the details; the collapse toggle sits above it. */}
      <button
        type="button"
        className="absolute inset-0 z-0 rounded-[inherit] focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        onClick={() => data.onOpen(node.id)}
        tabIndex={-1}
        aria-hidden="true"
      />
      <span className="pointer-events-none relative flex items-center gap-1.5">
        <KindIcon kind={node.kind} />
        <span className="text-[11.5px] font-semibold text-ink">{kind.label}</span>
        {visual.thinking ? (
          <span className="gx-thinking-badge rounded bg-indigo-700 px-1 text-[11px] font-semibold text-white" title="The agent is waiting for the model">
            thinking…
          </span>
        ) : (
          visual.current && (
            <span className="rounded bg-indigo-100 px-1 text-[11px] font-semibold text-indigo-800" title="The agent's current cycle">
              current
            </span>
          )
        )}
        {(fresh || changed) && (
          <span className="rounded bg-accent px-1 text-[11px] font-semibold uppercase tracking-wide text-white">
            {fresh ? "new" : "updated"}
          </span>
        )}
        <span className="ml-auto flex items-center gap-1">
          {sev && (
            <span className={`rounded border px-1 text-[11px] font-semibold uppercase ${SEVERITY_CHIP[sev] ?? ""}`}>{sev}</span>
          )}
        </span>
      </span>
      <span className="pointer-events-none relative mt-1 line-clamp-2 break-words text-[11.5px] leading-[15px] text-ink/80" title={node.label}>
        {node.label}
      </span>
      <span className="pointer-events-none relative mt-auto flex min-w-0 items-center gap-1.5 pt-1 text-[11px] font-semibold text-slate">
        <StatusChip node={node} className={visual.pulse ? "gx-live" : ""} spinner={visual.pulse && !visual.thinking} />
        {node.outcome && <span className="shrink-0 font-medium text-ink/70">{OUTCOME_LABEL[node.outcome]}</span>}
        {folded ? (
          <span className="truncate">{foldedSummary(folded)}</span>
        ) : (
          agentName && <span className="truncate">{agentName}</span>
        )}
        <span className="ml-auto shrink-0 tabular-nums">{shortTime(node.updated_at ?? node.created_at)}</span>
      </span>
      {childCount > 0 && (
        <button
          type="button"
          className="nodrag absolute -right-3 top-1/2 z-10 flex h-6 min-w-6 -translate-y-1/2 items-center justify-center rounded-full border border-line bg-surface px-1 text-[11px] font-semibold text-slate shadow-card hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          onClick={(e) => {
            e.stopPropagation();
            data.onToggle(node.id);
          }}
          aria-expanded={!collapsed}
          aria-label={collapsed ? `Expand branch (${hiddenBelow} hidden)` : `Collapse branch (${childCount} children)`}
          title={collapsed ? `Expand: ${hiddenBelow} hidden below` : "Collapse this branch"}
        >
          {collapsed ? `+${hiddenBelow}` : "−"}
        </button>
      )}
    </div>
  );
}

export const GraphNodeCard = memo(GraphNodeCardImpl);
