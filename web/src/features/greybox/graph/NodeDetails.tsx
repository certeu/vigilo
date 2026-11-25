import type { ReactNode } from "react";
import { Link, useInRouterContext } from "react-router-dom";
import { CopyableRule, DefenseChips } from "../run/DefensesTab";
import { useRunLiveStatusOptional } from "../run/RunLiveContext";
import { useDefenses } from "../run/useDefenses";
import { suggestTarget } from "../run/hintLogic";
import { useRunChatOptional } from "../run/RunChatContext";
import { OUTCOME_LABEL, type ExplorationEdge, type ExplorationNode } from "./types";
import { explorerDetail, formatTokens, TODO_LABEL } from "../explorerView";
import { KIND_STYLE, REL_STYLE, SEVERITY_CHIP } from "./encoding";
import { KindIcon } from "./KindIcon";
import { StatusChip } from "./GraphNodeCard";

export interface GraphDeepLinks {
  onOpenFinding?: (findingId: string) => void;
  /** Live Activity at an event seq. */
  onOpenEvent?: (seq: number) => void;
  onOpenWorkOrder?: (workOrderId: string) => void;
  onOpenAgent?: (agentId: string) => void;
  onOpenAsset?: (assetId: string) => void;
  onOpenExchange?: (exchangeId: number) => void;
}

const short = (id: string) => (id.length > 12 ? `${id.slice(0, 8)}…` : id);

function Row({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="grid grid-cols-[7.5rem_1fr] gap-2 py-1">
      <dt className="text-slate">{label}</dt>
      <dd className="min-w-0 break-words text-ink">{children}</dd>
    </div>
  );
}

function LinkButton({ onClick, children, label }: { onClick: () => void; children: ReactNode; label?: string }) {
  return (
    <button type="button" className="text-accent underline-offset-2 hover:underline" onClick={onClick} aria-label={label}>
      {children}
    </button>
  );
}

/** Defense node: the rule text. Finding node: its defenses and a link to the Defenses tab. */
function DefenseSection({ node }: { node: ExplorationNode }) {
  const live = useRunLiveStatusOptional();
  const inRouter = useInRouterContext();
  const enabled = !!live && (node.kind === "defense" || node.kind === "finding");
  const { items, loading } = useDefenses(live?.runId ?? "", live?.runStatus ?? null, enabled);
  if (!enabled) return null;
  if (node.kind === "defense") {
    const d = items.find((x) => x.node_id === node.id || (node.key && x.id === node.key));
    const k = node.data?.kind, f = node.data?.format;
    return (
      <section>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Suggested rule</h3>
        {d ? (
          <div className="space-y-2">
            <DefenseChips d={d} />
            {d.rationale && <p className="whitespace-pre-wrap break-words text-[13px] text-slate">{d.rationale}</p>}
            <CopyableRule text={d.content} label={d.title} />
            <p className="text-xs text-slate">Derived from target data. Review and test before deploying.</p>
          </div>
        ) : (
          <p className="text-[13px] text-slate">
            {loading ? "Loading the rule…" : `The rule text is not available${typeof k === "string" && typeof f === "string" ? ` (${k}, ${f})` : ""}.`}
          </p>
        )}
      </section>
    );
  }
  const findingId = node.finding_id ?? node.id;
  const mine = items.filter((x) => x.finding_id === findingId || x.finding_id === node.id);
  if (mine.length === 0) return null;
  return (
    <section>
      <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Defenses ({mine.length})</h3>
      <ul className="space-y-1">
        {mine.map((d) => (
          <li key={d.id} className="flex flex-wrap items-center gap-2 text-[13px] text-ink">
            <span className="min-w-0 break-words">{d.title}</span>
            <DefenseChips d={d} />
          </li>
        ))}
      </ul>
      {inRouter && (
        <Link className="mt-1.5 inline-block text-[13px] text-accent underline-offset-2 hover:underline" to={`?tab=defenses&finding=${encodeURIComponent(findingId)}`}>
          Open in Defenses tab
        </Link>
      )}
    </section>
  );
}

/** Reasoning node: the explorer cycle's analysis, todo list and model accounting. */
export function ReasoningSection({ node }: { node: ExplorationNode }) {
  if (node.kind !== "reasoning") return null;
  const d = explorerDetail(node.data);
  return (
    <section className={`space-y-3 ${node.status === "superseded" ? "opacity-75" : ""}`} data-testid="reasoning-section">
      {node.status === "superseded" && <p className="text-xs text-slate">Superseded by a later reasoning cycle.</p>}
      {d.assessment && <p className="text-[13px] text-ink"><span className="text-slate">Assessment: </span>{d.assessment}</p>}
      <div>
        <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Reasoning</h3>
        <p className="whitespace-pre-wrap break-words text-[13px] text-ink">{d.reasoning ?? "No reasoning text recorded."}</p>
      </div>
      {d.todolist.length > 0 && (
        <div>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Todo list</h3>
          <ul className="space-y-1">
            {d.todolist.map((t, i) => (
              <li key={i} className="flex gap-2 text-[13px]">
                <span className="w-20 shrink-0 text-[11px] uppercase tracking-wide text-slate">{TODO_LABEL[t.status]}</span>
                <span className={`min-w-0 break-words ${t.status === "done" ? "text-slate line-through" : "text-ink"}`}>{t.step}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
      <dl className="divide-y divide-line text-[13px]">
        {d.model && <Row label="Model">{d.model}</Row>}
        {d.tokens !== null && <Row label="Tokens">{formatTokens(d.tokens)}</Row>}
        {d.trigger && <Row label="Trigger">{d.trigger}</Row>}
      </dl>
    </section>
  );
}

function fmtTs(iso: string | undefined): string | null {
  if (!iso) return null;
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? iso : `${d.toISOString().slice(0, 19).replace("T", " ")}Z`;
}

export function NodeDetails({
  node,
  nodes,
  edges,
  agentName,
  fresh,
  folded,
  collapsed,
  hasChildren,
  links,
  onSelect,
  onFocus,
  onToggle,
  onCenter,
  onClose,
}: {
  node: ExplorationNode;
  nodes: ReadonlyMap<string, ExplorationNode>;
  edges: readonly ExplorationEdge[];
  agentName: string | null;
  fresh: boolean;
  folded: Record<string, number> | null;
  collapsed: boolean;
  hasChildren: boolean;
  links: GraphDeepLinks;
  onSelect: (id: string) => void;
  onFocus: () => void;
  onToggle: () => void;
  onCenter: () => void;
  /** Close the surrounding drawer (used when handing off to the run chat). */
  onClose?: () => void;
}) {
  const related = edges
    .filter((e) => e.src === node.id || e.dst === node.id)
    .map((e) => ({ e, out: e.src === node.id, other: nodes.get(e.src === node.id ? e.dst : e.src) }))
    .filter((r): r is { e: ExplorationEdge; out: boolean; other: ExplorationNode } => !!r.other)
    .sort((a, b) => Number(a.out) - Number(b.out) || a.e.rel.localeCompare(b.e.rel));
  const sev = node.kind === "finding" ? (node.severity ?? (node.data?.severity as string | undefined)) : undefined;
  const exchanges = node.exchange_ids ?? (Array.isArray(node.data?.exchange_ids) ? (node.data.exchange_ids as number[]) : []);
  const dataText = JSON.stringify(node.data ?? {}, null, 2);
  const chat = useRunChatOptional();
  const guide = () => {
    chat?.openWith({ nodeId: node.id, label: node.label, target: suggestTarget(node.data, node.label) });
    onClose?.();
  };

  return (
    <div className="space-y-5 text-sm">
      <div>
        <div className="flex flex-wrap items-center gap-1.5">
          <KindIcon kind={node.kind} size={20} />
          <span className="font-semibold text-ink">{KIND_STYLE[node.kind].label}</span>
          <StatusChip node={node} />
          {sev && <span className={`rounded border px-1.5 text-[11px] font-semibold uppercase ${SEVERITY_CHIP[sev] ?? ""}`}>{sev}</span>}
          {fresh && <span className="rounded bg-accent px-1 text-[11px] font-semibold uppercase text-white">new</span>}
        </div>
        <p className="mt-2 break-words font-medium text-ink">{node.label}</p>
        <p className="mono mt-1 break-all text-xs text-slate">{node.key}</p>
      </div>

      <div className="flex flex-wrap gap-2">
        <button type="button" className="btn-ghost" onClick={onCenter}>Show in graph</button>
        <button type="button" className="btn-ghost" onClick={onFocus}>Focus neighbourhood</button>
        {hasChildren && (
          <button type="button" className="btn-ghost" onClick={onToggle} aria-expanded={!collapsed}>
            {collapsed ? "Expand branch" : "Collapse branch"}
          </button>
        )}
        {node.kind !== "hint" && chat?.accepting && (
          <button type="button" className="btn-ghost border-hint-line text-hint-ink" onClick={guide} title="Message the exploration agent about this node">
            Guide from here
          </button>
        )}
        {node.kind === "finding" && node.finding_id && links.onOpenFinding && (
          <button type="button" className="btn-primary" onClick={() => links.onOpenFinding!(node.finding_id!)}>
            Open finding
          </button>
        )}
      </div>

      <dl className="divide-y divide-line text-[13px]">
        {node.outcome && <Row label="Outcome">{OUTCOME_LABEL[node.outcome]}</Row>}
        <Row label="Agent">
          {node.agent_id ? (
            links.onOpenAgent ? (
              <LinkButton onClick={() => links.onOpenAgent!(node.agent_id!)}>{agentName ?? short(node.agent_id)}</LinkButton>
            ) : (
              (agentName ?? short(node.agent_id))
            )
          ) : (
            <span className="text-slate">planner / system</span>
          )}
        </Row>
        {node.work_order_id && (
          <Row label="Work order">
            {links.onOpenWorkOrder ? (
              <LinkButton onClick={() => links.onOpenWorkOrder!(node.work_order_id!)}>{short(node.work_order_id)}</LinkButton>
            ) : (
              <span className="mono">{short(node.work_order_id)}</span>
            )}
          </Row>
        )}
        {node.finding_id && (
          <Row label="Finding">
            {links.onOpenFinding ? (
              <LinkButton onClick={() => links.onOpenFinding!(node.finding_id!)}>{short(node.finding_id)}</LinkButton>
            ) : (
              <span className="mono">{short(node.finding_id)}</span>
            )}
          </Row>
        )}
        {node.asset_id && (
          <Row label="Asset">
            {links.onOpenAsset ? (
              <LinkButton onClick={() => links.onOpenAsset!(node.asset_id!)}>{short(node.asset_id)}</LinkButton>
            ) : (
              <span className="mono">{short(node.asset_id)}</span>
            )}
          </Row>
        )}
        {(node.asset_ids ?? []).filter((a) => a !== node.asset_id).length > 0 && (
          <Row label="Also touched">
            <span className="flex flex-wrap gap-x-2">
              {(node.asset_ids ?? []).filter((a) => a !== node.asset_id).slice(0, 20).map((a) =>
                links.onOpenAsset ? (
                  <LinkButton key={a} onClick={() => links.onOpenAsset!(a)}>{short(a)}</LinkButton>
                ) : (
                  <span key={a} className="mono">{short(a)}</span>
                ),
              )}
            </span>
          </Row>
        )}
        {node.event_seq != null && (
          <Row label="Created by">
            {links.onOpenEvent ? (
              <LinkButton onClick={() => links.onOpenEvent!(node.event_seq!)} label={`Open event ${node.event_seq} in Live Activity`}>
                event #{node.event_seq}
              </LinkButton>
            ) : (
              <>event #{node.event_seq}</>
            )}
          </Row>
        )}
        {node.last_event_seq != null && node.last_event_seq !== node.event_seq && (
          <Row label="Last change">
            {links.onOpenEvent ? (
              <LinkButton onClick={() => links.onOpenEvent!(node.last_event_seq!)}>event #{node.last_event_seq}</LinkButton>
            ) : (
              <>event #{node.last_event_seq}</>
            )}
          </Row>
        )}
        {fmtTs(node.created_at) && <Row label="Created">{fmtTs(node.created_at)}</Row>}
        {fmtTs(node.updated_at) && <Row label="Updated">{fmtTs(node.updated_at)}</Row>}
        <Row label="Graph version">{node.version}</Row>
      </dl>

      <DefenseSection node={node} />
      <ReasoningSection node={node} />

      {folded && (
        <section>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Folded actions</h3>
          <p className="text-[13px] text-ink">
            {Object.entries(folded).map(([s, n]) => `${n} ${s}`).join(" · ")}. Turn off “Fold actions” to see them.
          </p>
        </section>
      )}

      {exchanges.length > 0 && (
        <section>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Evidence (HTTP exchanges)</h3>
          <ul className="flex flex-wrap gap-1.5">
            {exchanges.slice(0, 20).map((x) => (
              <li key={x}>
                {links.onOpenExchange ? (
                  <button type="button" className="mono rounded border border-line px-1.5 py-0.5 text-xs text-accent hover:bg-canvas" onClick={() => links.onOpenExchange!(x)}>
                    #{x}
                  </button>
                ) : (
                  <span className="mono rounded border border-line px-1.5 py-0.5 text-xs">#{x}</span>
                )}
              </li>
            ))}
          </ul>
        </section>
      )}

      {related.length > 0 && (
        <section>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Links ({related.length})</h3>
          <ul className="space-y-0.5">
            {related.slice(0, 60).map(({ e, out, other }) => (
              <li key={e.id}>
                <button
                  type="button"
                  className="flex w-full items-center gap-2 rounded px-1.5 py-1 text-left hover:bg-canvas focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
                  onClick={() => onSelect(other.id)}
                >
                  <span className="w-24 shrink-0 text-[12px] font-medium" style={{ color: REL_STYLE[e.rel].color }}>
                    {out ? `${REL_STYLE[e.rel].label} →` : `← ${REL_STYLE[e.rel].label}`}
                  </span>
                  <KindIcon kind={other.kind} size={15} />
                  <span className="min-w-0 flex-1 truncate text-[13px] text-ink">{other.label}</span>
                  <StatusChip node={other} />
                </button>
              </li>
            ))}
          </ul>
          {related.length > 60 && <p className="mt-1 text-xs text-slate">{related.length - 60} more in the table view.</p>}
        </section>
      )}

      {dataText !== "{}" && (
        <section>
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Data (redacted)</h3>
          <pre className="mono max-h-64 overflow-auto whitespace-pre-wrap break-words rounded border border-line bg-canvas p-2 text-xs text-ink">
            {dataText.length > 4000 ? `${dataText.slice(0, 4000)}\n… truncated` : dataText}
          </pre>
        </section>
      )}
    </div>
  );
}
