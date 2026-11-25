// React Flow node cards of the Network map. Each card is ONE focusable button (Enter or
// click opens the asset drawer); expand/collapse controls are separate buttons on top.
// Text is >= 12 px; state is a ring AND a text chip (colour is never the only cue).
import { memo, type ReactNode } from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { ChevronDownIcon, ChevronRightIcon, ComputerDesktopIcon, ServerStackIcon, ShieldCheckIcon } from "@heroicons/react/20/solid";
import type { AssetNode } from "../types";
import { CATEGORY_STYLE, KIND_STYLE } from "../graph/encoding";
import { formatBytes, groupLabel } from "../assetClass";
import { assetVisual, displayService, endpointMethod, endpointPath, serviceSurface, VISUAL_STYLE, type ViewNode } from "./model";
import { HeaderPostureBar, RiskBadge } from "./SurfacePanel";
import { SIZE } from "./layout";

export interface NetCardData extends Record<string, unknown> {
  v: ViewNode;
  fresh: boolean;
  changed: boolean;
  selected: boolean;
  dim: boolean;
  onOpen: (id: string) => void;
  onToggleCluster: (id: string, expanded: boolean) => void;
  onToggleParams: (id: string) => void;
}
export type NetCardNode = Node<NetCardData, "net">;

const handles = (
  <>
    <Handle id="l" type="target" position={Position.Left} isConnectable={false} className="nm-handle" />
    <Handle id="r" type="source" position={Position.Right} isConnectable={false} className="nm-handle" />
    <Handle id="t" type="target" position={Position.Top} isConnectable={false} className="nm-handle" />
    <Handle id="b" type="source" position={Position.Bottom} isConnectable={false} className="nm-handle" />
  </>
);

function StateChip({ n }: { n: AssetNode }) {
  const s = VISUAL_STYLE[assetVisual(n)];
  return (
    <span className={`inline-flex h-5 shrink-0 items-center gap-1 rounded border px-1.5 text-[12px] font-semibold leading-none ${s.chip}`} title={s.description}>
      <span aria-hidden="true">{s.glyph}</span>
      {s.label}
    </span>
  );
}

function Marks({ fresh, changed }: { fresh: boolean; changed: boolean }) {
  if (!fresh && !changed) return null;
  return <span className="rounded bg-accent px-1 text-[11px] font-semibold uppercase tracking-wide text-white">{fresh ? "new" : "updated"}</span>;
}

function Shell({ d, ring, shape = "rounded-lg", children, label }: { d: NetCardData; ring: string; shape?: string; children: ReactNode; label: string }) {
  const { v } = d;
  const { w, h } = SIZE[v.kind];
  return (
    <div
      className={`nm-card relative border bg-surface text-left shadow-card transition-opacity duration-200 ${shape} ${ring} ${d.selected ? "ring-2 ring-accent ring-offset-2" : ""} ${d.dim ? "!opacity-35" : ""} ${d.fresh ? "nm-fresh" : ""} ${d.changed ? "nm-changed" : ""}`}
      style={{ width: "100%", maxWidth: w, height: h }}
      data-kind={v.kind}
      data-testid={`net-node-${v.id}`}
    >
      {handles}
      <button
        type="button"
        className="absolute inset-0 z-0 rounded-[inherit] focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        onClick={() => d.onOpen(v.id)}
        aria-label={label}
      />
      {children}
    </div>
  );
}

const pad = "pointer-events-none relative px-2.5";

function HostCard({ d }: { d: NetCardData }) {
  const n = d.v.asset!;
  const s = VISUAL_STYLE[assetVisual(n)];
  return (
    <Shell d={d} ring={`${s.border} ${s.body}`} label={`Host ${n.label}. ${s.label}. Open details.`}>
      <div className={`${pad} flex h-full flex-col justify-center gap-1`}>
        <span className="flex items-center gap-1.5">
          <span aria-hidden="true" className="grid h-5 w-5 shrink-0 place-items-center rounded bg-ink text-white"><ComputerDesktopIcon className="h-3.5 w-3.5" /></span>
          <span className="text-[12px] font-semibold text-slate">Host</span>
          <Marks fresh={d.fresh} changed={d.changed} />
        </span>
        <span className="truncate text-[13px] font-semibold text-ink" title={n.label}>{n.label}</span>
      </div>
    </Shell>
  );
}

function ServiceCard({ d }: { d: NetCardData }) {
  const n = d.v.asset!;
  const s = VISUAL_STYLE[assetVisual(n)];
  const sf = serviceSurface(n.data);
  const techs = sf ? [...(sf.server ? [sf.server] : []), ...sf.technologies] : [];
  return (
    <Shell d={d} ring={`${s.border} ${s.body}`} label={`Service ${n.label}. ${s.label}${sf?.riskScore != null ? `, risk ${sf.riskScore} of 100` : ""}. Open details.`}>
      <div className={`${pad} flex h-full flex-col gap-1.5 py-2`}>
        <span className="flex items-center gap-1.5">
          <span aria-hidden="true" className="grid h-5 w-5 shrink-0 place-items-center rounded bg-sky-800 text-white"><ServerStackIcon className="h-3.5 w-3.5" /></span>
          <span className="text-[12px] font-semibold text-slate">Service</span>
          <Marks fresh={d.fresh} changed={d.changed} />
          <span className="ml-auto">{sf && <RiskBadge score={sf.riskScore} />}</span>
        </span>
        <span className="truncate text-[13px] font-semibold text-ink" title={n.label}>{displayService(n.label)}</span>
        <span className="flex min-h-[22px] flex-wrap gap-1 overflow-hidden">
          {techs.slice(0, 3).map((t) => (
            <span key={t} className="mono max-w-[130px] truncate rounded border border-line bg-canvas px-1.5 text-[12px] leading-5 text-ink" title={t}>{t}</span>
          ))}
          {techs.length > 3 && <span className="text-[12px] leading-5 text-slate">+{techs.length - 3}</span>}
          {techs.length === 0 && <span className="text-[12px] leading-5 text-slate">server not identified yet</span>}
        </span>
        <span className="mt-auto flex flex-col gap-1">
          {sf && sf.headers.total > 0 ? (
            <>
              <HeaderPostureBar present={sf.headers.presentCount} missing={sf.headers.missingCount} />
              <span className="flex items-center gap-2 text-[12px] text-slate">
                <span className="tabular-nums">{sf.headers.presentCount}/{sf.headers.total} headers</span>
                <StateChip n={n} />
              </span>
            </>
          ) : (
            <span className="flex items-center gap-2 text-[12px] text-slate">headers not observed <StateChip n={n} /></span>
          )}
        </span>
      </div>
    </Shell>
  );
}

function EndpointCard({ d }: { d: NetCardData }) {
  const n = d.v.asset!;
  const s = VISUAL_STYLE[assetVisual(n)];
  const method = endpointMethod(n);
  const path = endpointPath(n);
  const params = d.v.params;
  return (
    <Shell d={d} ring={`${s.border} ${s.body}`} shape="rounded-md" label={`Endpoint ${method ?? ""} ${path}. ${s.label}${n.finding_count ? `, ${n.finding_count} findings` : ""}. Open details.`}>
      <div className={`${pad} flex h-full flex-col justify-center gap-0.5 ${params && params.count > 0 ? "pr-14" : ""}`}>
        <span className="flex items-center gap-1.5">
          {method && <span className="mono rounded bg-canvas px-1 text-[12px] font-semibold text-slate">{method}</span>}
          <span className="mono min-w-0 truncate text-[12.5px] text-ink" title={path}>{path}</span>
          <Marks fresh={d.fresh} changed={d.changed} />
        </span>
        <span className="flex items-center gap-1.5 text-[12px]">
          <StateChip n={n} />
          {n.finding_count > 0 && (
            <span className="rounded border border-severity-critical/40 px-1 font-semibold tabular-nums text-severity-critical" title={`${n.finding_count} finding(s) linked`}>
              {n.finding_count} finding{n.finding_count === 1 ? "" : "s"}
            </span>
          )}
        </span>
      </div>
      {params && params.count > 0 && (
        <button
          type="button"
          className="nodrag absolute right-1.5 top-1/2 z-10 flex h-7 -translate-y-1/2 items-center gap-0.5 rounded-md border border-line bg-surface px-1.5 text-[12px] font-semibold tabular-nums text-slate shadow-card hover:text-ink focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
          aria-expanded={params.expanded}
          aria-label={`${params.expanded ? "Hide" : "Show"} ${params.count} parameters of ${path}`}
          onClick={(e) => {
            e.stopPropagation();
            d.onToggleParams(d.v.id);
          }}
        >
          {params.expanded ? <ChevronDownIcon className="h-3.5 w-3.5" aria-hidden="true" /> : <ChevronRightIcon className="h-3.5 w-3.5" aria-hidden="true" />}
          {params.count}p
        </button>
      )}
    </Shell>
  );
}

function ClusterCard({ d }: { d: NetCardData }) {
  const c = d.v.cluster!;
  const stat = !!c.isStatic;
  const worst = stat ? { border: "border-dashed border-slate/50" } : c.findings > 0 ? VISUAL_STYLE.finding : c.tested === c.total ? VISUAL_STYLE.tested : VISUAL_STYLE.in_scope;
  return (
    <div
      className={`nm-card relative rounded-md border bg-canvas text-left shadow-card ${worst.border} ${d.selected ? "ring-2 ring-accent ring-offset-2" : ""} ${d.dim ? "!opacity-35" : ""}`}
      style={{ width: "100%", maxWidth: SIZE.cluster.w, height: SIZE.cluster.h }}
      data-kind="cluster"
      data-testid={`net-node-${d.v.id}`}
    >
      {handles}
      <button
        type="button"
        className="absolute inset-0 z-0 flex items-center gap-2 rounded-[inherit] px-2.5 text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-accent"
        aria-expanded={c.expanded}
        aria-label={stat ? `Static assets ${groupLabel(c.prefix, c.total, c.bytes ?? null)}. ${c.expanded ? "Collapse" : "Expand"}.` : `Group ${c.prefix}, ${c.total} endpoints, ${c.tested} tested, ${c.findings} with findings. ${c.expanded ? "Collapse" : "Expand"}.`}
        onClick={() => d.onToggleCluster(d.v.id, !c.expanded)}
      >
        {c.expanded ? <ChevronDownIcon className="h-4 w-4 shrink-0 text-slate" aria-hidden="true" /> : <ChevronRightIcon className="h-4 w-4 shrink-0 text-slate" aria-hidden="true" />}
        <span className="min-w-0">
          {stat ? (
            <>
              <span className="mono block truncate text-[12.5px] font-semibold text-slate" title={groupLabel(c.prefix, c.total, c.bytes ?? null)}>{c.prefix === "/" ? "root files" : c.prefix}</span>
              <span className="block text-[12px] tabular-nums text-slate">{c.total} file{c.total === 1 ? "" : "s"}{c.bytes ? ` · ${formatBytes(c.bytes)}` : ""} · static</span>
            </>
          ) : (
            <>
              <span className="mono block truncate text-[12.5px] font-semibold text-ink">{c.prefix}/…</span>
              <span className="block text-[12px] tabular-nums text-slate">
                {c.total} endpoints · {c.tested} tested{c.findings ? ` · ${c.findings} with findings` : ""}
              </span>
            </>
          )}
        </span>
      </button>
    </div>
  );
}

function ParamCard({ d }: { d: NetCardData }) {
  const n = d.v.asset!;
  const s = VISUAL_STYLE[assetVisual(n)];
  return (
    <Shell d={d} ring={`${s.border} ${s.body}`} shape="rounded" label={`Parameter ${n.label}. Open details.`}>
      <div className={`${pad} flex h-full items-center gap-1.5`}>
        <span aria-hidden="true" className="text-[12px] text-slate">⌗</span>
        <span className="mono truncate text-[12px] text-ink" title={n.label}>{n.label}</span>
        {n.finding_count > 0 && <span className="ml-auto text-[12px] font-semibold text-severity-critical">{n.finding_count}!</span>}
      </div>
    </Shell>
  );
}

function DefenseCard({ d }: { d: NetCardData }) {
  const n = d.v.asset!;
  const cat = CATEGORY_STYLE.defense_proposed;
  const kind = KIND_STYLE.defense;
  const meta = [n.data?.kind, n.data?.format].filter((x): x is string => typeof x === "string");
  return (
    <Shell d={d} ring={`${cat.border} ${kind.shape}`} shape="" label={`Defense ${n.label}. Open details.`}>
      <div className={`${pad} flex h-full flex-col justify-center gap-0.5`}>
        <span className="flex items-center gap-1.5">
          <span aria-hidden="true" className={`grid h-5 w-5 shrink-0 place-items-center rounded ${kind.tile}`}><ShieldCheckIcon className="h-3.5 w-3.5" /></span>
          <span className="text-[12px] font-semibold text-teal-800">Defense</span>
          {meta.length > 0 && <span className="mono truncate text-[12px] text-slate">{meta.join(" · ")}</span>}
          <Marks fresh={d.fresh} changed={d.changed} />
        </span>
        <span className="truncate text-[12.5px] text-ink" title={n.label}>{n.label}</span>
      </div>
    </Shell>
  );
}

function NetCardImpl({ data }: NodeProps<NetCardNode>) {
  switch (data.v.kind) {
    case "host": return <HostCard d={data} />;
    case "service": return <ServiceCard d={data} />;
    case "endpoint": return <EndpointCard d={data} />;
    case "cluster": return <ClusterCard d={data} />;
    case "parameter": return <ParamCard d={data} />;
    case "defense": return <DefenseCard d={data} />;
  }
}

export const NetCard = memo(NetCardImpl);
