// Asset drawer: surface, findings, work orders, exchanges and the recommendations that
// protect the asset. Opened by click or Enter on a card or table row; the panel
// re-fetches when the asset's graph version moves (live runs).
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { Drawer, SeverityChip } from "../../../components/ui";
import { greyboxApi } from "../api";
import type { AssetDetail, AssetNode, Defense } from "../types";
import { CopyableRule, DefenseChips } from "../run/DefensesTab";
import { assetVisual, VISUAL_STYLE } from "./model";
import { assetTitle } from "./AssetsTable";
import { EndpointSurfaceBlock, SurfacePanel } from "./SurfacePanel";

function useAssetDetail(runId: string, asset: AssetNode) {
  const [detail, setDetail] = useState<AssetDetail | null>(null);
  const [defenses, setDefenses] = useState<Defense[]>([]);
  const [state, setState] = useState<"loading" | "ready" | "unavailable">("loading");
  const id = asset.id;
  useEffect(() => {
    setDetail(null);
    setDefenses([]);
    setState("loading");
  }, [id]);
  useEffect(() => {
    const ctrl = new AbortController();
    greyboxApi
      .asset(runId, id, ctrl.signal)
      .then((d) => {
        if (ctrl.signal.aborted) return;
        setDetail(d);
        setState("ready");
      })
      .catch(() => !ctrl.signal.aborted && setState((s) => (s === "ready" ? s : "unavailable")));
    greyboxApi
      .defenses(runId, { asset_id: id })
      .then((r) => !ctrl.signal.aborted && setDefenses(r.items.filter((d) => !d.asset_id || d.asset_id === id)))
      .catch(() => {});
    return () => ctrl.abort();
  }, [runId, id, asset.version]);
  return { detail, defenses, state };
}

const H = ({ children, count }: { children: string; count?: number }) => (
  <h3 className="mb-1.5 mt-5 text-xs font-medium uppercase tracking-wide text-slate">
    {children}
    {count !== undefined && <span className="ml-1 normal-case tabular-nums">({count})</span>}
  </h3>
);

export function AssetDrawer({ runId, asset, onClose }: { runId: string; asset: AssetNode; onClose: () => void }) {
  const { detail, defenses, state } = useAssetDetail(runId, asset);
  const v = VISUAL_STYLE[assetVisual(asset)];
  const node = detail ?? asset;
  return (
    <Drawer
      onClose={onClose}
      widthClass="max-w-xl"
      title={
        <span className="flex min-w-0 flex-col">
          <span className="text-xs font-medium capitalize text-slate">{asset.kind}</span>
          <span className="mono break-all text-sm">{assetTitle(asset)}</span>
        </span>
      }
    >
      <div className="space-y-1 text-[13px]">
        <p className="flex flex-wrap items-center gap-2">
          <span className={`inline-flex items-center gap-1 rounded border px-1.5 text-[12px] font-semibold ${v.chip}`}><span aria-hidden="true">{v.glyph}</span>{v.label}</span>
          <span className="text-slate">{node.in_scope ? "in scope" : "out of scope"} · {node.tested ? "tested" : "not tested"}{detail?.children_count ? ` · ${detail.children_count} children` : ""}</span>
        </p>
        <p className="mono break-all text-xs text-slate">{asset.key}</p>
      </div>

      {asset.kind === "service" && (<><H>Surface</H><SurfacePanel service={node} /></>)}
      {asset.kind === "endpoint" && (<><H>Surface</H><EndpointSurfaceBlock node={node} /></>)}
      {asset.kind === "defense" && (
        <>
          <H>Recommendation</H>
          <p className="text-[13px] text-ink">{asset.label}</p>
          <p className="mt-1 text-xs text-slate">See the Defenses tab for the full rule text.</p>
          <Link className="mt-1 inline-block text-[13px] text-accent hover:underline" to="?tab=defenses">Open the Defenses tab</Link>
        </>
      )}

      {state === "unavailable" && <p className="mt-4 rounded border border-dashed border-line p-2.5 text-[13px] text-slate">Findings, work orders and exchanges are not available for this asset yet.</p>}
      {state === "loading" && <p role="status" className="mt-4 text-[13px] text-slate">Loading details…</p>}

      {detail && (
        <>
          <H count={detail.findings?.length ?? 0}>Findings</H>
          {detail.findings?.length ? (
            <ul className="space-y-1 text-[13px]">
              {detail.findings.map((f) => (
                <li key={f.id} className="flex items-start gap-2">
                  {f.severity && <SeverityChip severity={f.severity} />}
                  <Link className="min-w-0 break-words text-accent hover:underline" to={`?tab=findings&open=${encodeURIComponent(f.id)}`}>{f.title || f.id}</Link>
                  {f.status && <span className="shrink-0 text-xs text-slate">{f.status}</span>}
                </li>
              ))}
            </ul>
          ) : <p className="text-[13px] text-slate">None linked.</p>}

          <H count={detail.work_orders?.length ?? 0}>Work orders</H>
          {detail.work_orders?.length ? (
            <ul className="space-y-1 text-[13px]">
              {detail.work_orders.map((w) => (
                <li key={w.id} className="flex items-start gap-2">
                  <span className="min-w-0 break-words text-ink">{w.title || w.tool || w.id}</span>
                  <span className="shrink-0 text-xs text-slate">{w.status ?? ""}</span>
                </li>
              ))}
            </ul>
          ) : <p className="text-[13px] text-slate">None yet.</p>}

          <H count={detail.exchanges?.length ?? 0}>Exchanges</H>
          {detail.exchanges?.length ? (
            <ul className="space-y-1 text-[13px]">
              {detail.exchanges.map((x) => (
                <li key={x.id} className="flex items-start gap-2">
                  <Link className="mono min-w-0 break-all text-accent hover:underline" to={`?tab=traffic&exchange=${x.id}`}>
                    {x.method ?? ""} {x.path ?? `#${x.id}`}
                  </Link>
                  {x.status_code != null && <span className="mono shrink-0 text-xs text-slate">{x.status_code}</span>}
                </li>
              ))}
            </ul>
          ) : <p className="text-[13px] text-slate">No traffic recorded.</p>}
        </>
      )}

      <H count={defenses.length}>Recommendations protecting this asset</H>
      {defenses.length ? (
        <ul className="space-y-3">
          {defenses.map((d) => (
            <li key={d.id} className="space-y-1.5">
              <div className="flex flex-wrap items-center gap-2"><span className="break-words text-[13px] font-medium text-ink">{d.title}</span><DefenseChips d={d} /></div>
              {d.rationale && <p className="whitespace-pre-wrap break-words text-[13px] text-slate">{d.rationale}</p>}
              <CopyableRule text={d.content} label={d.title} />
            </li>
          ))}
        </ul>
      ) : <p className="text-[13px] text-slate">No recommendation targets this asset. Network-wide recommendations are generated when the run finishes.</p>}
    </Drawer>
  );
}
