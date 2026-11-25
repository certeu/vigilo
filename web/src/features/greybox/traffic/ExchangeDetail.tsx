// Detail of one captured exchange. Everything is rendered as React text: headers and
// bodies come from the target and are untrusted, so there is no HTML rendering at all.
import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import { Badge, ErrorState, Skeleton } from "../../../components/ui";
import type { Exchange, ExchangeSide } from "../types";
import { formatDateMs, shortId } from "../format";
import {
  BODY_STORE_CAP_KB, blockSentence, buildCurl, contentTypeOf, CURL_NOTE, errorSentence, formatMs, formatSize,
  isJsonType, isRedacted, omittedSentence, prettyJson, statusColor, trafficLink,
} from "./trafficModel";
import { useExchange } from "./useTraffic";

const REDACT_TIP = "Redacted: Vigilo masks credentials (cookies, authorization, tokens) before storing traffic, so the original value is not available.";

export function HeadersTable({ headers }: { headers: [string, string][] }) {
  if (headers.length === 0) return <p className="text-xs text-slate">No headers recorded.</p>;
  return (
    <table className="w-full table-fixed text-xs">
      <caption className="sr-only">Headers</caption>
      <tbody>
        {headers.map(([n, v], i) => (
          <tr key={i} className="border-t border-line first:border-t-0 align-top">
            <th scope="row" className="mono w-2/5 break-all py-1 pr-2 text-left font-medium">{n}</th>
            <td className="mono break-all py-1">
              {v}
              {isRedacted(v) && (
                <span className="ml-1.5 align-middle">
                  <Badge tone="warning" title={REDACT_TIP}>redacted</Badge>
                </span>
              )}
            </td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

export function BodyViewer({ side, contentType }: { side: ExchangeSide; contentType: string | null }) {
  const body = side.body;
  const json = body != null && isJsonType(contentType, body);
  const pretty = useMemo(() => (json && body ? prettyJson(body) : null), [json, body]);
  const [on, setOn] = useState(false);
  if (body == null || body === "") {
    return (
      <p className="text-xs text-slate">
        {side.body_omitted_reason ? `Body omitted: ${omittedSentence(side.body_omitted_reason)}` : "No body."}
      </p>
    );
  }
  const shown = on && pretty ? pretty : body;
  return (
    <div>
      <div className="mb-1 flex flex-wrap items-center gap-2 text-xs">
        {side.body_truncated && (
          <Badge tone="warning" title={`Only the first ${BODY_STORE_CAP_KB} KB of each body is stored.`}>truncated</Badge>
        )}
        {json && (
          <button type="button" className="btn-ghost px-2 py-0.5 text-xs" aria-pressed={on} onClick={() => setOn(!on)} disabled={!pretty}
            title={pretty ? undefined : "Not valid JSON (it may be truncated), shown as stored"}>
            {on ? "Raw" : "Pretty-print JSON"}
          </button>
        )}
        <span className="text-slate">{formatSize(body.length)} stored, shown as plain text</span>
      </div>
      <pre className="mono max-h-72 overflow-auto whitespace-pre-wrap break-words rounded border border-line bg-canvas p-2.5 text-xs" tabIndex={0}>{shown}</pre>
    </div>
  );
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="border-t border-line pt-3">
      <h4 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate">{title}</h4>
      {children}
    </section>
  );
}

export function ExchangeDetail({ runId, exchangeId, onClose }: { runId: string; exchangeId: number; onClose: () => void }) {
  const { exchange: x, loading, error } = useExchange(runId, exchangeId);
  const [copied, setCopied] = useState<"ok" | "fail" | null>(null);

  const copy = (e: Exchange) => {
    Promise.resolve(navigator.clipboard?.writeText(buildCurl(e)))
      .then(() => setCopied("ok"))
      .catch(() => setCopied("fail"));
  };

  return (
    <aside className="card min-w-0 space-y-3 p-4" aria-label={`Exchange ${exchangeId}`}>
      <div className="flex items-start justify-between gap-2">
        <h3 className="text-sm font-semibold">Exchange #{exchangeId}</h3>
        <button type="button" className="text-xs text-slate hover:text-ink" onClick={onClose} aria-label="Close detail">Close</button>
      </div>
      {loading && <div role="status" aria-label="Loading exchange"><Skeleton className="h-24 w-full" /></div>}
      {error === "missing" && <p className="text-sm text-slate">This exchange does not exist in this run.</p>}
      {error && error !== "missing" && <ErrorState title="Could not load this exchange" message={error} />}
      {x && (
        <>
          <p className="mono break-all text-xs">
            <span className="font-semibold">{x.method}</span> {x.url}
          </p>
          <p className="text-xs">
            <span className={`mono font-semibold ${statusColor(x.status_code)}`}>{x.status_code ?? "no response"}</span>
            <span className="text-slate"> · {formatMs(x.duration_ms)} · {formatSize(x.response_size)} · {formatDateMs(x.ts)}</span>
          </p>
          {x.blocked && (
            <p role="note" className="rounded border border-severity-critical/30 bg-red-50 p-2 text-xs text-severity-critical">
              {blockSentence(x.block_reason)}. The request was never sent.
            </p>
          )}
          {x.via_proxy && <p role="note" className="rounded border border-line bg-canvas p-2 text-xs text-slate">Sent via egress proxy. The proxy resolved DNS, so the resolved IP is not pinned.</p>}
          {x.error && <p className="rounded border border-severity-medium/30 bg-amber-50 p-2 text-xs">Request failed: {errorSentence(x.error)}</p>}

          <div className="flex flex-wrap items-center gap-2">
            <button type="button" className="btn-ghost py-1 text-xs" onClick={() => copy(x)}>Copy as curl</button>
            <span className="text-xs text-slate" role="status">
              {copied === "ok" ? "Copied. " : copied === "fail" ? "Copy failed. " : ""}{CURL_NOTE}
            </span>
          </div>

          <dl className="grid grid-cols-[7rem_1fr] gap-x-3 gap-y-1 text-xs">
            <dt className="text-slate">Resolved IP</dt>
            <dd className="mono">{x.resolved_ip ?? "—"}</dd>
            <dt className="text-slate">Tool</dt>
            <dd>{x.tool}{x.agent_name ? ` · ${x.agent_name}` : ""}</dd>
            <dt className="text-slate">Work order</dt>
            <dd>
              {x.work_order_id ? (
                <Link className="mono text-accent hover:underline" to={`?tab=traffic&work_order=${x.work_order_id}`} title="Show traffic of this work order">{shortId(x.work_order_id)}</Link>
              ) : "—"}
            </dd>
            <dt className="text-slate">Redirect</dt>
            <dd>
              {x.parent_exchange_id != null || x.redirect_hop > 0 ? (
                <>
                  hop {x.redirect_hop}
                  {x.parent_exchange_id != null && (
                    <> from <Link className="mono text-accent hover:underline" to={trafficLink(x.parent_exchange_id)}>exchange #{x.parent_exchange_id}</Link></>
                  )}
                </>
              ) : "not a redirect hop"}
            </dd>
            <dt className="text-slate">Findings</dt>
            <dd>
              {x.finding_ids.length === 0 ? "none linked" : (
                <ul className="flex flex-wrap gap-x-3">
                  {x.finding_ids.map((f) => (
                    <li key={f}><Link className="mono text-accent hover:underline" to={`?tab=findings&open=${f}`}>{shortId(f)}</Link></li>
                  ))}
                </ul>
              )}
            </dd>
          </dl>

          <Section title="Request headers"><HeadersTable headers={x.request.headers} /></Section>
          <Section title="Request body"><BodyViewer side={x.request} contentType={contentTypeOf(x.request)} /></Section>
          <Section title="Response headers"><HeadersTable headers={x.response.headers} /></Section>
          <Section title="Response body"><BodyViewer side={x.response} contentType={contentTypeOf(x.response) ?? x.content_type} /></Section>
        </>
      )}
    </aside>
  );
}
