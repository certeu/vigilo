import { useMemo, useState } from "react";
import { Link, useSearchParams } from "react-router-dom";
import { BugAntIcon, ChevronDownIcon, ChevronUpIcon } from "@heroicons/react/24/outline";
import { Badge, Drawer, EmptyState, ErrorState, SeverityChip, SkeletonRows, type BadgeTone } from "../../../components/ui";
import { RelativeTime } from "../RelativeTime";
import type { Finding, FindingClass, FindingStatus, FindingSummary, RunStatus, Severity } from "../types";
import { CopyableRule } from "./DefensesTab";
import {
  CLASS_LABEL, CLASS_ORDER, countBy, DEFAULT_SORT, defenseCount, defensesLinkParams, filterFindings, findingAsset,
  findingClass, graphLinkParams, groupFindings, nextSort, SEVERITY_ORDER, sortFindings, STATUS_LABEL, STATUS_ORDER,
  type Sort, type SortKey,
} from "./findingsModel";
import { useFindingDetail, useFindings } from "./useFindings";

const STATUS_TONE: Record<FindingStatus, BadgeTone> = { verified: "success", candidate: "warning", rejected: "neutral" };

export function StatusPill({ status }: { status: FindingStatus }) {
  return <Badge tone={STATUS_TONE[status]}>{STATUS_LABEL[status]}</Badge>;
}

const COLUMNS: { key: SortKey; label: string; className?: string }[] = [
  { key: "severity", label: "Severity" },
  { key: "title", label: "Finding" },
  { key: "asset", label: "Affected", className: "hidden md:table-cell" },
  { key: "check", label: "Check", className: "hidden lg:table-cell" },
  { key: "status", label: "Status" },
  { key: "evidence", label: "Evidence", className: "hidden sm:table-cell text-right" },
  { key: "defenses", label: "Defenses", className: "hidden sm:table-cell text-right" },
];

function FilterSelect<T extends string>({
  label, value, options, counts, onChange, format = (k) => k,
}: {
  label: string;
  value: T | "";
  options: readonly T[];
  counts: Partial<Record<T, number>>;
  onChange: (v: T | "") => void;
  format?: (k: T) => string;
}) {
  return (
    <label className="flex items-center gap-1.5 text-sm text-slate">
      {label}
      <select className="rounded border border-line bg-surface px-2 py-1 text-sm capitalize text-ink" value={value} onChange={(e) => onChange(e.target.value as T | "")}>
        <option value="">All</option>
        {options.map((k) => (
          <option key={k} value={k}>{format(k)} ({counts[k] ?? 0})</option>
        ))}
      </select>
    </label>
  );
}

export function FindingsTab({ runId, runStatus }: { runId: string; runStatus: RunStatus }) {
  const { items, loading, error, version, refresh } = useFindings(runId, runStatus);
  const [params, setParams] = useSearchParams();
  const open = params.get("open");
  const [sort, setSort] = useState<Sort>(DEFAULT_SORT);
  const [severity, setSeverity] = useState<Severity | "">("");
  const [status, setStatus] = useState<FindingStatus | "">("");
  const [klass, setKlass] = useState<FindingClass | "">("");

  const shown = useMemo(
    () => sortFindings(filterFindings(items, { severity: severity || null, status: status || null }), sort)
      .filter((f) => !klass || findingClass(f) === klass),
    [items, severity, status, klass, sort],
  );
  // Report-style sections: confirmed vulnerabilities never mix with hardening advice.
  const groups = useMemo(() => groupFindings(shown), [shown]);
  const bySeverity = useMemo(() => countBy(items, (f) => f.severity), [items]);
  const byStatus = useMemo(() => countBy(items, (f) => f.status), [items]);
  const byClass = useMemo(() => countBy(items, (f) => findingClass(f)), [items]);

  const setOpen = (id: string | null) => {
    const next = new URLSearchParams(params);
    if (id) next.set("open", id);
    else next.delete("open");
    setParams(next, { replace: true });
  };

  if (loading) return <SkeletonRows rows={6} />;
  if (error && items.length === 0) {
    return <ErrorState icon={BugAntIcon} title="Could not load findings" error={error} what="the findings" onRetry={refresh} />;
  }
  if (items.length === 0) {
    const active = !(["succeeded", "failed", "cancelled"] as RunStatus[]).includes(runStatus);
    return (
      <div className="card">
        <EmptyState icon={BugAntIcon} title={active ? "No findings yet" : "No findings"}>
          {active
            ? "Findings appear here as the checks report them and the engine verifies them."
            : "This run did not report any findings."}
        </EmptyState>
      </div>
    );
  }
  const filtering = !!(severity || status || klass);

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-2">
        <FilterSelect label="Severity" value={severity} options={SEVERITY_ORDER} counts={bySeverity} onChange={setSeverity} />
        <FilterSelect label="Status" value={status} options={STATUS_ORDER} counts={byStatus} onChange={setStatus} format={(k) => STATUS_LABEL[k]} />
        <FilterSelect label="Class" value={klass} options={CLASS_ORDER} counts={byClass} onChange={setKlass} format={(k) => CLASS_LABEL[k]} />
        {filtering && (
          <button type="button" className="text-sm text-accent hover:underline" onClick={() => { setSeverity(""); setStatus(""); setKlass(""); }}>
            Clear filters
          </button>
        )}
        <span className="ml-auto text-xs text-slate" role="status">
          {shown.length === items.length ? `${items.length} findings` : `${shown.length} of ${items.length} findings`}
        </span>
      </div>
      {error ? <p role="alert" className="text-xs text-severity-critical">Could not refresh the list. Showing the last loaded findings.</p> : null}

      <div className="card overflow-x-auto">
        <table className="w-full text-left text-sm">
          <caption className="sr-only">Findings of this run. Select a column heading to sort.</caption>
          <thead className="border-b border-line text-xs uppercase tracking-wide text-slate">
            <tr>
              {COLUMNS.map((c) => {
                const active = sort.key === c.key;
                return (
                  <th
                    key={c.key}
                    scope="col"
                    className={`px-3 py-2 font-medium ${c.className ?? ""}`}
                    aria-sort={active ? (sort.dir === "asc" ? "ascending" : "descending") : "none"}
                  >
                    <button type="button" className="inline-flex items-center gap-1 uppercase tracking-wide hover:text-ink" onClick={() => setSort(nextSort(sort, c.key))}>
                      {c.label}
                      {active && (sort.dir === "asc" ? <ChevronUpIcon className="h-3 w-3" aria-hidden="true" /> : <ChevronDownIcon className="h-3 w-3" aria-hidden="true" />)}
                    </button>
                  </th>
                );
              })}
            </tr>
          </thead>
          <tbody className="divide-y divide-line">
            {shown.length === 0 && (
              <tr>
                <td colSpan={COLUMNS.length} className="px-3 py-8 text-center text-slate">No findings match these filters.</td>
              </tr>
            )}
            {groups.map((g) => [
              <tr key={`h-${g.key}`} className="bg-canvas">
                <th scope="rowgroup" colSpan={COLUMNS.length} className="px-3 py-1.5 text-xs font-semibold uppercase tracking-wide text-slate">
                  {g.label} ({g.items.length})
                </th>
              </tr>,
              ...g.items.map((f) => (
                <Row key={f.id} f={f} onOpen={() => setOpen(f.id)} selected={open === f.id} />
              )),
            ])}
          </tbody>
        </table>
      </div>

      {open && (
        <Drawer title="Finding" onClose={() => setOpen(null)} widthClass="max-w-2xl">
          <FindingDetail runId={runId} findingId={open} listVersion={version} />
        </Drawer>
      )}
    </div>
  );
}

function Row({ f, onOpen, selected }: { f: FindingSummary; onOpen: () => void; selected: boolean }) {
  const asset = findingAsset(f);
  return (
    <tr className={`hover:bg-canvas ${selected ? "bg-accent/5" : ""}`}>
      <td className="whitespace-nowrap px-3 py-2.5 align-top"><SeverityChip severity={f.severity} /></td>
      <td className="max-w-[28rem] px-3 py-2.5 align-top">
        <button type="button" className="break-words text-left font-medium text-ink hover:text-accent hover:underline" onClick={onOpen}>
          {f.title}
        </button>
        <div className="mt-0.5 text-xs text-slate">{CLASS_LABEL[findingClass(f)]}</div>
        {asset && <div className="mono mt-0.5 break-all text-xs text-slate md:hidden">{asset}</div>}
      </td>
      <td className="mono hidden max-w-[16rem] break-all px-3 py-2.5 align-top text-xs text-slate md:table-cell">{asset || "—"}</td>
      <td className="mono hidden px-3 py-2.5 align-top text-xs text-slate lg:table-cell">{f.check_id}</td>
      <td className="whitespace-nowrap px-3 py-2.5 align-top"><StatusPill status={f.status} /></td>
      <td className="mono hidden px-3 py-2.5 text-right align-top sm:table-cell">{f.evidence_count}</td>
      <td className="mono hidden px-3 py-2.5 text-right align-top sm:table-cell">{defenseCount(f)}</td>
    </tr>
  );
}

const ROLE_LABEL = { baseline: "Baseline", proof: "Proof", verification: "Verification" } as const;

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <section className="mt-5">
      <h3 className="mb-1.5 text-xs font-semibold uppercase tracking-wide text-slate">{title}</h3>
      {children}
    </section>
  );
}

/** All finding text derives from the target: rendered as text children only, never as HTML. */
function FindingDetail({ runId, findingId, listVersion }: { runId: string; findingId: string; listVersion: number }) {
  const [params, setParams] = useSearchParams();
  const { finding: f, loading, error, retry } = useFindingDetail(runId, findingId, listVersion);

  if (loading && !f) return <p className="text-sm text-slate" role="status">Loading finding…</p>;
  if (!f) return <ErrorState card={false} title="Could not load this finding" error={error} what="this finding" onRetry={retry} />;

  return <DetailBody f={f} onGraph={(n) => setParams(graphLinkParams(params, n))} onDefenses={() => setParams(defensesLinkParams(params, f.id))} />;
}

export function DetailBody({ f, onGraph, onDefenses }: { f: Finding; onGraph: (nodeId: string) => void; onDefenses: () => void }) {
  const nodeId = f.provenance.node_id;
  const defenses = f.defense_ids?.length ?? f.defense_count ?? 0;
  return (
    <article>
      <div className="flex flex-wrap items-center gap-2">
        <SeverityChip severity={f.severity} />
        <StatusPill status={f.status} />
        <Badge>{f.confidence} confidence</Badge>
        {f.cwe && <Badge>{f.cwe}</Badge>}
      </div>
      <h2 className="mt-2 break-words font-display text-lg font-semibold">{f.title}</h2>
      <div className="mt-3 flex flex-wrap gap-2">
        {nodeId ? (
          <button type="button" className="btn-ghost py-1" onClick={() => onGraph(nodeId)}>Show in graph</button>
        ) : (
          <span className="text-xs text-slate">Not linked to a graph node.</span>
        )}
        <button type="button" className="btn-ghost py-1" onClick={onDefenses}>
          Defenses ({defenses})
        </button>
      </div>

      <Section title="Description">
        <p className="whitespace-pre-wrap break-words text-sm">{f.description || "No description."}</p>
      </Section>

      <Section title="Location">
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-sm">
          <dt className="text-slate">Request</dt>
          <dd className="mono break-all text-xs">{f.location.method} {f.location.url}</dd>
          {f.location.parameter && (<><dt className="text-slate">Parameter</dt><dd className="mono break-all text-xs">{f.location.parameter}</dd></>)}
          <dt className="text-slate">Check</dt>
          <dd className="mono text-xs">{f.check_id}</dd>
          {f.agent_name && (<><dt className="text-slate">Found by</dt><dd className="text-xs">{f.agent_name}</dd></>)}
        </dl>
      </Section>

      <Section title={`Evidence (${f.evidence.length})`}>
        {f.evidence.length === 0 ? (
          <p className="text-sm text-slate">No evidence was recorded.</p>
        ) : (
          <ul className="space-y-3">
            {f.evidence.map((e, i) => (
              <li key={i}>
                <div className="mb-1 flex flex-wrap items-center gap-2 text-xs text-slate">
                  <Badge>{ROLE_LABEL[e.role] ?? e.role}</Badge>
                  {e.exchange_id != null && (
                    <Link className="mono text-accent hover:underline" to={`?tab=traffic&exchange=${e.exchange_id}`}>exchange #{e.exchange_id}</Link>
                  )}
                  {e.note && <span>{e.note}</span>}
                </div>
                <pre className="mono max-h-60 overflow-auto whitespace-pre-wrap break-words rounded border border-line bg-canvas p-2.5 text-xs">{e.excerpt}</pre>
              </li>
            ))}
          </ul>
        )}
      </Section>

      {f.remediation && (f.remediation.summary || f.remediation.steps?.length) ? (
        <Section title="Remediation">
          {f.remediation.severity_rationale && <p className="text-sm text-slate">Why this severity: {f.remediation.severity_rationale}</p>}
          {f.remediation.summary && <p className="text-sm">{f.remediation.summary}</p>}
          {f.remediation.steps?.length ? (
            <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm">{f.remediation.steps.map((x, i) => <li key={i}>{x}</li>)}</ul>
          ) : null}
          {f.remediation.reproduction?.length ? (
            <>
              <p className="mt-2 text-xs font-semibold uppercase tracking-wide text-slate">Reproduce</p>
              <ul className="list-disc space-y-0.5 pl-5 text-sm">{f.remediation.reproduction.map((x, i) => <li key={i}>{x}</li>)}</ul>
            </>
          ) : null}
          {f.remediation.validation?.length ? (
            <>
              <p className="mt-2 text-xs font-semibold uppercase tracking-wide text-slate">How to verify the fix</p>
              <ul className="list-disc space-y-0.5 pl-5 text-sm">{f.remediation.validation.map((x, i) => <li key={i}>{x}</li>)}</ul>
            </>
          ) : null}
        </Section>
      ) : null}

      <Section title="Verification">
        {f.verification ? (
          <p className="text-sm">
            <span className="font-medium">{f.verification.result === "confirmed" ? "Confirmed" : "Not reproduced"}</span>
            {" by "}
            <span className="mono text-xs">{f.verification.method}</span>
            {` after ${f.verification.attempts} attempt${f.verification.attempts === 1 ? "" : "s"}, `}
            <RelativeTime iso={f.verification.verified_at} />.
          </p>
        ) : (
          <p className="text-sm text-slate">Not verified yet.</p>
        )}
      </Section>

      {f.detection_hints.length > 0 && (
        <Section title="Detection hints">
          <ul className="space-y-3">
            {f.detection_hints.map((h, i) => (
              <li key={i}>
                <div className="mb-1 text-sm font-medium">{h.title} <span className="mono text-xs font-normal text-slate">({h.type})</span></div>
                <CopyableRule text={h.content} label={h.title} />
              </li>
            ))}
          </ul>
        </Section>
      )}

      {f.references.length > 0 && (
        <Section title="References">
          <ul className="list-disc space-y-0.5 pl-5 text-sm">
            {f.references.map((r, i) => (
              <li key={i}>
                {/^https?:\/\//i.test(r.url) ? (
                  <a href={r.url} target="_blank" rel="noopener noreferrer nofollow" className="text-accent hover:underline break-all">{r.title || r.url}</a>
                ) : (
                  <span className="break-all">{r.title} <span className="mono text-xs text-slate">{r.url}</span></span>
                )}
              </li>
            ))}
          </ul>
        </Section>
      )}
    </article>
  );
}
