import { useEffect, useState } from "react";
import { ChevronDownIcon, ChevronRightIcon, MagnifyingGlassIcon } from "@heroicons/react/24/outline";
import { Link } from "react-router-dom";
import { Breadcrumb, EmptyState, ErrorState, SeverityChip, SkeletonRows } from "../components/ui";
import { greyboxApi } from "../features/greybox/api";
import type { Finding, RunSummary } from "../features/greybox/types";
import { canonicalIssues, type CanonicalIssue, type CanonicalLocation, verificationLabel } from "./findingsModel";

function issueClass(issue: CanonicalIssue) {
  return issue.findingClass.charAt(0).toUpperCase() + issue.findingClass.slice(1);
}

function locationsWithDetail(issue: CanonicalIssue, details: readonly Finding[]): CanonicalLocation[] {
  if (!details.length) return issue.affectedLocations;
  return canonicalIssues(details, issue.runId, issue.runName)[0]?.affectedLocations ?? issue.affectedLocations;
}

function IssueRow({ issue }: { issue: CanonicalIssue }) {
  const [open, setOpen] = useState(false);
  const [details, setDetails] = useState<Finding[]>([]);
  const [error, setError] = useState<unknown>(null);
  useEffect(() => {
    if (!open || details.length || error) return;
    Promise.all(issue.findingIds.map((id) => greyboxApi.finding(issue.runId, id))).then(setDetails).catch(setError);
  }, [open, details.length, error, issue.findingIds, issue.runId]);
  const locations = locationsWithDetail(issue, details);
  return <>
    <tr className="cursor-pointer border-t border-line hover:bg-slate-50" onClick={() => setOpen((value) => !value)} aria-expanded={open}>
      <td className="px-4 py-3"><button aria-label={`Expand ${issue.title}`}>{open ? <ChevronDownIcon className="h-4 w-4" /> : <ChevronRightIcon className="h-4 w-4" />}</button></td>
      <td className="px-4 py-3"><SeverityChip severity={issue.severity} /></td>
      <td className="px-4 py-3 font-medium">{issue.title}<div className="text-xs text-slate">{issue.runName}</div></td>
      <td className="px-4 py-3">{issueClass(issue)}</td>
      <td className="px-4 py-3">{verificationLabel(issue.verificationStatus, issue.findingClass)}</td>
      <td className="px-4 py-3 text-center">{issue.affectedLocationCount}</td>
      <td className="px-4 py-3 text-center">{issue.observationCount}</td>
    </tr>
    {open && <tr className="border-t border-line"><td colSpan={7} className="bg-surface-subtle px-8 py-5">
      {error != null && <ErrorState title="Could not load evidence" error={error} what="evidence" onRetry={() => setError(null)} />}
      {!error && !details.length && <div className="text-sm text-slate">Loading evidence…</div>}
      <div className="grid gap-4 lg:grid-cols-2">
        {locations.map((location, index) => <section className="card p-4" key={`${location.location}-${index}`}>
          <h3 className="font-medium">{location.location}</h3>
          <p className="mt-1 text-xs text-slate">Observation: {verificationLabel(location.observationStatus || "candidate", issue.findingClass)} · Impact: {verificationLabel(location.impactStatus || "unverified", "vulnerability")} · {location.observationCount} observation{location.observationCount === 1 ? "" : "s"}</p>
          {(location.method || location.parameter) && <p className="mt-2 text-sm"><span className="font-medium">Interface:</span> {[location.method, location.parameter && `parameter ${location.parameter}`].filter(Boolean).join(" · ")}</p>}
          {!!location.identities.length && <p className="mt-2 text-sm"><span className="font-medium">Identities:</span> {location.identities.join(", ")}</p>}
          {location.verification != null && <pre className="mt-3 overflow-auto whitespace-pre-wrap rounded bg-slate-950 p-3 text-xs text-white">{JSON.stringify(location.verification, null, 2)}</pre>}
          {location.observations.map((observation) => <div className="mt-3 rounded border border-line p-3 text-xs" key={observation.observation_id ?? JSON.stringify(observation)}><span className="font-medium">Observation {observation.observation_id ?? "history"}</span><span className="text-slate"> · {verificationLabel(observation.verification_status ?? "candidate", issue.findingClass)} · {verificationLabel(observation.impact_status ?? "unverified", "vulnerability")}</span>{observation.identity && <div className="mt-1">Identity: {observation.identity}</div>}{(observation.evidence ?? []).map((evidence: unknown, evidenceIndex: number) => <pre className="mt-2 overflow-auto whitespace-pre-wrap rounded bg-slate-950 p-2 text-white" key={evidenceIndex}>{typeof evidence === "string" ? evidence : JSON.stringify(evidence, null, 2)}</pre>)}</div>)}
          {!location.observations.length && location.evidence.map((evidence, evidenceIndex) => <pre className="mt-3 overflow-auto whitespace-pre-wrap rounded bg-slate-950 p-3 text-xs text-white" key={evidenceIndex}>{typeof evidence === "string" ? evidence : JSON.stringify(evidence, null, 2)}</pre>)}
        </section>)}
      </div>
      {issue.rootCause && <p className="mt-4 text-sm"><span className="font-medium">Root cause:</span> {issue.rootCause}</p>}
      {issue.correlationRationale && <p className="mt-2 text-sm"><span className="font-medium">Correlation rationale:</span> {issue.correlationRationale}</p>}
      {issue.remediation && <p className="mt-2 text-sm"><span className="font-medium">Remediation:</span> {issue.remediation}</p>}
      {issue.retest && <p className="mt-2 text-sm"><span className="font-medium">Retest:</span> {issue.retest}</p>}
      <Link className="mt-4 inline-block text-sm text-accent hover:underline" to={`/greybox/runs/${issue.runId}?tab=findings&open=${issue.findingIds[0]}`}>Open assessment</Link>
    </td></tr>}
  </>;
}

export function Findings() {
  const [issues, setIssues] = useState<CanonicalIssue[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const load = () => {
    setLoading(true); setError(null);
    greyboxApi.runs({ limit: 100 }).then(async ({ items }) => {
      const findings = await Promise.all(items.map(async (run: RunSummary) => canonicalIssues((await greyboxApi.findings(run.id)).items, run.id, run.target.name)));
      setIssues(findings.flat().filter((issue) => issue.verificationStatus !== "rejected"));
    }).catch(setError).finally(() => setLoading(false));
  };
  useEffect(load, []);
  return <div>
    <Breadcrumb items={[{ label: "Findings" }]} />
    <h1 className="mb-6 text-xl font-semibold">Findings</h1>
    {error ? <ErrorState title="Could not load findings" error={error} what="findings" onRetry={load} /> : loading ? <div className="card"><SkeletonRows rows={6} /></div> : !issues.length ? <div className="card"><EmptyState icon={MagnifyingGlassIcon} title="No actionable findings">Completed assessments with actionable issues appear here.</EmptyState></div> :
      <div className="card overflow-x-auto"><table className="w-full text-left text-sm"><thead><tr><th /><th className="px-4 py-3">Severity</th><th className="px-4 py-3">Finding</th><th className="px-4 py-3">Class</th><th className="px-4 py-3">Verification</th><th className="px-4 py-3 text-center">Locations</th><th className="px-4 py-3 text-center">Observations</th></tr></thead><tbody>{issues.map((issue) => <IssueRow issue={issue} key={`${issue.runId}:${issue.id}`} />)}</tbody></table></div>}
  </div>;
}
