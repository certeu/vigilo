import type { CoverageOutcome, CoverageVerdict } from "../types";

/** Outcome wording mirrors the server (coverage.headline). */
export const OUTCOME_LABEL: Record<CoverageOutcome, string> = {
  completed: "Assessment completed",
  partial: "Assessment partially completed",
  blocked: "Assessment blocked",
  needs_authorisation: "Assessment needs additional authorisation",
  budget_exhausted: "Assessment stopped at its budget",
};

const OUTCOME_TONE: Record<CoverageOutcome, string> = {
  completed: "border-emerald-300 bg-emerald-50",
  partial: "border-amber-300 bg-amber-50",
  blocked: "border-severity-critical/40 bg-red-50",
  needs_authorisation: "border-amber-300 bg-amber-50",
  budget_exhausted: "border-amber-300 bg-amber-50",
};

/** The honest completion verdict: what was covered, what blocked it, what was not
 *  examined, and each loaded skill's definition of done. Text comes from the
 *  engine (and may quote target data): rendered as text only. */
export function CoverageVerdictPanel({ verdict, authStates }: { verdict: CoverageVerdict | null | undefined; authStates?: string[] }) {
  if (!verdict) return null;
  const skills = Object.entries(verdict.skills ?? {});
  return (
    <section aria-label="Coverage verdict" className={`rounded-md border p-4 ${OUTCOME_TONE[verdict.outcome] ?? "border-line"}`}>
      <h2 className="text-sm font-semibold text-ink">{OUTCOME_LABEL[verdict.outcome] ?? verdict.outcome}</h2>
      {verdict.reasons.length > 0 && (
        <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm">{verdict.reasons.map((r, i) => <li key={i}>{r}</li>)}</ul>
      )}
      {authStates && authStates.length > 0 && (
        <p className="mt-2 text-sm">Authentication boundary met: {authStates.join(", ")}</p>
      )}
      {verdict.limitations.length > 0 && (
        <details className="mt-2">
          <summary className="cursor-pointer text-sm font-medium">Not covered by this assessment ({verdict.limitations.length})</summary>
          <ul className="mt-1 list-disc space-y-0.5 pl-5 text-sm">{verdict.limitations.map((r, i) => <li key={i}>{r}</li>)}</ul>
        </details>
      )}
      {skills.length > 0 && (
        <table className="mt-3 w-full text-left text-xs">
          <caption className="mb-1 text-left text-xs font-semibold uppercase tracking-wide text-slate">Methodology (skills) — definition of done</caption>
          <thead className="text-slate">
            <tr><th scope="col">Skill</th><th scope="col">Met</th><th scope="col">Not met</th><th scope="col">Blocked</th><th scope="col">N/A</th></tr>
          </thead>
          <tbody>
            {skills.map(([name, c]) => (
              <tr key={name}>
                <td className="mono">{name}</td>
                <td>{c.satisfied}</td><td>{c.unsatisfied}</td><td>{c.blocked}</td><td>{c.not_applicable}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
