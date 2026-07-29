import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api, type GlobalMetrics } from "../api/client";
import { CategoryBar, Kpi, SeverityDonut } from "../components/Charts";
import { SEVERITY_COLORS } from "../lib/severity";

function severityTone(sev: string): string {
  return SEVERITY_COLORS[sev] ?? "#606A7B";
}

export function Dashboard() {
  const [m, setM] = useState<GlobalMetrics | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    api.dashboardMetrics().then(setM).catch((e) => setError(String(e.message ?? e)));
  }, []);

  if (error) return <p className="text-sm text-severity-critical">{error}</p>;
  if (!m) return <p className="text-slate">Loading…</p>;

  const empty = m.repositories_scanned === 0;

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold">Security overview</h1>

      {empty ? (
        <div className="card p-10 text-center text-slate">
          No completed scans yet. Run a job to populate the dashboard.
        </div>
      ) : (
        <>
          <div className="mb-6 grid grid-cols-2 gap-4 md:grid-cols-4">
            <Kpi label="Repositories scanned" value={m.repositories_scanned} />
            <Kpi label="Total findings" value={m.total_findings} />
            <Kpi label="Exploited" value={m.exploited} tone={SEVERITY_COLORS.critical} />
            <Kpi label="Supply chain" value={m.supply_chain} />
          </div>

          <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
            <section className="card p-5">
              <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">
                Findings by severity
              </h2>
              <SeverityDonut counts={m.severity_totals as unknown as Record<string, number>} />
            </section>
            <section className="card p-5">
              <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">
                Findings by category
              </h2>
              <CategoryBar
                counts={Object.fromEntries(
                  Object.entries(m.category_totals).filter(([k]) => k !== "supply_chain"),
                )}
              />
            </section>
          </div>

          <section className="card overflow-x-auto">
            <h2 className="border-b border-line px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate">
              Repositories with the most findings
            </h2>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-slate">
                  <th className="px-4 py-2 font-medium">Repository</th>
                  <th className="px-4 py-2 font-medium">Total</th>
                  <th className="px-4 py-2 font-medium">Critical</th>
                  <th className="px-4 py-2 font-medium">High</th>
                  <th className="px-4 py-2 font-medium">Exploited</th>
                  <th className="px-4 py-2 font-medium">Supply chain</th>
                </tr>
              </thead>
              <tbody>
                {m.top_repositories.map((r) => (
                  <tr key={r.repository_id} className="border-b border-line/60 hover:bg-canvas">
                    <td className="px-4 py-2">
                      <Link to={`/repos/${r.repository_id}`} className="font-medium hover:text-accent">
                        {r.repository_name}
                      </Link>
                    </td>
                    <td className="px-4 py-2 mono">{r.total_findings}</td>
                    <td className="px-4 py-2 mono" style={{ color: SEVERITY_COLORS.critical }}>{r.critical}</td>
                    <td className="px-4 py-2 mono" style={{ color: SEVERITY_COLORS.high }}>{r.high}</td>
                    <td className="px-4 py-2 mono">{r.exploited}</td>
                    <td className="px-4 py-2 mono">{r.supply_chain}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>

          <section className="card mt-6 overflow-hidden">
            <h2 className="border-b border-line px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate">
              Vulnerable dependencies across repositories
            </h2>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-slate">
                  <th className="px-4 py-2 font-medium">Package</th>
                  <th className="px-3 py-2 font-medium">Version</th>
                  <th className="px-3 py-2 font-medium">Ecosystem</th>
                  <th className="px-3 py-2 font-medium">Severity</th>
                  <th className="px-3 py-2 font-medium">CVE</th>
                  <th className="px-3 py-2 font-medium">Fix</th>
                  <th className="px-4 py-2 font-medium">Repos</th>
                </tr>
              </thead>
              <tbody>
                {m.top_packages.map((p, i) => (
                  <tr key={i} className="border-b border-line/60">
                    <td className="px-4 py-2 mono">{p.package}</td>
                    <td className="px-3 py-2 mono text-slate">{p.version}</td>
                    <td className="px-3 py-2 text-slate">{p.ecosystem}</td>
                    <td className="px-3 py-2 mono text-xs" style={{ color: severityTone(p.severity) }}>
                      {p.severity}
                    </td>
                    <td className="px-3 py-2 mono text-xs text-slate">{p.cve ?? ""}</td>
                    <td className="px-3 py-2 mono text-xs text-slate">{p.fixed_version ?? ""}</td>
                    <td className="px-4 py-2 mono">{p.repos ?? 1}</td>
                  </tr>
                ))}
                {m.top_packages.length === 0 && (
                  <tr><td className="px-4 py-6 text-center text-slate" colSpan={7}>No supply-chain findings.</td></tr>
                )}
              </tbody>
            </table>
          </section>
        </>
      )}
    </div>
  );
}
