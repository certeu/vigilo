import { useEffect, useState } from "react";
import { Link, useNavigate, useParams } from "react-router-dom";
import { Cog6ToothIcon, LockClosedIcon, TrashIcon } from "@heroicons/react/24/outline";
import { api, type RepoTree, type Repository, type Run, type RunMetrics } from "../api/client";
import { SeverityDonut, TimelineChart, type TimelinePoint } from "../components/Charts";
import { FileTree } from "../components/FileTree";
import { RepoSettingsDrawer } from "../components/RepoSettingsDrawer";
import { StatusDot } from "../components/StatusDot";
import { SEVERITY_COLORS } from "../lib/severity";

// Build a commit web URL. GitLab uses /-/commit/<sha>; gitea/forgejo/codeberg use
// /commit/<sha>. Best-effort — returns null if we can't parse the host.
function commitUrl(gitlabUrl: string | null, sha: string | null): string | null {
  if (!gitlabUrl || !sha) return null;
  const base = gitlabUrl.replace(/\.git$/, "").replace(/\/$/, "");
  try {
    const seg = new URL(base).host.includes("gitlab") ? "/-/commit/" : "/commit/";
    return base + seg + sha;
  } catch {
    return null;
  }
}

export function RepoDetail() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [repo, setRepo] = useState<Repository | null>(null);
  const [timeline, setTimeline] = useState<RunMetrics[]>([]);
  const [runs, setRuns] = useState<Run[]>([]);
  const [tree, setTree] = useState<RepoTree | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    if (!id) return;
    try {
      setError(null);
      setRepo(await api.repository(id));
      setTimeline((await api.repoTimeline(id)).timeline);
      setRuns(await api.runs(id));
      api.repoTree(id).then(setTree).catch(() => setTree(null));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load repository");
    }
  }
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  // Poll while source ingestion/validation is in flight so the status updates live.
  useEffect(() => {
    if (repo?.ingestion_status !== "importing") return;
    const t = setInterval(() => void load(), 3000);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [repo?.ingestion_status]);

  async function deleteRun(runId: string) {
    if (!window.confirm("Delete this run and its report, logs, and metrics? This cannot be undone.")) return;
    try {
      await api.deleteRun(runId);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to delete run");
    }
  }

  if (error && !repo) return <p className="text-sm text-severity-critical">Could not load repository: {error}</p>;
  if (!repo) return <p className="text-slate">Loading…</p>;

  // Chart excludes unparseable runs (their zeros aren't real data points).
  const points: TimelinePoint[] = timeline
    .filter((m) => !m.parse_error)
    .map((m) => ({
      label: new Date(m.computed_at).toLocaleDateString(),
      total: m.total_findings,
      critical: m.severity_counts.critical,
      high: m.severity_counts.high,
    }));
  const latest = timeline[timeline.length - 1];
  const latestParseFailed = !!latest?.parse_error;
  const scaScanned = latest?.supply_chain_scanned;
  const pkgs = latest?.supply_chain_packages ?? [];

  return (
    <div>
      <div className="mb-1 flex items-center gap-2">
        <h1 className="text-xl font-semibold">{repo.name}</h1>
        {repo.is_private && <LockClosedIcon className="h-4 w-4 text-slate" title="Private" />}
        <button
          className="ml-auto inline-flex items-center gap-1 rounded-md border border-line px-2.5 py-1.5 text-sm text-slate hover:text-ink"
          onClick={() => setSettingsOpen(true)}
        >
          <Cog6ToothIcon className="h-4 w-4" /> Settings
        </button>
      </div>
      <p className="mb-2 mono text-sm text-slate">
        {repo.source_type}{repo.gitlab_url ? ` · ${repo.gitlab_url}` : ""}
      </p>
      {repo.ingestion_status && repo.ingestion_status !== "idle" && (
        <p className="mb-6 text-sm">
          <span className="text-slate">Source status: </span>
          <span
            className={
              repo.ingestion_status === "ready"
                ? "text-emerald-700"
                : repo.ingestion_status === "failed"
                  ? "text-severity-critical"
                  : "text-accent"
            }
          >
            {repo.ingestion_status === "importing"
              ? (repo.source_type === "gitlab" ? "verifying access…" : "importing…")
              : repo.ingestion_status === "ready"
                ? (repo.source_type === "gitlab" ? "access verified" : "ready")
                : `failed — ${repo.ingestion_error ?? "unknown error"}`}
          </span>
        </p>
      )}

      <section className="card mb-6 p-5">
        <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">Findings over time</h2>
        <p className="mb-3 text-sm text-slate">
          Each point is a completed scan — re-run after fixes to watch findings fall.
        </p>
        <TimelineChart data={points} />
        {points.length === 1 && (
          <p className="mt-2 text-xs text-slate">Run more scans to see a trend line.</p>
        )}
      </section>

      <div className="mb-6 grid grid-cols-1 gap-6 lg:grid-cols-2">
        <section className="card p-5">
          <h2 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">Latest scan — severity</h2>
          {!latest ? (
            <div className="flex h-40 items-center justify-center text-sm text-slate">No scans yet.</div>
          ) : latestParseFailed ? (
            <div className="flex h-40 items-center justify-center px-4 text-center text-sm text-severity-critical">
              Couldn't parse findings for the latest run. The scan completed but its
              findings output was missing or unreadable — numbers are not shown rather
              than displaying zeros.
            </div>
          ) : (
            <SeverityDonut counts={latest.severity_counts as unknown as Record<string, number>} />
          )}
        </section>

        <section className="card overflow-x-auto">
          <h2 className="border-b border-line px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate">
            Vulnerable dependencies (latest)
          </h2>
          <div className="max-h-[240px] overflow-auto">
            <table className="w-full text-sm">
              <tbody>
                {pkgs.map((p, i) => (
                  <tr key={i} className="border-b border-line/60">
                    <td className="px-4 py-2 mono">{p.package}<span className="text-slate">@{p.version}</span></td>
                    <td className="px-3 py-2">
                      <span className="mono text-xs" style={{ color: SEVERITY_COLORS[p.severity] ?? "#606A7B" }}>
                        {p.severity}
                      </span>
                    </td>
                    <td className="px-3 py-2 mono text-xs text-slate">{p.cve ?? ""}</td>
                    <td className="px-4 py-2 text-xs text-slate">{p.fixed_version ? `→ ${p.fixed_version}` : ""}</td>
                  </tr>
                ))}
                {pkgs.length === 0 && (
                  <tr><td className="px-4 py-6 text-center text-slate" colSpan={4}>
                    {latest && scaScanned === false
                      ? "Supply-chain analysis wasn't part of this scan (run the full preset to include it)."
                      : latest
                        ? "No vulnerable dependencies found."
                        : "No scans yet."}
                  </td></tr>
                )}
              </tbody>
            </table>
          </div>
        </section>
      </div>

      <section className="card overflow-x-auto">
        <h2 className="border-b border-line px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate">
          Executions ({runs.length})
        </h2>
        <table className="w-full text-sm">
          <tbody>
            {runs.map((r) => (
              <tr key={r.id} className="border-b border-line/60 hover:bg-canvas">
                <td className="px-4 py-2">
                  <Link to={`/runs/${r.id}`} className="flex items-center gap-2">
                    <StatusDot status={r.status} />
                    <span className="text-slate">{r.status}</span>
                  </Link>
                </td>
                <td className="px-3 py-2 mono text-slate">{r.trigger_type}</td>
                <td className="px-3 py-2 mono text-xs">
                  {r.commit_sha ? (
                    commitUrl(repo.gitlab_url, r.commit_sha) ? (
                      <a
                        href={commitUrl(repo.gitlab_url, r.commit_sha)!}
                        target="_blank"
                        rel="noreferrer"
                        className="text-accent hover:underline"
                        title={r.commit_sha}
                      >
                        {r.commit_sha.slice(0, 8)}
                      </a>
                    ) : (
                      <span className="text-slate" title={r.commit_sha}>{r.commit_sha.slice(0, 8)}</span>
                    )
                  ) : (
                    <span className="text-slate">—</span>
                  )}
                </td>
                <td className="px-3 py-2 mono text-slate">{r.current_phase ?? "—"}</td>
                <td className="px-3 py-2 mono text-slate">
                  {r.total_cost_usd != null ? `$${r.total_cost_usd.toFixed(2)}` : "—"}
                </td>
                <td className="px-4 py-2 text-slate">
                  {new Date(r.created_at).toLocaleString()}
                </td>
                <td className="px-3 py-2 text-right">
                  <button
                    className="text-slate hover:text-severity-critical"
                    title="Delete run"
                    onClick={() => deleteRun(r.id)}
                  >
                    <TrashIcon className="h-4 w-4" />
                  </button>
                </td>
              </tr>
            ))}
            {runs.length === 0 && (
              <tr><td className="px-4 py-6 text-center text-slate" colSpan={7}>No executions yet.</td></tr>
            )}
          </tbody>
        </table>
      </section>

      <section className="card mt-6">
        <h2 className="border-b border-line px-4 py-3 text-xs font-semibold uppercase tracking-wide text-slate">
          Files{tree?.available ? ` (${tree.count}${tree.truncated ? "+" : ""})` : ""}
        </h2>
        <div className="p-3">
          {tree?.available ? (
            <FileTree paths={tree.paths} />
          ) : (
            <div className="py-6 text-center text-sm text-slate">
              {repo.source_type === "gitlab"
                ? "File structure becomes available after the first scan clones the repository."
                : "No files captured yet."}
            </div>
          )}
          {tree?.truncated && (
            <p className="mt-2 px-1 text-xs text-slate">Large repository — showing the first {tree.count} files.</p>
          )}
        </div>
      </section>

      {settingsOpen && (
        <RepoSettingsDrawer
          repo={repo}
          onClose={() => setSettingsOpen(false)}
          onSaved={load}
          onDeleted={() => navigate("/repos")}
        />
      )}
    </div>
  );
}
