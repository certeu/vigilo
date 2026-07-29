import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { TrashIcon } from "@heroicons/react/24/outline";
import { api, type Job, type Repository, type Run } from "../api/client";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { StatusDot } from "../components/StatusDot";

export function RunsList() {
  const [runs, setRuns] = useState<Run[]>([]);
  const [jobs, setJobs] = useState<Record<string, Job>>({});
  const [repos, setRepos] = useState<Record<string, Repository>>({});
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Run | null>(null);

  async function load() {
    try {
      const [r, j, rp] = await Promise.all([api.runs(), api.jobs(), api.repositories()]);
      setRuns(r);
      setJobs(Object.fromEntries(j.map((x) => [x.id, x])));
      setRepos(Object.fromEntries(rp.map((x) => [x.id, x])));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load");
    }
  }

  useEffect(() => {
    void load();
    const t = setInterval(load, 3000); // live control board
    return () => clearInterval(t);
  }, []);

  async function remove(run: Run) {
    await api.deleteRun(run.id);  // cancels first if still active, frees disk
    setConfirm(null);
    await load();
  }

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Runs</h1>
        <Link to="/jobs" className="btn-primary">
          New job
        </Link>
      </div>
      {error && <p className="mb-4 text-sm text-severity-critical">{error}</p>}
      <div className="card overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-line text-left text-slate">
              <th className="px-4 py-3 font-medium">Status</th>
              <th className="px-4 py-3 font-medium">Repository</th>
              <th className="px-4 py-3 font-medium">Preset</th>
              <th className="px-4 py-3 font-medium">Phase</th>
              <th className="px-4 py-3 font-medium">Cost</th>
              <th className="px-4 py-3 font-medium">Started</th>
              <th className="px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => {
              const job = jobs[run.job_id];
              const repo = job ? repos[job.repository_id] : undefined;
              return (
                <tr key={run.id} className="border-b border-line/60 hover:bg-canvas">
                  <td className="px-4 py-3">
                    <Link to={`/runs/${run.id}`} className="flex items-center gap-2">
                      <StatusDot status={run.status} />
                      <span className="text-slate">{run.status}</span>
                    </Link>
                  </td>
                  <td className="px-4 py-3">
                    <Link to={`/runs/${run.id}`} className="font-medium hover:text-accent">
                      {repo?.name ?? "—"}
                    </Link>
                  </td>
                  <td className="px-4 py-3 mono text-slate">{job?.stage_preset ?? "—"}</td>
                  <td className="px-4 py-3 mono text-slate">{run.current_phase ?? "—"}</td>
                  <td className="px-4 py-3 mono text-slate">
                    {run.total_cost_usd != null ? `$${run.total_cost_usd.toFixed(2)}` : "—"}
                  </td>
                  <td className="px-4 py-3 text-slate">
                    {run.started_at ? new Date(run.started_at).toLocaleString() : "—"}
                  </td>
                  <td className="px-4 py-3 text-right">
                    <button
                      className="text-slate hover:text-severity-critical"
                      title="Delete run"
                      onClick={() => setConfirm(run)}
                    >
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              );
            })}
            {runs.length === 0 && (
              <tr>
                <td colSpan={7} className="px-4 py-10 text-center text-slate">
                  No runs yet. Create a job and run it.
                </td>
              </tr>
            )}
          </tbody>
        </table>
      </div>

      {confirm && (
        <ConfirmDialog
          title="Delete run"
          body={
            <>
              Delete this run and its report, logs, and metrics
              {["running", "preparing", "queued"].includes(confirm.status)
                ? " (it will be cancelled first)"
                : ""}
              ? This cannot be undone.
            </>
          }
          onConfirm={() => remove(confirm)}
          onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  );
}
