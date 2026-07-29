import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { TrashIcon } from "@heroicons/react/24/outline";
import { api, type Job, type Repository } from "../api/client";
import { ConfirmDialog } from "../components/ConfirmDialog";

const PRESETS = [
  { value: "vuln", label: "Vulnerability scan (vuln + exploit)" },
  { value: "vuln_patch", label: "Vulnerability + patch" },
  { value: "full", label: "Full pipeline" },
];

export function Jobs() {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [repos, setRepos] = useState<Repository[]>([]);
  const [repositoryId, setRepositoryId] = useState("");
  const [name, setName] = useState("");
  const [preset, setPreset] = useState("vuln");
  const [targetUrl, setTargetUrl] = useState("");
  const [notifyEmail, setNotifyEmail] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Job | null>(null);

  async function load() {
    try {
      const [j, r] = await Promise.all([api.jobs(), api.repositories()]);
      setJobs(j);
      setRepos(r);
      if (!repositoryId && r[0]) setRepositoryId(r[0].id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load jobs");
    }
  }
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.createJob({
        repository_id: repositoryId,
        name,
        stage_preset: preset,
        target_url: targetUrl || null,
        notify_email: notifyEmail,
      });
      setName("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  async function run(jobId: string) {
    const r = await api.runJob(jobId);
    navigate(`/runs/${r.id}`);
  }

  async function remove(job: Job) {
    await api.deleteJob(job.id);
    setConfirm(null);
    await load();
  }

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold">Jobs</h1>
      <form onSubmit={create} className="card mb-8 grid max-w-3xl grid-cols-2 gap-4 p-6">
        <div>
          <label htmlFor="job-repo" className="mb-1 block text-sm text-slate">Repository</label>
          <select id="job-repo" className="field" value={repositoryId} onChange={(e) => setRepositoryId(e.target.value)} required>
            {repos.map((r) => (
              <option key={r.id} value={r.id}>{r.name}</option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="job-name" className="mb-1 block text-sm text-slate">Name</label>
          <input id="job-name" className="field" value={name} onChange={(e) => setName(e.target.value)} required />
        </div>
        <div>
          <label htmlFor="job-preset" className="mb-1 block text-sm text-slate">Stages</label>
          <select id="job-preset" className="field" value={preset} onChange={(e) => setPreset(e.target.value)}>
            {PRESETS.map((p) => (
              <option key={p.value} value={p.value}>{p.label}</option>
            ))}
          </select>
        </div>
        <div>
          <label htmlFor="job-target" className="mb-1 block text-sm text-slate">
            Live target URL (optional)
          </label>
          <input
            id="job-target"
            className="field"
            value={targetUrl}
            onChange={(e) => setTargetUrl(e.target.value)}
            placeholder="Leave empty for source-only (code) analysis"
          />
          <p className="mt-1 text-xs text-slate">
            Supplements the repository scan — the live app is used for reachability + agent
            context. This is <b>not</b> a standalone black-box (URL-only) scan; a repository
            is always required.
          </p>
        </div>
        <label className="col-span-2 flex items-center gap-2 text-sm text-slate">
          <input type="checkbox" checked={notifyEmail} onChange={(e) => setNotifyEmail(e.target.checked)} />
          Email me the report when this job finishes
        </label>
        {error && <p className="col-span-2 text-sm text-severity-critical">{error}</p>}
        <div className="col-span-2">
          <button className="btn-primary" disabled={!repositoryId}>Create job</button>
        </div>
      </form>

      <div className="card divide-y divide-line">
        {jobs.map((j) => (
          <div key={j.id} className="flex items-center justify-between px-4 py-3">
            <div>
              <div className="font-medium">{j.name}</div>
              <div className="mono text-xs text-slate">
                {j.stage_preset}
                {j.target_url ? ` · ${j.target_url}` : " · source-only"}
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button className="btn-ghost" onClick={() => run(j.id)}>
                Run
              </button>
              <button
                className="text-slate hover:text-severity-critical"
                title="Delete job"
                onClick={() => setConfirm(j)}
              >
                <TrashIcon className="h-4 w-4" />
              </button>
            </div>
          </div>
        ))}
        {jobs.length === 0 && <div className="px-4 py-8 text-center text-slate">No jobs yet.</div>}
      </div>

      {confirm && (
        <ConfirmDialog
          title="Delete job"
          body={
            <>
              Delete job <b>{confirm.name}</b> and all of its runs, reports, and logs?
              This cannot be undone.
            </>
          }
          onConfirm={() => remove(confirm)}
          onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  );
}
