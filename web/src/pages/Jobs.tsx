import { useEffect, useState, type FormEvent } from "react";
import { useNavigate } from "react-router-dom";
import { TrashIcon } from "@heroicons/react/24/outline";
import { api, type Credential, type Job, type Repository } from "../api/client";
import { ConfirmDialog } from "../components/ConfirmDialog";

const PRESETS = [
  { value: "vuln", label: "Findings" },
  { value: "vuln_patch", label: "Findings + patches" },
  { value: "full", label: "Full (adds supply-chain and integrity analysis)" },
];

// Optional per-job tuning, sent as pipeline_overrides (empty = server default).
// Bounds mirror PipelineConfig.BOUNDS (src/types/config.py); the API rejects values outside them.
const TUNING = [
  { key: "max_concurrent_pipelines", label: "Max parallel agents", min: 1, max: 32 },
  { key: "leads_per_investigator", label: "Leads per investigator", min: 1, max: 25 },
  { key: "findings_per_prover", label: "Findings per prover", min: 1, max: 25 },
  { key: "investigation_followup_rounds", label: "Follow-up investigation rounds", min: 0, max: 5 },
] as const;

export function Jobs() {
  const navigate = useNavigate();
  const [jobs, setJobs] = useState<Job[]>([]);
  const [repos, setRepos] = useState<Repository[]>([]);
  const [repositoryId, setRepositoryId] = useState("");
  const [name, setName] = useState("");
  const [preset, setPreset] = useState("vuln");
  const [targetUrl, setTargetUrl] = useState("");
  const [cookies, setCookies] = useState<Credential[]>([]);
  const [credentialId, setCredentialId] = useState("");
  const [notifyEmail, setNotifyEmail] = useState(false);
  const [tuning, setTuning] = useState<Record<string, string>>({});
  const [retryPreset, setRetryPreset] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [starting, setStarting] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<Job | null>(null);

  async function load() {
    try {
      const [j, r, c] = await Promise.all([
        api.jobs(),
        api.repositories(),
        api.credentials().catch(() => [] as Credential[]),
      ]);
      setJobs(j);
      setRepos(r);
      setCookies(c.filter((x) => x.kind === "cookie_header"));
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
    const overrides: Record<string, number | string> = {};
    for (const t of TUNING) {
      const v = tuning[t.key];
      if (v !== undefined && v !== "") overrides[t.key] = Number(v);
    }
    if (retryPreset) overrides.retry_preset = retryPreset;
    try {
      await api.createJob({
        repository_id: repositoryId,
        name,
        stage_preset: preset,
        target_url: targetUrl || null,
        target_credential_id: targetUrl && credentialId ? credentialId : null,
        notify_email: notifyEmail,
        pipeline_overrides: overrides,
      });
      setName("");
      setCredentialId("");
      setTuning({});
      setRetryPreset("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  async function run(jobId: string) {
    setError(null);
    setStarting(jobId);
    try {
      const r = await api.runJob(jobId);
      navigate(`/runs/${r.id}`);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to start the run");
    } finally {
      setStarting(null);
    }
  }

  async function setJobCredential(job: Job, value: string) {
    setError(null);
    try {
      await api.patchJob(job.id, { target_credential_id: value || null });
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to update the job");
    }
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
            Supplements the repository analysis — the live app is used for reachability + agent
            context. This is <b>not</b> a standalone black-box (URL-only) analysis; a repository
            is always required.
          </p>
        </div>
        <div className="col-span-2">
          <label htmlFor="job-cookie" className="mb-1 block text-sm text-slate">
            Logged-in testing (optional)
          </label>
          <select
            id="job-cookie"
            className="field"
            value={targetUrl ? credentialId : ""}
            onChange={(e) => setCredentialId(e.target.value)}
            disabled={!targetUrl}
          >
            <option value="">None: test the live app unauthenticated</option>
            {cookies.map((c) => (
              <option key={c.id} value={c.id}>{c.label}</option>
            ))}
          </select>
          <p className="mt-1 text-xs text-slate">
            {targetUrl
              ? cookies.length === 0
                ? "You have no cookie_header credentials yet. Create one with POST /credentials (kind cookie_header)."
                : "The agents that test the live app (not the planner) receive this session cookie in their prompt, " +
                  "so SSO and 2FA logins work. It is stored encrypted, never written to disk or to the run logs, and " +
                  "is masked in saved prompts and logs. Use a low-privilege test session."
              : "Needs a live target URL: a cookie only applies to a running app."}
          </p>
        </div>
        <label className="col-span-2 flex items-center gap-2 text-sm text-slate">
          <input type="checkbox" checked={notifyEmail} onChange={(e) => setNotifyEmail(e.target.checked)} />
          Email me the report when this job finishes
        </label>
        <details className="col-span-2">
          <summary className="cursor-pointer text-sm text-slate">Advanced</summary>
          <div className="mt-3 grid grid-cols-2 gap-4">
            {TUNING.map((t) => (
              <div key={t.key}>
                <label htmlFor={`job-${t.key}`} className="mb-1 block text-sm text-slate">{t.label}</label>
                <input
                  id={`job-${t.key}`}
                  className="field"
                  type="number"
                  min={t.min}
                  max={t.max}
                  placeholder="Default"
                  value={tuning[t.key] ?? ""}
                  onChange={(e) => setTuning({ ...tuning, [t.key]: e.target.value })}
                />
              </div>
            ))}
            <div>
              <label htmlFor="job-retry" className="mb-1 block text-sm text-slate">Retry policy</label>
              <select id="job-retry" className="field" value={retryPreset} onChange={(e) => setRetryPreset(e.target.value)}>
                <option value="">Default</option>
                <option value="production">Production</option>
                <option value="subscription">Subscription (long back-off)</option>
              </select>
            </div>
          </div>
        </details>
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
                {j.target_credential_id ? " · logged-in testing" : ""}
              </div>
            </div>
            <div className="flex items-center gap-2">
              {j.target_url && (
                <select
                  aria-label={`Cookie credential for ${j.name}`}
                  className="field w-48 py-1 text-xs"
                  value={j.target_credential_id ?? ""}
                  onChange={(e) => void setJobCredential(j, e.target.value)}
                >
                  <option value="">Unauthenticated</option>
                  {cookies.map((c) => (
                    <option key={c.id} value={c.id}>{c.label}</option>
                  ))}
                </select>
              )}
              <button className="btn-ghost" onClick={() => void run(j.id)}
                      disabled={starting !== null}>
                {starting === j.id ? "Starting…" : "Run"}
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
