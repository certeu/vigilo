import { useEffect, useState, type FormEvent } from "react";
import { api, type Job, type Schedule } from "../api/client";

export function Schedules() {
  const [schedules, setSchedules] = useState<Schedule[]>([]);
  const [jobs, setJobs] = useState<Record<string, Job>>({});
  const [jobId, setJobId] = useState("");
  const [kind, setKind] = useState("once");
  const [runAt, setRunAt] = useState("");
  const [cron, setCron] = useState("0 3 * * *");
  const [notifyEmail, setNotifyEmail] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Keep the checkbox in sync with the selected job's stored setting.
  useEffect(() => {
    setNotifyEmail(!!jobs[jobId]?.notify_email);
  }, [jobId, jobs]);

  async function toggleNotify(v: boolean) {
    setNotifyEmail(v); // optimistic; PATCH persists to the SAME job.notify_email field
    try {
      await api.patchJob(jobId, { notify_email: v });
      await load();
    } catch (err) {
      setNotifyEmail(!v); // revert on failure
      setError(err instanceof Error ? err.message : "Failed to update job");
    }
  }

  async function load() {
    try {
      const [s, j] = await Promise.all([api.schedules(), api.jobs()]);
      setSchedules(s);
      setJobs(Object.fromEntries(j.map((x) => [x.id, x])));
      if (!jobId && j[0]) setJobId(j[0].id);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load schedules");
    }
  }
  useEffect(() => {
    void load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    const body: Record<string, unknown> = { job_id: jobId, kind };
    if (kind === "once") body.run_at = new Date(runAt).toISOString();
    if (kind === "recurring") body.cron = cron;
    try {
      await api.createSchedule(body);
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  function describe(s: Schedule): string {
    if (s.kind === "once") return `once @ ${s.run_at ? new Date(s.run_at).toLocaleString() : "?"}`;
    if (s.kind === "recurring") return `cron ${s.cron}`;
    return "on GitLab merge request";
  }

  return (
    <div>
      <h1 className="mb-6 text-xl font-semibold">Schedules</h1>

      <form onSubmit={create} className="card mb-8 grid max-w-3xl grid-cols-2 gap-4 p-6">
        <div>
          <label htmlFor="sch-job" className="mb-1 block text-sm text-slate">Job</label>
          <select id="sch-job" className="field" value={jobId} onChange={(e) => setJobId(e.target.value)} required>
            {Object.values(jobs).map((j) => (
              <option key={j.id} value={j.id}>{j.name}</option>
            ))}
          </select>
          <label className="mt-2 flex items-center gap-2 text-sm text-slate">
            <input
              type="checkbox"
              checked={notifyEmail}
              disabled={!jobId}
              onChange={(e) => toggleNotify(e.target.checked)}
            />
            Email me the report when this job finishes
          </label>
          <p className="mt-1 text-xs text-slate">
            Edits the selected job's setting — applies to scheduled and manual runs of it.
          </p>
        </div>
        <div>
          <label htmlFor="sch-kind" className="mb-1 block text-sm text-slate">Trigger</label>
          <select id="sch-kind" className="field" value={kind} onChange={(e) => setKind(e.target.value)}>
            <option value="once">Once (specific date/time)</option>
            <option value="recurring">Recurring (cron)</option>
            <option value="gitlab_mr">On GitLab merge request</option>
          </select>
        </div>
        {kind === "once" && (
          <div>
            <label htmlFor="sch-runat" className="mb-1 block text-sm text-slate">Run at</label>
            <input id="sch-runat" className="field" type="datetime-local" value={runAt}
                   onChange={(e) => setRunAt(e.target.value)} required />
          </div>
        )}
        {kind === "recurring" && (
          <div>
            <label htmlFor="sch-cron" className="mb-1 block text-sm text-slate">Cron</label>
            <input id="sch-cron" className="field mono" value={cron} onChange={(e) => setCron(e.target.value)} />
          </div>
        )}
        {error && <p className="col-span-2 text-sm text-severity-critical">{error}</p>}
        <div className="col-span-2">
          <button className="btn-primary" disabled={!jobId}>Create schedule</button>
        </div>
      </form>

      <div className="card divide-y divide-line">
        {schedules.map((s) => (
          <div key={s.id} className="flex items-center justify-between px-4 py-3 text-sm">
            <div>
              <div className="flex items-center gap-2 font-medium">
                {jobs[s.job_id]?.name ?? s.job_id.slice(0, 8)}
                {jobs[s.job_id]?.notify_email && (
                  <span className="rounded bg-accent/15 px-1.5 py-0.5 text-xs font-normal text-accent">
                    emails report
                  </span>
                )}
              </div>
              <div className="mono text-xs text-slate">{describe(s)}</div>
            </div>
            <span className="flex items-center gap-3">
              <span className={s.enabled ? "text-emerald-600" : "text-slate"}>
                {s.enabled ? "enabled" : "disabled"}
              </span>
              <button className="btn-ghost py-1" onClick={() => api.deleteSchedule(s.id).then(load)}>
                Delete
              </button>
            </span>
          </div>
        ))}
        {schedules.length === 0 && <div className="px-4 py-8 text-center text-slate">No schedules.</div>}
      </div>
    </div>
  );
}
