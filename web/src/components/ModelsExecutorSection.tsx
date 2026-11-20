import { useEffect, useState, type FormEvent } from "react";
import { api, type AdminConfig, type ExecutorStatus, type ModelDefaults } from "../api/client";

const EXECUTORS = ["claude", "codex", "opencode"] as const;
const TIERS = [
  { key: "model_small", label: "Model (small)" },
  { key: "model_medium", label: "Model (medium)" },
  { key: "model_large", label: "Model (large)" },
] as const;
type TierKey = (typeof TIERS)[number]["key"];

export function ModelsExecutorSection({ cfg, onSaved }: { cfg: AdminConfig; onSaved: (c: AdminConfig) => void }) {
  const [executor, setExecutor] = useState(cfg.executor);
  const [models, setModels] = useState<Record<TierKey, string>>({
    model_small: cfg.model_small,
    model_medium: cfg.model_medium,
    model_large: cfg.model_large,
  });
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [status, setStatus] = useState<ExecutorStatus[] | null>(null);
  const [checking, setChecking] = useState(false);
  const [checkErr, setCheckErr] = useState<string | null>(null);
  const [workerDefaults, setWorkerDefaults] = useState<ModelDefaults["worker_defaults"]>(undefined);
  useEffect(() => {
    api.modelDefaults().then((d) => setWorkerDefaults(d.worker_defaults)).catch(() => undefined);
  }, []);

  async function check() {
    setChecking(true);
    setCheckErr(null);
    try {
      setStatus((await api.executorStatus()).executors);
    } catch (e) {
      setCheckErr(e instanceof Error ? e.message : "Check failed");
    } finally {
      setChecking(false);
    }
  }
  useEffect(() => {
    void check();
  }, []);

  const dirty =
    executor !== cfg.executor || TIERS.some((t) => models[t.key].trim() !== (cfg[t.key] as string));
  const selected = status?.find((s) => s.executor === executor);

  async function save(e: FormEvent) {
    e.preventDefault();
    setMsg(null);
    setBusy(true);
    try {
      const updated = await api.updateAdminConfig({
        executor,
        model_small: models.model_small,
        model_medium: models.model_medium,
        model_large: models.model_large,
      });
      onSaved(updated);
      setExecutor(updated.executor);
      setModels({
        model_small: updated.model_small,
        model_medium: updated.model_medium,
        model_large: updated.model_large,
      });
      setMsg({ ok: true, text: "Saved. The next run will use these settings." });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Save failed" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <section>
      <h2 className="mb-3 text-sm font-semibold text-ink">Models &amp; executor</h2>
      <form onSubmit={save} className="card space-y-4 p-4">
        <div>
          <label htmlFor="adm-executor" className="mb-1 block text-sm text-slate">Executor</label>
          <select id="adm-executor" className="field w-48" value={executor}
                  onChange={(e) => setExecutor(e.target.value)}>
            {EXECUTORS.map((x) => <option key={x} value={x}>{x}</option>)}
          </select>
          {selected && !selected.configured && (
            <p className="mt-2 text-sm text-severity-critical" role="alert">
              {executor} is selected but no credentials were found in the API environment
              (missing: <span className="mono">{selected.missing.join(", ")}</span>). {selected.detail}
            </p>
          )}
        </div>
        <div className="grid grid-cols-3 gap-3">
          {TIERS.map((t) => (
            <div key={t.key}>
              <label htmlFor={`adm-${t.key}`} className="mb-1 block text-sm text-slate">{t.label}</label>
              <input id={`adm-${t.key}`} className="field mono" value={models[t.key]}
                     placeholder={
                       workerDefaults?.[executor]?.[t.key]
                         ? `worker default (${workerDefaults[executor][t.key]})`
                         : "worker default"
                     }
                     maxLength={100} spellCheck={false}
                     onChange={(e) => setModels({ ...models, [t.key]: e.target.value })} />
            </div>
          ))}
        </div>
        <p className="text-sm text-slate">
          Applies to the next run; no restart needed. Repositories can override these in their
          settings. Credentials and endpoints come from the worker's environment, not from here.
          Leave a model empty to use the worker's own default. Model names must be ones your endpoint is allowed to serve for the selected executor.
        </p>
        <div className="flex items-center gap-3">
          <button className="btn-primary" disabled={busy || !dirty}>{busy ? "Saving…" : "Save"}</button>
          <button type="button" className="btn-ghost" onClick={check} disabled={checking}>
            {checking ? "Checking…" : "Check credentials"}
          </button>
          {msg && (
            <span role="status" className={`text-sm ${msg.ok ? "text-emerald-600" : "text-severity-critical"}`}>
              {msg.text}
            </span>
          )}
        </div>
      </form>

      <div className="card mt-3 divide-y divide-line">
        {checkErr && <div className="px-4 py-2 text-sm text-severity-critical">{checkErr}</div>}
        {status?.map((s) => (
          <div key={s.executor} className="flex items-center justify-between px-4 py-2 text-sm">
            <span className="mono">{s.executor}{s.executor === cfg.executor ? " (active)" : ""}</span>
            <span className={s.configured ? "text-emerald-600" : "text-slate"}>
              {s.configured
                ? `credentials found${s.mode ? ` (${s.mode})` : ""}`
                : `not configured (missing ${s.missing.join(", ")})`}
            </span>
          </div>
        ))}
      </div>
      <p className="mt-2 text-xs text-slate">
        The check only looks at which environment variables are set in the API process; it does
        not contact any model endpoint, and never shows values.
      </p>
    </section>
  );
}
