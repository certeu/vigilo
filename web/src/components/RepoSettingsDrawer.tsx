import { useEffect, useState } from "react";
import { TrashIcon, XMarkIcon } from "@heroicons/react/24/outline";
import { api, type AccessGrant, type Repository } from "../api/client";

const CONFIG_FIELDS = [
  { key: "executor", label: "Executor (claude/codex)" },
  { key: "model_small", label: "Model — small" },
  { key: "model_medium", label: "Model — medium" },
  { key: "model_large", label: "Model — large" },
];
const SCAN_FIELDS = [
  { key: "description", label: "Description / context" },
  { key: "focus", label: "Focus on" },
  { key: "avoid", label: "Skip / avoid" },
];

export function RepoSettingsDrawer({
  repo,
  onClose,
  onSaved,
  onDeleted,
}: {
  repo: Repository;
  onClose: () => void;
  onSaved: () => void;
  onDeleted?: () => void;
}) {
  const [isPrivate, setIsPrivate] = useState(repo.is_private);
  const [pushPatches, setPushPatches] = useState(repo.push_patches);
  const [gitlabToken, setGitlabToken] = useState("");
  const [cfg, setCfg] = useState<Record<string, string>>({ ...repo.pipeline_config });
  const [scan, setScan] = useState<Record<string, string>>({ ...repo.scan_config });
  const [grants, setGrants] = useState<AccessGrant[]>([]);
  const [grantEmail, setGrantEmail] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  async function loadGrants() {
    try {
      setGrants(await api.repoAccess(repo.id));
    } catch {
      /* non-owner: ignore */
    }
  }
  useEffect(() => {
    void loadGrants();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [repo.id]);

  async function save() {
    setMsg(null);
    const clean = (o: Record<string, string>) =>
      Object.fromEntries(Object.entries(o).filter(([, v]) => v.trim() !== ""));
    try {
      await api.updateRepository(repo.id, {
        is_private: isPrivate,
        push_patches: pushPatches,
        pipeline_config: clean(cfg),
        scan_config: clean(scan),
        ...(gitlabToken ? { gitlab_token: gitlabToken } : {}),
      });
      setGitlabToken("");
      setMsg(gitlabToken ? "Saved — verifying token…" : "Saved");
      onSaved();
      setTimeout(() => setMsg(null), 1500);
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Failed");
    }
  }

  async function addGrant() {
    if (!grantEmail.trim()) return;
    try {
      await api.grantAccessByEmail(repo.id, grantEmail.trim());
      setGrantEmail("");
      await loadGrants();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Grant failed");
    }
  }

  async function remove() {
    if (!window.confirm(
      `Delete repository "${repo.name}" and ALL its jobs, runs, reports, and uploaded ` +
      `source? This cannot be undone.`,
    )) return;
    try {
      await api.deleteRepository(repo.id);
      onDeleted?.();
    } catch (e) {
      setMsg(e instanceof Error ? e.message : "Delete failed");
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-ink/20" onClick={onClose}>
      <div
        className="h-full w-[420px] overflow-auto bg-surface p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-6 flex items-center justify-between">
          <h2 className="font-display text-lg font-semibold">Repository settings</h2>
          <button className="text-slate hover:text-ink" onClick={onClose}>
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        <section className="mb-6">
          <label className="flex items-center gap-3">
            <input type="checkbox" checked={isPrivate} onChange={(e) => setIsPrivate(e.target.checked)} />
            <span className="text-sm">
              <span className="font-medium">Private</span>
              <span className="block text-slate">Only you, granted users, and admins can see it.</span>
            </span>
          </label>
        </section>

        {isPrivate && (
          <section className="mb-6">
            <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">Access</h3>
            <div className="mb-2 flex gap-2">
              <input className="field" placeholder="colleague@example.com" value={grantEmail}
                     onChange={(e) => setGrantEmail(e.target.value)} />
              <button className="btn-ghost" onClick={addGrant}>Grant</button>
            </div>
            <div className="divide-y divide-line rounded-md border border-line">
              {grants.map((g) => (
                <div key={g.user_id} className="flex items-center justify-between px-3 py-2 text-sm">
                  <span className="mono">{g.email}</span>
                  <button className="text-xs text-severity-critical hover:underline"
                          onClick={() => api.revokeAccess(repo.id, g.user_id).then(loadGrants)}>
                    Revoke
                  </button>
                </div>
              ))}
              {grants.length === 0 && <div className="px-3 py-2 text-sm text-slate">No grants yet.</div>}
            </div>
          </section>
        )}

        {repo.source_type === "gitlab" && (
          <section className="mb-6">
            <label className="flex items-center gap-3">
              <input type="checkbox" checked={pushPatches}
                     onChange={(e) => setPushPatches(e.target.checked)} />
              <span className="text-sm">
                <span className="font-medium">Push patches back to GitLab</span>
                <span className="block text-slate">
                  On remediation, push fix branches and open merge requests. Push-back uses the
                  deployment's configured GitLab token (server-side, write-scoped) — not the
                  per-repository access token below.
                </span>
              </span>
            </label>
            <div className="mt-3">
              <label htmlFor="gl-token" className="mb-1 block text-sm text-slate">
                Repository access token {repo.ingestion_status === "ready" ? "(set — paste to replace)" : ""}
              </label>
              <input
                id="gl-token"
                className="field"
                type="password"
                autoComplete="off"
                placeholder="glpat-…"
                value={gitlabToken}
                onChange={(e) => setGitlabToken(e.target.value)}
              />
              <p className="mt-1 text-xs text-slate">
                Used to <b>clone</b> this repository. Stored encrypted. Saving verifies access
                against the host and resolves to a clear valid/invalid state.
                {repo.ingestion_status === "failed" && repo.ingestion_error
                  ? ` Last check failed: ${repo.ingestion_error}`
                  : ""}
              </p>
            </div>
          </section>
        )}

        <section className="mb-6">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">
            Custom scan instructions
          </h3>
          {SCAN_FIELDS.map((f) => (
            <div key={f.key} className="mb-3">
              <label htmlFor={`scan-${f.key}`} className="mb-1 block text-sm text-slate">{f.label}</label>
              <textarea id={`scan-${f.key}`} className="field min-h-[60px]" value={scan[f.key] ?? ""}
                        onChange={(e) => setScan({ ...scan, [f.key]: e.target.value })} />
            </div>
          ))}
        </section>

        <section className="mb-6">
          <h3 className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">
            Pipeline config (overrides global)
          </h3>
          {CONFIG_FIELDS.map((f) => (
            <div key={f.key} className="mb-3">
              <label htmlFor={`cfg-${f.key}`} className="mb-1 block text-sm text-slate">{f.label}</label>
              <input id={`cfg-${f.key}`} className="field" placeholder="(use global default)"
                     value={cfg[f.key] ?? ""} onChange={(e) => setCfg({ ...cfg, [f.key]: e.target.value })} />
            </div>
          ))}
        </section>

        <div className="flex items-center gap-3">
          <button className="btn-primary" onClick={save}>Save</button>
          {msg && <span className="text-sm text-emerald-600">{msg}</span>}
        </div>

        <section className="mt-8 rounded-md border border-severity-critical/30 p-4">
          <h3 className="mb-1 text-xs font-semibold uppercase tracking-wide text-severity-critical">
            Danger zone
          </h3>
          <p className="mb-3 text-sm text-slate">
            Permanently delete this repository and all of its jobs, runs, reports, and
            uploaded source.
          </p>
          <button
            className="inline-flex items-center gap-1.5 rounded-md border border-severity-critical/40 px-3 py-1.5 text-sm text-severity-critical hover:bg-severity-critical/5"
            onClick={remove}
          >
            <TrashIcon className="h-4 w-4" /> Delete repository
          </button>
        </section>
      </div>
    </div>
  );
}
