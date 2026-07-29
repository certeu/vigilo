import { useEffect, useRef, useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { PlusIcon, TrashIcon, XMarkIcon, LockClosedIcon } from "@heroicons/react/24/outline";
import { api, type Repository } from "../api/client";
import { ConfirmDialog } from "../components/ConfirmDialog";

function StatusBadge({ status, error }: { status: string; error: string | null }) {
  if (!status || status === "idle") return null;
  const styles: Record<string, string> = {
    importing: "bg-accent/15 text-accent",
    ready: "bg-emerald-600/15 text-emerald-700",
    failed: "bg-severity-critical/15 text-severity-critical",
  };
  const label = status === "importing" ? "importing…" : status;
  return (
    <span
      className={`rounded px-2 py-0.5 text-xs font-medium ${styles[status] ?? "bg-slate/15 text-slate"}`}
      title={status === "failed" && error ? error : undefined}
    >
      {label}
    </span>
  );
}

export function Repos() {
  const [repos, setRepos] = useState<Repository[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [open, setOpen] = useState(false);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  // Pending confirmation: either a single repo or the current bulk selection.
  const [confirm, setConfirm] = useState<{ ids: string[]; label: string } | null>(null);
  const pollRef = useRef<number | null>(null);

  async function load() {
    try {
      setRepos(await api.repositories());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load repositories");
    }
  }

  function toggle(id: string) {
    setSelected((prev) => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
  }

  async function doDelete(ids: string[]) {
    if (ids.length === 1) {
      await api.deleteRepository(ids[0]);
    } else {
      await api.bulkDeleteRepositories(ids);
    }
    setSelected(new Set());
    setConfirm(null);
    await load();
  }
  useEffect(() => {
    void load();
  }, []);

  // Poll while any repo is still importing so the badge flips to ready/failed live.
  useEffect(() => {
    const importing = repos.some((r) => r.ingestion_status === "importing");
    if (importing && pollRef.current == null) {
      pollRef.current = window.setInterval(load, 2000);
    } else if (!importing && pollRef.current != null) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
    return () => {
      if (pollRef.current != null) {
        clearInterval(pollRef.current);
        pollRef.current = null;
      }
    };
  }, [repos]);

  const allSelected = repos.length > 0 && selected.size === repos.length;

  return (
    <div>
      <div className="mb-6 flex items-center justify-between">
        <h1 className="text-xl font-semibold">Repositories</h1>
        <button className="btn-primary inline-flex items-center gap-1.5" onClick={() => setOpen(true)}>
          <PlusIcon className="h-4 w-4" /> Add repository
        </button>
      </div>

      {error && <p className="mb-4 text-sm text-severity-critical">{error}</p>}

      {/* Selection toolbar (appears once something is checked) */}
      <div className="mb-3 flex h-8 items-center gap-3 text-sm">
        {repos.length > 0 && (
          <label className="flex items-center gap-2 text-slate">
            <input
              type="checkbox"
              checked={allSelected}
              onChange={(e) => setSelected(e.target.checked ? new Set(repos.map((r) => r.id)) : new Set())}
            />
            Select all
          </label>
        )}
        {selected.size > 0 && (
          <>
            <span className="text-slate">{selected.size} selected</span>
            <button
              className="inline-flex items-center gap-1.5 rounded-md border border-severity-critical/40 px-2.5 py-1 text-severity-critical hover:bg-severity-critical/5"
              onClick={() => setConfirm({ ids: [...selected], label: `${selected.size} repositories` })}
            >
              <TrashIcon className="h-4 w-4" /> Delete selected
            </button>
          </>
        )}
      </div>

      <div className="card divide-y divide-line">
        {repos.map((r) => (
          <div key={r.id} className="flex items-center gap-3 px-4 py-3">
            <input
              type="checkbox"
              checked={selected.has(r.id)}
              onChange={() => toggle(r.id)}
              aria-label={`Select ${r.name}`}
            />
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2">
                <Link to={`/repos/${r.id}`} className="font-medium hover:text-accent">
                  {r.name}
                </Link>
                {r.is_private && <LockClosedIcon className="h-3.5 w-3.5 text-slate" />}
                <StatusBadge status={r.ingestion_status} error={r.ingestion_error} />
              </div>
              <div className="mono text-xs text-slate">
                {r.source_type}
                {r.gitlab_url ? ` · ${r.gitlab_url}` : ""}
                {r.ingestion_status === "failed" && r.ingestion_error ? ` · ${r.ingestion_error}` : ""}
              </div>
            </div>
            <Link to={`/repos/${r.id}`} className="btn-ghost py-1">Open</Link>
            <button
              className="text-slate hover:text-severity-critical"
              title="Delete repository"
              onClick={() => setConfirm({ ids: [r.id], label: `"${r.name}"` })}
            >
              <TrashIcon className="h-4 w-4" />
            </button>
          </div>
        ))}
        {repos.length === 0 && <div className="px-4 py-8 text-center text-slate">No repositories yet.</div>}
      </div>

      {open && (
        <AddRepoModal
          onClose={() => setOpen(false)}
          onCreated={() => {
            setOpen(false);
            void load();
          }}
        />
      )}

      {confirm && (
        <ConfirmDialog
          title="Delete repositories"
          body={
            <>
              Permanently delete {confirm.label} and <b>all</b> associated jobs, runs,
              reports, and uploaded source? Dashboard totals will update accordingly.
              This cannot be undone.
            </>
          }
          confirmLabel={confirm.ids.length > 1 ? `Delete ${confirm.ids.length}` : "Delete"}
          onConfirm={() => doDelete(confirm.ids)}
          onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  );
}

function AddRepoModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [name, setName] = useState("");
  const [sourceType, setSourceType] = useState("upload");
  const [gitlabUrl, setGitlabUrl] = useState("");
  const [gitlabToken, setGitlabToken] = useState("");
  const [pushPatches, setPushPatches] = useState(false);
  const [isPrivate, setIsPrivate] = useState(false);
  const [uploadFiles, setUploadFiles] = useState<FileList | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function create(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (sourceType === "upload" && (!uploadFiles || uploadFiles.length === 0)) {
      setError("Select a .zip/.tar.gz archive or a folder to upload.");
      return;
    }
    setBusy(true);
    try {
      const repo = await api.createRepository({
        name,
        source_type: sourceType,
        gitlab_url: sourceType === "gitlab" ? gitlabUrl : null,
        is_private: isPrivate,
        ...(sourceType === "gitlab"
          ? { gitlab_token: gitlabToken || undefined, push_patches: pushPatches }
          : {}),
      });
      // Upload returns immediately; ingestion runs in the background (repo shows
      // "importing" → ready/failed on the card), so this never blocks the UI.
      if (sourceType === "upload" && uploadFiles) {
        await api.uploadSource(repo.id, uploadFiles);
      }
      onCreated();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to add repository");
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-ink/20" onClick={onClose}>
      <div
        className="h-full w-[440px] overflow-auto bg-surface p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-6 flex items-center justify-between">
          <h2 className="font-display text-lg font-semibold">Add repository</h2>
          <button className="text-slate hover:text-ink" onClick={onClose} aria-label="Close">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={create} className="flex flex-col gap-4">
          <div>
            <label htmlFor="repo-name" className="mb-1 block text-sm text-slate">Name</label>
            <input id="repo-name" className="field" value={name} onChange={(e) => setName(e.target.value)} required />
          </div>
          <div>
            <label htmlFor="repo-source" className="mb-1 block text-sm text-slate">Source</label>
            <select id="repo-source" className="field" value={sourceType} onChange={(e) => setSourceType(e.target.value)}>
              <option value="upload">Upload</option>
              <option value="gitlab">GitLab</option>
            </select>
          </div>
          {sourceType === "gitlab" && (
            <>
              <div>
                <label htmlFor="repo-gitlab-url" className="mb-1 block text-sm text-slate">GitLab URL</label>
                <input
                  id="repo-gitlab-url"
                  className="field"
                  value={gitlabUrl}
                  onChange={(e) => setGitlabUrl(e.target.value)}
                  placeholder="https://gitlab.internal/group/project.git"
                />
              </div>
              <div>
                <label htmlFor="repo-gitlab-token" className="mb-1 block text-sm text-slate">
                  Repository access token
                </label>
                <input
                  id="repo-gitlab-token"
                  className="field"
                  type="password"
                  value={gitlabToken}
                  onChange={(e) => setGitlabToken(e.target.value)}
                  placeholder="glpat-…"
                  autoComplete="off"
                />
                <p className="mt-1 text-xs text-slate">
                  Used to <b>clone</b> this repository. Stored encrypted (never shown again);
                  access is verified right after adding.
                </p>
              </div>
              <label className="flex items-center gap-2 text-sm text-slate">
                <input type="checkbox" checked={pushPatches} onChange={(e) => setPushPatches(e.target.checked)} />
                Push fix branches / MRs back to GitLab (uses the deployment's GitLab token)
              </label>
            </>
          )}
          {sourceType === "upload" && (
            <div>
              <label htmlFor="repo-upload" className="mb-1 block text-sm text-slate">
                Source (a .zip / .tar.gz archive, or select multiple files)
              </label>
              <input
                id="repo-upload"
                className="field"
                type="file"
                accept=".zip,.tar,.tar.gz,.tgz"
                multiple
                onChange={(e) => setUploadFiles(e.target.files)}
              />
              <p className="mt-1 text-xs text-slate">
                {uploadFiles && uploadFiles.length > 0
                  ? `${uploadFiles.length} file(s) selected`
                  : "Ingestion runs in the background — you can keep working."}
              </p>
            </div>
          )}
          <label className="flex items-center gap-2 text-sm text-slate">
            <input type="checkbox" checked={isPrivate} onChange={(e) => setIsPrivate(e.target.checked)} />
            Private (only you, granted users, and admins can see it)
          </label>
          {error && <p className="text-sm text-severity-critical">{error}</p>}
          <div className="flex items-center gap-3">
            <button className="btn-primary" disabled={busy}>
              {busy ? "Adding…" : "Add repository"}
            </button>
            <button type="button" className="btn-ghost" onClick={onClose}>Cancel</button>
          </div>
        </form>
      </div>
    </div>
  );
}
