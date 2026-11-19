import { useEffect, useId, useState, type FormEvent } from "react";
import { KeyIcon, PlusIcon, TrashIcon } from "@heroicons/react/24/outline";
import { api, ApiError, type Credential } from "../../api/client";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { Badge, Breadcrumb, Drawer, EmptyState, FieldError, asLocErrors, errorsFor, groupErrors } from "../../components/ui";

type Kind = "cookie_header" | "login_account" | "gitlab_token";
const KINDS: { value: Kind; label: string; hint: string; secretLabel: string }[] = [
  {
    value: "cookie_header",
    label: "Session cookie",
    hint: "A Cookie header value (for example session=abc123) for logged-in testing of a live application. Use a low-privilege test session.",
    secretLabel: "Cookie header value",
  },
  {
    value: "login_account",
    label: "Login account",
    hint: "A synthetic test account (username + password) a grey-box assessment logs in with to compare what different users can access. The agent never sees the password.",
    secretLabel: "Password",
  },
  {
    value: "gitlab_token",
    label: "GitLab token",
    hint: "A GitLab access token used to clone private repositories.",
    secretLabel: "Token",
  },
];
// GitHub credentials are created with their repository, so they are only listed here.
const KIND_LABEL: Record<string, string> = {
  ...Object.fromEntries(KINDS.map((k) => [k.value, k.label])),
  github_token: "GitHub token",
  github_app: "GitHub App",
};

// Lists and creates the caller's credentials through the existing /credentials API.
// Secrets are write-only: the API never returns them, and the form clears the secret
// field as soon as the credential is saved.
export function Credentials() {
  const ids = useId();
  const [items, setItems] = useState<Credential[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [creating, setCreating] = useState(false);
  const [confirm, setConfirm] = useState<Credential | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [kind, setKind] = useState<Kind>("cookie_header");
  const [username, setUsername] = useState("");
  const [label, setLabel] = useState("");
  const [secret, setSecret] = useState("");
  const [gitlabUrl, setGitlabUrl] = useState("");
  const [formErrors, setFormErrors] = useState<Record<string, string[]>>({});
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function load() {
    try {
      setItems(await api.credentials());
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load credentials");
    }
  }
  useEffect(() => {
    void load();
  }, []);

  function openCreate() {
    setKind("cookie_header");
    setLabel("");
    setSecret("");
    setUsername("");
    setGitlabUrl("");
    setFormErrors({});
    setFormError(null);
    setCreating(true);
  }
  function closeCreate() {
    setSecret("");
    setCreating(false);
  }

  async function create(e: FormEvent) {
    e.preventDefault();
    const errs: Record<string, string[]> = {};
    if (!label.trim()) errs.label = ["Enter a label."];
    if (!secret) errs.secret = ["Enter the secret value."];
    if (kind === "login_account" && !username.trim()) errs.username = ["Enter the username."];
    setFormErrors(errs);
    setFormError(null);
    if (Object.keys(errs).length) return;
    setBusy(true);
    try {
      const c = await api.createCredential({
        kind,
        label: label.trim(),
        // a login account is stored as {"user", "password"} (encrypted like any secret)
        secret: kind === "login_account" ? JSON.stringify({ user: username.trim(), password: secret }) : secret,
        forge_base_url: kind === "gitlab_token" && gitlabUrl.trim() ? gitlabUrl.trim() : null,
      });
      setSecret("");
      setUsername("");
      setCreating(false);
      setNotice(`Saved “${c.label}”. The secret is stored encrypted and will not be shown again.`);
      await load();
    } catch (err) {
      const locs = err instanceof ApiError ? asLocErrors(err.detail) : null;
      if (locs) setFormErrors(groupErrors(locs));
      setFormError(err instanceof Error ? err.message : "Saving failed");
    } finally {
      setBusy(false);
    }
  }

  async function remove(c: Credential) {
    await api.deleteCredential(c.id);
    setConfirm(null);
    setNotice(`Deleted “${c.label}”.`);
    await load();
  }

  const k = KINDS.find((x) => x.value === kind)!;

  return (
    <div>
      <Breadcrumb items={[{ label: "Settings" }, { label: "Credentials" }]} />
      <div className="mb-2 flex flex-wrap items-center justify-between gap-3">
        <h1 className="text-xl font-semibold">Credentials</h1>
        <button type="button" className="btn-primary" onClick={openCreate}>
          <PlusIcon className="h-4 w-4" /> New credential
        </button>
      </div>
      <p className="mb-6 max-w-3xl text-sm text-slate">
        Secrets are encrypted at rest and never shown after saving. Session cookies can be used by white-box jobs
        with a live URL and by grey-box targets; they are sent only to the target in scope.
      </p>
      {notice && <p role="status" className="mb-4 rounded-md border border-line bg-surface p-3 text-sm">{notice}</p>}
      {error && <p role="alert" className="mb-4 text-sm text-severity-critical">{error}</p>}

      <div className="card overflow-x-auto">
        {items === null && !error ? (
          <p className="p-4 text-sm text-slate">Loading credentials…</p>
        ) : items && items.length === 0 ? (
          <EmptyState icon={KeyIcon} title="No credentials yet" action={<button type="button" className="btn-primary" onClick={openCreate}><PlusIcon className="h-4 w-4" /> New credential</button>}>
            Add a session cookie for logged-in testing, or a GitLab token for private repositories.
          </EmptyState>
        ) : items ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-line text-left text-slate">
                <th className="px-4 py-3 font-medium">Label</th>
                <th className="px-4 py-3 font-medium">Kind</th>
                <th className="px-4 py-3 font-medium">Secret</th>
                <th className="px-4 py-3 font-medium">Created</th>
                <th className="px-4 py-3"><span className="sr-only">Actions</span></th>
              </tr>
            </thead>
            <tbody>
              {items.map((c) => (
                <tr key={c.id} className="border-b border-line/60">
                  <td className="px-4 py-3 font-medium">
                    {c.label}
                    {c.forge_base_url && <span className="mono block text-xs font-normal text-slate">{c.forge_base_url}</span>}
                  </td>
                  <td className="px-4 py-3"><Badge>{KIND_LABEL[c.kind] ?? c.kind}</Badge></td>
                  <td className="px-4 py-3 text-slate">{c.has_secret ? "Stored (hidden)" : "Missing"}</td>
                  <td className="px-4 py-3 text-slate">{new Date(c.created_at).toLocaleString()}</td>
                  <td className="px-4 py-3 text-right">
                    <button
                      type="button"
                      className="text-slate hover:text-severity-critical"
                      aria-label={`Delete credential ${c.label}`}
                      title="Delete credential"
                      onClick={() => setConfirm(c)}
                    >
                      <TrashIcon className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
      </div>

      {creating && (
        <Drawer
          title="New credential"
          onClose={closeCreate}
          footer={
            <div className="flex justify-end gap-3">
              <button type="button" className="btn-ghost" onClick={closeCreate}>Cancel</button>
              <button type="submit" form={`${ids}-form`} className="btn-primary disabled:opacity-60" disabled={busy}>
                {busy ? "Saving…" : "Save credential"}
              </button>
            </div>
          }
        >
          <form id={`${ids}-form`} onSubmit={create} className="grid gap-4" noValidate autoComplete="off">
            <fieldset>
              <legend className="mb-1 text-sm text-slate">Kind</legend>
              <div className="flex flex-col gap-2">
                {KINDS.map((x) => (
                  <label key={x.value} className="flex items-start gap-2 text-sm">
                    <input type="radio" name={`${ids}-kind`} className="mt-1" checked={kind === x.value} onChange={() => setKind(x.value)} />
                    <span>
                      {x.label}
                      <span className="block text-xs text-slate">{x.hint}</span>
                    </span>
                  </label>
                ))}
              </div>
            </fieldset>
            <div>
              <label htmlFor={`${ids}-label`} className="mb-1 block text-sm text-slate">Label</label>
              <input
                id={`${ids}-label`}
                data-autofocus
                className="field"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder={kind === "cookie_header" ? "staging session" : "gitlab.example.org token"}
                aria-invalid={errorsFor(formErrors, "label").length > 0}
                aria-describedby={`${ids}-label-err`}
              />
              <FieldError id={`${ids}-label-err`} messages={errorsFor(formErrors, "label")} />
            </div>
            <div>
              {kind === "login_account" && (
                <div className="mb-3">
                  <label htmlFor={`${ids}-user`} className="mb-1 block text-sm text-slate">Username</label>
                  <input id={`${ids}-user`} className="field" autoComplete="off" value={username}
                    onChange={(e) => setUsername(e.target.value)}
                    aria-invalid={errorsFor(formErrors, "username").length > 0} aria-describedby={`${ids}-user-err`} />
                  <FieldError id={`${ids}-user-err`} messages={errorsFor(formErrors, "username")} />
                </div>
              )}
              <label htmlFor={`${ids}-secret`} className="mb-1 block text-sm text-slate">{k.secretLabel}</label>
              <input
                id={`${ids}-secret`}
                type="password"
                className="field mono"
                value={secret}
                onChange={(e) => setSecret(e.target.value)}
                autoComplete="new-password"
                spellCheck={false}
                aria-invalid={errorsFor(formErrors, "secret").length > 0}
                aria-describedby={`${ids}-secret-hint ${ids}-secret-err`}
              />
              <p id={`${ids}-secret-hint`} className="mt-1 text-xs text-slate">Write-only: you will not be able to view it after saving.</p>
              <FieldError id={`${ids}-secret-err`} messages={errorsFor(formErrors, "secret")} />
            </div>
            {kind === "gitlab_token" && (
              <div>
                <label htmlFor={`${ids}-gl`} className="mb-1 block text-sm text-slate">GitLab base URL (optional)</label>
                <input
                  id={`${ids}-gl`}
                  className="field mono"
                  value={gitlabUrl}
                  onChange={(e) => setGitlabUrl(e.target.value)}
                  placeholder="https://gitlab.example.org"
                  aria-describedby={`${ids}-gl-err`}
                />
                <FieldError id={`${ids}-gl-err`} messages={errorsFor(formErrors, "forge_base_url")} />
              </div>
            )}
            {formError && <p role="alert" className="text-sm text-severity-critical">{formError}</p>}
          </form>
        </Drawer>
      )}

      {confirm && (
        <ConfirmDialog
          title="Delete credential"
          body={
            <>
              Delete “{confirm.label}”? Jobs and grey-box targets that use it lose the reference (they test
              unauthenticated), and active white-box runs using it lose access to it immediately. This cannot be undone.
            </>
          }
          onConfirm={() => remove(confirm)}
          onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  );
}
