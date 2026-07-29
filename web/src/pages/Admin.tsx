import { useEffect, useState, type FormEvent } from "react";
import { api, type Invitation, type User } from "../api/client";
import { ConfirmDialog } from "../components/ConfirmDialog";

interface AdminConfig {
  model_small: string;
  model_medium: string;
  model_large: string;
  executor: string;
  global_concurrent_run_cap: number;
  smtp_host: string | null;
}

export function Admin() {
  const [users, setUsers] = useState<User[]>([]);
  const [invites, setInvites] = useState<Invitation[]>([]);
  const [cfg, setCfg] = useState<AdminConfig | null>(null);
  const [email, setEmail] = useState("");
  const [role, setRole] = useState("user");
  const [error, setError] = useState<string | null>(null);
  const [lastInvite, setLastInvite] = useState<{ url: string; sent: boolean; error: string | null } | null>(null);
  const [meId, setMeId] = useState<string | null>(null);
  const [confirmUser, setConfirmUser] = useState<User | null>(null);
  const [resetUser, setResetUser] = useState<User | null>(null);
  const [resetResult, setResetResult] = useState<
    { email: string; url: string; sent: boolean; error: string | null } | null
  >(null);

  async function load() {
    try {
      setMeId((await api.me()).id);
      setUsers(await api.users());
      setInvites(await api.invitations());
      const c = await fetch("/api/admin/config", {
        headers: { Authorization: `Bearer ${localStorage.getItem("vigilo_token")}` },
      });
      if (c.ok) setCfg(await c.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Admin access required.");
    }
  }
  useEffect(() => {
    void load();
  }, []);

  async function invite(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      const inv = await api.createInvitation(email, role);
      setLastInvite({ url: inv.accept_url, sent: inv.email_sent, error: inv.email_error });
      setEmail("");
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  if (error) return <p className="text-severity-critical">{error}</p>;

  return (
    <div className="max-w-4xl space-y-8">
      <h1 className="text-xl font-semibold">Admin</h1>

      <section>
        <h2 className="mb-3 text-sm font-semibold text-ink">Invite a colleague</h2>
        <form onSubmit={invite} className="card flex items-end gap-3 p-4">
          <div className="flex-1">
            <label htmlFor="inv-email" className="mb-1 block text-sm text-slate">Email</label>
            <input id="inv-email" className="field" type="email" value={email}
                   onChange={(e) => setEmail(e.target.value)} required />
          </div>
          <div>
            <label htmlFor="inv-role" className="mb-1 block text-sm text-slate">Role</label>
            <select id="inv-role" className="field" value={role} onChange={(e) => setRole(e.target.value)}>
              <option value="user">user</option>
              <option value="admin">admin</option>
            </select>
          </div>
          <button className="btn-primary">Send invite</button>
        </form>
        {lastInvite && (
          <div className="card mt-3 p-4 text-sm">
            {lastInvite.sent ? (
              <span className="text-emerald-600">Invitation email sent. </span>
            ) : (
              <span className="text-severity-critical">
                {lastInvite.error && lastInvite.error !== "SMTP not configured"
                  ? `Email not delivered (${lastInvite.error}). Share this link manually: `
                  : "SMTP not configured — share this link with the invitee: "}
              </span>
            )}
            <a className="mono break-all text-accent underline" href={lastInvite.url}>
              {lastInvite.url}
            </a>
          </div>
        )}
        {invites.length > 0 && (
          <div className="card mt-3 divide-y divide-line">
            {invites.map((i) => (
              <div key={i.id} className="flex items-center justify-between px-4 py-2 text-sm">
                <span className="mono">{i.email}</span>
                <span className="flex items-center gap-3">
                  <span className="text-slate">{i.role}</span>
                  <span className={i.accepted ? "text-emerald-600" : "text-slate"}>
                    {i.accepted ? "accepted" : "pending"}
                  </span>
                  {!i.accepted && (
                    <button className="btn-ghost py-1"
                            onClick={() => api.revokeInvitation(i.id).then(load)}>
                      Revoke
                    </button>
                  )}
                </span>
              </div>
            ))}
          </div>
        )}
      </section>

      <section>
        <h2 className="mb-3 text-sm font-semibold text-ink">Users</h2>
        <div className="card divide-y divide-line">
          {users.map((u) => {
            const inactive = u.is_active === false;
            return (
              <div key={u.id} className="flex items-center justify-between px-4 py-2 text-sm">
                <span className="flex items-center gap-2">
                  <span className="mono">{u.email}</span>
                  {inactive && (
                    <span className="rounded bg-slate/15 px-1.5 py-0.5 text-xs text-slate">deactivated</span>
                  )}
                  {u.id === meId && <span className="text-xs text-slate">(you)</span>}
                </span>
                <span className="flex items-center gap-3">
                  <select
                    className="field w-28 py-1"
                    value={u.role}
                    onChange={(e) => api.patchUser(u.id, { role: e.target.value }).then(load).catch((err) =>
                      setError(err instanceof Error ? err.message : "Failed"))}
                  >
                    <option value="user">user</option>
                    <option value="admin">admin</option>
                  </select>
                  <button
                    className="text-xs text-slate hover:text-ink"
                    onClick={() => setResetUser(u)}
                  >
                    Reset password
                  </button>
                  {inactive ? (
                    <button
                      className="text-xs text-accent hover:underline"
                      onClick={() => api.patchUser(u.id, { is_active: true }).then(load)}
                    >
                      Reactivate
                    </button>
                  ) : (
                    // Can't deactivate yourself (avoid self-lockout); backend also guards the last admin.
                    u.id !== meId && (
                      <button
                        className="text-xs text-severity-critical hover:underline"
                        onClick={() => setConfirmUser(u)}
                      >
                        Deactivate
                      </button>
                    )
                  )}
                </span>
              </div>
            );
          })}
        </div>
      </section>

      {confirmUser && (
        <ConfirmDialog
          title="Deactivate user"
          confirmLabel="Deactivate"
          body={
            <>
              Deactivate <b>{confirmUser.email}</b>? They will no longer be able to sign in.
              Their repositories, jobs, and runs are <b>kept</b> (under this disabled
              account) — nothing is deleted. You can reactivate them later.
            </>
          }
          onConfirm={async () => {
            await api.patchUser(confirmUser.id, { is_active: false });
            setConfirmUser(null);
            await load();
          }}
          onCancel={() => setConfirmUser(null)}
        />
      )}

      {resetUser && (
        <ConfirmDialog
          title="Reset password"
          confirmLabel="Reset password"
          body={
            <>
              Generate a password-reset link for <b>{resetUser.email}</b>? This immediately
              signs them out of all sessions; they'll set a new password via the link
              (emailed, and shown here so you can share it if email is unavailable).
            </>
          }
          onConfirm={async () => {
            const r = await api.adminResetPassword(resetUser.id);
            setResetResult({ email: resetUser.email, url: r.reset_url, sent: r.email_sent, error: r.email_error });
            setResetUser(null);
          }}
          onCancel={() => setResetUser(null)}
        />
      )}

      {resetResult && (
        <div className="card mt-4 p-4 text-sm">
          <div className="mb-1 flex items-center justify-between">
            <span className="font-medium">Reset link for {resetResult.email}</span>
            <button className="text-xs text-slate hover:text-ink" onClick={() => setResetResult(null)}>Dismiss</button>
          </div>
          <span className={resetResult.sent ? "text-emerald-600" : "text-severity-critical"}>
            {resetResult.sent
              ? "Emailed to the user. "
              : `Email not sent (${resetResult.error ?? "SMTP not configured"}). Share this link: `}
          </span>
          <a className="mono break-all text-accent underline" href={resetResult.url}>{resetResult.url}</a>
        </div>
      )}

      <section>
        <h2 className="mb-3 text-sm font-semibold text-ink">Global defaults (per-repository overridable)</h2>
        {cfg && (
          <div className="card divide-y divide-line">
            {([
              ["Executor", cfg.executor],
              ["Model (small)", cfg.model_small],
              ["Model (medium)", cfg.model_medium],
              ["Model (large)", cfg.model_large],
              ["Global run cap", String(cfg.global_concurrent_run_cap)],
              ["SMTP host", cfg.smtp_host ?? "—"],
            ] as [string, string][]).map(([k, v]) => (
              <div key={k} className="flex items-center justify-between px-4 py-2 text-sm">
                <span className="text-slate">{k}</span>
                <span className="mono">{v}</span>
              </div>
            ))}
          </div>
        )}
        <p className="mt-2 text-sm text-slate">
          Models/executor are set globally here and can be overridden per repository on the
          repository page.
        </p>
      </section>
    </div>
  );
}
