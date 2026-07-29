import { useState, type FormEvent } from "react";
import { api } from "../api/client";
import { useAuth } from "../auth/AuthContext";

export function Account() {
  const { user } = useAuth();
  const [cur, setCur] = useState("");
  const [nw, setNw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setMsg(null);
    if (nw !== confirm) {
      setMsg({ ok: false, text: "New passwords don't match." });
      return;
    }
    setBusy(true);
    try {
      await api.changePassword(cur, nw); // updates the stored token on success
      setCur(""); setNw(""); setConfirm("");
      setMsg({ ok: true, text: "Password changed. All other sessions have been signed out." });
    } catch (err) {
      setMsg({ ok: false, text: err instanceof Error ? err.message : "Failed to change password" });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="max-w-md">
      <h1 className="mb-1 text-xl font-semibold">Account</h1>
      <p className="mb-6 mono text-sm text-slate">{user?.email}</p>

      <form onSubmit={submit} className="card space-y-4 p-6">
        <h2 className="text-sm font-semibold text-ink">Change password</h2>
        <div>
          <label htmlFor="cur" className="mb-1 block text-sm text-slate">Current password</label>
          <input id="cur" type="password" autoComplete="current-password" className="field"
                 value={cur} onChange={(e) => setCur(e.target.value)} required />
        </div>
        <div>
          <label htmlFor="nw" className="mb-1 block text-sm text-slate">New password</label>
          <input id="nw" type="password" autoComplete="new-password" className="field"
                 value={nw} onChange={(e) => setNw(e.target.value)} required />
          <p className="mt-1 text-xs text-slate">At least 10 characters; must not contain your email.</p>
        </div>
        <div>
          <label htmlFor="cf" className="mb-1 block text-sm text-slate">Confirm new password</label>
          <input id="cf" type="password" autoComplete="new-password" className="field"
                 value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
        </div>
        {msg && (
          <p className={msg.ok ? "text-sm text-emerald-600" : "text-sm text-severity-critical"}>
            {msg.text}
          </p>
        )}
        <button className="btn-primary" disabled={busy}>
          {busy ? "Changing…" : "Change password"}
        </button>
      </form>
    </div>
  );
}
