import { useState, type FormEvent } from "react";
import { Link, useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";

export function ResetPassword() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get("token") ?? "";
  const [pw, setPw] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    if (pw !== confirm) {
      setError("Passwords don't match.");
      return;
    }
    try {
      await api.resetPassword(token, pw);
      setOk(true);
      setTimeout(() => navigate("/login"), 1500);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Reset link is invalid or expired.");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-sm">
        <h1 className="mb-1 font-display text-2xl font-semibold">Set a new password</h1>
        {!token && <p className="text-sm text-severity-critical">Missing reset token.</p>}
        {ok ? (
          <p className="card p-6 text-sm text-emerald-600">Password updated — redirecting to sign in…</p>
        ) : (
          <form onSubmit={submit} className="card space-y-4 p-6">
            <div>
              <label htmlFor="pw" className="mb-1 block text-sm text-slate">New password</label>
              <input id="pw" className="field" type="password" autoComplete="new-password"
                     value={pw} onChange={(e) => setPw(e.target.value)} required />
              <p className="mt-1 text-xs text-slate">At least 10 characters.</p>
            </div>
            <div>
              <label htmlFor="cf" className="mb-1 block text-sm text-slate">Confirm new password</label>
              <input id="cf" className="field" type="password" autoComplete="new-password"
                     value={confirm} onChange={(e) => setConfirm(e.target.value)} required />
            </div>
            {error && <p className="text-sm text-severity-critical">{error}</p>}
            <button className="btn-primary w-full justify-center" disabled={!token}>Set password</button>
            <Link to="/login" className="block text-center text-sm text-slate hover:text-ink">
              Back to sign in
            </Link>
          </form>
        )}
      </div>
    </div>
  );
}
