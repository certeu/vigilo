import { useState, type FormEvent } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { api } from "../api/client";

export function AcceptInvite() {
  const [params] = useSearchParams();
  const navigate = useNavigate();
  const token = params.get("token") ?? "";
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [ok, setOk] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    try {
      await api.acceptInvite(token, password);
      setOk(true);
      setTimeout(() => navigate("/login"), 1500);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed");
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-sm">
        <h1 className="mb-1 font-display text-2xl font-semibold">Accept invitation</h1>
        <p className="mb-6 text-sm text-slate">Set a password to activate your account.</p>
        {!token && <p className="text-sm text-severity-critical">Missing invitation token.</p>}
        {ok ? (
          <p className="card p-6 text-sm text-emerald-600">Account created — redirecting to sign in…</p>
        ) : (
          <form onSubmit={submit} className="card space-y-4 p-6">
            <div>
              <label htmlFor="new-password" className="mb-1 block text-sm text-slate">New password</label>
              <input id="new-password" className="field" type="password" value={password}
                     onChange={(e) => setPassword(e.target.value)} minLength={8} required />
            </div>
            {error && <p className="text-sm text-severity-critical">{error}</p>}
            <button className="btn-primary w-full justify-center" disabled={!token}>Activate account</button>
          </form>
        )}
      </div>
    </div>
  );
}
