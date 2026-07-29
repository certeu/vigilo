import { useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { useAuth } from "../auth/AuthContext";

export function Login() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function onSubmit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setError(null);
    try {
      await login(email, password);
      navigate("/");
    } catch {
      setError("Invalid email or password.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-sm">
        <h1 className="mb-1 font-display text-2xl font-semibold">Vigilo</h1>
        <p className="mb-6 text-sm text-slate">Sign in to run assessments.</p>
        <form onSubmit={onSubmit} className="card space-y-4 p-6" data-testid="login-form">
          <div>
            <label htmlFor="email" className="mb-1 block text-sm text-slate">Email</label>
            <input
              id="email"
              className="field"
              type="email"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              autoFocus
              required
            />
          </div>
          <div>
            <label htmlFor="password" className="mb-1 block text-sm text-slate">Password</label>
            <input
              id="password"
              className="field"
              type="password"
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              required
            />
          </div>
          {error && <p className="text-sm text-severity-critical">{error}</p>}
          <button className="btn-primary w-full justify-center" disabled={busy}>
            {busy ? "Signing in…" : "Sign in"}
          </button>
          <Link to="/forgot-password" className="block text-center text-sm text-slate hover:text-ink">
            Forgot password?
          </Link>
        </form>
      </div>
    </div>
  );
}
