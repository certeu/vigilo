import { useState, type FormEvent } from "react";
import { Link } from "react-router-dom";
import { api } from "../api/client";

export function ForgotPassword() {
  const [email, setEmail] = useState("");
  const [sent, setSent] = useState(false);
  const [busy, setBusy] = useState(false);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    try {
      await api.forgotPassword(email);
    } catch {
      /* deliberately ignore — never reveal whether the email exists */
    } finally {
      setBusy(false);
      setSent(true); // same outcome regardless, to avoid user enumeration
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center bg-canvas px-4">
      <div className="w-full max-w-sm">
        <h1 className="mb-1 font-display text-2xl font-semibold">Reset password</h1>
        {sent ? (
          <div className="card space-y-3 p-6 text-sm">
            <p className="text-emerald-600">
              If an account exists for that email, a reset link has been sent. The link
              expires shortly and can be used once.
            </p>
            <Link to="/login" className="text-accent hover:underline">Back to sign in</Link>
          </div>
        ) : (
          <>
            <p className="mb-6 text-sm text-slate">
              Enter your email and we'll send a reset link.
            </p>
            <form onSubmit={submit} className="card space-y-4 p-6">
              <div>
                <label htmlFor="email" className="mb-1 block text-sm text-slate">Email</label>
                <input id="email" className="field" type="email" autoComplete="email"
                       value={email} onChange={(e) => setEmail(e.target.value)} required />
              </div>
              <button className="btn-primary w-full justify-center" disabled={busy}>
                {busy ? "Sending…" : "Send reset link"}
              </button>
              <Link to="/login" className="block text-center text-sm text-slate hover:text-ink">
                Back to sign in
              </Link>
            </form>
          </>
        )}
      </div>
    </div>
  );
}
