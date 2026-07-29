import { useState, type ReactNode } from "react";
import { ExclamationTriangleIcon } from "@heroicons/react/24/outline";

// Minimalist confirmation modal for destructive actions. Rendered by the parent only
// when a confirmation is pending; `onConfirm` may be async (button shows a busy state).
export function ConfirmDialog({
  title,
  body,
  confirmLabel = "Delete",
  danger = true,
  onConfirm,
  onCancel,
}: {
  title: string;
  body: ReactNode;
  confirmLabel?: string;
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function confirm() {
    setBusy(true);
    setErr(null);
    try {
      await onConfirm();
    } catch (e) {
      setErr(e instanceof Error ? e.message : "Action failed");
      setBusy(false);
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/30 p-4" onClick={onCancel}>
      <div
        className="w-full max-w-md rounded-lg bg-surface p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="mb-3 flex items-center gap-2">
          {danger && <ExclamationTriangleIcon className="h-5 w-5 text-severity-critical" />}
          <h2 className="font-display text-lg font-semibold">{title}</h2>
        </div>
        <div className="mb-5 text-sm text-slate">{body}</div>
        {err && <p className="mb-3 text-sm text-severity-critical">{err}</p>}
        <div className="flex justify-end gap-3">
          <button type="button" className="btn-ghost" onClick={onCancel} disabled={busy}>
            Cancel
          </button>
          <button
            type="button"
            className={danger
              ? "rounded-md bg-severity-critical px-4 py-2 text-sm font-medium text-white hover:opacity-90 disabled:opacity-60"
              : "btn-primary"}
            onClick={confirm}
            disabled={busy}
          >
            {busy ? "Working…" : confirmLabel}
          </button>
        </div>
      </div>
    </div>
  );
}
