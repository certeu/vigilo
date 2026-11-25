import { useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";
import { ExclamationTriangleIcon } from "@heroicons/react/24/outline";

// Minimalist confirmation modal for destructive actions. Rendered by the parent only
// when a confirmation is pending; `onConfirm` may be async (button shows a busy state).
// Accessible: role="dialog" + aria-modal, labelled by the title, Esc cancels, focus
// starts on the safe (cancel) button, Tab is trapped and focus returns to the opener.
export function ConfirmDialog({
  title,
  body,
  confirmLabel = "Delete",
  cancelLabel = "Cancel",
  danger = true,
  onConfirm,
  onCancel,
}: {
  title: string;
  body: ReactNode;
  confirmLabel?: string;
  cancelLabel?: string;
  danger?: boolean;
  onConfirm: () => void | Promise<void>;
  onCancel: () => void;
}) {
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const ids = useId();
  const panel = useRef<HTMLDivElement>(null);
  const cancelBtn = useRef<HTMLButtonElement>(null);

  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    cancelBtn.current?.focus();
    return () => opener?.focus?.();
  }, []);

  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key === "Escape" && !busy) {
      e.stopPropagation();
      onCancel();
      return;
    }
    if (e.key !== "Tab" || !panel.current) return;
    const f = Array.from(panel.current.querySelectorAll<HTMLElement>("button:not([disabled]), [href], input, select, textarea"));
    if (!f.length) return;
    const first = f[0];
    const last = f[f.length - 1];
    if (e.shiftKey && document.activeElement === first) {
      e.preventDefault();
      last.focus();
    } else if (!e.shiftKey && document.activeElement === last) {
      e.preventDefault();
      first.focus();
    }
  }

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
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-ink/30 p-4" onClick={busy ? undefined : onCancel}>
      <div
        ref={panel}
        role="dialog"
        aria-modal="true"
        aria-labelledby={`${ids}-title`}
        aria-describedby={`${ids}-body`}
        className="w-full max-w-md rounded-lg bg-surface p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={onKeyDown}
      >
        <div className="mb-3 flex items-center gap-2">
          {danger && <ExclamationTriangleIcon className="h-5 w-5 text-severity-critical" />}
          <h2 id={`${ids}-title`} className="font-display text-lg font-semibold">{title}</h2>
        </div>
        <div id={`${ids}-body`} className="mb-5 text-sm text-slate">{body}</div>
        {err && <p role="alert" className="mb-3 text-sm text-severity-critical">{err}</p>}
        <div className="flex justify-end gap-3">
          <button ref={cancelBtn} type="button" className="btn-ghost" onClick={onCancel} disabled={busy}>
            {cancelLabel}
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
