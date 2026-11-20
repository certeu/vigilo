import { useEffect, useRef, useState } from "react";

export type ReportFormat = "markdown" | "docx" | "pdf";

const LABELS: Record<ReportFormat, string> = {
  markdown: "Markdown",
  docx: "Docx",
  pdf: "PDF",
};

/**
 * "Download report as …" button: opens a small menu listing the available
 * formats. Docx/PDF are rendered by the API on demand, so a menu item may
 * take a second on the Pi — the trigger shows progress.
 */
export function ReportDownloadMenu({
  onDownload,
  disabled,
}: {
  onDownload: (format: ReportFormat) => Promise<void>;
  disabled?: boolean;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState<ReportFormat | null>(null);
  const ref = useRef<HTMLDivElement>(null);

  // Close on outside click / Escape — the menu is absolutely positioned.
  useEffect(() => {
    if (!open) return;
    function onDoc(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false);
    }
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") setOpen(false);
    }
    document.addEventListener("mousedown", onDoc);
    document.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      document.removeEventListener("keydown", onKey);
    };
  }, [open]);

  async function run(format: ReportFormat) {
    setOpen(false);
    setBusy(format);
    try {
      await onDownload(format);
    } finally {
      setBusy(null);
    }
  }

  const label = busy ? `Preparing ${LABELS[busy]}…` : "Download report as …";

  return (
    <div ref={ref} className="relative inline-flex">
      <button
        className="btn-ghost-sm"
        disabled={disabled || busy !== null}
        aria-haspopup="menu"
        aria-expanded={open}
        title="Download the report in Markdown, Docx or PDF"
        onClick={() => setOpen((o) => !o)}
      >
        {label}
        <svg width="10" height="6" viewBox="0 0 10 6" aria-hidden="true" className="ml-2 inline-block">
          <path d="M1 1l4 4 4-4" fill="none" stroke="currentColor" strokeWidth="1.5" />
        </svg>
      </button>
      {open && (
        <ul
          role="menu"
          className="absolute right-0 top-full z-20 mt-1 min-w-[10rem] overflow-hidden rounded-md border border-line bg-surface py-1 text-xs shadow-card"
        >
          {(Object.keys(LABELS) as ReportFormat[]).map((format) => (
            <li key={format} role="none">
              <button
                role="menuitem"
                className="block w-full px-3 py-1.5 text-left hover:bg-canvas text-ink"
                onClick={() => void run(format)}
              >
                {LABELS[format]}
              </button>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
