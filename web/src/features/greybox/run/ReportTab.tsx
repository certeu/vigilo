import { useEffect, useState } from "react";
import ReactMarkdown, { type Components } from "react-markdown";
import remarkGfm from "remark-gfm";
import { ArrowDownTrayIcon, DocumentTextIcon } from "@heroicons/react/24/outline";
import { ApiError } from "../../../api/client";
import { EmptyState, ErrorState, humanizeError, Skeleton } from "../../../components/ui";
import { greyboxApi } from "../api";
import { formatDate } from "../format";
import { RUN_TERMINAL, type ReportRead, type ReportStatus, type RunStatus } from "../types";

// Safe rendering of untrusted report markdown (it quotes target responses):
// - no raw HTML (skipHtml; react-markdown never injects HTML without rehype-raw),
// - react-markdown's default URL transform drops javascript:/data: links,
// - links open in a new tab without referrer or opener,
// - remote images are not loaded (they could beacon out); the alt text is shown instead.
const MD_COMPONENTS: Components = {
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noopener noreferrer nofollow">
      {children}
    </a>
  ),
  img: ({ alt, src }) => (
    <span className="mono text-xs text-slate" title={typeof src === "string" ? src : undefined}>
      [image{alt ? `: ${alt}` : ""}]
    </span>
  ),
};

const REPORT_POLL_MS = 3000;

type State =
  | { kind: "loading" }
  | { kind: "ok"; report: ReportRead }
  | { kind: "unavailable" }
  | { kind: "error"; error: unknown };

export function ReportTab({
  runId,
  runStatus,
  reportStatus,
}: {
  runId: string;
  runStatus: RunStatus;
  /** RunRead.report_status when the API returns it. */
  reportStatus?: ReportStatus;
}) {
  const [state, setState] = useState<State>({ kind: "loading" });
  const [downloadError, setDownloadError] = useState<string | null>(null);
  const [downloading, setDownloading] = useState(false);
  const [nonce, setNonce] = useState(0);
  // A run that failed or was cancelled never reports (the report is generated
  // before a successful run turns terminal), so a pending report is final then.
  const noReportComing = runStatus === "failed" || runStatus === "cancelled";
  const settled =
    state.kind === "unavailable" ||
    (state.kind === "ok" &&
      (state.report.status === "ready" ||
        state.report.status === "failed" ||
        (state.report.status === "pending" && noReportComing)));

  // Fetch now, then every 3 s until the report is ready or failed (it may still be
  // generating right after the run turns terminal, when run polling has stopped).
  // A change of report_status/run status from the run poll triggers an immediate fetch.
  useEffect(() => {
    if (settled) return;
    let alive = true;
    const fetchOnce = () =>
      greyboxApi
        .report(runId)
        .then((r) => alive && setState({ kind: "ok", report: r }))
        .catch((e: unknown) => {
          if (!alive) return;
          if (e instanceof ApiError && e.status === 404) setState({ kind: "unavailable" });
          else setState({ kind: "error", error: e });
        });
    void fetchOnce();
    const t = setInterval(() => !document.hidden && void fetchOnce(), REPORT_POLL_MS);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, [runId, reportStatus, runStatus, settled, nonce]);

  async function download() {
    setDownloading(true);
    setDownloadError(null);
    try {
      await greyboxApi.downloadReport(runId);
    } catch (e) {
      setDownloadError(e instanceof Error ? e.message : "Download failed");
    } finally {
      setDownloading(false);
    }
  }

  if (state.kind === "loading")
    return (
      <div className="card space-y-3 p-6" role="status" aria-label="Loading report">
        <Skeleton className="h-5 w-1/3" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-full" />
        <Skeleton className="h-4 w-2/3" />
      </div>
    );
  if (state.kind === "unavailable")
    return (
      <div className="card">
        <EmptyState icon={DocumentTextIcon} title="Report not available">
          This server does not provide grey-box reports yet.
        </EmptyState>
      </div>
    );
  if (state.kind === "error")
    return (
      <ErrorState
        icon={DocumentTextIcon}
        title="Could not load the report"
        message={humanizeError(state.error, "the report")}
        onRetry={() => setNonce((n) => n + 1)}
      />
    );

  const r = state.report;
  const terminal = RUN_TERMINAL.has(runStatus);

  if (r.status !== "ready" || !r.markdown) {
    const msg =
      r.status === "failed"
        ? `Report generation failed${r.error ? `: ${r.error}` : "."}`
        : r.status === "generating"
          ? "The report is being generated. This page updates when it is ready."
          : terminal
            ? runStatus === "cancelled"
              ? "The run was cancelled before a report was produced."
              : runStatus === "failed"
                ? "The run failed before a report was produced. The error is shown above the tabs."
                : "The report has not been produced yet."
            : "The report is generated when the run finishes. It will appear here automatically.";
    return (
      <div className="card" aria-live="polite">
        <EmptyState
          icon={DocumentTextIcon}
          title={
            r.status === "failed"
              ? "Report failed"
              : r.status === "generating"
                ? "Generating report…"
                : terminal && noReportComing
                  ? "No report"
                  : "Report pending"
          }
        >
          {msg}
        </EmptyState>
      </div>
    );
  }

  return (
    <section className="card overflow-hidden" aria-label="Report">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-line px-4 py-2">
        <span className="text-xs text-slate">
          Generated {formatDate(r.generated_at)}
        </span>
        <div className="flex items-center gap-2">
          {downloadError && <span role="alert" className="text-xs text-severity-critical">{downloadError}</span>}
          <button type="button" className="btn-ghost py-1" onClick={download} disabled={downloading}>
            <ArrowDownTrayIcon className="h-4 w-4" /> {downloading ? "Downloading…" : "Download (.md)"}
          </button>
        </div>
      </div>
      <div className="markdown overflow-auto break-words p-4 sm:p-6">
        <ReactMarkdown remarkPlugins={[remarkGfm]} skipHtml components={MD_COMPONENTS}>
          {r.markdown}
        </ReactMarkdown>
      </div>
    </section>
  );
}
