import { useEffect, useState } from "react";
import { getToken } from "../api/client";

// The report references its evidence relatively (`screenshots/x.png`), which the
// browser would resolve against the page URL. Fetch those through the API with
// the normal Bearer header and show them as blob URLs, so the session token
// never ends up in an image URL (and from there in access logs).

function safeDecode(segment: string): string {
  try {
    return decodeURIComponent(segment);
  } catch {
    return segment;
  }
}

/** API path for a report-relative screenshot, or null for any other src. */
export function screenshotApiPath(runId: string, src: string | undefined): string | null {
  if (!src) return null;
  const rel = src.replace(/^\.\//, "");
  if (!rel.startsWith("screenshots/")) return null;
  // Markdown destinations are already percent-encoded (`xss%20alert.png`):
  // decode each segment before encoding it, so it isn't encoded twice.
  const encoded = rel
    .split("/")
    .filter((seg) => seg !== "" && seg !== ".")
    .map((seg) => encodeURIComponent(safeDecode(seg)))
    .join("/");
  return `/api/runs/${runId}/files/${encoded}`;
}

export function ReportImage({
  runId,
  src,
  alt,
  title,
}: {
  runId: string;
  src?: string;
  alt?: string;
  title?: string;
}) {
  const apiPath = screenshotApiPath(runId, src);
  const [blobUrl, setBlobUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);

  useEffect(() => {
    if (!apiPath) return;
    const controller = new AbortController();
    let objectUrl: string | null = null;
    setBlobUrl(null);
    setFailed(false);
    fetch(apiPath, {
      headers: { Authorization: `Bearer ${getToken()}` },
      signal: controller.signal,
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`);
        return r.blob();
      })
      .then((blob) => {
        if (controller.signal.aborted) return;
        objectUrl = URL.createObjectURL(blob);
        setBlobUrl(objectUrl);
      })
      .catch(() => {
        if (!controller.signal.aborted) setFailed(true);
      });
    return () => {
      controller.abort();
      if (objectUrl) URL.revokeObjectURL(objectUrl);
    };
  }, [apiPath]);

  if (!apiPath) return <img src={src} alt={alt} title={title} />;
  if (failed)
    return (
      <span className="text-xs text-slate-500" title={title}>
        [Screenshot unavailable: {alt || src}]
      </span>
    );
  if (!blobUrl) return <span className="text-xs text-slate-500">Loading {alt || "screenshot"}…</span>;
  return <img src={blobUrl} alt={alt} title={title} />;
}
