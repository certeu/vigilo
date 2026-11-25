// Typed grey-box client. Backend paths are listed without /api;
// `request` adds it.
import { ApiError, getToken, request } from "../../api/client";
import type {
  AssetDetail, AssetGraphResponse, AssetNode, CancelRunRequest, ResumeRunRequest,
  Defense, DefenseDownloadFormat, SecurityModelView, DefenseFilter, Finding, FindingStatus, FindingSummary, GreyboxConfig, Severity, Hint, HintCreate, ReportRead, Page, RunRead, RunStatus, RunSummary, StartRunRequest,
  Exchange, ExchangeList, TrafficQuery, TargetCreate, TargetRead, TargetUpdate, TargetValidation,
  EgressProxy, EgressProxyWrite, AvailableEgressProxy, PreflightResult,
} from "./types";

function qs(params: Record<string, string | number | boolean | null | undefined>): string {
  const sp = new URLSearchParams();
  for (const [k, v] of Object.entries(params)) {
    if (v !== undefined && v !== null && v !== "") sp.set(k, String(v));
  }
  const s = sp.toString();
  return s ? `?${s}` : "";
}

const json = (body: unknown): RequestInit => ({ body: JSON.stringify(body) });

export const greyboxApi = {
  config: () => request<GreyboxConfig>("/greybox/config"),

  validateTarget: (body: TargetCreate) =>
    request<TargetValidation>("/greybox/targets/validate", { method: "POST", ...json(body) }),
  createTarget: (body: TargetCreate) =>
    request<TargetRead>("/greybox/targets", { method: "POST", ...json(body) }),
  targets: (p: { q?: string; archived?: boolean; limit?: number; cursor?: string | null } = {}) =>
    request<Page<TargetRead>>(`/greybox/targets${qs(p)}`),
  target: (id: string) => request<TargetRead>(`/greybox/targets/${encodeURIComponent(id)}`),
  updateTarget: (id: string, body: TargetUpdate) =>
    request<TargetRead>(`/greybox/targets/${encodeURIComponent(id)}`, { method: "PATCH", ...json(body) }),
  deleteTarget: (id: string) =>
    request<void>(`/greybox/targets/${encodeURIComponent(id)}`, { method: "DELETE" }),

  preflight: (targetId: string) =>
    request<PreflightResult>(`/greybox/targets/${encodeURIComponent(targetId)}/preflight`, { method: "POST" }),

  egressProxies: () => request<EgressProxy[]>("/greybox/egress-proxies"),
  createEgressProxy: (body: EgressProxyWrite) =>
    request<EgressProxy>("/greybox/egress-proxies", { method: "POST", ...json(body) }),
  updateEgressProxy: (id: string, body: Partial<EgressProxyWrite>) =>
    request<EgressProxy>(`/greybox/egress-proxies/${encodeURIComponent(id)}`, { method: "PATCH", ...json(body) }),
  deleteEgressProxy: (id: string) =>
    request<void>(`/greybox/egress-proxies/${encodeURIComponent(id)}`, { method: "DELETE" }),
  /** Any user. Resolves null when the route 404s (feature off); callers hide everything. */
  availableEgressProxies: (): Promise<AvailableEgressProxy[] | null> =>
    request<AvailableEgressProxy[]>("/greybox/egress-proxies/available").catch((e: unknown) => {
      if (e instanceof ApiError && e.status === 404) return null;
      throw e;
    }),

  startRun: (targetId: string, body: StartRunRequest) =>
    request<RunRead>(`/greybox/targets/${encodeURIComponent(targetId)}/runs`, { method: "POST", ...json(body) }),
  runs: (p: { target_id?: string; status?: RunStatus | string; limit?: number; cursor?: string | null } = {}) =>
    request<Page<RunSummary>>(`/greybox/runs${qs(p)}`),
  run: (id: string) => request<RunRead>(`/greybox/runs/${encodeURIComponent(id)}`),
  resumeRun: (id: string, body: ResumeRunRequest = {}) =>
    request<RunRead>(`/greybox/runs/${encodeURIComponent(id)}/resume`, { method: "POST", ...json(body) }),
  cancelRun: (id: string, body: CancelRunRequest = {}) =>
    request<RunRead>(`/greybox/runs/${encodeURIComponent(id)}/cancel`, { method: "POST", ...json(body) }),
  hints: (runId: string) =>
    request<{ items: Hint[] }>(`/greybox/runs/${encodeURIComponent(runId)}/hints`),
  addHint: (runId: string, body: HintCreate) =>
    request<Hint>(`/greybox/runs/${encodeURIComponent(runId)}/hints`, { method: "POST", ...json(body) }),
  report: (id: string) => request<ReportRead>(`/greybox/runs/${encodeURIComponent(id)}/report`),
  findings: (runId: string, f: { status?: FindingStatus; severity?: Severity } = {}) =>
    request<{ items: FindingSummary[] }>(`/greybox/runs/${encodeURIComponent(runId)}/findings${qs({ ...f })}`),
  traffic: (runId: string, q: TrafficQuery = {}) =>
    request<ExchangeList>(`/greybox/runs/${encodeURIComponent(runId)}/traffic${qs({ ...q })}`),
  exchange: (runId: string, exchangeId: number) =>
    request<Exchange>(`/greybox/runs/${encodeURIComponent(runId)}/traffic/${exchangeId}`),
  finding: (runId: string, findingId: string) =>
    request<Finding>(`/greybox/runs/${encodeURIComponent(runId)}/findings/${encodeURIComponent(findingId)}`),
  securityModel: (runId: string) =>
    request<SecurityModelView>(`/greybox/runs/${encodeURIComponent(runId)}/model`),
  defenses: (runId: string, f: DefenseFilter = {}) =>
    request<{ items: Defense[] }>(`/greybox/runs/${encodeURIComponent(runId)}/defenses${qs({ ...f })}`),
  assetGraph: (runId: string, sinceVersion = 0, limit = 5000, signal?: AbortSignal) =>
    request<AssetGraphResponse>(
      `/greybox/runs/${encodeURIComponent(runId)}/graph/assets${qs({ since_version: sinceVersion, limit })}`,
      { signal },
    ),
  asset: (runId: string, assetId: string, signal?: AbortSignal) =>
    request<AssetDetail & { node?: AssetNode }>(`/greybox/runs/${encodeURIComponent(runId)}/assets/${encodeURIComponent(assetId)}`, { signal }).then(
      (d): AssetDetail => (d.node ? { ...d.node, ...d } : d),
    ),
  /** Same authenticated attachment download as the report; `all` returns a zip. */
  downloadDefenses: async (id: string, format: DefenseDownloadFormat, includeUnverified = false): Promise<void> => {
    const qs = `format=${encodeURIComponent(format)}${includeUnverified ? "&include_unverified=true" : ""}`;
    const resp = await fetch(`/api/greybox/runs/${encodeURIComponent(id)}/defenses/download?${qs}`, {
      headers: { Authorization: `Bearer ${getToken() ?? ""}` },
    });
    if (!resp.ok) throw new ApiError(resp.status, resp.status === 404 ? "No defenses to download for this format." : `Download failed (${resp.status})`);
    const cd = resp.headers.get("Content-Disposition") ?? "";
    const name = /filename="?([^";]+)"?/i.exec(cd)?.[1] ?? `greybox-defenses-${id.slice(0, 8)}.${format === "all" ? "zip" : "txt"}`;
    const url = URL.createObjectURL(await resp.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  },
  /** Fetch the markdown attachment with the Bearer header and hand it to the browser. */
  downloadReport: async (id: string): Promise<void> => {
    const resp = await fetch(`/api/greybox/runs/${encodeURIComponent(id)}/report/download`, {
      headers: { Authorization: `Bearer ${getToken() ?? ""}` },
    });
    if (!resp.ok) throw new ApiError(resp.status, resp.status === 404 ? "The report is not ready yet." : `Download failed (${resp.status})`);
    const cd = resp.headers.get("Content-Disposition") ?? "";
    const name = /filename="?([^";]+)"?/i.exec(cd)?.[1] ?? `greybox-report-${id.slice(0, 8)}.md`;
    const url = URL.createObjectURL(await resp.blob());
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  },
};

export { qs };
