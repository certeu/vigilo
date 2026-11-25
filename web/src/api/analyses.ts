// Unified cross-mode list: GET /analyses.
import { request } from "./client";
import type { AnalysisMode } from "../components/ui/ModeBadge";
import type { Severity } from "../features/greybox/types";

export interface AnalysisItem {
  mode: AnalysisMode;
  id: string;
  /** Job name (white-box) or target name (grey-box). */
  name: string;
  subject:
    /** The backend sends `base_url: null` on white-box rows. */
    | { type: "repository"; id: string; name: string; base_url?: null }
    | { type: "target"; id: string; name: string; base_url: string };
  status: string;
  phase: string | null;
  owner_id: string;
  created_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_s: number | null;
  /** null when no metrics exist yet (white-box without a RunMetrics row). */
  findings: { total: number; by_severity: Record<Severity, number> } | null;
  href: string;
}

export interface AnalysesPage {
  items: AnalysisItem[];
  next_cursor: string | null;
}

export type AnalysisModeFilter = "all" | AnalysisMode;

export function listAnalyses(p: {
  mode?: AnalysisModeFilter;
  /** One status or a comma-separated list (e.g. "queued,preparing,running,cancelling"). */
  status?: string;
  q?: string;
  limit?: number;
  cursor?: string | null;
}): Promise<AnalysesPage> {
  const sp = new URLSearchParams();
  if (p.mode) sp.set("mode", p.mode);
  if (p.status) sp.set("status", p.status);
  if (p.q) sp.set("q", p.q);
  if (p.limit) sp.set("limit", String(p.limit)); // the server clamps to 1..100
  if (p.cursor) sp.set("cursor", p.cursor);
  const s = sp.toString();
  return request<AnalysesPage>(`/analyses${s ? `?${s}` : ""}`);
}
