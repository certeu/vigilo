// Thin API client. Stores the JWT in localStorage and attaches it as a Bearer
// token. All calls go through the same-origin /api proxy (see vite.config.ts).

const TOKEN_KEY = "vigilo_token";

export function getToken(): string | null {
  return localStorage.getItem(TOKEN_KEY);
}
export function setToken(t: string | null): void {
  if (t) localStorage.setItem(TOKEN_KEY, t);
  else localStorage.removeItem(TOKEN_KEY);
}

async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  const token = getToken();
  if (token) headers.set("Authorization", `Bearer ${token}`);
  if (init.body && !headers.has("Content-Type"))
    headers.set("Content-Type", "application/json");
  const resp = await fetch(`/api${path}`, { ...init, headers });
  if (resp.status === 401) {
    setToken(null);
    throw new ApiError(401, "Unauthorized");
  }
  if (!resp.ok) {
    let detail = resp.statusText;
    try {
      detail = (await resp.json()).detail ?? detail;
    } catch {
      /* ignore */
    }
    throw new ApiError(resp.status, String(detail));
  }
  if (resp.status === 204) return undefined as T;
  return (await resp.json()) as T;
}

export class ApiError extends Error {
  constructor(public status: number, message: string) {
    super(message);
  }
}

export interface User {
  id: string;
  email: string;
  role: string;
  is_active?: boolean;
}
export interface Repository {
  id: string;
  created_by: string;
  name: string;
  source_type: string;
  gitlab_url: string | null;
  has_webhook: boolean;
  is_private: boolean;
  upload_ready: boolean;
  push_patches: boolean;
  ingestion_status: string;
  ingestion_error: string | null;
  pipeline_config: Record<string, string>;
  scan_config: Record<string, string>;
  created_at: string;
}
export interface AccessGrant {
  user_id: string;
  email: string;
  created_at: string;
}
export interface Package {
  package: string;
  version: string;
  ecosystem: string;
  severity: string;
  cve: string | null;
  fixed_version: string | null;
  repos?: number;
}
export interface Job {
  id: string;
  repository_id: string;
  name: string;
  stage_preset: string;
  target_url: string | null;
  engine: string;
  notify_email: boolean;
}
export interface Run {
  id: string;
  job_id: string;
  status: string;
  trigger_type: string;
  current_phase: string | null;
  session_id: string;
  workflow_id: string | null;
  total_cost_usd: number | null;
  error_summary: string | null;
  commit_sha: string | null;
  started_at: string | null;
  finished_at: string | null;
  created_at: string;
}

export interface Schedule {
  id: string;
  job_id: string;
  kind: string;
  cron: string | null;
  run_at: string | null;
  enabled: boolean;
  created_at: string;
}
export interface Invitation {
  id: string;
  email: string;
  role: string;
  accepted: boolean;
  created_at: string;
}
export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
}
export interface RunMetrics {
  run_id: string;
  repository_id: string;
  computed_at: string;
  total_findings: number;
  severity_counts: SeverityCounts;
  exploited: number;
  supply_chain: number;
  category_counts: Record<string, number>;
  display_names: Record<string, string>;
  supply_chain_packages: Package[];
  parse_error?: boolean;
  supply_chain_scanned?: boolean;
}
export interface RepoTree {
  available: boolean;
  paths: string[];
  truncated: boolean;
  count: number;
}
export interface GlobalMetrics {
  repositories_scanned: number;
  total_findings: number;
  exploited: number;
  supply_chain: number;
  severity_totals: SeverityCounts;
  category_totals: Record<string, number>;
  top_repositories: Array<{
    repository_id: string;
    repository_name: string;
    total_findings: number;
    critical: number;
    high: number;
    exploited: number;
    supply_chain: number;
  }>;
  top_packages: Package[];
}

export interface TraceRailConfig {
  steps: { key: string; label: string }[];
  presets: Record<string, string[]>;
  phase_to_step: Record<string, string>;
  agent_to_step: Record<string, string>;
}

export const api = {
  traceRail: () => request<TraceRailConfig>("/pipeline/trace-rail"),
  async login(email: string, password: string): Promise<string> {
    const form = new URLSearchParams({ username: email, password });
    const resp = await fetch(`/api/auth/jwt/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form,
    });
    if (!resp.ok) throw new ApiError(resp.status, "Login failed");
    const { access_token } = await resp.json();
    setToken(access_token);
    return access_token;
  },
  me: () => request<User>("/users/me"),
  repositories: () => request<Repository[]>("/repositories"),
  createRepository: (body: Partial<Repository> & { gitlab_token?: string; push_patches?: boolean }) =>
    request<Repository>("/repositories", { method: "POST", body: JSON.stringify(body) }),
  deleteRepository: (id: string) =>
    request<void>(`/repositories/${id}`, { method: "DELETE" }),
  deleteRun: (id: string) => request<void>(`/runs/${id}`, { method: "DELETE" }),
  bulkDeleteRepositories: (ids: string[]) =>
    request<{ deleted: string[]; denied: string[] }>("/repositories/bulk-delete", {
      method: "POST", body: JSON.stringify({ ids }),
    }),
  jobs: () => request<Job[]>("/jobs"),
  deleteJob: (id: string) => request<void>(`/jobs/${id}`, { method: "DELETE" }),
  patchJob: (id: string, body: Record<string, unknown>) =>
    request<Job>(`/jobs/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  createJob: (body: Record<string, unknown>) =>
    request<Job>("/jobs", { method: "POST", body: JSON.stringify(body) }),
  runJob: (jobId: string) =>
    request<Run>(`/jobs/${jobId}/run`, { method: "POST" }),
  runs: (repositoryId?: string) =>
    request<Run[]>(`/runs${repositoryId ? `?repository_id=${repositoryId}` : ""}`),
  run: (id: string) => request<Run>(`/runs/${id}`),
  cancelRun: (id: string) => request<Run>(`/runs/${id}/cancel`, { method: "POST" }),
  repository: (id: string) => request<Repository>(`/repositories/${id}`),
  updateRepository: (id: string, body: Record<string, unknown>) =>
    request<Repository>(`/repositories/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  async uploadSource(id: string, files: FileList | File[]): Promise<Repository> {
    const form = new FormData();
    for (const f of Array.from(files)) {
      // preserve relative path for folder uploads
      const name = (f as File & { webkitRelativePath?: string }).webkitRelativePath || f.name;
      form.append("files", f, name);
    }
    const resp = await fetch(`/api/repositories/${id}/upload`, {
      method: "POST",
      headers: { Authorization: `Bearer ${getToken()}` },
      body: form,
    });
    if (!resp.ok) throw new ApiError(resp.status, "Upload failed");
    return (await resp.json()) as Repository;
  },
  repoAccess: (id: string) => request<AccessGrant[]>(`/repositories/${id}/access`),
  grantAccessByEmail: (id: string, email: string) =>
    request<AccessGrant>(`/repositories/${id}/access`, {
      method: "POST", body: JSON.stringify({ email }),
    }),
  revokeAccess: (id: string, userId: string) =>
    request<void>(`/repositories/${id}/access/${userId}`, { method: "DELETE" }),

  // Dashboards
  dashboardMetrics: () => request<GlobalMetrics>("/dashboard/metrics"),
  runMetrics: (id: string) => request<RunMetrics>(`/runs/${id}/metrics`),
  repoTimeline: (id: string) =>
    request<{ timeline: RunMetrics[] }>(`/repositories/${id}/metrics/timeline`),
  repoTree: (id: string) => request<RepoTree>(`/repositories/${id}/tree`),

  // Schedules
  schedules: () => request<Schedule[]>("/schedules"),
  createSchedule: (body: Record<string, unknown>) =>
    request<Schedule>("/schedules", { method: "POST", body: JSON.stringify(body) }),
  patchSchedule: (id: string, body: Record<string, unknown>) =>
    request<Schedule>(`/schedules/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteSchedule: (id: string) =>
    request<void>(`/schedules/${id}`, { method: "DELETE" }),

  // Password: self change (returns a fresh token to keep this session), forgot/reset
  async changePassword(current_password: string, new_password: string) {
    const r = await request<{ access_token: string }>("/users/me/change-password", {
      method: "POST", body: JSON.stringify({ current_password, new_password }),
    });
    setToken(r.access_token); // other sessions were invalidated; keep THIS one alive
    return r;
  },
  forgotPassword: (email: string) =>
    request<void>("/auth/forgot-password", { method: "POST", body: JSON.stringify({ email }) }),
  resetPassword: (token: string, password: string) =>
    request<void>("/auth/reset-password", { method: "POST", body: JSON.stringify({ token, password }) }),

  // Admin: users + invitations
  users: () => request<User[]>("/users"),
  patchUser: (id: string, body: Record<string, unknown>) =>
    request<User>(`/users/${id}`, { method: "PATCH", body: JSON.stringify(body) }),
  deleteUser: (id: string) => request<void>(`/users/${id}`, { method: "DELETE" }),
  adminResetPassword: (id: string) =>
    request<{ reset_url: string; email_sent: boolean; email_error: string | null }>(
      `/users/${id}/reset-password`, { method: "POST" }),
  invitations: () => request<Invitation[]>("/invitations"),
  createInvitation: (email: string, role: string) =>
    request<Invitation & { accept_url: string; email_sent: boolean; email_error: string | null }>(
      "/invitations", { method: "POST", body: JSON.stringify({ email, role }) }),
  revokeInvitation: (id: string) =>
    request<void>(`/invitations/${id}`, { method: "DELETE" }),
  acceptInvite: (token: string, password: string) =>
    request<{ status: string; email: string }>("/auth/accept-invite", {
      method: "POST",
      body: JSON.stringify({ token, password }),
    }),
};
