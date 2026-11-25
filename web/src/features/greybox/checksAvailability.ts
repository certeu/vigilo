import type { GreyboxCheck, SkippedCheck } from "./types";

export const UNAVAILABLE_BADGE = "Not available in this build";

/** A missing flag (older backend) means available. */
export function isAvailable(c: Pick<GreyboxCheck, "available">): boolean {
  return c.available !== false;
}

export function unavailableIds(checks: GreyboxCheck[]): Set<string> {
  return new Set(checks.filter((c) => !isAvailable(c)).map((c) => c.id));
}

export function unavailableReason(c: GreyboxCheck): string {
  return c.unavailable_reason || UNAVAILABLE_BADGE;
}

export interface CheckAreaGroup {
  area: string;
  evidence: string;
  checks: GreyboxCheck[];
}

/** Groups server-driven catalogue entries while retaining their advertised order. */
export function checksByArea(checks: GreyboxCheck[]): CheckAreaGroup[] {
  const groups = new Map<string, CheckAreaGroup>();
  for (const check of checks) {
    const area = check.area ?? "Other checks";
    const evidence = check.evidence ?? "A reproducible observation from the affected interface.";
    const group = groups.get(area) ?? { area, evidence, checks: [] };
    group.checks.push(check);
    groups.set(area, group);
  }
  return [...groups.values()];
}

/** Selected ids that this build cannot run (they will be skipped). */
export function willBeSkipped(selected: string[], checks: GreyboxCheck[]): string[] {
  const un = unavailableIds(checks);
  return selected.filter((id) => un.has(id));
}

/** Short summary, e.g. "5 checks not available in this build". null when none. */
export function skippedSummary(skipped: SkippedCheck[] | null | undefined): string | null {
  const n = skipped?.length ?? 0;
  return n ? `${n} check${n === 1 ? "" : "s"} not available in this build` : null;
}

/** Multi-line hover text listing each skipped check and its reason. */
export function skippedDetail(skipped: SkippedCheck[] | null | undefined): string {
  return (skipped ?? []).map((s) => `${s.id}: ${s.reason}`).join("\n");
}
