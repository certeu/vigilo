import type { AccessCounts, SecurityModelView } from "../types";

/** Human labels for where an access expectation comes from. */
export const BASIS_LABEL: Record<string, string> = {
  documented: "documented",
  configured: "configured by the operator",
  observed_ui: "observed in the application",
  stated: "assumption",
};

/** "3 / 1 / 0" — allowed / denied / not found reads of one identity on one interface. */
export function accessCell(c: AccessCounts | undefined): string {
  if (!c) return "—";
  return `${c.allow ?? 0} / ${c.deny ?? 0} / ${c.missing ?? 0}`;
}

/** Strip the entity kind prefix for display: "identity:dave" -> "dave". */
export function entityName(key: string): string {
  const i = key.indexOf(":");
  return i >= 0 ? key.slice(i + 1) : key;
}

export interface ModelSummary {
  identities: number;
  interfaces: number;
  expectations: number;
  assumptions: number;
  signals: number;
  unresolved: number;
  empty: boolean;
}

export function summarise(m: SecurityModelView | null): ModelSummary {
  const assumptions = (m?.expectations ?? []).filter((e) => e.basis === "stated").length;
  const s = {
    identities: m?.identities.length ?? 0,
    interfaces: m?.interfaces.length ?? 0,
    expectations: m?.expectations.length ?? 0,
    assumptions,
    signals: m?.signals.length ?? 0,
    unresolved: m?.unresolved.length ?? 0,
  };
  return { ...s, empty: !s.interfaces && !s.expectations && !(m?.entities.length ?? 0) };
}

/** Identities worth a column: the ones that made comparable requests. */
export function identityColumns(m: SecurityModelView): string[] {
  return m.identities.map((i) => i.identity);
}
