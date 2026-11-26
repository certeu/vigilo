import type { FindingClass, FindingSummary } from "../features/greybox/types";

export interface CanonicalLocation {
  location: string;
  method: string;
  parameter: string;
  observationStatus: string;
  impactStatus: string;
  identities: string[];
  evidence: unknown[];
  observations: Record<string, any>[];
  verification: unknown | null;
  observationCount: number;
}

export interface CanonicalIssue {
  id: string;
  findingIds: string[];
  severity: FindingSummary["severity"];
  title: string;
  findingClass: FindingClass;
  verificationStatus: string;
  observationCount: number;
  affectedLocationCount: number;
  affectedLocations: CanonicalLocation[];
  rootCause: string;
  remediation: string;
  retest: string;
  correlationRationale: string;
  runId: string;
  runName: string;
}

type AnyFinding = FindingSummary & Record<string, any>;

const array = <T>(value: unknown): T[] => Array.isArray(value) ? value as T[] : [];
const text = (value: unknown): string => typeof value === "string" ? value : "";
const unique = <T>(values: T[]): T[] => [...new Map(values.map((value) =>
  [typeof value === "object" ? JSON.stringify(value) : String(value), value])).values()];

function locationOf(finding: AnyFinding): CanonicalLocation[] {
  const locations = array<Record<string, any>>(finding.affected_locations);
  if (locations.length) return locations.map((entry) => {
    const location = typeof entry.location === "object" ? entry.location : entry;
    const observations = array<Record<string, any>>(entry.observations);
    return {
      location: text(typeof entry.location === "string" ? entry.location : location.url ?? entry.url ?? entry.label) || "Unknown location",
      method: text(location.method), parameter: text(location.parameter),
      observationStatus: text(entry.observation_status ?? entry.verification_status),
      impactStatus: text(entry.impact_status), identities: array<string>(entry.identities).map(String),
      evidence: array(entry.evidence), observations, verification: entry.verification ?? null,
      observationCount: Number(entry.observation_count) || observations.length || Math.max(1, array(entry.evidence).length),
    };
  });

  const legacyLocation = finding.location ?? {};
  const primary = text(legacyLocation.url) || text(finding.affected_asset?.label) || "Unknown location";
  return [primary, ...array<string>(legacyLocation.also_at)].map((location, index) => ({
    location, method: text(legacyLocation.method), parameter: text(legacyLocation.parameter),
    observationStatus: text(finding.verification_status ?? finding.status), impactStatus: "",
    identities: array<string>(finding.identities).map(String), evidence: index === 0 ? array(finding.evidence) : [],
    observations: [], verification: index === 0 ? finding.verification ?? null : null,
    observationCount: index === 0 ? Number(finding.observation_count ?? finding.evidence_count) || 1 : 1,
  }));
}

function deduplicate(locations: CanonicalLocation[]): CanonicalLocation[] {
  const result = new Map<string, CanonicalLocation>();
  for (const location of locations) {
    const key = JSON.stringify([location.location, location.method, location.parameter]);
    const previous = result.get(key);
    if (!previous) result.set(key, location);
    else result.set(key, { ...previous,
      identities: unique([...previous.identities, ...location.identities]),
      evidence: unique([...previous.evidence, ...location.evidence]),
      observations: unique([...previous.observations, ...location.observations]),
      observationCount: Math.max(previous.observationCount, location.observationCount),
    });
  }
  return [...result.values()];
}

/** Uses only an explicit backend correlation identity; titles, routes and classes never merge issues. */
export function canonicalIssues(findings: readonly FindingSummary[], runId: string, runName: string): CanonicalIssue[] {
  const grouped = new Map<string, AnyFinding[]>();
  for (const finding of findings as readonly AnyFinding[]) {
    const canonicalId = text(finding.canonical_issue_id) || finding.id;
    grouped.set(canonicalId, [...(grouped.get(canonicalId) ?? []), finding]);
  }
  return [...grouped.entries()].map(([id, members]) => {
    const representative = members.find((member) => member.canonical_issue_id === id) ?? members[0];
    const locations = deduplicate(members.flatMap(locationOf));
    const recordedIds = array<Record<string, any>>(representative.findings).map((finding) => text(finding.finding_id)).filter(Boolean);
    return {
      id, findingIds: unique([...members.map((member) => member.id), ...recordedIds]), severity: representative.severity,
      title: representative.title, findingClass: representative.finding_class ?? "vulnerability",
      verificationStatus: text(representative.verification_status ?? representative.status),
      observationCount: Number(representative.observation_count) || locations.reduce((total, location) => total + location.observationCount, 0),
      affectedLocationCount: Number(representative.affected_location_count) || locations.length,
      affectedLocations: locations, rootCause: text(representative.root_cause),
      remediation: text(representative.remediation?.summary ?? representative.remediation),
      retest: text(representative.retesting_guidance ?? representative.retest ?? representative.remediation?.validation?.join("; ")),
      correlationRationale: text(representative.correlation_rationale ?? representative.correlation?.rationale),
      runId, runName,
    };
  });
}

export function verificationLabel(status: string, findingClass: FindingClass): string {
  const labels: Record<string, string> = {
    verified_impact: "Verified impact", confirmed_configuration: "Confirmed configuration weakness",
    confirmed_observation: "Confirmed observation", verified: findingClass === "vulnerability" ? "Verified impact" : "Confirmed observation",
    candidate: "Unverified impact", inconclusive: "Inconclusive", rejected: "Rejected",
    confirmed: "Confirmed observation", contradicted: "Contradicted", unverified: "Unverified impact",
  };
  return labels[status] ?? status.replace(/_/g, " ");
}
