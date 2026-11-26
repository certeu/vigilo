import { useId } from "react";
import type { AssessmentMode, NetworkScope } from "./types";

/** Comma/space separated ports and "a-b" ranges, as the server accepts them. */
export function parsePorts(raw: string): (number | string)[] {
  return raw.split(/[\s,]+/).map((p) => p.trim()).filter(Boolean)
    .map((p) => (/^\d+$/.test(p) ? Number(p) : p));
}

/** One address, CIDR block or exact host name per line (or comma separated). */
export function parseTargets(raw: string): string[] {
  return raw.split(/[\n,]+/).map((t) => t.trim()).filter(Boolean);
}

export const EMPTY_NETWORK: NetworkScope = { targets: [], ports: [], protocols: ["tcp"], rate_per_s: 5 };

const PROTOCOLS: { id: NetworkScope["protocols"][number]; label: string }[] = [
  { id: "tcp", label: "TCP connect + banner" },
  { id: "dns", label: "DNS for listed names" },
  { id: "http", label: "HTTP to listed address:port" },
];

/** Assessment mode and, for a network assessment, the explicit boundary: listed
 *  addresses / CIDR blocks / names and ports only — the server re-validates and caps
 *  it (at most 256 addresses and 256 ports, no wildcards). */
export function AssessmentModeEditor({
  mode, network, onMode, onNetwork, errors = [],
}: {
  mode: AssessmentMode;
  network: NetworkScope;
  onMode: (m: AssessmentMode) => void;
  onNetwork: (n: NetworkScope) => void;
  errors?: string[];
}) {
  const id = useId();
  return (
    <fieldset>
      <legend className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">Assessment type</legend>
      <label className="flex items-center gap-2 text-sm" htmlFor={`${id}-mode`}>
        Target
        <select id={`${id}-mode`} className="rounded border border-line bg-surface px-2 py-1 text-sm"
          value={mode} onChange={(e) => onMode(e.target.value as AssessmentMode)}>
          <option value="web">Web application / API (HTTP + browser)</option>
          <option value="network">Network segment (hosts and services)</option>
        </select>
      </label>
      {mode === "network" && (
        <div className="mt-3 grid gap-3 sm:grid-cols-2">
          <label className="block text-sm" htmlFor={`${id}-targets`}>
            Authorised targets
            <textarea id={`${id}-targets`} rows={3} className="mt-1 w-full rounded border border-line bg-surface px-2 py-1 font-mono text-sm"
              placeholder={"10.0.4.0/28\ndb.lab.example"} value={network.targets.join("\n")}
              onChange={(e) => onNetwork({ ...network, targets: parseTargets(e.target.value) })} />
            <span className="text-xs text-slate">Addresses, CIDR blocks (≤ 256 addresses) or exact names. Neighbours are never contacted.</span>
          </label>
          <div className="space-y-2">
            <label className="block text-sm" htmlFor={`${id}-ports`}>
              Authorised ports
              <input id={`${id}-ports`} className="mt-1 w-full rounded border border-line bg-surface px-2 py-1 font-mono text-sm"
                placeholder="22, 80, 443, 8000-8010" value={network.ports.join(", ")}
                onChange={(e) => onNetwork({ ...network, ports: parsePorts(e.target.value) })} />
            </label>
            <div className="text-sm">
              Protocols
              {PROTOCOLS.map((p) => (
                <label key={p.id} className="ml-3 inline-flex items-center gap-1">
                  <input type="checkbox" checked={network.protocols.includes(p.id)}
                    onChange={(e) => onNetwork({ ...network, protocols: e.target.checked
                      ? [...network.protocols, p.id] : network.protocols.filter((x) => x !== p.id) })} />
                  {p.label}
                </label>
              ))}
            </div>
            <label className="block text-sm" htmlFor={`${id}-rate`}>
              Connections per second
              <input id={`${id}-rate`} type="number" min={0.2} max={20} step={0.2}
                className="ml-2 w-20 rounded border border-line bg-surface px-2 py-1 text-sm"
                value={network.rate_per_s ?? 5}
                onChange={(e) => onNetwork({ ...network, rate_per_s: Number(e.target.value) })} />
            </label>
          </div>
          {errors.length > 0 && (
            <ul role="alert" className="text-xs text-severity-critical sm:col-span-2">{errors.map((e, i) => <li key={i}>{e}</li>)}</ul>
          )}
        </div>
      )}
    </fieldset>
  );
}
