// Per-service attack-surface panel. Pure rendering of serviceSurface(); it re-renders
// whenever the asset graph delta replaces the service node (live). All values are
// untrusted target data and rendered as text.
import type { ReactNode } from "react";
import type { AssetNode } from "../types";
import { assetVisual, endpointSurface, riskLevel, serviceSurface, VISUAL_STYLE, type RiskLevel } from "./model";

export const RISK_STYLE: Record<RiskLevel, { label: string; chip: string; bar: string }> = {
  low: { label: "Low", chip: "border-emerald-600/40 bg-emerald-50 text-emerald-800", bar: "bg-emerald-600" },
  medium: { label: "Medium", chip: "border-severity-medium/40 bg-amber-50 text-severity-medium", bar: "bg-severity-medium" },
  high: { label: "High", chip: "border-severity-critical/40 bg-red-50 text-severity-critical", bar: "bg-severity-critical" },
};

export function RiskBadge({ score }: { score: number | null }) {
  const lvl = riskLevel(score);
  if (score === null || !lvl) return null;
  const s = RISK_STYLE[lvl];
  return (
    <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-px text-[12px] font-semibold tabular-nums ${s.chip}`} title={`Risk score ${score} of 100 (${s.label})`}>
      Risk {score}
      <span className="sr-only"> of 100, {s.label}</span>
    </span>
  );
}

/** Present vs missing security headers as a segmented bar (text counts accompany it). */
export function HeaderPostureBar({ present, missing, className = "" }: { present: number; missing: number; className?: string }) {
  const total = present + missing;
  if (!total) return null;
  return (
    <span
      className={`flex h-1.5 w-full overflow-hidden rounded-full bg-line ${className}`}
      role="img"
      aria-label={`${present} of ${total} security headers present, ${missing} missing`}
    >
      <span className="bg-emerald-600" style={{ width: `${(present / total) * 100}%` }} />
      <span className="bg-severity-high/80" style={{ width: `${(missing / total) * 100}%` }} />
    </span>
  );
}

function Yes({ ok, yes, no }: { ok: boolean | null; yes: string; no: string }) {
  if (ok === null) return <span className="text-slate">unknown</span>;
  return <span className={ok ? "text-emerald-800" : "text-severity-critical"}>{ok ? `✓ ${yes}` : `✕ ${no}`}</span>;
}

function Chip({ children, tone = "plain" }: { children: ReactNode; tone?: "plain" | "good" | "bad" }) {
  const cls = tone === "good" ? "border-emerald-600/30 bg-emerald-50 text-emerald-800" : tone === "bad" ? "border-severity-high/40 bg-orange-50 text-severity-high" : "border-line bg-canvas text-ink";
  return <span className={`mono inline-block rounded border px-1.5 py-px text-[12px] ${cls}`}>{children}</span>;
}

export function SurfacePanel({ service }: { service: AssetNode }) {
  const s = serviceSurface(service.data);
  if (!s) {
    return (
      <section aria-label={`Surface of ${service.label}`} className="rounded-lg border border-dashed border-line p-3 text-[13px] text-slate">
        No surface data for this service yet. It fills in as the run observes responses.
      </section>
    );
  }
  const lvl = s.riskLevel ? RISK_STYLE[s.riskLevel] : null;
  return (
    <section aria-label={`Surface of ${service.label}`} className="space-y-3 text-[13px]">
      {s.riskScore !== null && lvl && (
        <div>
          <div className="flex items-center gap-2">
            <RiskBadge score={s.riskScore} />
            <span className="h-2 flex-1 overflow-hidden rounded-full bg-line" aria-hidden="true">
              <span className={`block h-full ${lvl.bar}`} style={{ width: `${s.riskScore}%` }} />
            </span>
          </div>
          <p className="mt-1.5 text-xs font-medium uppercase tracking-wide text-slate">Why this score</p>
          <ul className="mt-0.5 list-disc space-y-0.5 pl-4 text-ink">
            {s.explanation.map((x) => (
              <li key={x} className="break-words">{x}</li>
            ))}
          </ul>
        </div>
      )}

      {(s.server || s.technologies.length > 0) && (
        <div>
          <h4 className="text-xs font-medium uppercase tracking-wide text-slate">Server and technologies</h4>
          <div className="mt-1 flex flex-wrap gap-1">
            {s.server && <Chip>{s.server}</Chip>}
            {s.technologies.map((t) => <Chip key={t}>{t}</Chip>)}
          </div>
        </div>
      )}

      <div>
        <h4 className="text-xs font-medium uppercase tracking-wide text-slate">
          Security headers <span className="normal-case tabular-nums">({s.headers.presentCount} present, {s.headers.missingCount} missing)</span>
        </h4>
        <HeaderPostureBar present={s.headers.presentCount} missing={s.headers.missingCount} className="mt-1" />
        <div className="mt-1.5 flex flex-wrap gap-1">
          {s.headers.present.map((h) => <Chip key={`p:${h}`} tone="good">✓ {h}</Chip>)}
          {s.headers.missing.map((h) => <Chip key={`m:${h}`} tone="bad">✕ {h}</Chip>)}
        </div>
      </div>

      {s.cookies.length > 0 && (
        <div>
          <h4 className="text-xs font-medium uppercase tracking-wide text-slate">Cookies</h4>
          <div className="mt-1 overflow-x-auto">
            <table className="w-full text-left text-[12px]">
              <caption className="sr-only">Cookie flags</caption>
              <thead className="text-slate">
                <tr><th scope="col" className="pr-2 font-medium">Name</th><th scope="col" className="pr-2 font-medium">Secure</th><th scope="col" className="pr-2 font-medium">HttpOnly</th><th scope="col" className="font-medium">SameSite</th></tr>
              </thead>
              <tbody>
                {s.cookies.map((c) => (
                  <tr key={c.name} className="border-t border-line align-top">
                    <th scope="row" className="mono break-all py-1 pr-2 font-normal">{c.name}</th>
                    <td className="pr-2"><Yes ok={c.secure} yes="yes" no="no" /></td>
                    <td className="pr-2"><Yes ok={c.httpOnly} yes="yes" no="no" /></td>
                    <td>{c.sameSite ?? <span className="text-severity-critical">✕ none</span>}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
        {s.cors && (
          <>
            <dt className="text-slate">CORS</dt>
            <dd className={s.cors.risky ? "font-medium text-severity-critical" : "text-ink"}>
              {s.cors.reflectsOrigin ? "reflects the Origin header" : s.cors.wildcard ? "allows any origin" : "does not reflect the Origin header"}
              {s.cors.allowsCredentials ? ", allows credentials" : ""}
              {s.cors.risky ? " (risky combination)" : ""}
            </dd>
          </>
        )}
        {s.versionDisclosure.length > 0 && (<><dt className="text-slate">Version banner</dt><dd className="break-words">{s.versionDisclosure.join(", ")}</dd></>)}
        {s.tls && (<><dt className="text-slate">TLS</dt><dd className="break-words">{s.tls}</dd></>)}
        {s.redirects && (
          <>
            <dt className="text-slate">Redirects</dt>
            <dd>{s.redirects.count} followed{s.redirects.externalBlocked ? `, ${s.redirects.externalBlocked} to other hosts blocked` : ""}</dd>
          </>
        )}
        {s.endpoints && (
          <>
            <dt className="text-slate">Endpoints</dt>
            <dd className="tabular-nums">
              {s.endpoints.total} pages and API endpoints found, {s.endpoints.tested} tested, {s.endpoints.withFindings} with findings{s.endpoints.static > 0 ? `; ${s.endpoints.static} static asset${s.endpoints.static === 1 ? "" : "s"} not counted` : ""}
            </dd>
            <dt className="text-slate">Sensitive</dt>
            <dd className="tabular-nums">{s.endpoints.sensitive} sensitive, {s.endpoints.authLike} authentication-like</dd>
          </>
        )}
      </dl>

      {s.sensitivePaths.length > 0 && (
        <div>
          <h4 className="text-xs font-medium uppercase tracking-wide text-slate">Sensitive endpoints</h4>
          <ul className="mt-1 space-y-0.5">
            {s.sensitivePaths.map((p) => (
              <li key={p.path} className="flex flex-wrap gap-x-2">
                <span className="mono break-all text-[12px] text-ink">{p.path}</span>
                <span className="text-[12px] text-slate">{p.reason}{p.served ? ", served" : ""}</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}

/** Surface facts of one endpoint (drawer). */
export function EndpointSurfaceBlock({ node }: { node: AssetNode }) {
  const s = endpointSurface(node.data);
  const v = VISUAL_STYLE[assetVisual(node)];
  return (
    <div className="space-y-2 text-[13px]">
      <p>
        <span className={`inline-flex items-center gap-1 rounded border px-1.5 py-px text-[12px] font-semibold ${v.chip}`}><span aria-hidden="true">{v.glyph}</span>{v.label}</span>
      </p>
      {s ? (
        <dl className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1">
          {s.methods.length > 0 && (<><dt className="text-slate">Methods</dt><dd className="mono break-words">{s.methods.join(", ")}</dd></>)}
          {s.statusCodes.length > 0 && (<><dt className="text-slate">Status codes</dt><dd className="mono break-words">{s.statusCodes.join(", ")}</dd></>)}
          {s.contentTypes.length > 0 && (<><dt className="text-slate">Content types</dt><dd className="mono break-words">{s.contentTypes.join(", ")}</dd></>)}
          {s.params > 0 && (<><dt className="text-slate">Parameters</dt><dd className="tabular-nums">{s.params}</dd></>)}
          <dt className="text-slate">Form</dt>
          <dd>{s.passwordForm ? "contains a password form" : s.hasForm ? "contains a form" : "no form"}</dd>
          {s.sensitive && (<><dt className="text-slate">Sensitive</dt><dd className="break-words font-medium text-severity-high">{s.sensitive}</dd></>)}
        </dl>
      ) : (
        <p className="text-slate">No surface details for this endpoint yet.</p>
      )}
    </div>
  );
}
