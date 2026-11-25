import { useEffect, useId, useMemo, useRef, useState, type FormEvent } from "react";
import { Link, useNavigate } from "react-router-dom";
import { ExclamationTriangleIcon, ShieldCheckIcon } from "@heroicons/react/24/outline";
import { api, ApiError, type Credential } from "../../api/client";
import { FieldError, asLocErrors, errorsFor, groupErrors, locLabel, type LocError } from "../../components/ui/FieldError";
import { greyboxApi } from "./api";
import { proxyChoices } from "./egressProxy";
import { useAvailableProxies } from "./egressProxyUi";
import { AssessmentModeEditor, EMPTY_NETWORK } from "./AssessmentModeEditor";
import { ScopeEditor } from "./ScopeEditor";
import { newIdempotencyKey } from "./format";
import { UNAVAILABLE_BADGE, checksByArea, isAvailable, unavailableReason } from "./checksAvailability";
import type { AssessmentMode, GreyboxConfig, Limits, NetworkScope, ScopePolicy, TargetCreate, TargetRead, TargetValidation } from "./types";

// Limits shown here are exactly the ones in the API contract; all are enforced by the
// engine. Minimums come from the contract; maximums from /greybox/config.
const LIMIT_FIELDS: { key: keyof Limits; label: string; unit: string; min: number; minutes?: boolean }[] = [
  { key: "max_requests", label: "Max requests", unit: "requests", min: 1 },
  { key: "max_duration_s", label: "Max duration", unit: "minutes", min: 60, minutes: true },
  { key: "max_concurrency", label: "Concurrency", unit: "parallel requests", min: 1 },
  { key: "rate_limit_rps", label: "Rate limit", unit: "requests / s", min: 1 },
  { key: "request_timeout_s", label: "Request timeout", unit: "seconds", min: 1 },
  { key: "max_pages", label: "Max pages", unit: "pages", min: 1 },
];

const EMPTY_SCOPE: ScopePolicy = {
  allowed_hosts: [],
  allowed_schemes: [],
  allowed_ports: [],
  path_prefixes: ["/"],
  excluded_paths: [],
  redirect_policy: "in_scope",
  // Mirrors the server default (scope.build_scope): authorised access-control testing
  // with the operator's own test identities is on unless the operator turns it off.
  allow_auth_testing: true,
};

/** Client-side mirror of the server's scope defaults derived from base_url. */
function deriveFromUrl(raw: string): Pick<ScopePolicy, "allowed_hosts" | "allowed_schemes" | "allowed_ports"> | null {
  try {
    const u = new URL(raw.trim());
    if (u.protocol !== "http:" && u.protocol !== "https:") return null;
    const scheme = u.protocol.slice(0, -1) as "http" | "https";
    const port = u.port ? Number(u.port) : scheme === "https" ? 443 : 80;
    return {
      allowed_hosts: [u.hostname.toLowerCase().replace(/^\[|\]$/g, "")],
      allowed_schemes: [scheme],
      allowed_ports: [port],
    };
  } catch {
    return null;
  }
}

type FieldKey = "name" | "description" | "base_url" | "scope" | "limits" | "checks" | "credential_id" | "account_ids" | "egress_proxy_id" | "model_backend" | "model";

export const NO_MODEL_MESSAGE = "No AI model configured — set the model variables in .env; see deploy/config-reference.md";

/** Blocking notice: grey-box is AI-only, so without a model no run can start. */
export function NoModelNotice() {
  return (
    <div role="alert" className="flex items-start gap-2 rounded-md border border-severity-critical/30 bg-red-50 p-3 text-sm" data-testid="no-model-notice">
      <ExclamationTriangleIcon className="mt-0.5 h-4 w-4 shrink-0 text-severity-critical" aria-hidden="true" />
      <span>{NO_MODEL_MESSAGE}</span>
    </div>
  );
}

export function TestAccountPicker({ accounts, selected, onChange }: {
  accounts: Credential[] | null;
  selected: string[];
  onChange: (ids: string[]) => void;
}) {
  const [query, setQuery] = useState("");
  const selectedSet = new Set(selected);
  const visible = (accounts ?? []).filter((account) => account.label.toLowerCase().includes(query.trim().toLowerCase()));

  if (accounts === null) return <p className="text-xs text-slate">Loading test accounts…</p>;

  if (accounts.length === 0) {
    return (
      <p className="text-xs text-slate">
        No login accounts yet. Add synthetic test accounts in{" "}
        <Link to="/settings/credentials" className="text-accent hover:underline">credentials</Link>.
      </p>
    );
  }

  return (
    <details className="rounded-md border border-line bg-surface">
      <summary className="cursor-pointer select-none px-3 py-2 text-sm font-medium">
        <span className="ml-1 inline-flex w-[calc(100%-1rem)] items-center justify-between gap-3 align-middle">
          <span>Test accounts</span>
          <span className="rounded-full border border-line bg-canvas px-2 py-0.5 text-xs font-normal text-slate">
            {selected.length} selected
          </span>
        </span>
      </summary>
      <div className="border-t border-line p-3">
        <div className="mb-2 flex flex-wrap gap-2">
          <input
            type="search"
            className="field min-w-[14rem] flex-1"
            placeholder={`Search ${accounts.length} test accounts`}
            value={query}
            onChange={(event) => setQuery(event.target.value)}
          />
          <button type="button" className="btn-ghost py-1 text-xs"
                  disabled={visible.length === 0}
                  onClick={() => onChange([...new Set([...selected, ...visible.map((account) => account.id)])])}>
            Select visible
          </button>
          <button type="button" className="btn-ghost py-1 text-xs"
                  disabled={selected.length === 0} onClick={() => onChange([])}>
            Clear
          </button>
        </div>
        <div className="max-h-56 overflow-y-auto rounded border border-line p-2">
          <div className="grid gap-1 sm:grid-cols-2 xl:grid-cols-3">
            {visible.map((account) => (
              <label key={account.id} className="flex min-w-0 items-center gap-2 rounded px-2 py-1 text-sm hover:bg-canvas">
                <input
                  type="checkbox"
                  checked={selectedSet.has(account.id)}
                  onChange={(event) => onChange(event.target.checked
                    ? [...selected, account.id]
                    : selected.filter((id) => id !== account.id))}
                />
                <span className="truncate" title={account.label}>{account.label}</span>
              </label>
            ))}
            {visible.length === 0 && <p className="col-span-full px-2 py-3 text-xs text-slate">No matching accounts.</p>}
          </div>
        </div>
        <p className="mt-2 text-xs text-slate">
          The agent logs in as each selected identity but never sees its password. Select distinct owners, roles or tenants for access-control comparisons.
        </p>
      </div>
    </details>
  );
}

export function NewGreyboxForm({ config, initial }: { config: GreyboxConfig; initial?: TargetRead }) {
  const navigate = useNavigate();
  const ids = useId();
  const editing = !!initial;

  const [name, setName] = useState(initial?.name ?? "");
  const [description, setDescription] = useState(initial?.description ?? "");
  const [baseUrl, setBaseUrl] = useState(initial?.base_url ?? "");
  const [scope, setScope] = useState<ScopePolicy>(initial?.scope ?? EMPTY_SCOPE);
  // Hosts/schemes/ports follow the base URL until the user edits one of them.
  const [scopeLinked, setScopeLinked] = useState(!editing);
  const [limits, setLimits] = useState<Limits>(initial?.limits ?? config.limits.defaults);
  // `checks: null` means "server defaults" (default_enabled, plus auth-only checks when
  // auth testing is allowed). Until the user changes a check we send null on create and
  // omit the field on edit, so the stored value (possibly null) is kept.
  const defaultChecks = (auth: boolean) =>
    config.checks.filter((c) => isAvailable(c) && c.default_enabled && (!c.requires_auth_testing || auth)).map((c) => c.id);
  const [checksTouched, setChecksTouched] = useState(false);
  const [checks, setChecks] = useState<string[]>(initial?.checks ?? defaultChecks(EMPTY_SCOPE.allow_auth_testing));
  const [mode, setMode] = useState<AssessmentMode>(initial?.assessment_mode ?? "web");
  const [network, setNetwork] = useState<NetworkScope>(initial?.scope?.network ?? EMPTY_NETWORK);
  const [credentialId, setCredentialId] = useState(initial?.credential?.id ?? "");
  const [cookies, setCookies] = useState<Credential[] | null>(null);
  const [logins, setLogins] = useState<Credential[] | null>(null);
  const [accountIds, setAccountIds] = useState<string[]>((initial?.accounts ?? []).map((a) => a.id));
  const [accountsTouched, setAccountsTouched] = useState(false);
  const [proxyId, setProxyId] = useState(initial?.egress_proxy_id ?? "");
  const agentBackends = config.agent?.backends ?? [];
  const noModel = config.agent?.available === false;
  const unavailable = agentBackends.filter((b) => b.available === false);
  const a = config.agent;
  const limitsHint = a && a.max_calls ? `Up to ${a.max_calls} model calls${a.max_tokens ? `, ${a.max_tokens.toLocaleString()} tokens` : ""}${a.timeout_s ? `, ${a.timeout_s}s per call` : ""} per run.` : "";
  // "" = the server default backend / model.
  const [modelBackend, setModelBackend] = useState(initial?.model_backend ?? "");
  const [model, setModel] = useState(initial?.model ?? "");
  const selectedBackend = agentBackends.find((b) => b.id === modelBackend);
  const proxies = useAvailableProxies();
  const [proxyServerError, setProxyServerError] = useState<string | null>(null);
  const [authorized, setAuthorized] = useState(false);

  const [touched, setTouched] = useState<Set<FieldKey>>(new Set());
  const [submitted, setSubmitted] = useState(false);
  const [validation, setValidation] = useState<TargetValidation | null>(null);
  const [validating, setValidating] = useState(false);
  const [validationError, setValidationError] = useState<string | null>(null);
  const [serverErrors, setServerErrors] = useState<LocError[] | null>(null);
  const [formError, setFormError] = useState<string | null>(null);
  const [busy, setBusy] = useState<null | "save" | "start">(null);
  const [advOpen, setAdvOpen] = useState(false);

  useEffect(() => {
    api
      .credentials()
      .then((c) => {
        setCookies(c.filter((x) => x.kind === "cookie_header"));
        setLogins(c.filter((x) => x.kind === "login_account"));
      })
      .catch(() => { setCookies([]); setLogins([]); });
  }, []);

  const touch = (k: FieldKey) => setTouched((t) => (t.has(k) ? t : new Set(t).add(k)));

  function onBaseUrl(v: string) {
    setBaseUrl(v);
    touch("base_url");
    if (scopeLinked) {
      const d = deriveFromUrl(v);
      if (d) setScope((s) => ({ ...s, ...d }));
    }
  }

  function onScope(next: ScopePolicy, field: keyof ScopePolicy) {
    if (field === "allowed_hosts" || field === "allowed_schemes" || field === "allowed_ports") setScopeLinked(false);
    if (field === "allow_auth_testing" && !checksTouched && !editing) setChecks(defaultChecks(next.allow_auth_testing));
    if (field === "allow_auth_testing" && !next.allow_auth_testing) {
      const needsAuth = new Set(config.checks.filter((c) => c.requires_auth_testing).map((c) => c.id));
      setChecks((cs) => cs.filter((c) => !needsAuth.has(c)));
    }
    setScope(next);
    touch("scope");
  }

  const body: TargetCreate = useMemo(
    () => ({
      name: name.trim(),
      description: description.trim() || null,
      base_url: baseUrl.trim(),
      scope: mode === "network" ? { ...scope, network } : (({ network: _n, ...rest }) => rest)(scope),
      limits,
      assessment_mode: mode,
      ...(checksTouched ? { checks } : editing ? {} : { checks: null }),
      credential_id: credentialId || null,
      // Sent only when chosen or changed, so editing never clears accounts unseen.
      ...(accountIds.length > 0 || accountsTouched ? { account_ids: accountIds } : {}),
      // Only send the field when the feature is on, so older servers never see it.
      ...(proxies && proxies.length > 0 ? { egress_proxy_id: proxyId || null } : {}),
      ...(agentBackends.length > 0 ? { model_backend: modelBackend || null, model: model || null } : {}),
    }),
    [name, description, baseUrl, scope, limits, checks, checksTouched, editing, credentialId, accountIds, accountsTouched, proxies, proxyId, modelBackend, model, agentBackends.length, mode, network],
  );

  // Debounced server-side validation: the scope summary shown before saving is the
  // server's own wording, and errors carry `loc` for field-level display.
  const seq = useRef(0);
  useEffect(() => {
    if (!body.base_url) {
      setValidation(null);
      return;
    }
    const my = ++seq.current;
    setValidating(true);
    const t = setTimeout(() => {
      greyboxApi
        .validateTarget(body)
        .then((v) => {
          if (my !== seq.current) return;
          setValidation(v);
          setValidationError(null);
          setServerErrors(null);
        })
        .catch((e: unknown) => {
          if (my !== seq.current) return;
          // A 422 here means the body itself failed schema parsing (e.g. a bad type).
          const locs = e instanceof ApiError ? asLocErrors(e.detail) : null;
          if (locs) {
            setValidation({ valid: false, normalized: null, scope_summary: [], errors: locs.map((l) => ({ loc: [...l.loc], msg: l.msg })), warnings: [] });
            setValidationError(null);
          } else {
            setValidation(null);
            setValidationError(e instanceof Error ? e.message : "Validation failed");
          }
        })
        .finally(() => my === seq.current && setValidating(false));
    }, 500);
    return () => clearTimeout(t);
  }, [body]);

  const allErrors: LocError[] = serverErrors ?? validation?.errors ?? [];
  const grouped = groupErrors(allErrors);
  // Field-level errors appear once the user has touched that field or tried to save.
  const visible = (k: FieldKey): Record<string, string[]> =>
    submitted || touched.has(k) ? grouped : {};
  const fieldErr = (k: FieldKey) => errorsFor(visible(k), k);

  const ADV_KEYS: FieldKey[] = ["scope", "limits", "checks", "credential_id", "account_ids", "egress_proxy_id", "description"];
  const advErrorOpen = ADV_KEYS.some((k) => Object.keys(visible(k)).some((g) => g === k || g.startsWith(`${k}.`)));

  async function submit(e: FormEvent, start: boolean) {
    e.preventDefault();
    setSubmitted(true);
    setFormError(null);
    setProxyServerError(null);
    if (!authorized) {
      setFormError("Confirm that you are authorised to test this target before saving.");
      return;
    }
    setBusy(start ? "start" : "save");
    let target: TargetRead;
    try {
      target = initial ? await greyboxApi.updateTarget(initial.id, body) : await greyboxApi.createTarget(body);
    } catch (err) {
      const locs = err instanceof ApiError ? asLocErrors(err.detail) : null;
      if (locs) {
        setServerErrors(locs);
        setFormError("The server rejected some fields. Fix the highlighted errors and try again.");
      } else if (err instanceof ApiError && err.status === 422 && proxyId && /proxy|allowed.?host/i.test(err.message)) {
        setProxyServerError(err.message);
        setAdvOpen(true);
        setFormError("The selected network path was rejected. Choose Direct or another proxy.");
      } else {
        setFormError(err instanceof Error ? err.message : "Saving failed");
      }
      setBusy(null);
      return;
    }
    let notice = initial ? "Target updated." : "Target saved.";
    let noticeError = false;
    if (start) {
      try {
        const run = await greyboxApi.startRun(target.id, { authorization_confirmed: true, idempotency_key: newIdempotencyKey() });
        setBusy(null);
        navigate(`/greybox/runs/${run.id}`, { state: { notice: `${notice} Analysis started.` } });
        return;
      } catch (err) {
        notice += ` The analysis did not start: ${startErrorMessage(err)}`;
        noticeError = true;
      }
    }
    setBusy(null);
    navigate(`/greybox/targets/${target.id}`, { state: { notice, noticeError } });
  }

  const authChecksAllowed = scope.allow_auth_testing;

  return (
    <form onSubmit={(e) => submit(e, false)} className={`card grid gap-6 p-6 ${editing ? "w-full max-w-none" : "max-w-4xl"}`} noValidate>
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor={`${ids}-name`} className="mb-1 block text-sm text-slate">Name</label>
          <input
            id={`${ids}-name`}
            className="field"
            value={name}
            maxLength={200}
            required
            onChange={(e) => { setName(e.target.value); touch("name"); }}
            aria-invalid={fieldErr("name").length > 0}
            aria-describedby={`${ids}-name-err`}
          />
          <FieldError id={`${ids}-name-err`} messages={fieldErr("name")} />
        </div>
        <div>
          <label htmlFor={`${ids}-url`} className="mb-1 block text-sm text-slate">Target base URL</label>
          <input
            id={`${ids}-url`}
            className="field mono"
            value={baseUrl}
            maxLength={500}
            required
            inputMode="url"
            autoComplete="off"
            placeholder="https://staging.example.test/"
            onChange={(e) => onBaseUrl(e.target.value)}
            aria-invalid={fieldErr("base_url").length > 0}
            aria-describedby={`${ids}-url-err`}
          />
          <FieldError id={`${ids}-url-err`} messages={fieldErr("base_url")} />
        </div>
      </div>

      <ScopeSummary
        baseUrl={body.base_url}
        validation={validation}
        validating={validating}
        validationError={validationError}
        allErrors={allErrors}
      />

      <details
        className="rounded-md border border-line"
        open={advOpen || advErrorOpen || !!proxyServerError}
        onToggle={(e) => setAdvOpen((e.currentTarget as HTMLDetailsElement).open)}
      >
        <summary className="cursor-pointer select-none px-4 py-3 text-sm font-medium text-ink">
          Advanced options
          <span className="ml-2 font-normal text-slate">objective, scope, authentication, limits and checks (defaults are safe)</span>
        </summary>
        <div className="grid gap-6 border-t border-line p-4">
        <div className="grid gap-4 sm:grid-cols-2">
        <div className="sm:col-span-2">
          <label htmlFor={`${ids}-desc`} className="mb-1 block text-sm text-slate">
            Objective and application context (optional)
          </label>
          <textarea
            id={`${ids}-desc`}
            className="field min-h-[5rem]"
            value={description}
            maxLength={2000}
            placeholder="What should this analysis focus on? What does the application do, and which areas are sensitive?"
            onChange={(e) => { setDescription(e.target.value); touch("description"); }}
            aria-describedby={`${ids}-desc-hint ${ids}-desc-err`}
          />
          <p id={`${ids}-desc-hint`} className="mt-1 text-xs text-slate">
            Stored with the target and shown in the report. The checks are deterministic; this text does not steer them.
          </p>
          <FieldError id={`${ids}-desc-err`} messages={fieldErr("description")} />
        </div>
        </div>

      <AssessmentModeEditor mode={mode} network={network} onMode={(m) => { setMode(m); touch("scope"); }}
        onNetwork={(n) => { setNetwork(n); touch("scope"); }}
        errors={(serverErrors ?? validation?.errors ?? [])
          .filter((e) => e.loc.includes("network") || e.loc.includes("assessment_mode")).map((e) => e.msg)} />
      <ScopeEditor value={scope} onChange={onScope} errors={visible("scope")} />

      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label htmlFor={`${ids}-cred`} className="mb-1 block text-sm text-slate">Authentication</label>
          <select
            id={`${ids}-cred`}
            className="field"
            value={credentialId}
            onChange={(e) => { setCredentialId(e.target.value); touch("credential_id"); }}
            aria-describedby={`${ids}-cred-hint ${ids}-cred-err`}
          >
            <option value="">None: test unauthenticated</option>
            {(cookies ?? []).map((c) => (
              <option key={c.id} value={c.id}>Cookie: {c.label}</option>
            ))}
          </select>
          <p id={`${ids}-cred-hint`} className="mt-1 text-xs text-slate">
            {cookies && cookies.length === 0 ? "You have no session-cookie credentials yet. " : "Session cookie sent only to in-scope hosts. "}
            <Link to="/settings/credentials" className="text-accent hover:underline">Manage credentials</Link>
          </p>
          <FieldError id={`${ids}-cred-err`} messages={fieldErr("credential_id")} />
        </div>
        {agentBackends.length > 0 && !noModel && (
          <div>
            <label htmlFor={`${ids}-backend`} className="mb-1 block text-sm text-slate">AI model</label>
            <div className="grid gap-2 sm:grid-cols-2">
              <select
                id={`${ids}-backend`}
                className="field"
                value={modelBackend}
                onChange={(e) => { setModelBackend(e.target.value); setModel(""); touch("model_backend"); }}
                aria-describedby={`${ids}-model-hint ${ids}-model-err`}
              >
                <option value="">Default backend</option>
                {agentBackends.map((b) => (
                  <option key={b.id} value={b.id} disabled={b.available === false && b.id !== modelBackend}>
                    {b.label}{b.available === false ? " (unavailable)" : ""}
                  </option>
                ))}
              </select>
              <select
                id={`${ids}-model`}
                className="field"
                aria-label="Model"
                value={model}
                disabled={!modelBackend}
                onChange={(e) => { setModel(e.target.value); touch("model"); }}
              >
                <option value="">Default model</option>
                {(agentBackends.find((b) => b.id === modelBackend)?.models ?? []).map((m) => <option key={m} value={m}>{m}</option>)}
              </select>
            </div>
            <p id={`${ids}-model-hint`} className="mt-1 text-xs text-slate">
              The AI exploration agent reasons about the target with this model; every step is still checked against scope and budgets.
              {selectedBackend?.available === false && selectedBackend.reason ? ` ${selectedBackend.label} is unavailable: ${selectedBackend.reason}` : ""}
              {unavailable.length > 0 && !(selectedBackend?.available === false) ? ` Unavailable: ${unavailable.map((b) => `${b.label}${b.reason ? ` (${b.reason})` : ""}`).join("; ")}.` : ""}
              {limitsHint ? ` ${limitsHint}` : ""}
            </p>
            <FieldError id={`${ids}-model-err`} messages={[...fieldErr("model_backend"), ...fieldErr("model")]} />
          </div>
        )}
      </div>

      <fieldset>
        <legend className="sr-only">Test accounts</legend>
        <TestAccountPicker accounts={logins} selected={accountIds} onChange={(next) => {
          setAccountsTouched(true);
          setAccountIds(next);
        }} />
        <FieldError id={`${ids}-acct-err`} messages={fieldErr("account_ids")} />
      </fieldset>

      {proxies && proxies.length > 0 && (() => {
        const choices = proxyChoices(baseUrl, proxies, proxyId);
        const cur = choices.find((c) => c.selected);
        const errs = [...fieldErr("egress_proxy_id"), ...(proxyServerError ? [proxyServerError] : [])];
        return (
          <div className="grid gap-4 sm:grid-cols-2">
            <div>
              <label htmlFor={`${ids}-proxy`} className="mb-1 block text-sm text-slate">Network path</label>
              <select
                id={`${ids}-proxy`}
                className="field"
                value={proxyId}
                onChange={(e) => { setProxyId(e.target.value); setProxyServerError(null); touch("egress_proxy_id"); }}
                aria-invalid={errs.length > 0}
                aria-describedby={`${ids}-proxy-hint ${ids}-proxy-err`}
              >
                <option value="">Direct (default)</option>
                {choices.map((c) => (
                  <option key={c.id} value={c.id}>
                    {c.name}{c.matches ? "" : " (host not allowed)"}
                  </option>
                ))}
              </select>
              <p id={`${ids}-proxy-hint`} className="mt-1 text-xs text-slate">
                Use a proxy only if the target is reachable through the organisation&apos;s forward proxy. The proxy resolves DNS, so the IP cannot be pinned; scope checks still apply.
              </p>
              {cur && !cur.matches && (
                <p role="note" className="mt-1 text-xs text-severity-medium">This target&apos;s host is not in the proxy&apos;s allowed hosts ({cur.allowed_hosts.join(", ")}); the server will reject it.</p>
              )}
              <FieldError id={`${ids}-proxy-err`} messages={errs} />
            </div>
          </div>
        );
      })()}

      <fieldset>
        <legend className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">
          Limits <span className="normal-case tracking-normal">(all enforced by the engine)</span>
        </legend>
        <div className="grid gap-4 sm:grid-cols-3 lg:grid-cols-4">
          {LIMIT_FIELDS.map((f) => {
            const max = config.limits.max[f.key];
            const raw = limits[f.key];
            const shown = f.minutes ? Math.round(raw / 60) : raw;
            const errs = errorsFor(visible("limits"), `limits.${f.key}`);
            const id = `${ids}-lim-${f.key}`;
            return (
              <div key={f.key}>
                <label htmlFor={id} className="mb-1 block text-sm text-slate">{f.label}</label>
                <input
                  id={id}
                  type="number"
                  className="field"
                  min={f.minutes ? f.min / 60 : f.min}
                  max={f.minutes ? max / 60 : max}
                  value={Number.isFinite(shown) ? shown : ""}
                  onChange={(e) => {
                    const n = e.target.value === "" ? NaN : Number(e.target.value);
                    setLimits((l) => ({ ...l, [f.key]: f.minutes ? n * 60 : n }));
                    touch("limits");
                  }}
                  aria-invalid={errs.length > 0}
                  aria-describedby={`${id}-hint ${id}-err`}
                />
                <p id={`${id}-hint`} className="mt-1 text-xs text-slate">
                  {f.unit}, max {f.minutes ? max / 60 : max}
                </p>
                <FieldError id={`${id}-err`} messages={errs} />
              </div>
            );
          })}
        </div>
      </fieldset>

      {config.checks.length > 0 && (
        <fieldset>
          <legend className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">Checks</legend>
          <div className="grid gap-3 lg:grid-cols-2">
            {checksByArea(config.checks).map((group) => (
              <section key={group.area} className="rounded-md border border-line bg-surface p-3">
                <h4 className="text-sm font-semibold text-ink">{group.area}</h4>
                <p className="mb-2 text-xs text-slate">Useful evidence: {group.evidence}</p>
                <div className="space-y-2">
                  {group.checks.map((c) => {
                    const unavailable = !isAvailable(c);
                    const selected = checks.includes(c.id);
                    // An unavailable check stays unchecked and disabled, unless an existing target
                    // has it selected: then it can be unchecked (it will be skipped meanwhile).
                    const disabled = (c.requires_auth_testing && !authChecksAllowed) || (unavailable && !selected);
                    return (
                      <label
                        key={c.id}
                        className={`flex items-start gap-2 text-sm ${disabled ? "opacity-60" : ""}`}
                        title={unavailable ? unavailableReason(c) : undefined}
                      >
                        <input
                          type="checkbox"
                          className="mt-1"
                          disabled={disabled}
                          checked={checks.includes(c.id)}
                          onChange={(e) => {
                            setChecks((cs) => (e.target.checked ? [...cs, c.id] : cs.filter((x) => x !== c.id)));
                            setChecksTouched(true);
                            touch("checks");
                          }}
                        />
                        <span>
                          {c.title}
                          {unavailable && (
                            <span className="ml-2 rounded-full border border-line bg-canvas px-2 py-0.5 text-xs font-medium text-slate">
                              {selected ? "Will be skipped (not available in this build)" : UNAVAILABLE_BADGE}
                            </span>
                          )}
                          <span className="block text-xs text-slate">
                            {c.description}
                            {c.requires_auth_testing && " Requires authentication testing to be allowed in the scope."}
                          </span>
                        </span>
                      </label>
                    );
                  })}
                </div>
              </section>
            ))}
          </div>
          {!checksTouched && (
            <p className="mt-2 text-xs text-slate">
              {editing ? "Unchanged checks keep their stored setting." : "Using the server defaults until you change a check."}
            </p>
          )}
          <FieldError id={`${ids}-checks-err`} messages={fieldErr("checks")} />
        </fieldset>
      )}

        </div>
      </details>

      <div className="space-y-3">
        <p className="flex items-start gap-2 rounded-md border border-severity-medium/30 bg-amber-50 p-3 text-sm text-ink">
          <ExclamationTriangleIcon className="mt-0.5 h-5 w-5 shrink-0 text-severity-medium" aria-hidden="true" />
          <span>
            Grey-box analyses send real HTTP requests to the target. Only test systems you own or are explicitly
            authorised to test, and only within the scope above. Every request is checked against this scope
            before it is sent.
          </span>
        </p>
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={authorized}
            onChange={(e) => setAuthorized(e.target.checked)}
            aria-invalid={submitted && !authorized}
          />
          <span>I confirm I am authorised to test this target within the scope above.</span>
        </label>
      </div>

      {noModel && <NoModelNotice />}

      {formError && <p role="alert" className="text-sm text-severity-critical">{formError}</p>}

      <div className="flex flex-wrap items-center gap-3">
        {editing ? (
          <button type="submit" className="btn-primary disabled:opacity-60" disabled={busy !== null || !authorized} aria-describedby={authorized ? undefined : `${ids}-why`}>
            {busy === "save" ? "Saving…" : "Save changes"}
          </button>
        ) : (
          <>
            <button
              type="button"
              className="btn-primary disabled:opacity-60"
              disabled={busy !== null || !authorized || noModel}
              aria-describedby={authorized ? undefined : `${ids}-why`}
              onClick={(e) => submit(e, true)}
            >
              {busy === "start" ? "Starting…" : "Start analysis"}
            </button>
            <button type="submit" className="btn-ghost disabled:opacity-60" disabled={busy !== null || !authorized} aria-describedby={authorized ? undefined : `${ids}-why`}>
              {busy === "save" ? "Saving…" : "Save without starting"}
            </button>
          </>
        )}
        {!authorized && <p id={`${ids}-why`} className="text-xs text-slate">Confirm authorisation to continue.</p>}
      </div>
    </form>
  );
}

/** What will be tested, derived locally as soon as the URL is valid, then replaced by the server's wording. */
export function localScopeSummary(baseUrl: string): string | null {
  const d = deriveFromUrl(baseUrl);
  if (!d) return null;
  return `Only ${d.allowed_hosts[0]} over ${d.allowed_schemes[0]} on port ${d.allowed_ports[0]}, all paths.`;
}

function ScopeSummary({
  baseUrl, validation, validating, validationError, allErrors,
}: {
  baseUrl: string;
  validation: TargetValidation | null;
  validating: boolean;
  validationError: string | null;
  allErrors: LocError[];
}) {
  const local = localScopeSummary(baseUrl);
  return (
      <section aria-labelledby={`scope-summary`} aria-live="polite" className="rounded-md border border-line bg-canvas p-4">
        <h3 id={`scope-summary`} className="mb-2 flex items-center gap-2 text-xs font-semibold uppercase tracking-wide text-slate">
          <ShieldCheckIcon className="h-4 w-4" aria-hidden="true" />
          Scope summary {validating && <span className="font-normal normal-case tracking-normal">(checking…)</span>}
        </h3>
        {!baseUrl ? (
          <p className="text-sm text-slate">Enter a target base URL to see what will be tested.</p>
        ) : validationError ? (
          <p className="text-sm text-severity-critical">Could not validate on the server: {validationError}</p>
        ) : validation ? (
          <>
            {validation.scope_summary.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-5 text-sm text-ink">
                {validation.scope_summary.map((l, i) => <li key={i}>{l}</li>)}
              </ul>
            )}
            {validation.warnings.length > 0 && (
              <ul className="mt-2 space-y-0.5 text-sm text-severity-medium">
                {validation.warnings.map((w, i) => <li key={i}>Warning: {w}</li>)}
              </ul>
            )}
            {allErrors.length > 0 && (
              <div className="mt-2 text-sm text-severity-critical">
                <p className="font-medium">Not valid yet:</p>
                <ul className="list-disc pl-5">
                  {allErrors.map((er, i) => (
                    <li key={i}><span className="mono text-xs">{locLabel(er.loc) || "target"}</span>: {er.msg}</li>
                  ))}
                </ul>
              </div>
            )}
            {validation.valid && allErrors.length === 0 && (
              <p className="mt-2 text-xs text-slate">Validated by the server.</p>
            )}
          </>
        ) : (
          local ? <p className="text-sm text-ink">{local}</p> : <p className="text-sm text-slate">Checking…</p>
        )}
      </section>

  );
}

/** Honest, contract-based messages for POST /greybox/targets/{id}/runs failures. */
export function startErrorMessage(err: unknown): string {
  if (!(err instanceof ApiError)) return err instanceof Error ? err.message : "unknown error";
  switch (err.status) {
    case 503:
      return "the grey-box executor is not running on this server, so runs cannot start yet. The target is saved and can be started later.";
    case 404:
      return "starting runs is not available on this server (grey-box is disabled or not yet deployed).";
    case 409:
      // Without a run_id this is not "already active" (e.g. no AI model configured): show the server's reason.
      return (err.body as { run_id?: string } | null)?.run_id || !err.message ? "a run for this target is already active." : err.message;
    case 429:
      return "you have too many active grey-box runs. Wait for one to finish.";
    case 422:
      // e.g. the credential is no longer usable ("Unknown credential") at run start.
      return `the server rejected the request: ${err.message}`;
    default:
      return err.message;
  }
}
