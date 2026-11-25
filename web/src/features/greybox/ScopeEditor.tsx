import { useId, useState, type KeyboardEvent } from "react";
import { XMarkIcon } from "@heroicons/react/20/solid";
import { FieldError, errorsFor, listErrors } from "../../components/ui/FieldError";
import type { ScopePolicy } from "./types";

// Editable list of short values shown as removable chips. Enter or "Add" appends.
// Client-side checks are only for obvious typos; the server is authoritative
// (POST /greybox/targets/validate).
function ListInput({
  id,
  label,
  hint,
  values,
  onChange,
  placeholder,
  parse,
  errors,
  itemErrors,
}: {
  id: string;
  label: string;
  hint?: string;
  values: string[];
  onChange: (values: string[]) => void;
  placeholder?: string;
  /** Returns the normalised value, or an error string prefixed with "!". */
  parse?: (raw: string) => string;
  errors?: string[];
  /** Server errors for individual entries, keyed by list index. */
  itemErrors?: Record<number, string[]>;
}) {
  const [draft, setDraft] = useState("");
  const [local, setLocal] = useState<string | null>(null);
  const errId = `${id}-err`;
  const hintId = `${id}-hint`;

  function add() {
    const raw = draft.trim();
    if (!raw) return;
    const v = parse ? parse(raw) : raw;
    if (v.startsWith("!")) {
      setLocal(v.slice(1));
      return;
    }
    if (!values.includes(v)) onChange([...values, v]);
    setDraft("");
    setLocal(null);
  }
  function onKey(e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === "Enter" || e.key === ",") {
      e.preventDefault();
      add();
    } else if (e.key === "Backspace" && !draft && values.length) {
      onChange(values.slice(0, -1));
    }
  }
  const itemMsgs = Object.entries(itemErrors ?? {})
    .filter(([i]) => values[Number(i)] !== undefined)
    .flatMap(([i, msgs]) => msgs.map((m) => `“${values[Number(i)]}”: ${m}`));
  const allErrors = [...(local ? [local] : []), ...(errors ?? []), ...itemMsgs];

  return (
    <div>
      <label htmlFor={id} className="mb-1 block text-sm text-slate">{label}</label>
      <div
        className={`flex flex-wrap items-center gap-1.5 rounded-md border bg-surface px-2 py-1.5 focus-within:border-accent focus-within:ring-2 focus-within:ring-accent/20 ${
          allErrors.length ? "border-severity-critical" : "border-line"
        }`}
      >
        <ul className="contents" aria-label={`${label} values`}>
          {values.map((v, i) => {
            const bad = !!itemErrors?.[i]?.length;
            return (
            <li
              key={v}
              className={`mono inline-flex items-center gap-1 rounded px-1.5 py-0.5 text-xs text-ink ring-1 ${
                bad ? "bg-red-50 ring-severity-critical" : "bg-canvas ring-line"
              }`}
              title={bad ? itemErrors![i].join(" ") : undefined}
            >
              {bad && <span className="sr-only">Invalid: </span>}
              {v}
              <button
                type="button"
                className="rounded text-slate hover:text-severity-critical focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40"
                onClick={() => onChange(values.filter((x) => x !== v))}
                aria-label={`Remove ${v} from ${label}`}
              >
                <XMarkIcon className="h-3.5 w-3.5" />
              </button>
            </li>
            );
          })}
        </ul>
        <input
          id={id}
          className="mono min-w-[8rem] flex-1 bg-transparent px-1 py-0.5 text-xs outline-none"
          value={draft}
          placeholder={placeholder}
          onChange={(e) => {
            setDraft(e.target.value);
            setLocal(null);
          }}
          onKeyDown={onKey}
          onBlur={add}
          aria-invalid={allErrors.length > 0}
          aria-describedby={[hint ? hintId : "", allErrors.length ? errId : ""].filter(Boolean).join(" ") || undefined}
        />
        <button type="button" className="text-xs font-medium text-accent hover:underline" onClick={add}>
          Add
        </button>
      </div>
      {hint && <p id={hintId} className="mt-1 text-xs text-slate">{hint}</p>}
      <FieldError id={errId} messages={allErrors} />
    </div>
  );
}

const parseHost = (raw: string) => {
  const v = raw.toLowerCase().replace(/^\[|\]$/g, "");
  if (v === "*") return "!A bare * is not allowed. Use a suffix such as *.example.test.";
  if (/[/@\s]/.test(v)) return "!Enter a hostname or IP only (no scheme, path or user info).";
  return v;
};
const parsePort = (raw: string) => {
  const n = Number(raw);
  return Number.isInteger(n) && n >= 1 && n <= 65535 ? String(n) : "!Ports are whole numbers from 1 to 65535.";
};
const parsePath = (raw: string) => (raw.startsWith("/") ? raw : "!Paths must start with /.");

export function ScopeEditor({
  value,
  onChange,
  errors,
}: {
  value: ScopePolicy;
  onChange: (next: ScopePolicy, field: keyof ScopePolicy) => void;
  /** Grouped server errors keyed like "scope.allowed_hosts". */
  errors: Record<string, string[]>;
}) {
  const base = useId();
  const set = <K extends keyof ScopePolicy>(k: K, v: ScopePolicy[K]) => onChange({ ...value, [k]: v }, k);
  const e = (k: keyof ScopePolicy) => errorsFor(errors, `scope.${k}`);
  // List fields: whole-field messages plus per-entry messages mapped to the chip.
  const le = (k: keyof ScopePolicy) => listErrors(errors, `scope.${k}`);

  return (
    <fieldset className="grid gap-4 sm:grid-cols-2">
      <legend className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate">Authorised scope</legend>
      <ListInput
        id={`${base}-hosts`}
        label="Allowed hosts"
        hint="Hostnames or IPs. *.example.test matches subdomains only. Must include the base URL host."
        values={value.allowed_hosts}
        onChange={(v) => set("allowed_hosts", v)}
        placeholder="app.example.test"
        parse={parseHost}
        errors={le("allowed_hosts").field}
        itemErrors={le("allowed_hosts").items}
      />
      <div>
        <span className="mb-1 block text-sm text-slate" id={`${base}-schemes-label`}>Schemes</span>
        <div role="group" aria-labelledby={`${base}-schemes-label`} className="flex gap-4 py-2">
          {(["http", "https"] as const).map((s) => (
            <label key={s} className="flex items-center gap-2 text-sm">
              <input
                type="checkbox"
                checked={value.allowed_schemes.includes(s)}
                onChange={(ev) =>
                  set(
                    "allowed_schemes",
                    ev.target.checked
                      ? [...value.allowed_schemes, s]
                      : value.allowed_schemes.filter((x) => x !== s),
                  )
                }
              />
              <span className="mono">{s}</span>
            </label>
          ))}
        </div>
        <FieldError id={`${base}-schemes-err`} messages={e("allowed_schemes")} />
      </div>
      <ListInput
        id={`${base}-ports`}
        label="Allowed ports"
        values={value.allowed_ports.map(String)}
        onChange={(v) => set("allowed_ports", v.map(Number))}
        placeholder="443"
        parse={parsePort}
        errors={le("allowed_ports").field}
        itemErrors={le("allowed_ports").items}
      />
      <ListInput
        id={`${base}-paths`}
        label="Path prefixes in scope"
        values={value.path_prefixes}
        onChange={(v) => set("path_prefixes", v)}
        placeholder="/"
        parse={parsePath}
        errors={le("path_prefixes").field}
        itemErrors={le("path_prefixes").items}
      />
      <ListInput
        id={`${base}-excl`}
        label="Excluded paths"
        hint="Prefix match; exclusions win over the prefixes above (e.g. /logout)."
        values={value.excluded_paths}
        onChange={(v) => set("excluded_paths", v)}
        placeholder="/logout"
        parse={parsePath}
        errors={le("excluded_paths").field}
        itemErrors={le("excluded_paths").items}
      />
      <div>
        <span className="mb-1 block text-sm text-slate" id={`${base}-redir-label`}>Redirects</span>
        <div role="radiogroup" aria-labelledby={`${base}-redir-label`} className="flex flex-col gap-1 py-1">
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              name={`${base}-redir`}
              checked={value.redirect_policy === "in_scope"}
              onChange={() => set("redirect_policy", "in_scope")}
            />
            Follow only within scope (max 5 hops)
          </label>
          <label className="flex items-center gap-2 text-sm">
            <input
              type="radio"
              name={`${base}-redir`}
              checked={value.redirect_policy === "none"}
              onChange={() => set("redirect_policy", "none")}
            />
            Never follow
          </label>
        </div>
        <FieldError id={`${base}-redir-err`} messages={e("redirect_policy")} />
      </div>
      <div className="sm:col-span-2">
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={value.allow_auth_testing}
            onChange={(ev) => set("allow_auth_testing", ev.target.checked)}
          />
          <span>
            Allow authentication testing
            <span className="block text-xs text-slate">
              Enables checks that try to log in (for example the default-credential check). Off by default.
            </span>
          </span>
        </label>
        <FieldError id={`${base}-auth-err`} messages={e("allow_auth_testing")} />
      </div>
      <div className="sm:col-span-2">
        <label className="flex items-start gap-2 text-sm">
          <input
            type="checkbox"
            className="mt-1"
            checked={value.activity?.state_changing ?? false}
            onChange={(ev) => onChange({ ...value, activity: { state_changing: ev.target.checked } }, "activity")}
          />
          <span>
            Allow controlled state-changing tests
            <span className="block text-xs text-slate">
              Lets the agent create or modify disposable test data to validate workflows, stored input and exploit impact. Use only where reset or cleanup is safe.
            </span>
          </span>
        </label>
        <FieldError id={`${base}-activity-err`} messages={e("activity")} />
      </div>
    </fieldset>
  );
}
