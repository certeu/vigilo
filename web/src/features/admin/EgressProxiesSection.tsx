import { useCallback, useEffect, useId, useState, type FormEvent } from "react";
import { ApiError } from "../../api/client";
import { ConfirmDialog } from "../../components/ConfirmDialog";
import { greyboxApi } from "../greybox/api";
import { buildProxyPayload, parseHosts, validateProxyForm, type ProxyFormValues } from "../greybox/egressProxy";
import type { EgressProxy } from "../greybox/types";

const EMPTY: ProxyFormValues = { name: "", url: "", username: "", password: "", hostsText: "", enabled: true };

/** Admin section for opt-in grey-box egress proxies. Renders nothing when the routes 404 (feature off). */
export function EgressProxiesSection() {
  const [items, setItems] = useState<EgressProxy[] | null>(null);
  const [off, setOff] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [editing, setEditing] = useState<EgressProxy | "new" | null>(null);
  const [del, setDel] = useState<EgressProxy | null>(null);

  const load = useCallback(async () => {
    try {
      setItems(await greyboxApi.egressProxies());
      setError(null);
    } catch (e) {
      if (e instanceof ApiError && e.status === 404) setOff(true);
      else setError(e instanceof Error ? e.message : "Failed to load egress proxies");
    }
  }, []);
  useEffect(() => {
    void load();
  }, [load]);

  useEffect(() => {
    if (items && window.location.hash === "#egress-proxies") document.getElementById("egress-proxies")?.scrollIntoView();
  }, [items]);

  if (off) return null;

  async function toggle(p: EgressProxy) {
    try {
      await greyboxApi.updateEgressProxy(p.id, { enabled: !p.enabled });
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Update failed");
    }
  }

  return (
    <section id="egress-proxies" aria-labelledby="egress-h">
      <div className="mb-3 flex items-center justify-between">
        <h2 id="egress-h" className="text-sm font-semibold text-ink">Grey-box egress proxies</h2>
        <button type="button" className="btn-ghost py-1" onClick={() => setEditing("new")}>Add proxy</button>
      </div>
      <HelpText />
      {error && <p role="alert" className="mb-2 text-sm text-severity-critical">{error}</p>}
      <div className="card overflow-x-auto">
        {items === null && !error ? (
          <p className="p-4 text-sm text-slate">Loading…</p>
        ) : items && items.length === 0 ? (
          <p className="p-4 text-sm text-slate">No egress proxies configured. Grey-box runs connect directly.</p>
        ) : (
          items && (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-line text-left text-slate">
                  <th className="px-4 py-2 font-medium">Name</th>
                  <th className="px-4 py-2 font-medium">URL</th>
                  <th className="px-4 py-2 font-medium">Allowed hosts</th>
                  <th className="px-4 py-2 font-medium">Credentials</th>
                  <th className="px-4 py-2 font-medium">Enabled</th>
                  <th className="px-4 py-2" />
                </tr>
              </thead>
              <tbody>
                {items.map((p) => (
                  <tr key={p.id} className="border-b border-line/60 align-top">
                    <td className="px-4 py-2 font-medium">{p.name}</td>
                    <td className="mono px-4 py-2 text-xs break-all">{p.url}</td>
                    <td className="mono px-4 py-2 text-xs">{p.allowed_hosts.join(", ")}</td>
                    <td className="px-4 py-2">{p.has_credentials ? "Yes" : "No"}</td>
                    <td className="px-4 py-2">
                      <input type="checkbox" checked={p.enabled} onChange={() => void toggle(p)} aria-label={`Enabled: ${p.name}`} />
                    </td>
                    <td className="whitespace-nowrap px-4 py-2 text-right">
                      <button type="button" className="mr-3 text-xs text-accent hover:underline" onClick={() => setEditing(p)}>Edit</button>
                      <button type="button" className="text-xs text-severity-critical hover:underline" onClick={() => setDel(p)}>Delete</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )
        )}
      </div>

      {editing && (
        <ProxyDrawer
          proxy={editing === "new" ? null : editing}
          onClose={() => setEditing(null)}
          onSaved={async () => {
            setEditing(null);
            await load();
          }}
        />
      )}
      {del && (
        <ConfirmDialog
          title="Delete egress proxy"
          body={<>Delete <b>{del.name}</b>? Targets using it go back to a direct connection. A proxy used by an active run cannot be deleted.</>}
          onConfirm={async () => {
            try {
              await greyboxApi.deleteEgressProxy(del.id);
            } catch (e) {
              if (e instanceof ApiError && e.status === 409) throw new Error("This proxy is in use by an active run. Wait for it to finish, or cancel the run, then try again.");
              throw e;
            }
            setDel(null);
            await load();
          }}
          onCancel={() => setDel(null)}
        />
      )}
    </section>
  );
}

function HelpText() {
  return (
    <div className="card mb-3 space-y-2 p-4 text-xs text-slate">
      <p>
        <b className="text-ink">What it is.</b> Some authorised targets are only reachable through the organisation&apos;s forward proxy
        (for example Squid). Vigilo never uses system proxy settings, so a target must opt in to one of the proxies below.
      </p>
      <p>
        <b className="text-ink">When you need one.</b> The target works in a browser, but Vigilo reports connection refused or unreachable.
      </p>
      <p>
        <b className="text-ink">Security.</b> The proxy resolves DNS, so Vigilo cannot pin the target IP address. The scope policy and
        the proxy&apos;s allowed-hosts list are still enforced before every request.
      </p>
      <p>
        <b className="text-ink">Finding the right proxy.</b> Open the organisation&apos;s PAC file (the WPAD URL is in your system network
        settings) and look for the rule that matches the target host.
      </p>
    </div>
  );
}

function ProxyDrawer({ proxy, onClose, onSaved }: { proxy: EgressProxy | null; onClose: () => void; onSaved: () => void | Promise<void> }) {
  const ids = useId();
  const editing = !!proxy;
  const [v, setV] = useState<ProxyFormValues>(
    proxy ? { name: proxy.name, url: proxy.url, username: "", password: "", hostsText: proxy.allowed_hosts.join("\n"), enabled: proxy.enabled } : EMPTY,
  );
  const [clearCreds, setClearCreds] = useState(false);
  const [submitted, setSubmitted] = useState(false);
  const [busy, setBusy] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const errs = validateProxyForm(v);
  const set = <K extends keyof ProxyFormValues>(k: K, val: ProxyFormValues[K]) => setV((x) => ({ ...x, [k]: val }));
  const show = (k: keyof typeof errs) => (submitted ? errs[k] : undefined);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setSubmitted(true);
    setServerError(null);
    if (Object.keys(errs).length) return;
    setBusy(true);
    try {
      const body = buildProxyPayload(v, editing, clearCreds);
      if (proxy) await greyboxApi.updateEgressProxy(proxy.id, body);
      else await greyboxApi.createEgressProxy(body);
      await onSaved();
    } catch (err) {
      setServerError(err instanceof Error ? err.message : "Saving failed");
      setBusy(false);
    }
  }

  const credHint = editing && proxy!.has_credentials && !clearCreds ? "Credentials are stored. Leave blank to keep them." : null;

  return (
    <div className="fixed inset-0 z-40 flex justify-end bg-ink/30" onClick={busy ? undefined : onClose}>
      <form
        role="dialog"
        aria-modal="true"
        aria-label={editing ? "Edit egress proxy" : "Add egress proxy"}
        className="h-full w-full max-w-md overflow-y-auto bg-surface p-6 shadow-xl"
        onClick={(e) => e.stopPropagation()}
        onKeyDown={(e) => e.key === "Escape" && !busy && onClose()}
        onSubmit={submit}
        noValidate
      >
        <h3 className="mb-4 font-display text-lg font-semibold">{editing ? "Edit egress proxy" : "Add egress proxy"}</h3>
        <div className="space-y-4">
          <div>
            <label htmlFor={`${ids}-name`} className="mb-1 block text-sm text-slate">Name</label>
            <input id={`${ids}-name`} className="field" value={v.name} maxLength={200} onChange={(e) => set("name", e.target.value)} aria-invalid={!!show("name")} />
            {show("name") && <p className="mt-1 text-xs text-severity-critical">{show("name")}</p>}
          </div>
          <div>
            <label htmlFor={`${ids}-url`} className="mb-1 block text-sm text-slate">Proxy URL</label>
            <input id={`${ids}-url`} className="field mono" value={v.url} placeholder="http://proxy.example.org:3128" autoComplete="off" onChange={(e) => set("url", e.target.value)} aria-invalid={!!show("url")} />
            {show("url") && <p className="mt-1 text-xs text-severity-critical">{show("url")}</p>}
          </div>
          <div>
            <label htmlFor={`${ids}-hosts`} className="mb-1 block text-sm text-slate">Allowed hosts</label>
            <textarea id={`${ids}-hosts`} className="field mono min-h-[5rem]" value={v.hostsText} placeholder={"app.internal.example.org\n*.staging.example.org"} onChange={(e) => set("hostsText", e.target.value)} aria-invalid={!!show("hosts")} />
            <p className="mt-1 text-xs text-slate">One per line: exact hosts or <span className="mono">*.suffix</span>. Targets can only use this proxy for these hosts. {parseHosts(v.hostsText).length} entered.</p>
            {show("hosts") && <p className="mt-1 text-xs text-severity-critical">{show("hosts")}</p>}
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label htmlFor={`${ids}-user`} className="mb-1 block text-sm text-slate">Username (optional)</label>
              <input id={`${ids}-user`} className="field" value={v.username} autoComplete="off" disabled={clearCreds} onChange={(e) => set("username", e.target.value)} aria-invalid={!!show("username")} />
            </div>
            <div>
              <label htmlFor={`${ids}-pass`} className="mb-1 block text-sm text-slate">Password (optional)</label>
              <input id={`${ids}-pass`} className="field" type="password" value={v.password} autoComplete="new-password" disabled={clearCreds} onChange={(e) => set("password", e.target.value)} />
            </div>
            {show("username") && <p className="col-span-2 text-xs text-severity-critical">{show("username")}</p>}
            {credHint && <p className="col-span-2 text-xs text-slate">{credHint}</p>}
            {editing && proxy!.has_credentials && (
              <label className="col-span-2 flex items-center gap-2 text-xs">
                <input type="checkbox" checked={clearCreds} onChange={(e) => setClearCreds(e.target.checked)} /> Remove the stored credentials
              </label>
            )}
          </div>
          <label className="flex items-center gap-2 text-sm">
            <input type="checkbox" checked={v.enabled} onChange={(e) => set("enabled", e.target.checked)} /> Enabled
          </label>
        </div>
        {serverError && <p role="alert" className="mt-4 text-sm text-severity-critical">{serverError}</p>}
        <div className="mt-6 flex justify-end gap-3">
          <button type="button" className="btn-ghost" onClick={onClose} disabled={busy}>Cancel</button>
          <button type="submit" className="btn-primary disabled:opacity-60" disabled={busy}>{busy ? "Saving…" : editing ? "Save changes" : "Add proxy"}</button>
        </div>
      </form>
    </div>
  );
}
