import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import { api } from "../../api/client";
import { greyboxApi } from "./api";
import { egressFailure } from "./egressProxy";
import type { AvailableEgressProxy } from "./types";

export const ADMIN_PROXIES_PATH = "/admin#egress-proxies";

/** Available proxies for the current user; `null` = feature off (404) or failed: hide everything. */
export function useAvailableProxies(): AvailableEgressProxy[] | null | undefined {
  const [list, setList] = useState<AvailableEgressProxy[] | null | undefined>(undefined);
  useEffect(() => {
    let live = true;
    greyboxApi
      .availableEgressProxies()
      .then((l) => live && setList(l))
      .catch(() => live && setList(null));
    return () => {
      live = false;
    };
  }, []);
  return list;
}

export function useIsAdmin(): boolean {
  const [admin, setAdmin] = useState(false);
  useEffect(() => {
    let live = true;
    api.me().then((m) => live && setAdmin(m.role === "admin")).catch(() => undefined);
    return () => {
      live = false;
    };
  }, []);
  return admin;
}

/** Distinct network-path failure message (proxy unreachable / refused via proxy / direct hint). */
export function EgressFailureNote({
  text, proxyName, viaProxy, className = "",
}: { text: string | null | undefined; proxyName?: string | null; viaProxy: boolean; className?: string }) {
  const isAdmin = useIsAdmin();
  const f = egressFailure(text, viaProxy, proxyName);
  if (!f) return null;
  return (
    <p role="note" className={`text-sm ${className}`} data-testid="egress-failure">
      {f.message}
      {f.showProxyHint && (
        <>
          {" "}
          {isAdmin ? (
            <Link to={ADMIN_PROXIES_PATH} className="text-accent hover:underline">Configure an egress proxy</Link>
          ) : (
            <span>Ask an administrator.</span>
          )}
        </>
      )}
    </p>
  );
}

export function ViaProxyChip({ name }: { name: string }) {
  return (
    <span className="inline-flex items-center rounded-full border border-line bg-canvas px-2 py-0.5 text-xs font-medium text-slate" title="Requests are sent through this egress proxy">
      via {name}
    </span>
  );
}
