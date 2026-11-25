import { useEffect, useState } from "react";
import { greyboxApi } from "../api";
import type { SecurityModelView } from "../types";
import { BASIS_LABEL, accessCell, entityName, identityColumns, summarise } from "./securityModel";

/**
 * The run's security model (GET /greybox/runs/{id}/model): expected access with its
 * basis, observed access per interface and identity, and correlation signals.
 * Read-only; refreshed when the run status changes.
 */
export function SecurityModelPanel({ runId, runStatus }: { runId: string; runStatus: string }) {
  const [model, setModel] = useState<SecurityModelView | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let live = true;
    greyboxApi
      .securityModel(runId)
      .then((m) => live && (setModel(m), setError(null)))
      .catch((e: unknown) => live && setError(e instanceof Error ? e.message : "Failed to load"));
    return () => {
      live = false;
    };
  }, [runId, runStatus]);

  const s = summarise(model);
  if (error) return null;
  if (!model || s.empty) return null;
  const cols = identityColumns(model);

  return (
    <section className="card p-5">
      <h2 className="mb-1 text-xs font-semibold uppercase tracking-wide text-slate">Security model</h2>
      <p className="mb-3 text-xs text-slate">
        Expected access is what the application established; observed access is what each identity received. An
        observation alone is not a conclusion. {s.identities} identities · {s.interfaces} interfaces ·{" "}
        {s.expectations} expectations ({s.assumptions} assumptions) · {s.signals} signals · {s.unresolved} unresolved
      </p>

      {model.expectations.length > 0 && (
        <div className="mb-4 overflow-x-auto">
          <h3 className="mb-1 text-sm font-semibold">Expected access</h3>
          <table className="w-full text-left text-xs">
            <thead className="text-slate">
              <tr>
                <th className="py-1 pr-3">Who</th>
                <th className="py-1 pr-3">Operation</th>
                <th className="py-1 pr-3">Resource</th>
                <th className="py-1 pr-3">Expected</th>
                <th className="py-1 pr-3">Basis</th>
              </tr>
            </thead>
            <tbody>
              {model.expectations.map((e, i) => (
                <tr key={i} className="border-t border-line">
                  <td className="py-1 pr-3">{entityName(e.subject)}</td>
                  <td className="py-1 pr-3">{e.operation}</td>
                  <td className="py-1 pr-3">{entityName(e.resource)}</td>
                  <td className="py-1 pr-3 font-medium">{e.expected}</td>
                  <td className="py-1 pr-3">{BASIS_LABEL[e.basis] ?? e.basis}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {model.interfaces.length > 0 && (
        <div className="mb-4 overflow-x-auto">
          <h3 className="mb-1 text-sm font-semibold">Observed access (allowed / denied / not found)</h3>
          <table className="w-full text-left text-xs">
            <thead className="text-slate">
              <tr>
                <th className="py-1 pr-3">Interface</th>
                {cols.map((c) => (
                  <th key={c} className="py-1 pr-3">
                    {c}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {model.interfaces.slice(0, 20).map((it) => (
                <tr key={it.interface} className="border-t border-line">
                  <td className="py-1 pr-3 font-mono">{it.interface}</td>
                  {cols.map((c) => (
                    <td key={c} className="py-1 pr-3">
                      {accessCell(it.access[c])}
                    </td>
                  ))}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {model.signals.length > 0 && (
        <div>
          <h3 className="mb-1 text-sm font-semibold">Correlation signals (to verify, not findings)</h3>
          <ul className="list-disc pl-5 text-xs">
            {model.signals.map((sig, i) => (
              <li key={i}>
                {sig.summary} <span className="text-slate">({sig.evidence.join(", ")})</span>
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
