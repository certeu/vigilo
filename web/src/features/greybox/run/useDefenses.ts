import { useCallback, useEffect, useRef, useState } from "react";
import { greyboxApi } from "../api";
import type { Defense } from "../types";
import { shouldRefreshDefenses } from "./defensesModel";
import { useRunEvents } from "./RunLiveContext";

export interface DefensesState {
  items: Defense[];
  loading: boolean;
  error: string | null;
  refresh: () => void;
}

/**
 * Defenses of a run. Loads once, and after the run is terminal refreshes (debounced)
 * on defense.* and report.ready events, since the defenses are generated while the
 * run reports. Safe outside a RunLiveProvider (no live refresh then).
 */
export function useDefenses(runId: string, runStatus: string | null, enabled = true): DefensesState {
  const [items, setItems] = useState<Defense[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const seq = useRef(0);

  const load = useCallback(() => {
    if (!enabled || !runId) return setLoading(false);
    const mine = ++seq.current;
    greyboxApi
      .defenses(runId)
      .then((r) => {
        if (mine !== seq.current) return;
        setItems(r.items);
        setError(null);
      })
      .catch((e: unknown) => mine === seq.current && setError(e instanceof Error ? e.message : "Failed to load defenses"))
      .finally(() => mine === seq.current && setLoading(false));
  }, [runId, enabled]);

  // Initial load, and again when the run status changes (e.g. it just finished).
  useEffect(() => {
    load();
    return () => void ++seq.current;
  }, [load, runStatus]);

  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);
  useRunEvents(["defense.*", "report.ready"], (e) => {
    if (!enabled || !shouldRefreshDefenses(runStatus, e.kind)) return;
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(load, 400);
  });

  return { items, loading, error, refresh: load };
}
