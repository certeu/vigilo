import { useCallback, useEffect, useRef, useState } from "react";
import { greyboxApi } from "../api";
import type { Finding, FindingSummary } from "../types";
import { FINDING_EVENTS } from "./findingsModel";
import { useRunEvents } from "./RunLiveContext";

export interface FindingsState {
  items: FindingSummary[];
  loading: boolean;
  error: unknown;
  /** Bumps on every successful reload; the detail panel refetches when it changes. */
  version: number;
  refresh: () => void;
}

/**
 * Findings of a run: loads once, again when the run status changes, and (debounced) on
 * finding.* events. Safe outside a RunLiveProvider (no live refresh then).
 */
export function useFindings(runId: string, runStatus: string): FindingsState {
  const [items, setItems] = useState<FindingSummary[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<unknown>(null);
  const [version, setVersion] = useState(0);
  const seq = useRef(0);

  const load = useCallback(() => {
    const mine = ++seq.current;
    greyboxApi
      .findings(runId)
      .then((r) => {
        if (mine !== seq.current) return;
        setItems(r.items);
        setError(null);
        setVersion((v) => v + 1);
      })
      .catch((e: unknown) => mine === seq.current && setError(e))
      .finally(() => mine === seq.current && setLoading(false));
  }, [runId]);

  useEffect(() => {
    load();
    return () => void ++seq.current;
  }, [load, runStatus]);

  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => void (timer.current && clearTimeout(timer.current)), []);
  useRunEvents(FINDING_EVENTS, () => {
    if (timer.current) clearTimeout(timer.current);
    timer.current = setTimeout(load, 400);
  });

  return { items, loading, error, version, refresh: load };
}

export interface FindingDetailState {
  finding: Finding | null;
  loading: boolean;
  error: unknown;
  retry: () => void;
}

/** One finding's detail; refetches when the list version changes (a finding.* event arrived). */
export function useFindingDetail(runId: string, findingId: string | null, version: number): FindingDetailState {
  const [finding, setFinding] = useState<Finding | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<unknown>(null);
  const [nonce, setNonce] = useState(0);
  const shown = useRef<string | null>(null);

  useEffect(() => {
    if (!findingId) {
      shown.current = null;
      setFinding(null);
      setError(null);
      return;
    }
    let alive = true;
    // Keep showing the previous data while refetching the same finding; reset for another one.
    if (shown.current !== findingId) {
      shown.current = findingId;
      setFinding(null);
      setLoading(true);
    }
    setError(null);
    greyboxApi
      .finding(runId, findingId)
      .then((f) => alive && setFinding(f))
      .catch((e: unknown) => alive && setError(e))
      .finally(() => alive && setLoading(false));
    return () => {
      alive = false;
    };
  }, [runId, findingId, version, nonce]);

  return { finding, loading, error, retry: () => setNonce((n) => n + 1) };
}
