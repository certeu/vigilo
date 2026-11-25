// Live run-chat data: the run's hints (messages) plus which ones the agent is reading.
//
// Live updates: hint.* events (added / addressed / rejected / replied) from the run's
// live stream (RunLiveContext) trigger a refetch; an llm.request event naming
// `data.hint_ids` marks those messages as being read. GET /hints every 2 s is only the
// fallback while the stream is not live (or outside a RunLiveProvider).
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { greyboxApi } from "../api";
import type { Hint, HintCreate } from "../types";
import { upsertHint } from "./hintLogic";
import { hintIdsOf } from "./chatModel";
import { useRunLiveStatusOptional } from "./RunLiveContext";

const POLL_MS = 2000;

export interface RunChatData {
  /** Newest first (as served). */
  hints: Hint[];
  loaded: boolean;
  loadError: string | null;
  /** Hints named by the agent's latest model calls (llm.request data.hint_ids). */
  readingIds: ReadonlySet<string>;
  submit: (body: HintCreate) => Promise<Hint>;
  refresh: () => Promise<void>;
}

export function useRunChat(runId: string, active: boolean): RunChatData {
  const [hints, setHints] = useState<Hint[]>([]);
  const [loaded, setLoaded] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [readingIds, setReadingIds] = useState<ReadonlySet<string>>(() => new Set());
  const alive = useRef(true);
  useEffect(() => {
    alive.current = true;
    return () => { alive.current = false; };
  }, []);

  const refresh = useCallback(async () => {
    try {
      const r = await greyboxApi.hints(runId);
      if (!alive.current) return;
      setHints([...r.items].sort((a, b) => b.created_at.localeCompare(a.created_at)));
      setLoadError(null);
    } catch (e) {
      if (alive.current) setLoadError(e instanceof Error ? e.message : "Could not load messages");
    } finally {
      if (alive.current) setLoaded(true);
    }
  }, [runId]);

  useEffect(() => { void refresh(); }, [refresh]);

  const live = useRunLiveStatusOptional();
  const isLive = live?.isLive ?? false;
  const subscribe = live?.subscribe;
  const refreshRef = useRef(refresh);
  refreshRef.current = refresh;
  useEffect(() => {
    if (!subscribe) return;
    const offHints = subscribe("hint.*", () => { void refreshRef.current(); });
    const offLlm = subscribe("llm.request", (e) => {
      const ids = hintIdsOf(e.data);
      if (ids.length === 0) return;
      setReadingIds((prev) => (ids.every((id) => prev.has(id)) ? prev : new Set([...prev, ...ids])));
      void refreshRef.current();
    });
    return () => { offHints(); offLlm(); };
  }, [subscribe]);
  useEffect(() => {
    if (!active || isLive) return;
    const t = setInterval(() => { void refreshRef.current(); }, POLL_MS);
    return () => clearInterval(t);
  }, [active, isLive]);

  const submit = useCallback(
    async (body: HintCreate) => {
      const h = await greyboxApi.addHint(runId, body);
      if (alive.current) setHints((l) => upsertHint(l, h));
      void refresh();
      return h;
    },
    [runId, refresh],
  );

  return useMemo(() => ({ hints, loaded, loadError, readingIds, submit, refresh }), [hints, loaded, loadError, readingIds, submit, refresh]);
}
