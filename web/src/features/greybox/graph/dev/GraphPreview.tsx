// DEV ONLY preview of the exploration graph against synthetic fixture data.
// Mounted by App.tsx behind `import.meta.env.DEV`; absent from production builds.
// Query params: ?step=N (start at version N), ?large=1 (3,000-node run), ?auto=1.
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useExplorationGraph } from "../useExplorationGraph";
import { LazyExplorationGraph } from "../ExplorationGraphPanel";
import type { ExplorationGraphFetcher } from "../api";
import { buildLargeRun, buildStoryRun } from "./syntheticRun";

export default function GraphPreview() {
  const params = new URLSearchParams(window.location.search);
  const large = params.get("large") === "1";
  const run = useMemo(() => (large ? buildLargeRun(3000) : buildStoryRun()), [large]);
  const [clock, setClock] = useState(() => Math.min(run.v, Math.max(1, Number(params.get("step") ?? 3))));
  const clockRef = useRef(clock);
  clockRef.current = clock;
  const failNext = useRef(false);
  const [playing, setPlaying] = useState(params.get("auto") === "1");
  const [log, setLog] = useState<string[]>([]);

  const fetcher: ExplorationGraphFetcher = useCallback(
    async (_runId, since, limit) => {
      await new Promise((r) => setTimeout(r, 120));
      if (failNext.current) {
        failNext.current = false;
        throw new Error("Synthetic network error (preview)");
      }
      const resp = run.respond(clockRef.current, since, limit);
      setLog((l) => [`since=${since} → v${resp.version}: ${resp.nodes.length} nodes, ${resp.edges.length} edges${resp.full ? " (full)" : ""}`, ...l].slice(0, 6));
      return resp;
    },
    [run],
  );
  const controller = useExplorationGraph("synthetic-run", { fetcher, active: false, pollMs: 0, debounceMs: 150 });

  const step = useCallback(() => {
    setClock((c) => Math.min(run.v, c + 1));
  }, [run]);
  // Each clock change is a `graph.updated` signal: debounced delta fetch.
  const first = useRef(true);
  useEffect(() => {
    if (first.current) {
      first.current = false;
      return;
    }
    controller.requestRefresh();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [clock]);
  useEffect(() => {
    if (!playing) return;
    const t = setInterval(() => setClock((c) => (c < run.v ? c + 1 : c)), 1600);
    return () => clearInterval(t);
  }, [playing, run]);

  return (
    <div className="flex h-screen flex-col bg-canvas">
      <div role="note" className="border-b border-severity-medium/40 bg-amber-50 px-4 py-2 text-sm text-severity-medium">
        <strong>Development preview — synthetic fixture data.</strong> Not a real run, not telemetry. This route only exists in
        <code className="mono mx-1">vite dev</code> builds.
      </div>
      <div className="flex flex-wrap items-center gap-2 border-b border-line bg-surface px-4 py-2 text-sm">
        <span className="font-semibold">Exploration graph preview</span>
        <span className="text-slate">
          version {clock} / {run.v}
        </span>
        <button type="button" className="btn-ghost !py-1" onClick={step} disabled={clock >= run.v}>
          Next delta
        </button>
        <button type="button" className="btn-ghost !py-1" onClick={() => setPlaying((p) => !p)} aria-pressed={playing}>
          {playing ? "Pause" : "Play"}
        </button>
        <button type="button" className="btn-ghost !py-1" onClick={() => setClock(run.v)}>
          Jump to end
        </button>
        <button
          type="button"
          className="btn-ghost !py-1"
          onClick={() => {
            failNext.current = true;
            void controller.refresh();
          }}
        >
          Simulate fetch error
        </button>
        <a className="text-accent hover:underline" href={large ? "?step=3" : "?large=1&step=999"}>
          {large ? "Small story run" : "Large run (3,000 nodes)"}
        </a>
        <span className="mono ml-auto hidden text-[11px] text-slate lg:inline">{log[0]}</span>
      </div>
      <div className="min-h-0 flex-1 p-3">
        <LazyExplorationGraph
          controller={controller}
          fill
          runActive={clock < run.v}
          onOpenFinding={(id) => window.alert(`(preview) open finding ${id}`)}
          onOpenEvent={(seq) => window.alert(`(preview) open event #${seq}`)}
          onOpenWorkOrder={(id) => window.alert(`(preview) open work order ${id}`)}
          onOpenExchange={(id) => window.alert(`(preview) open exchange #${id}`)}
        />
      </div>
    </div>
  );
}
