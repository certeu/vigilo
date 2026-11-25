// Exploration graph endpoint. Paths are listed without /api; `request` adds it.
import { request } from "../../../api/client";
import type { ExplorationGraphResponse, ExplorationNodeDetail } from "./types";

export const GRAPH_DEFAULT_LIMIT = 2000;
export const GRAPH_MAX_LIMIT = 5000;

export type ExplorationGraphFetcher = (
  runId: string,
  sinceVersion: number,
  limit: number,
  signal?: AbortSignal,
) => Promise<ExplorationGraphResponse>;

export const fetchExplorationGraph: ExplorationGraphFetcher = (runId, sinceVersion, limit, signal) =>
  request<ExplorationGraphResponse>(
    `/greybox/runs/${encodeURIComponent(runId)}/graph/exploration?since_version=${sinceVersion}&limit=${Math.min(limit, GRAPH_MAX_LIMIT)}`,
    { signal },
  );

/** GET .../graph/exploration/nodes/{node_id} (9.8): node, edges, neighbours, work order or finding, <=50 exchanges. */
export type ExplorationNodeDetailFetcher = (runId: string, nodeId: string, signal?: AbortSignal) => Promise<ExplorationNodeDetail>;

export const fetchExplorationNode: ExplorationNodeDetailFetcher = (runId, nodeId, signal) =>
  request<ExplorationNodeDetail>(
    `/greybox/runs/${encodeURIComponent(runId)}/graph/exploration/nodes/${encodeURIComponent(nodeId)}`,
    { signal },
  );
