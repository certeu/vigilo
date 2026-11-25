// Slot for the Exploration tab of the grey-box run workspace.
//
// RunWorkspace lazy-loads this module (React.lazy), so whatever is exported as
// `ExplorationTab` here lands in its own chunk. React Flow and dagre stay in the
// graph chunk that ExplorationGraphPanel loads on demand. Keep the props contract
// stable:
//
//   runId        the run id (GET /greybox/runs/{runId}/graph/exploration)
//   runStatus    current RunStatus; poll graph deltas only while non-terminal
//   graphVersion RunRead.graph_version when the API returns it (cheap change signal)
export { ExplorationTab, type ExplorationTabProps } from "../graph/ExplorationGraphPanel";
export { ExplorationTab as default } from "../graph/ExplorationGraphPanel";
