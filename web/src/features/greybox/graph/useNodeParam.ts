// `?node=<id>` on the run URL selects (and centres) a graph node and opens its drawer.
// Implemented with react-router's search params when a Router is present (the run
// workspace); without one (tests, the dev preview) it is a no-op.
import { useCallback } from "react";
import { useInRouterContext, useSearchParams } from "react-router-dom";

export type NodeParam = readonly [nodeId: string | null, setNodeId: (id: string | null) => void];

function useRouterNodeParam(): NodeParam {
  const [params, setParams] = useSearchParams();
  const id = params.get("node");
  const set = useCallback(
    (next: string | null) => {
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          if (next) p.set("node", next);
          else p.delete("node");
          return p;
        },
        { replace: true },
      );
    },
    [setParams],
  );
  return [id, set];
}

const NONE: NodeParam = [null, () => {}];
function useNoNodeParam(): NodeParam {
  return NONE;
}

// Router presence never changes for a mounted component, so the hook order is stable.
export const useNodeParam: () => NodeParam = (() => {
  return function useNodeParamImpl(): NodeParam {
    // eslint-disable-next-line react-hooks/rules-of-hooks
    return useInRouterContext() ? useRouterNodeParam() : useNoNodeParam();
  };
})();
