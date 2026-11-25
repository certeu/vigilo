import { memo, useState } from "react";
import { BaseEdge, getBezierPath, useStore, type Edge, type EdgeProps } from "@xyflow/react";
import { edgeLabelVisible } from "./edges";

export interface MergedEdgeData extends Record<string, unknown> {
  label: string;
  tooltip: string;
  color: string;
  touches: boolean;
  edgeCount: number;
  secondary: boolean;
}
export type MergedFlowEdge = Edge<MergedEdgeData, "merged">;

/** One edge per node pair: label on hover / selection / high zoom, full detail in the tooltip. */
function GraphEdgeImpl(p: EdgeProps<MergedFlowEdge>) {
  const [hovered, setHovered] = useState(false);
  const zoom = useStore((s) => s.transform[2]);
  const d = p.data;
  const [path, lx, ly] = getBezierPath({
    sourceX: p.sourceX, sourceY: p.sourceY, sourcePosition: p.sourcePosition,
    targetX: p.targetX, targetY: p.targetY, targetPosition: p.targetPosition,
  });
  const show = !!d && edgeLabelVisible({ touchesSelected: d.touches, hovered, zoom, edgeCount: d.edgeCount });
  return (
    <g onMouseEnter={() => setHovered(true)} onMouseLeave={() => setHovered(false)}>
      {d && <title>{d.tooltip}</title>}
      <BaseEdge
        id={p.id}
        path={path}
        labelX={lx}
        labelY={ly}
        markerStart={p.markerStart}
        markerEnd={p.markerEnd}
        style={p.style}
        interactionWidth={16}
        label={show ? d?.label : undefined}
        labelStyle={{ fill: d?.color, fontSize: 10, fontWeight: 600 }}
        labelBgStyle={{ fill: "#FBFBFD", fillOpacity: 0.95 }}
        labelBgPadding={[4, 2]}
        labelBgBorderRadius={3}
      />
    </g>
  );
}

export const GraphEdge = memo(GraphEdgeImpl);
