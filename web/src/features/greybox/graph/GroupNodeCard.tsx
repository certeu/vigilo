import { memo } from "react";
import { Handle, Position, type Node, type NodeProps } from "@xyflow/react";
import { KIND_STYLE } from "./encoding";
import { KindIcon } from "./KindIcon";
import type { SiblingGroup } from "./model";
import { NODE_H, NODE_W } from "./layout";

export interface GroupData extends Record<string, unknown> {
  group: SiblingGroup;
  step: number;
  onMore: (key: string, by: number | "all") => void;
}
export type GroupNode = Node<GroupData, "group">;

const plural = (label: string, n: number) => (n === 1 ? label.toLowerCase() : `${label.toLowerCase()}s`);

/** "+N more" placeholder for folded siblings (expand by a step, or all). */
function GroupNodeCardImpl({ data }: NodeProps<GroupNode>) {
  const { group, step, onMore } = data;
  const label = KIND_STYLE[group.kind].label;
  return (
    <div
      className="relative flex flex-col justify-center gap-1 rounded-lg border border-dashed border-slate/50 bg-canvas px-3 text-[12px] text-slate"
      style={{ width: NODE_W, height: NODE_H * 0.7 }}
    >
      <Handle type="target" position={Position.Left} isConnectable={false} className="gx-handle" />
      <span className="flex items-center gap-1.5 font-medium text-ink">
        <KindIcon kind={group.kind} size={15} />+{group.hidden} more {plural(label, group.hidden)}
      </span>
      <span className="flex gap-3">
        <button type="button" className="nodrag text-accent hover:underline" onClick={() => onMore(group.key, step)}>
          Show {Math.min(step, group.hidden)} more
        </button>
        <button type="button" className="nodrag text-accent hover:underline" onClick={() => onMore(group.key, "all")}>
          Show all {group.total}
        </button>
      </span>
    </div>
  );
}

export const GroupNodeCard = memo(GroupNodeCardImpl);
