import {
  BoltIcon, ChatBubbleLeftEllipsisIcon, ClipboardDocumentListIcon, EyeIcon, FlagIcon, LightBulbIcon, ShieldCheckIcon, ShieldExclamationIcon, SparklesIcon,
} from "@heroicons/react/20/solid";
import type { ComponentType, SVGProps } from "react";
import { KIND_STYLE } from "./encoding";
import type { ExplorationNodeKind } from "./types";

const ICON: Record<ExplorationNodeKind, ComponentType<SVGProps<SVGSVGElement>>> = {
  objective: FlagIcon,
  lead: LightBulbIcon,
  work_order: ClipboardDocumentListIcon,
  action: BoltIcon,
  observation: EyeIcon,
  finding: ShieldExclamationIcon,
  hint: ChatBubbleLeftEllipsisIcon,
  defense: ShieldCheckIcon,
  reasoning: SparklesIcon,
};

/** Kind tile: icon on the kind colour. Always paired with a text label by callers. */
export function KindIcon({ kind, size = 18 }: { kind: ExplorationNodeKind; size?: number }) {
  const Icon = ICON[kind];
  return (
    <span
      aria-hidden="true"
      className={`inline-grid shrink-0 place-items-center rounded ${KIND_STYLE[kind].tile}`}
      style={{ width: size, height: size }}
    >
      <Icon style={{ width: size * 0.66, height: size * 0.66 }} />
    </span>
  );
}
