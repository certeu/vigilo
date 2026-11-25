import { CodeBracketIcon, GlobeAltIcon } from "@heroicons/react/24/outline";
import { Badge } from "./Badge";

export type AnalysisMode = "whitebox" | "greybox";

export const MODE_LABEL: Record<AnalysisMode, string> = {
  whitebox: "White-box",
  greybox: "Grey-box",
};

// Mode is always shown as icon + text so it never depends on colour alone.
export function ModeBadge({ mode }: { mode: AnalysisMode }) {
  const Icon = mode === "whitebox" ? CodeBracketIcon : GlobeAltIcon;
  return (
    <Badge
      tone={mode === "whitebox" ? "neutral" : "accent"}
      icon={<Icon className="h-3.5 w-3.5" aria-hidden="true" />}
      title={mode === "whitebox" ? "White-box: source repository analysis" : "Grey-box: running application testing"}
    >
      {MODE_LABEL[mode]}
    </Badge>
  );
}
