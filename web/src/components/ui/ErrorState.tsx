import type { ComponentType, SVGProps } from "react";
import { ExclamationTriangleIcon } from "@heroicons/react/24/outline";
import { EmptyState } from "./EmptyState";
import { humanizeError } from "./humanizeError";

/**
 * The one error state for loading failures (run tabs and pages): humanised text and a
 * Retry button. Pass the caught `error` (any value) or a ready `message`.
 */
export function ErrorState({
  title,
  error,
  message,
  what,
  onRetry,
  icon = ExclamationTriangleIcon,
  card = true,
}: {
  title: string;
  error?: unknown;
  message?: string;
  /** Noun used in humanised text, e.g. "the findings". */
  what?: string;
  onRetry?: () => void;
  icon?: ComponentType<SVGProps<SVGSVGElement>>;
  card?: boolean;
}) {
  const text = message ?? humanizeError(error, what);
  const body = (
    <div role="alert">
      <EmptyState
        icon={icon}
        title={title}
        action={onRetry ? <button type="button" className="btn-ghost" onClick={onRetry}>Retry</button> : undefined}
      >
        {text}
      </EmptyState>
    </div>
  );
  return card ? <div className="card">{body}</div> : body;
}
