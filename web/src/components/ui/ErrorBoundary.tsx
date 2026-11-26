import { Component, type ErrorInfo, type ReactNode } from "react";
import { ExclamationTriangleIcon } from "@heroicons/react/24/outline";

interface Props {
  children: ReactNode;
  /** Optional custom fallback. */
  fallback?: (error: Error, reset: () => void) => ReactNode;
  /** Short label of what failed, e.g. "this page". */
  label?: string;
}
interface State {
  error: Error | null;
}

// Contains render errors so one broken view cannot blank the whole app. Give it a
// `key` (e.g. the pathname) to reset automatically on navigation.
export class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null };

  static getDerivedStateFromError(error: Error): State {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error("UI error boundary caught", error, info.componentStack);
  }

  reset = () => this.setState({ error: null });

  render() {
    const { error } = this.state;
    if (!error) return this.props.children;
    if (this.props.fallback) return this.props.fallback(error, this.reset);
    return (
      <div role="alert" className="card flex items-start gap-3 p-6">
        <ExclamationTriangleIcon className="h-5 w-5 shrink-0 text-severity-critical" aria-hidden="true" />
        <div className="min-w-0">
          <h2 className="font-display text-base font-semibold">
            Something went wrong while rendering {this.props.label ?? "this view"}.
          </h2>
          <p className="mono mt-1 break-words text-xs text-slate">{error.message}</p>
          <button type="button" className="btn-ghost mt-3" onClick={this.reset}>
            Try again
          </button>
        </div>
      </div>
    );
  }
}
