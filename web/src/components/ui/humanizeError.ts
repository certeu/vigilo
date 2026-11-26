import { ApiError } from "../../api/client";

/** Plain-language text for a failed request. Never shows raw "Failed to fetch" or status codes alone. */
export function humanizeError(e: unknown, what = "this"): string {
  if (e instanceof ApiError) {
    if (e.status === 401) return "Your session has expired. Sign in again.";
    if (e.status === 403) return `You do not have access to ${what}.`;
    if (e.status === 404) return `${capitalize(what)} is not available. It may not exist yet, or this server does not provide it.`;
    if (e.status >= 500) return "The server had a problem handling this request. Try again in a moment.";
    return e.message || `The request failed (${e.status}).`;
  }
  const msg = e instanceof Error ? e.message : "";
  if (!msg || /failed to fetch|networkerror|load failed|network request failed/i.test(msg)) {
    return "Could not reach the server. Check your connection and try again.";
  }
  return msg;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
