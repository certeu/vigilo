// Pure parts of the analyst-steering ("hints") feature behind the run chat: action
// vocabulary, payload builder, validation, outcome sentences and node target
// suggestions. No React here so it is unit-testable without a DOM.
import { ApiError } from "../../../api/client";
import type { Hint, HintAction, HintCreate } from "../types";

export const HINT_TEXT_MAX = 2000;

export const HINT_ACTIONS: readonly HintAction[] = ["note", "focus", "add_seed", "skip_check", "deprioritize"];

export interface ActionInfo {
  label: string;
  /** One-line plain-words explanation shown under the select. */
  help: string;
  /** What the target field holds; null = no target for this action. */
  target: "none" | "path" | "check";
  targetLabel?: string;
  placeholder?: string;
}

export const ACTION_INFO: Record<HintAction, ActionInfo> = {
  note: { label: "Message", help: "Read by the exploration agent at its next step; it may reply. Also kept on the timeline and in the report.", target: "none" },
  focus: {
    label: "Focus on a path",
    help: "Prioritise work on this path or URL, and queue it if it is new.",
    target: "path", targetLabel: "Path or URL", placeholder: "/admin or https://host/admin",
  },
  add_seed: {
    label: "Add a crawl seed",
    help: "Start crawling from this URL.",
    target: "path", targetLabel: "URL to crawl from", placeholder: "https://host/app/",
  },
  skip_check: {
    label: "Skip a check",
    help: "Stop running the selected check for the rest of the run.",
    target: "check", targetLabel: "Check",
  },
  deprioritize: {
    label: "Deprioritise a path",
    help: "Push this path or URL to the back of the queue.",
    target: "path", targetLabel: "Path or URL", placeholder: "/static/",
  },
};

export const HINT_SCOPE_NOTE =
  "Messages can never widen the scope or raise budgets. A target outside the run's scope is rejected, with the reason shown.";

export interface HintDraft {
  action: HintAction;
  target: string;
  text: string;
  aboutNodeId: string | null;
}

export const EMPTY_DRAFT: HintDraft = { action: "note", target: "", text: "", aboutNodeId: null };

export type HintErrors = Partial<Record<"text" | "target", string>>;

export function validateHint(d: HintDraft): HintErrors {
  const errs: HintErrors = {};
  const text = d.text.trim();
  if (!text) errs.text = "Write a message.";
  else if (text.length > HINT_TEXT_MAX) errs.text = `Keep it under ${HINT_TEXT_MAX} characters (${text.length}).`;
  const kind = ACTION_INFO[d.action].target;
  const target = d.target.trim();
  if (kind === "path") {
    if (!target) errs.target = "Enter a path or URL.";
    else if (!/^(https?:\/\/\S+|\/\S*)$/i.test(target)) errs.target = "Use a path starting with / or an http(s) URL, without spaces.";
  } else if (kind === "check" && !target) errs.target = "Select a check.";
  return errs;
}

/** Request body. `target` is null for notes (whatever is left in the field is dropped). */
export function buildHintPayload(d: HintDraft): HintCreate {
  const kind = ACTION_INFO[d.action].target;
  return {
    text: d.text.trim(),
    action: d.action,
    target: kind === "none" ? null : d.target.trim(),
    about_node_id: d.aboutNodeId,
  };
}

/** Plain-words message for a failed submit. */
export function hintErrorMessage(e: unknown): string {
  if (e instanceof ApiError) {
    if (e.status === 409) return "This run has finished, so it no longer accepts messages.";
    if (e.status === 404) return "Run not found, or you do not have access to it.";
    if (e.status === 429) return "Too many messages: the limit is 10 per minute. Wait a moment and try again.";
    if (e.status === 422) return `The message was not accepted: ${detailText(e.detail) ?? e.message}`;
    return e.message;
  }
  return e instanceof Error ? e.message : "Could not send the message.";
}

function detailText(detail: unknown): string | null {
  if (typeof detail === "string") return detail;
  if (Array.isArray(detail)) {
    const parts = detail
      .map((d) => (d && typeof d === "object" && "msg" in d ? String((d as { msg: unknown }).msg) : null))
      .filter((s): s is string => !!s);
    return parts.length ? parts.join("; ") : null;
  }
  return null;
}

/**
 * Plain-language sentences for every rejection reason the backend emits
 * (planner.py settle_hint, scope.py parse_url / ScopePolicy.check_url).
 */
export const REASON_TEXT: Record<string, string> = {
  invalid_url: "Rejected: that is not a valid http/https URL",
  userinfo_present: "Rejected: URLs with a username or password are not allowed",
  scheme_not_allowed: "Rejected: this URL scheme is not in the authorised scope (check http vs https)",
  host_not_allowed: "Rejected: that host is outside the authorised scope",
  port_not_allowed: "Rejected: that port is outside the authorised scope",
  path_excluded: "Rejected: that path is excluded from the scope",
  path_not_in_scope: "Rejected: that path is outside the authorised scope",
  out_of_scope: "Rejected: that target is outside the authorised scope",
  invalid_target: "Rejected: the target is not a usable path or URL",
  check_not_selected: "Rejected: that check is not enabled for this run",
  run_ended: "Not applied: the run ended before the analysis got to it",
  internal_error: "Not applied: the engine hit an internal error",
};

/** Sentence for a rejection reason; unknown codes are humanised rather than shown raw. */
export function reasonSentence(reason: string | null | undefined): string {
  if (!reason) return "Rejected: no reason given";
  const known = REASON_TEXT[reason];
  if (known) return known;
  // Free text from the server (contains spaces) is shown as is; codes are humanised.
  if (/\s/.test(reason)) return `Rejected: ${reason}`;
  const words = reason.replace(/[_-]+/g, " ").trim();
  return `Rejected: ${words.charAt(0).toLowerCase()}${words.slice(1)}`;
}

export type OutcomeTone = "success" | "neutral" | "warn";

export interface HintOutcome {
  text: string;
  /** success = something changed; neutral = accepted but no effect; warn = rejected. */
  tone: OutcomeTone;
}

const NO_EFFECT = [
  /^(?:de)?prioritised 0 work orders?(?:, added 0 seeds?)?$/i,
  /^seed already planned$/i,
  /^noted$/i,
];

/** Neutral grey text classes by tone (success is green; no-effect results are deliberately not). */
export const OUTCOME_CLASS: Record<OutcomeTone, string> = {
  success: "text-emerald-800",
  neutral: "text-slate",
  warn: "text-severity-high",
};

/** Second line of a list entry: the result (addressed) or the reason (rejected). */
export function hintOutcome(h: Pick<Hint, "status" | "result">): HintOutcome | null {
  if (h.status === "open") return null;
  if (h.status === "rejected") return { text: reasonSentence(h.result), tone: "warn" };
  const r = (h.result ?? "").trim();
  if (!r) return { text: "Addressed.", tone: "neutral" };
  const text = r.charAt(0).toUpperCase() + r.slice(1) + (/[.!?]$/.test(r) ? "" : ".");
  return { text, tone: NO_EFFECT.some((re) => re.test(r)) ? "neutral" : "success" };
}

// ---- list maintenance (shared by polling and live events) ----

/** Insert or replace by id, newest first. */
export function upsertHint(list: readonly Hint[], h: Hint): Hint[] {
  const next = list.filter((x) => x.id !== h.id);
  next.push(h);
  return next.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

// ---- node context ----

/** A sensible hint target for a graph node: its URL or path, if the data carries one. */
export function suggestTarget(data: Record<string, unknown> | null | undefined, label?: string): string | null {
  if (data) {
    for (const k of ["url", "path", "endpoint", "target", "asset_url", "asset_path"]) {
      const v = data[k];
      if (typeof v === "string" && /^(https?:\/\/\S+|\/\S*)$/i.test(v.trim())) return v.trim();
    }
  }
  const m = label ? /(?:^|\s)(https?:\/\/\S+|\/[^\s?]*\S*)/.exec(label) : null;
  return m ? m[1] : null;
}
