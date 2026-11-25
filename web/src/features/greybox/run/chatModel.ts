// Pure model of the run chat: derived message status, conversation ordering and the
// unread-reply count. Messages are hints (POST /greybox/runs/{id}/hints); the
// exploration agent reads open ones at its next cycle and may reply.
import type { Hint } from "../types";
import { hintOutcome, type HintOutcome } from "./hintLogic";

/**
 * queued   sent, not yet picked up (status open)
 * applied  the engine applied it (addressed); `result` says what changed
 * rejected the engine refused it (rejected); `result` is the reason
 * reading  the agent has it in its current step but has not answered yet
 * replied  the agent answered (`reply`)
 */
export type ChatStatus = "queued" | "applied" | "rejected" | "reading" | "replied";

export interface ChatTick {
  label: string;
  glyph: string;
  /** Tailwind text class (literal so the JIT keeps it). */
  cls: string;
}

export const CHAT_TICK: Record<ChatStatus, ChatTick> = {
  queued: { label: "Queued", glyph: "◷", cls: "text-slate" },
  applied: { label: "Applied", glyph: "✓", cls: "text-emerald-800" },
  rejected: { label: "Rejected", glyph: "⊘", cls: "text-severity-high" },
  reading: { label: "Agent reading…", glyph: "◐", cls: "text-hint-ink" },
  replied: { label: "Replied", glyph: "✓✓", cls: "text-hint-ink" },
};

const hasReply = (h: Pick<Hint, "reply">): boolean => !!h.reply?.trim();

/** `readingIds`: hints named in an `llm.request` event's `data.hint_ids` (live, before the backend sets `seen_cycle`). */
export function chatStatus(
  h: Pick<Hint, "id" | "status" | "reply" | "seen_cycle">,
  readingIds?: ReadonlySet<string>,
): ChatStatus {
  if (hasReply(h)) return "replied";
  if (h.seen_cycle != null || readingIds?.has(h.id)) return "reading";
  if (h.status === "rejected") return "rejected";
  if (h.status === "addressed") return "applied";
  return "queued";
}

/** Outcome line under a user bubble: shown for rejections and for actions; a plain message's "noted" adds nothing. */
export function chatOutcome(h: Pick<Hint, "action" | "status" | "result">): HintOutcome | null {
  if (h.status === "open") return null;
  if (h.status === "addressed" && h.action === "note") return null;
  return hintOutcome(h);
}

export type ChatItem =
  | { kind: "user"; key: string; at: string; hint: Hint; status: ChatStatus }
  | { kind: "agent"; key: string; at: string; hint: Hint; text: string };

/**
 * Conversation oldest -> newest: each message at its `created_at`, each reply at its
 * `replied_at` (or right after its message when the time is unknown). Ties keep a
 * reply after the message it answers.
 */
export function buildConversation(hints: readonly Hint[], readingIds?: ReadonlySet<string>): ChatItem[] {
  const items: (ChatItem & { order: number })[] = [];
  for (const h of hints) {
    items.push({ kind: "user", key: `u:${h.id}`, at: h.created_at, hint: h, status: chatStatus(h, readingIds), order: 0 });
    if (hasReply(h)) {
      const at = h.replied_at && h.replied_at >= h.created_at ? h.replied_at : h.created_at;
      items.push({ kind: "agent", key: `a:${h.id}`, at, hint: h, text: h.reply!.trim(), order: 1 });
    }
  }
  items.sort((a, b) => Date.parse(a.at) - Date.parse(b.at) || a.order - b.order || a.hint.id.localeCompare(b.hint.id));
  return items.map(({ order: _order, ...it }) => it as ChatItem);
}

/** Ids of hints that carry an agent reply. */
export function repliedIds(hints: readonly Hint[]): string[] {
  return hints.filter(hasReply).map((h) => h.id);
}

/** Replies not yet seen in the open dock. */
export function unreadCount(hints: readonly Hint[], seen: ReadonlySet<string>): number {
  return hints.reduce((n, h) => n + (hasReply(h) && !seen.has(h.id) ? 1 : 0), 0);
}

/** `data.hint_ids` of an `llm.request` event (the messages the agent is reading in that cycle). */
export function hintIdsOf(data: unknown): string[] {
  const ids = data && typeof data === "object" ? (data as { hint_ids?: unknown }).hint_ids : null;
  return Array.isArray(ids) ? ids.filter((x): x is string => typeof x === "string") : [];
}
