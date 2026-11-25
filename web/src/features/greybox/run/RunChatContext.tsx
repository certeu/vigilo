// Run chat state for one run workspace: whether the dock is open, the node the next
// message is about, the message list (useRunChat) and the unread-reply count. Mounted by
// RunWorkspace around the header, tabs and the dock; the graph's "Guide from here"
// reaches it with openWith().
import { createContext, useCallback, useContext, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import { repliedIds, unreadCount } from "./chatModel";
import { useRunChat, type RunChatData } from "./useRunChat";

export interface ChatNodeContext {
  nodeId: string;
  label: string;
  /** Suggested path/URL for a focus / seed / deprioritise quick action. */
  target?: string | null;
}

export interface RunChatValue {
  runId: string;
  /** False once the run is terminal: the dock shows read-only history. */
  accepting: boolean;
  /** Check ids of the run (options for "Skip a check"). */
  checks: string[];
  open: boolean;
  toggle: () => void;
  close: () => void;
  openWith: (ctx: ChatNodeContext) => void;
  /** Node the next message is about (removable chip in the composer). */
  context: ChatNodeContext | null;
  clearContext: () => void;
  /** Bumped by openWith so the composer can refocus even if the dock was already open. */
  focusToken: number;
  chat: RunChatData;
  unread: number;
}

const Ctx = createContext<RunChatValue | null>(null);

export function RunChatProvider({
  runId,
  accepting,
  checks,
  children,
}: {
  runId: string;
  accepting: boolean;
  checks: string[];
  children: ReactNode;
}) {
  const chat = useRunChat(runId, accepting);
  const [open, setOpen] = useState(false);
  const [context, setContext] = useState<ChatNodeContext | null>(null);
  const [focusToken, setFocusToken] = useState(0);
  // Replies already seen. Seeded with the replies present at first load so a page reload
  // does not flag old answers as new; afterwards a reply counts as seen once the dock shows it.
  const [seen, setSeen] = useState<ReadonlySet<string>>(() => new Set());
  const seeded = useRef(false);
  const { hints, loaded } = chat;

  useEffect(() => {
    if (!loaded) return;
    if (!seeded.current || open) {
      seeded.current = true;
      const ids = repliedIds(hints);
      setSeen((prev) => (ids.every((id) => prev.has(id)) ? prev : new Set([...prev, ...ids])));
    }
  }, [loaded, open, hints]);

  const toggle = useCallback(() => setOpen((o) => !o), []);
  const close = useCallback(() => setOpen(false), []);
  const clearContext = useCallback(() => setContext(null), []);
  const openWith = useCallback((ctx: ChatNodeContext) => {
    setContext(ctx);
    setOpen(true);
    setFocusToken((t) => t + 1);
  }, []);

  const unread = open ? 0 : unreadCount(hints, seen);
  const value = useMemo<RunChatValue>(
    () => ({ runId, accepting, checks, open, toggle, close, openWith, context, clearContext, focusToken, chat, unread }),
    [runId, accepting, checks, open, toggle, close, openWith, context, clearContext, focusToken, chat, unread],
  );
  return <Ctx.Provider value={value}>{children}</Ctx.Provider>;
}

/** Null outside a run workspace (graph dev preview, tests). */
export function useRunChatOptional(): RunChatValue | null {
  return useContext(Ctx);
}

export function useRunChatContext(): RunChatValue {
  const v = useContext(Ctx);
  if (!v) throw new Error("useRunChatContext must be used inside <RunChatProvider>");
  return v;
}
