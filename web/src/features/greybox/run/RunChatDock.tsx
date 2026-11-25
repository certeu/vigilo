import { useEffect, useId, useMemo, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { createPortal } from "react-dom";
import { Link } from "react-router-dom";
import { ArrowsPointingInIcon, ArrowsPointingOutIcon, PaperAirplaneIcon, XMarkIcon } from "@heroicons/react/24/outline";
import type { HintAction } from "../types";
import { RelativeTime } from "../RelativeTime";
import {
  ACTION_INFO, EMPTY_DRAFT, HINT_ACTIONS, HINT_SCOPE_NOTE, HINT_TEXT_MAX, OUTCOME_CLASS, buildHintPayload, hintErrorMessage, validateHint,
  type HintDraft, type HintErrors,
} from "./hintLogic";
import { CHAT_TICK, buildConversation, chatOutcome, type ChatItem } from "./chatModel";
import { graphNodeSearch } from "./activityModel";
import { useRunChatContext } from "./RunChatContext";

/**
 * Run chat: a non-modal dock (bottom right, above page overlays) where the analyst
 * queues messages for the exploration agent, which reads them at its next step and may
 * reply. The graph and the rest of the page stay usable while it is open. Messages can
 * also carry a quick action (focus / seed / skip / deprioritise) that the engine applies.
 * Read-only history once the run is terminal.
 */
export function RunChatDock() {
  const { open, close, accepting, checks, context, clearContext, focusToken, chat } = useRunChatContext();
  const { hints, loaded, loadError, readingIds, submit } = chat;
  const [wide, setWide] = useState(false);
  const [draft, setDraft] = useState<HintDraft>(EMPTY_DRAFT);
  const [touched, setTouched] = useState(false);
  const [sending, setSending] = useState(false);
  const [serverError, setServerError] = useState<string | null>(null);
  const uid = useId();
  const textRef = useRef<HTMLTextAreaElement>(null);
  const listRef = useRef<HTMLDivElement>(null);

  const items = useMemo(() => buildConversation(hints, readingIds), [hints, readingIds]);
  const signature = items.map((i) => `${i.key}:${i.kind === "user" ? i.status : ""}`).join("|");

  // Keep the newest message in view.
  useEffect(() => {
    const el = listRef.current;
    if (open && el) el.scrollTop = el.scrollHeight;
  }, [open, signature]);

  // Focus the composer on open and on every "Guide from here" (after the node drawer returns focus).
  useEffect(() => {
    if (!open || !accepting) return;
    const raf = requestAnimationFrame(() => textRef.current?.focus());
    return () => cancelAnimationFrame(raf);
  }, [open, accepting, focusToken]);

  if (!open) return null;

  const info = ACTION_INFO[draft.action];
  const full: HintDraft = { ...draft, aboutNodeId: context?.nodeId ?? null };
  const errors: HintErrors = validateHint(full);
  const invalid = Object.keys(errors).length > 0;

  const setAction = (action: HintAction) => {
    setDraft((d) => {
      if (action === d.action) return d;
      const kind = ACTION_INFO[action].target;
      const keep = kind === "path" && ACTION_INFO[d.action].target === "path";
      const target = kind === "path" ? (keep && d.target ? d.target : (context?.target ?? "")) : "";
      return { ...d, action, target };
    });
    setServerError(null);
  };

  async function send(e?: FormEvent) {
    e?.preventDefault();
    if (sending || !accepting) return;
    setTouched(true);
    if (invalid) return;
    setSending(true);
    setServerError(null);
    try {
      await submit(buildHintPayload(full));
      setDraft(EMPTY_DRAFT);
      clearContext();
      setTouched(false);
      textRef.current?.focus();
    } catch (err) {
      setServerError(hintErrorMessage(err));
    } finally {
      setSending(false);
    }
  }

  const onTextKey = (e: KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === "Enter" && !e.shiftKey && !e.nativeEvent.isComposing) {
      e.preventDefault();
      void send();
    }
  };

  const onDockKey = (e: KeyboardEvent) => {
    if (e.key === "Escape") {
      e.stopPropagation();
      close();
    }
  };

  return createPortal(
    <section
      role="dialog"
      aria-modal="false"
      aria-labelledby={`${uid}-title`}
      onKeyDown={onDockKey}
      className={`fixed bottom-4 right-4 z-[60] flex max-h-[70vh] w-[calc(100vw-2rem)] flex-col overflow-hidden rounded-lg border border-line bg-surface shadow-xl ${wide ? "sm:w-[560px]" : "sm:w-[380px]"}`}
    >
      <header className="flex items-start gap-2 border-b border-line px-4 py-2.5">
        <div className="min-w-0 flex-1">
          <h2 id={`${uid}-title`} className="font-display text-sm font-semibold text-ink">Run chat</h2>
          <p className="text-xs text-slate">
            {accepting ? "Delivered to the exploration agent at its next step." : "The run has ended. Read-only history."}
          </p>
        </div>
        <button
          type="button"
          className="hidden rounded p-1 text-slate hover:bg-canvas hover:text-ink sm:block"
          onClick={() => setWide((w) => !w)}
          aria-label={wide ? "Narrow the chat" : "Widen the chat"}
          title={wide ? "Narrow" : "Widen"}
        >
          {wide ? <ArrowsPointingInIcon className="h-4 w-4" /> : <ArrowsPointingOutIcon className="h-4 w-4" />}
        </button>
        <button type="button" className="rounded p-1 text-slate hover:bg-canvas hover:text-ink" onClick={close} aria-label="Close chat">
          <XMarkIcon className="h-4 w-4" />
        </button>
      </header>

      <div ref={listRef} className="min-h-[8rem] flex-1 overflow-y-auto bg-canvas/60 px-3 py-3">
        {!loaded ? (
          <p className="text-xs text-slate" role="status">Loading messages…</p>
        ) : items.length === 0 ? (
          <div className="px-2 py-4 text-center text-xs text-slate">
            <p className="font-medium text-ink">{accepting ? "No messages yet" : "No messages were sent in this run"}</p>
            {accepting && (
              <p className="mt-1">
                Tell the agent what to look at, what you know about the target, or ask why it did something. Messages are queued and
                delivered to the agent at its next step; its reply shows here.
              </p>
            )}
          </div>
        ) : (
          <ol className="space-y-2.5" aria-live="polite" aria-label="Messages">
            {items.map((it) => (it.kind === "user" ? <UserBubble key={it.key} item={it} ended={!accepting} onNavigate={close} /> : <AgentBubble key={it.key} item={it} />))}
          </ol>
        )}
        {loadError && <p className="mt-2 text-xs text-severity-medium">Could not refresh messages ({loadError}). Retrying.</p>}
      </div>

      {accepting && (
        <form onSubmit={send} className="space-y-2 border-t border-line px-3 py-2.5" noValidate>
          {context && (
            <p className="flex min-w-0 items-center gap-1.5 text-xs text-slate">
              About
              <span className="inline-flex min-w-0 items-center gap-1 rounded border border-hint-line bg-hint-soft py-px pl-1.5 pr-0.5 text-hint-ink">
                <span className="truncate" title={context.label}>{context.label}</span>
                <button type="button" className="rounded px-0.5 hover:bg-hint-line/40" onClick={clearContext} aria-label={`Remove context ${context.label}`}>
                  <XMarkIcon className="h-3 w-3" />
                </button>
              </span>
            </p>
          )}

          {info.target !== "none" && (
            <div>
              <label htmlFor={`${uid}-target`} className="mb-0.5 block text-xs font-medium text-ink">{info.targetLabel}</label>
              {info.target === "check" ? (
                <select
                  id={`${uid}-target`}
                  className="field py-1.5"
                  value={draft.target}
                  onChange={(e) => setDraft((d) => ({ ...d, target: e.target.value }))}
                  aria-invalid={touched && !!errors.target}
                >
                  <option value="">Select a check…</option>
                  {checks.map((c) => <option key={c} value={c}>{c}</option>)}
                </select>
              ) : (
                <input
                  id={`${uid}-target`}
                  className="field mono py-1.5"
                  value={draft.target}
                  placeholder={info.placeholder}
                  onChange={(e) => setDraft((d) => ({ ...d, target: e.target.value }))}
                  aria-invalid={touched && !!errors.target}
                  autoComplete="off"
                  spellCheck={false}
                />
              )}
              {touched && errors.target && <p role="alert" className="mt-0.5 text-xs text-severity-critical">{errors.target}</p>}
            </div>
          )}

          <div>
            <label htmlFor={`${uid}-text`} className="sr-only">Message</label>
            <textarea
              id={`${uid}-text`}
              ref={textRef}
              className="field max-h-40 min-h-[3.75rem] resize-y"
              rows={2}
              maxLength={HINT_TEXT_MAX + 200}
              value={draft.text}
              placeholder={context ? "What should the agent do about this?" : "Message the agent… e.g. The admin panel moved to /backoffice."}
              onChange={(e) => setDraft((d) => ({ ...d, text: e.target.value }))}
              onKeyDown={onTextKey}
              aria-invalid={touched && !!errors.text}
            />
            {touched && errors.text && <p role="alert" className="mt-0.5 text-xs text-severity-critical">{errors.text}</p>}
          </div>

          <div className="flex items-center gap-2">
            <label htmlFor={`${uid}-action`} className="sr-only">Send as</label>
            <select
              id={`${uid}-action`}
              className="field w-auto min-w-0 flex-1 py-1 text-xs"
              value={draft.action}
              onChange={(e) => setAction(e.target.value as HintAction)}
              title={info.help}
            >
              {HINT_ACTIONS.map((a) => <option key={a} value={a}>{ACTION_INFO[a].label}</option>)}
            </select>
            <button type="submit" className="btn-primary px-2.5 py-1.5 disabled:opacity-60" disabled={sending} aria-label="Send">
              <PaperAirplaneIcon className="h-4 w-4" aria-hidden="true" />
              <span className="text-xs">{sending ? "Sending…" : "Send"}</span>
            </button>
          </div>
          <p className="text-[11px] leading-snug text-slate">
            Enter to send, Shift+Enter for a new line. {draft.action === "note" ? "" : `${info.help} `}{HINT_SCOPE_NOTE}
          </p>
          {serverError && <p role="alert" className="rounded border border-severity-critical/40 bg-red-50 px-2 py-1.5 text-xs text-severity-critical">{serverError}</p>}
        </form>
      )}
    </section>,
    document.body,
  );
}

function UserBubble({ item, ended, onNavigate }: { item: Extract<ChatItem, { kind: "user" }>; ended: boolean; onNavigate: () => void }) {
  const h = item.hint;
  const tick = CHAT_TICK[item.status];
  // A message the agent read without answering before the run ended is not still "being read".
  const tickLabel = ended && item.status === "reading" ? "Read by the agent" : tick.label;
  const outcome = chatOutcome(h);
  const about = h.about_label ?? null;
  return (
    <li className="ml-8 flex flex-col items-end">
      <div className="max-w-full rounded-lg rounded-br-sm border border-hint-line bg-hint-soft px-3 py-2 text-[13px] text-ink">
        {(h.action !== "note" || about) && (
          <p className="mb-1 flex flex-wrap items-center gap-1 text-[11px] text-hint-ink">
            {h.action !== "note" && <span className="font-semibold">{ACTION_INFO[h.action]?.label ?? h.action}</span>}
            {h.target && <span className="mono break-all">{h.target}</span>}
            {about && <span className="truncate" title={about}>{h.action !== "note" ? "· " : ""}about {about}</span>}
          </p>
        )}
        <p className="whitespace-pre-wrap break-words">{h.text}</p>
      </div>
      <p className="mt-0.5 flex flex-wrap items-center justify-end gap-x-1.5 text-[11px] text-slate">
        <span>{h.created_by_name ?? "analyst"}</span>·<RelativeTime iso={h.created_at} />·
        <span className={`font-medium ${tick.cls}`}>
          <span aria-hidden="true">{tick.glyph} </span>{tickLabel}
        </span>
      </p>
      {outcome && <p className={`mt-0.5 text-right text-[11px] ${OUTCOME_CLASS[outcome.tone]}`}>{outcome.text}</p>}
      {h.node_id && (
        <Link to={graphNodeSearch(h.node_id)} className="text-[11px] text-accent hover:underline" onClick={onNavigate}>
          Show in graph
        </Link>
      )}
    </li>
  );
}

function AgentBubble({ item }: { item: Extract<ChatItem, { kind: "agent" }> }) {
  const h = item.hint;
  return (
    <li className="mr-8 flex flex-col items-start">
      <p className="mb-0.5 truncate text-[11px] text-slate" title={h.text}>
        <span className="font-medium text-indigo-800">Exploration agent</span>
        {h.reply_cycle != null && <> · cycle {h.reply_cycle}</>}
        {h.replied_at && <> · <RelativeTime iso={h.replied_at} /></>}
      </p>
      <div className="max-w-full rounded-lg rounded-bl-sm border border-line bg-surface px-3 py-2 text-[13px] text-ink shadow-card">
        <p className="mb-1 truncate border-l-2 border-hint-line pl-1.5 text-[11px] text-slate">{h.text}</p>
        <p className="whitespace-pre-wrap break-words">{item.text}</p>
      </div>
    </li>
  );
}
