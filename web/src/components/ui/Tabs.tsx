import { useCallback, useEffect, useId, useRef, useState, type KeyboardEvent, type ReactNode } from "react";

export interface TabItem<K extends string = string> {
  key: K;
  label: ReactNode;
  disabled?: boolean;
}

// WAI-ARIA tabs with roving tabindex: Left/Right (and Home/End) move focus and
// select (automatic activation). Controlled: the caller owns `value`, so the selected
// tab can live in the URL. Render the panel with <TabPanel> using the same idBase.
export function Tabs<K extends string>({
  items,
  value,
  onChange,
  label,
  idBase,
}: {
  items: TabItem<K>[];
  value: K;
  onChange: (key: K) => void;
  label: string;
  idBase?: string;
}) {
  const auto = useId();
  const base = idBase ?? auto;
  const refs = useRef<Array<HTMLButtonElement | null>>([]);
  const listRef = useRef<HTMLDivElement | null>(null);
  // Fade cue on the right edge while more tabs are scrolled out of view (narrow screens).
  const [moreRight, setMoreRight] = useState(false);
  const measure = useCallback(() => {
    const el = listRef.current;
    if (el) setMoreRight(el.scrollWidth - el.clientWidth - el.scrollLeft > 4);
  }, []);
  useEffect(() => {
    measure();
    window.addEventListener("resize", measure);
    return () => window.removeEventListener("resize", measure);
  }, [measure, items.length]);
  const enabled = items.map((t, i) => (t.disabled ? -1 : i)).filter((i) => i >= 0);

  function onKeyDown(e: KeyboardEvent<HTMLButtonElement>, index: number) {
    const pos = enabled.indexOf(index);
    let next: number | undefined;
    if (e.key === "ArrowRight") next = enabled[(pos + 1) % enabled.length];
    else if (e.key === "ArrowLeft") next = enabled[(pos - 1 + enabled.length) % enabled.length];
    else if (e.key === "Home") next = enabled[0];
    else if (e.key === "End") next = enabled[enabled.length - 1];
    if (next === undefined) return;
    e.preventDefault();
    refs.current[next]?.focus();
    onChange(items[next].key);
  }

  return (
    <div className="relative">
    <div ref={listRef} onScroll={measure} role="tablist" aria-label={label} className="flex gap-1 overflow-x-auto border-b border-line [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
      {items.map((t, i) => {
        const selected = t.key === value;
        return (
          <button
            key={t.key}
            ref={(el) => (refs.current[i] = el)}
            type="button"
            role="tab"
            id={`${base}-tab-${t.key}`}
            aria-selected={selected}
            aria-controls={`${base}-panel-${t.key}`}
            tabIndex={selected ? 0 : -1}
            disabled={t.disabled}
            onClick={() => onChange(t.key)}
            onKeyDown={(e) => onKeyDown(e, i)}
            className={[
              "-mb-px whitespace-nowrap border-b-2 px-3 py-2 text-sm transition",
              "focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-accent/40",
              selected
                ? "border-accent font-medium text-ink"
                : "border-transparent text-slate hover:text-ink",
              t.disabled ? "cursor-not-allowed opacity-50" : "",
            ].join(" ")}
          >
            {t.label}
          </button>
        );
      })}
    </div>
    {moreRight && (
      <span aria-hidden="true" className="pointer-events-none absolute inset-y-0 right-0 w-10 bg-gradient-to-l from-canvas to-transparent" />
    )}
    </div>
  );
}

export function TabPanel({
  idBase,
  tabKey,
  children,
  className = "",
}: {
  idBase: string;
  tabKey: string;
  children: ReactNode;
  className?: string;
}) {
  return (
    <div
      role="tabpanel"
      id={`${idBase}-panel-${tabKey}`}
      aria-labelledby={`${idBase}-tab-${tabKey}`}
      tabIndex={0}
      className={`focus-visible:outline-none ${className}`}
    >
      {children}
    </div>
  );
}
