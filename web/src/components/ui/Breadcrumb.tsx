import { Link } from "react-router-dom";
import { ChevronRightIcon } from "@heroicons/react/20/solid";

export interface Crumb {
  label: string;
  to?: string;
}

// The last crumb is the current page (aria-current); earlier ones are links when `to` is set.
export function Breadcrumb({ items }: { items: Crumb[] }) {
  return (
    <nav aria-label="Breadcrumb" className="mb-2">
      <ol className="flex flex-wrap items-center gap-1 text-xs text-slate">
        {items.map((c, i) => {
          const last = i === items.length - 1;
          return (
            <li key={`${c.label}-${i}`} className="flex items-center gap-1">
              {c.to && !last ? (
                <Link to={c.to} className="hover:text-ink hover:underline">
                  {c.label}
                </Link>
              ) : (
                <span aria-current={last ? "page" : undefined} className={last ? "text-ink" : undefined}>
                  {c.label}
                </span>
              )}
              {!last && <ChevronRightIcon className="h-3.5 w-3.5 text-slate/60" aria-hidden="true" />}
            </li>
          );
        })}
      </ol>
    </nav>
  );
}
