// Field-level error text, linked to its input with aria-describedby={id}.
export function FieldError({ id, messages }: { id: string; messages?: string[] }) {
  if (!messages || messages.length === 0) return null;
  return (
    <p id={id} role="alert" className="mt-1 text-xs text-severity-critical">
      {messages.join(" ")}
    </p>
  );
}

/** Turn a FastAPI-style `loc` into a dotted field key, dropping the leading "body". */
export function locKey(loc: ReadonlyArray<string | number>): string {
  const parts = loc[0] === "body" ? loc.slice(1) : loc;
  return parts.map(String).join(".");
}

export interface LocError {
  loc: ReadonlyArray<string | number>;
  msg: string;
}

/** Group errors by dotted key. */
export function groupErrors(errors: ReadonlyArray<LocError>): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const e of errors) {
    const k = locKey(e.loc);
    (out[k] ??= []).push(e.msg);
  }
  return out;
}

/** Messages for `key` and anything nested under it (e.g. "scope.allowed_hosts.0"). */
export function errorsFor(grouped: Record<string, string[]>, key: string): string[] {
  const out: string[] = [];
  for (const [k, v] of Object.entries(grouped)) {
    if (k === key || k.startsWith(`${key}.`)) out.push(...v);
  }
  return out;
}

/**
 * Split errors for a list field into whole-field messages and per-item messages.
 * The backend reports list items with a numeric index, e.g.
 * ["body","scope","allowed_hosts",1] -> key "scope.allowed_hosts.1" -> item 1.
 */
export function listErrors(
  grouped: Record<string, string[]>,
  key: string,
): { field: string[]; items: Record<number, string[]> } {
  const field: string[] = [];
  const items: Record<number, string[]> = {};
  for (const [k, v] of Object.entries(grouped)) {
    if (k === key) field.push(...v);
    else if (k.startsWith(`${key}.`)) {
      const idx = Number(k.slice(key.length + 1).split(".")[0]);
      if (Number.isInteger(idx) && idx >= 0) (items[idx] ??= []).push(...v);
      else field.push(...v);
    }
  }
  return { field, items };
}

/** Human label for a `loc`: drops "body", shows list indexes as 1-based "item N". */
export function locLabel(loc: ReadonlyArray<string | number>): string {
  const parts = loc[0] === "body" ? loc.slice(1) : loc;
  const out: string[] = [];
  for (const p of parts) {
    if (typeof p === "number" || /^\d+$/.test(String(p))) out.push(`item ${Number(p) + 1}`);
    else out.push(String(p));
  }
  return out.join(" › ");
}

/** Extract `[{loc,msg}]` from an ApiError-like `detail` value, if it is a 422 list. */
export function asLocErrors(detail: unknown): LocError[] | null {
  if (!Array.isArray(detail)) return null;
  const out: LocError[] = [];
  for (const d of detail) {
    if (d && typeof d === "object" && "msg" in d) {
      const loc = Array.isArray((d as { loc?: unknown }).loc) ? ((d as { loc: (string | number)[] }).loc) : [];
      out.push({ loc, msg: String((d as { msg: unknown }).msg) });
    }
  }
  return out;
}
