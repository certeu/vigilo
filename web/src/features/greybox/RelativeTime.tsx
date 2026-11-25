import { formatDate, formatRelative } from "./format";

/** Relative time ("5 min ago") with the exact local time as a tooltip. */
export function RelativeTime({ iso, className }: { iso: string | null | undefined; className?: string }) {
  if (!iso) return <span className={className}>—</span>;
  return (
    <time dateTime={iso} title={formatDate(iso)} className={className}>
      {formatRelative(iso)}
    </time>
  );
}
