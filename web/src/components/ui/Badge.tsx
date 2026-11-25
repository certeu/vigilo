import type { ReactNode } from "react";

// Small text pill. Tones are deliberately quiet; meaning is always carried by the
// text (and optional icon), never by colour alone.
export type BadgeTone = "neutral" | "accent" | "success" | "warning" | "danger";

const TONES: Record<BadgeTone, string> = {
  neutral: "border-line bg-canvas text-slate",
  accent: "border-accent/30 bg-accent/5 text-accent",
  success: "border-emerald-600/30 bg-emerald-50 text-emerald-800",
  warning: "border-severity-medium/30 bg-amber-50 text-severity-medium",
  danger: "border-severity-critical/30 bg-red-50 text-severity-critical",
};

export function Badge({
  children,
  tone = "neutral",
  icon,
  title,
  className = "",
}: {
  children: ReactNode;
  tone?: BadgeTone;
  icon?: ReactNode;
  title?: string;
  className?: string;
}) {
  return (
    <span
      title={title}
      className={`inline-flex items-center gap-1 whitespace-nowrap rounded-full border px-2 py-0.5 text-[11px] font-medium leading-4 ${TONES[tone]} ${className}`}
    >
      {icon}
      {children}
    </span>
  );
}
