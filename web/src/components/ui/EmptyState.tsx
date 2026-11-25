import type { ComponentType, ReactNode, SVGProps } from "react";

export function EmptyState({
  icon: Icon,
  title,
  children,
  action,
  className = "",
}: {
  icon?: ComponentType<SVGProps<SVGSVGElement>>;
  title: string;
  children?: ReactNode;
  action?: ReactNode;
  className?: string;
}) {
  return (
    <div className={`flex flex-col items-center px-6 py-12 text-center ${className}`}>
      {Icon && <Icon className="mb-3 h-8 w-8 text-slate/60" aria-hidden="true" />}
      <h2 className="font-display text-base font-semibold text-ink">{title}</h2>
      {children && <div className="mt-1 max-w-md text-sm text-slate">{children}</div>}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
}
