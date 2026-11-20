import { InformationCircleIcon } from "@heroicons/react/24/outline";

interface InfoTipProps {
  text: string;
}

/**
 * Info icon with a rich hover tooltip (title attribute only carries plain
 * text and wraps poorly on long explanations). Pure CSS group-hover, no
 * extra dependency.
 */
export function InfoTip({ text }: InfoTipProps) {
  return (
    <span className="group relative inline-flex shrink-0 align-middle">
      <InformationCircleIcon className="h-4 w-4 cursor-help text-slate/60 transition-colors group-hover:text-accent" />
      <span
        role="tooltip"
        className="pointer-events-none absolute left-1/2 top-full z-20 mt-1.5 w-72 -translate-x-1/2 rounded-md border border-line bg-surface px-3 py-2 text-left text-xs font-normal leading-relaxed text-slate opacity-0 shadow-card transition-opacity duration-150 group-hover:opacity-100"
      >
        {text}
      </span>
    </span>
  );
}
