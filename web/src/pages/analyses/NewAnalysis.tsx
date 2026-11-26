import { Link, useSearchParams } from "react-router-dom";
import { ArrowRightIcon, CodeBracketIcon, GlobeAltIcon, NoSymbolIcon } from "@heroicons/react/24/outline";
import { Breadcrumb, ErrorBoundary, MODE_LABEL, type AnalysisMode } from "../../components/ui";
import { NewGreyboxForm } from "../../features/greybox/NewGreyboxForm";
import { useGreyboxConfig, type GreyboxConfigState } from "../../features/greybox/useGreyboxConfig";

function parseMode(v: string | null): AnalysisMode | null {
  return v === "whitebox" || v === "greybox" ? v : null;
}

function ModeCard({
  mode,
  selected,
  title,
  lines,
  to,
  disabledReason,
}: {
  mode: AnalysisMode;
  selected: boolean;
  title: string;
  lines: string[];
  to: string;
  disabledReason?: string | null;
}) {
  const Icon = mode === "whitebox" ? CodeBracketIcon : GlobeAltIcon;
  const disabled = !!disabledReason;
  return (
    <div
      className={`card flex flex-col p-5 ${selected ? "border-accent bg-accent/5 ring-2 ring-accent" : ""} ${disabled ? "opacity-70" : ""}`}
      aria-current={selected ? "true" : undefined}
    >
      <div className="mb-2 flex items-center gap-2">
        <Icon className="h-6 w-6 text-accent" aria-hidden="true" />
        <h2 className="text-lg font-semibold">{MODE_LABEL[mode]}</h2>
        {selected && <span className="rounded-full bg-accent px-2 py-0.5 text-xs font-semibold text-white">Selected</span>}
      </div>
      <p className="mb-2 font-medium">{title}</p>
      <ul className="mb-4 space-y-1 text-sm text-slate">
        {lines.map((l) => <li key={l}>{l}</li>)}
      </ul>
      <div className="mt-auto">
        {selected && !disabled ? (
          <p className="text-sm text-slate">Fill in the details below.</p>
        ) : disabled ? (
          <p className="flex items-start gap-2 text-sm text-slate">
            <NoSymbolIcon className="mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />
            <span>{disabledReason}</span>
          </p>
        ) : (
          <Link to={to} className="btn-ghost" aria-label={`Choose ${MODE_LABEL[mode]}`}>
            Choose <ArrowRightIcon className="h-4 w-4" />
          </Link>
        )}
      </div>
    </div>
  );
}

function greyboxDisabledReason(cfg: GreyboxConfigState): string | null {
  if (cfg.status === "loading") return "Checking whether grey-box analysis is available…";
  if (cfg.status === "unavailable") return cfg.reason;
  if (!cfg.config.enabled)
    return "Grey-box analysis is disabled on this server. An administrator can enable it with VIGILO_GREYBOX_WEB_ENABLED.";
  return null;
}

export function NewAnalysis() {
  const [params] = useSearchParams();
  const mode = parseMode(params.get("mode"));
  const cfg = useGreyboxConfig();
  const gbReason = greyboxDisabledReason(cfg);

  return (
    <div>
      <Breadcrumb
        items={[
          { label: "Analyses", to: "/analyses" },
          { label: "New analysis", to: mode ? "/analyses/new" : undefined },
          ...(mode ? [{ label: MODE_LABEL[mode] }] : []),
        ]}
      />
      <h1 className="mb-1 text-xl font-semibold">
        New analysis{mode ? `: ${MODE_LABEL[mode]}` : ""}
      </h1>
      <p className="mb-6 text-sm text-slate">Choose what you want to assess. The two modes take different inputs and produce different outputs.</p>

      <div className="mb-8 grid max-w-4xl gap-4 md:grid-cols-2">
        <ModeCard
          mode="whitebox"
          selected={mode === "whitebox"}
          title="Inspect a repository"
          lines={["Input: source code, plus an optional live URL", "Output: evidence-backed findings and patches"]}
          to="/analyses/new?mode=whitebox"
        />
        <ModeCard
          mode="greybox"
          selected={mode === "greybox"}
          title="Test a running application"
          lines={["Input: target URL, plus an optional session cookie", "Output: verified findings with evidence and detection hints"]}
          to="/analyses/new?mode=greybox"
          disabledReason={gbReason}
        />
      </div>

      {mode === "whitebox" && (
        <section className="card max-w-4xl p-6" aria-labelledby="wb-next">
          <h2 id="wb-next" className="mb-2 text-base font-semibold">White-box configuration</h2>
          <p className="mb-4 text-sm text-slate">
            White-box analyses use the existing job form: pick a repository, choose the stages, optionally add a
            live URL and a session cookie, then run the job. Need a repository first?{" "}
            <Link to="/repos" className="text-accent hover:underline">Add one under Repositories</Link>.
          </p>
          <Link to="/jobs" className="btn-primary">
            Continue to the job form <ArrowRightIcon className="h-4 w-4" />
          </Link>
        </section>
      )}

      {mode === "greybox" && (
        <ErrorBoundary label="the grey-box form">
          {cfg.status === "ok" && cfg.config.enabled ? (
            <>
              <h2 className="mb-3 text-base font-semibold">Grey-box configuration</h2>
              <NewGreyboxForm config={cfg.config} />
            </>
          ) : cfg.status === "loading" ? (
            <p className="text-sm text-slate">Loading grey-box configuration…</p>
          ) : (
            <p className="card max-w-4xl p-6 text-sm text-slate">{gbReason}</p>
          )}
        </ErrorBoundary>
      )}
    </div>
  );
}
