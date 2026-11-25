import { useEffect, useState, type ComponentType, type SVGProps } from "react";
import { Link, Outlet, useLocation, useNavigate, type Location } from "react-router-dom";
import {
  Squares2X2Icon,
  BriefcaseIcon,
  FolderIcon,
  ClockIcon,
  Cog6ToothIcon,
  ArrowRightStartOnRectangleIcon,
  Bars3Icon,
  XMarkIcon,
  PlusIcon,
  QueueListIcon,
  CodeBracketIcon,
  GlobeAltIcon,
  KeyIcon,
  UserCircleIcon,
} from "@heroicons/react/24/outline";
import { useAuth } from "../auth/AuthContext";
import { ErrorBoundary } from "./ui/ErrorBoundary";
import { greyboxEnabled, useGreyboxConfig } from "../features/greybox/useGreyboxConfig";

interface NavItem {
  to: string;
  label: string;
  icon: ComponentType<SVGProps<SVGSVGElement>>;
  /** Query-aware active test (NavLink ignores the search string). */
  active: (loc: Location) => boolean;
  indent?: boolean;
}
interface NavGroup {
  heading?: string;
  items: NavItem[];
}

const mode = (loc: Location) => new URLSearchParams(loc.search).get("mode");
const under = (loc: Location, prefix: string) =>
  loc.pathname === prefix || loc.pathname.startsWith(`${prefix}/`);

function buildNav(isAdmin: boolean, greybox: boolean): NavGroup[] {
  return [
    {
      items: [{ to: "/", label: "Overview", icon: Squares2X2Icon, active: (l) => l.pathname === "/" }],
    },
    {
      heading: "Analyses",
      items: [
        {
          to: "/analyses",
          label: "All analyses",
          icon: QueueListIcon,
          active: (l) => l.pathname === "/analyses" && mode(l) !== "greybox" && mode(l) !== "whitebox",
        },
        // White-box keeps its existing pages: Runs, with Jobs and Schedules nested.
        {
          to: "/runs",
          label: "White-box",
          icon: CodeBracketIcon,
          active: (l) => under(l, "/runs") || (l.pathname === "/analyses" && mode(l) === "whitebox"),
        },
        { to: "/jobs", label: "Jobs", icon: BriefcaseIcon, active: (l) => under(l, "/jobs"), indent: true },
        { to: "/schedules", label: "Schedules", icon: ClockIcon, active: (l) => under(l, "/schedules"), indent: true },
        ...(greybox
          ? [{
              // Target-centric landing page; runs are reachable from each target and /analyses.
              to: "/greybox",
              label: "Grey-box",
              icon: GlobeAltIcon,
              active: (l: Location) => (l.pathname === "/analyses" && mode(l) === "greybox") || under(l, "/greybox"),
            }]
          : []),
      ],
    },
    {
      items: [{ to: "/repos", label: "Repositories", icon: FolderIcon, active: (l) => under(l, "/repos") }],
      // Findings (/findings) joins this group in M5, when the unified index exists.
    },
    {
      heading: "Settings",
      items: [
        { to: "/settings/credentials", label: "Credentials", icon: KeyIcon, active: (l) => under(l, "/settings/credentials") },
        { to: "/account", label: "Account", icon: UserCircleIcon, active: (l) => under(l, "/account") },
        ...(isAdmin
          ? [{ to: "/admin", label: "Admin", icon: Cog6ToothIcon, active: (l: Location) => under(l, "/admin") }]
          : []),
      ],
    },
  ];
}

function SideNav({ groups, onNavigate }: { groups: NavGroup[]; onNavigate?: () => void }) {
  const loc = useLocation();
  const newActive = loc.pathname === "/analyses/new";
  return (
    <>
      <Link
        to="/analyses/new"
        onClick={onNavigate}
        className={`btn-primary mb-4 w-full justify-center ${newActive ? "ring-2 ring-accent/30" : ""}`}
        aria-current={newActive ? "page" : undefined}
      >
        <PlusIcon className="h-4 w-4" /> New analysis
      </Link>
      <div className="flex flex-col gap-3">
        {groups.map((g, gi) => (
          <div key={g.heading ?? gi}>
            {g.heading && (
              <p className="mb-1 px-3 text-[11px] font-semibold uppercase tracking-wide text-slate" id={`nav-h-${gi}`}>
                {g.heading}
              </p>
            )}
            <ul className="flex flex-col gap-0.5" aria-labelledby={g.heading ? `nav-h-${gi}` : undefined}>
              {g.items.map((n) => {
                const isActive = n.active(loc);
                return (
                  <li key={n.to}>
                    <Link
                      to={n.to}
                      onClick={onNavigate}
                      aria-current={isActive ? "page" : undefined}
                      className={[
                        "flex items-center gap-3 rounded-md py-2 text-sm transition",
                        n.indent ? "pl-9 pr-3" : "px-3",
                        isActive ? "bg-canvas font-medium text-ink" : "text-slate hover:bg-canvas hover:text-ink",
                      ].join(" ")}
                    >
                      <n.icon className={n.indent ? "h-4 w-4" : "h-5 w-5"} aria-hidden="true" />
                      {n.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </>
  );
}

export function Shell() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const cfg = useGreyboxConfig();
  const groups = buildNav(user?.role === "admin", greyboxEnabled(cfg));
  const [menuOpen, setMenuOpen] = useState(false);

  // Close the mobile menu on navigation and with Escape.
  useEffect(() => setMenuOpen(false), [location.pathname, location.search]);
  useEffect(() => {
    if (!menuOpen) return;
    const onKey = (e: KeyboardEvent) => e.key === "Escape" && setMenuOpen(false);
    document.addEventListener("keydown", onKey);
    return () => document.removeEventListener("keydown", onKey);
  }, [menuOpen]);

  return (
    <div className="min-h-screen bg-canvas">
      <header className="flex h-14 items-center justify-between border-b border-line bg-surface px-4 sm:px-6">
        <div className="flex items-center gap-2">
          <button
            type="button"
            className="rounded-md p-1.5 text-slate hover:bg-canvas hover:text-ink md:hidden"
            aria-label={menuOpen ? "Close navigation" : "Open navigation"}
            aria-expanded={menuOpen}
            aria-controls="mobile-nav"
            onClick={() => setMenuOpen((o) => !o)}
          >
            {menuOpen ? <XMarkIcon className="h-5 w-5" /> : <Bars3Icon className="h-5 w-5" />}
          </button>
          <span className="font-display text-lg font-semibold tracking-tight">Vigilo</span>
        </div>
        <div className="flex items-center gap-3 text-sm text-slate">
          <Link to="/account" className="mono hidden hover:text-ink sm:inline" title="Account settings">{user?.email}</Link>
          <button className="btn-ghost py-1" onClick={() => { logout(); navigate("/login"); }}>
            <ArrowRightStartOnRectangleIcon className="h-4 w-4" /> Sign out
          </button>
        </div>
      </header>
      <div className="flex">
        <nav
          aria-label="Main"
          className="hidden min-h-[calc(100vh-3.5rem)] w-56 shrink-0 border-r border-line bg-surface p-3 md:block"
        >
          <SideNav groups={groups} />
        </nav>
        {menuOpen && (
          <div className="fixed inset-0 top-14 z-40 md:hidden">
            <div className="absolute inset-0 bg-ink/30" onClick={() => setMenuOpen(false)} aria-hidden="true" />
            <nav id="mobile-nav" aria-label="Main" className="relative h-full w-64 overflow-y-auto border-r border-line bg-surface p-3 shadow-xl">
              <SideNav groups={groups} onNavigate={() => setMenuOpen(false)} />
            </nav>
          </div>
        )}
        <main className="min-w-0 flex-1 p-4 sm:p-8">
          <ErrorBoundary key={location.pathname} label="this page">
            <Outlet />
          </ErrorBoundary>
        </main>
      </div>
    </div>
  );
}
