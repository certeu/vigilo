import { Link, NavLink, Outlet, useNavigate } from "react-router-dom";
import {
  Squares2X2Icon,
  PlayCircleIcon,
  BriefcaseIcon,
  FolderIcon,
  ClockIcon,
  Cog6ToothIcon,
  ArrowRightStartOnRectangleIcon,
} from "@heroicons/react/24/outline";
import { useAuth } from "../auth/AuthContext";

const NAV = [
  { to: "/", label: "Dashboard", icon: Squares2X2Icon, end: true },
  { to: "/runs", label: "Runs", icon: PlayCircleIcon },
  { to: "/jobs", label: "Jobs", icon: BriefcaseIcon },
  { to: "/repos", label: "Repositories", icon: FolderIcon },
  { to: "/schedules", label: "Schedules", icon: ClockIcon },
];

export function Shell() {
  const { user, logout } = useAuth();
  const navigate = useNavigate();

  return (
    <div className="min-h-screen bg-canvas">
      <header className="flex h-14 items-center justify-between border-b border-line bg-surface px-6">
        <span className="font-display text-lg font-semibold tracking-tight">Vigilo</span>
        <div className="flex items-center gap-3 text-sm text-slate">
          <Link to="/account" className="mono hover:text-ink" title="Account settings">{user?.email}</Link>
          <button className="btn-ghost py-1" onClick={() => { logout(); navigate("/login"); }}>
            <ArrowRightStartOnRectangleIcon className="h-4 w-4" /> Sign out
          </button>
        </div>
      </header>
      <div className="flex">
        <nav className="min-h-[calc(100vh-3.5rem)] w-44 shrink-0 border-r border-line bg-surface p-3 sm:w-56">
          <ul className="flex flex-col gap-1">
            {NAV.map((n) => (
              <li key={n.to}>
                <NavLink
                  to={n.to}
                  end={n.end}
                  className={({ isActive }) =>
                    [
                      "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition",
                      isActive
                        ? "bg-canvas text-ink font-medium"
                        : "text-slate hover:text-ink hover:bg-canvas",
                    ].join(" ")
                  }
                >
                  <n.icon className="h-5 w-5" />
                  {n.label}
                </NavLink>
              </li>
            ))}
            {user?.role === "admin" && (
              <li className="mt-2 border-t border-line pt-2">
                <NavLink
                  to="/admin"
                  className={({ isActive }) =>
                    [
                      "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition",
                      isActive
                        ? "bg-canvas text-ink font-medium"
                        : "text-slate hover:text-ink hover:bg-canvas",
                    ].join(" ")
                  }
                >
                  <Cog6ToothIcon className="h-5 w-5" />
                  Admin
                </NavLink>
              </li>
            )}
          </ul>
        </nav>
        <main className="min-w-0 flex-1 p-4 sm:p-8">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
