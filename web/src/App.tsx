import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { Shell } from "./components/Shell";
import { ShellSkeleton } from "./components/ShellSkeleton";
import { Login } from "./pages/Login";
import { Dashboard } from "./pages/Dashboard";
import { RunsList } from "./pages/RunsList";
import { RunDetail } from "./pages/RunDetail";
import { Jobs } from "./pages/Jobs";
import { Repos } from "./pages/Repos";
import { RepoDetail } from "./pages/RepoDetail";
import { Schedules } from "./pages/Schedules";
import { Admin } from "./pages/Admin";
import { Account } from "./pages/Account";
import { AcceptInvite } from "./pages/AcceptInvite";
import { ForgotPassword } from "./pages/ForgotPassword";
import { ResetPassword } from "./pages/ResetPassword";
import { AnalysesList } from "./pages/analyses/AnalysesList";
import { NewAnalysis } from "./pages/analyses/NewAnalysis";
import { Findings } from "./pages/Findings";
import { Credentials } from "./pages/settings/Credentials";
import { TargetDetail } from "./features/greybox/TargetDetail";
import { TargetsList } from "./features/greybox/TargetsList";
import { RunWorkspace } from "./features/greybox/run/RunWorkspace";
import { lazy, Suspense, type ReactNode } from "react";

// DEV ONLY: exploration-graph preview on synthetic fixtures. `import.meta.env.DEV` is
// statically false in production builds, so the import (and chunk) is dropped.
const DevGraphPreview = import.meta.env.DEV ? lazy(() => import("./features/greybox/graph/dev/GraphPreview")) : null;

function Protected({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <ShellSkeleton />;
  if (!user) return <Navigate to="/login" replace />;
  return <>{children}</>;
}

export default function App() {
  return (
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/login" element={<Login />} />
          <Route path="/accept-invite" element={<AcceptInvite />} />
          <Route path="/forgot-password" element={<ForgotPassword />} />
          <Route path="/reset-password" element={<ResetPassword />} />
          {DevGraphPreview && (
            <Route path="/__dev/graph" element={<Suspense fallback={null}><DevGraphPreview /></Suspense>} />
          )}
          <Route
            element={
              <Protected>
                <Shell />
              </Protected>
            }
          >
            <Route path="/" element={<Dashboard />} />
            <Route path="/runs" element={<RunsList />} />
            <Route path="/runs/:id" element={<RunDetail />} />
            <Route path="/jobs" element={<Jobs />} />
            <Route path="/repos" element={<Repos />} />
            <Route path="/repos/:id" element={<RepoDetail />} />
            <Route path="/schedules" element={<Schedules />} />
            <Route path="/account" element={<Account />} />
            <Route path="/admin" element={<Admin />} />
            {/* Mode-aware routes (grey-box web platform, additive). */}
            <Route path="/analyses" element={<AnalysesList />} />
            <Route path="/analyses/new" element={<NewAnalysis />} />
            <Route path="/greybox" element={<TargetsList />} />
            <Route path="/greybox/targets" element={<Navigate to="/greybox" replace />} />
            <Route path="/greybox/targets/:id" element={<TargetDetail />} />
            <Route path="/greybox/runs/:id" element={<RunWorkspace />} />
            <Route path="/findings" element={<Findings />} />
            <Route path="/settings/credentials" element={<Credentials />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
