import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import { AuthProvider, useAuth } from "./auth/AuthContext";
import { Shell } from "./components/Shell";
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
import type { ReactNode } from "react";

function Protected({ children }: { children: ReactNode }) {
  const { user, loading } = useAuth();
  if (loading) return <div className="p-8 text-slate">Loading…</div>;
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
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  );
}
