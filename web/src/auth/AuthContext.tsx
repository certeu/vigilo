import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";
import { useNavigate } from "react-router-dom";
import { api, getToken, setToken, setUnauthorizedHandler, type User } from "../api/client";

interface AuthState {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthCtx = createContext<AuthState | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  const refresh = useCallback(async () => {
    if (!getToken()) {
      setUser(null);
      setLoading(false);
      return;
    }
    try {
      setUser(await api.me());
    } catch {
      // A 401 is handled by the unauthorized handler below (redirect to /login).
      setUser(null);
    } finally {
      setLoading(false);
    }
  }, []);

  // ANY 401 on an authenticated call (not just the initial /users/me): drop the user and
  // redirect to /login so the "session expired" message shows on the auth page.
  useEffect(() => {
    setUnauthorizedHandler(() => {
      setUser(null);
      navigate("/login?reason=session_expired", { replace: true });
    });
    return () => setUnauthorizedHandler(null);
  }, [navigate]);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const login = useCallback(
    async (email: string, password: string) => {
      await api.login(email, password);
      await refresh();
    },
    [refresh],
  );

  const logout = useCallback(() => {
    setToken(null);
    setUser(null);
  }, []);

  const value = useMemo(
    () => ({ user, loading, login, logout }),
    [user, loading, login, logout],
  );
  return <AuthCtx.Provider value={value}>{children}</AuthCtx.Provider>;
}

export function useAuth(): AuthState {
  const ctx = useContext(AuthCtx);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
