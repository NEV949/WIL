import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import { api, onUnauthorized, setCsrfToken } from "../api/client";
import { AuthContext, type AuthValue } from "./context";
import { clearSession, loadSession, ROLE_ADMIN, saveSession, type SessionUser } from "./session";

export function AuthProvider({ children }: { children: ReactNode }): ReactNode {
  const [user, setUser] = useState<SessionUser | null>(null);
  const [ready, setReady] = useState(false);

  useEffect(() => {
    const session = loadSession();
    setCsrfToken(session.csrf);
    setUser(session.user);
    setReady(true);
  }, []);

  useEffect(
    () =>
      onUnauthorized(() => {
        clearSession();
        setCsrfToken(null);
        setUser(null);
      }),
    [],
  );

  const signIn = useCallback(async (username: string, password: string) => {
    const login = await api.login(username, password);
    const next = saveSession(login);
    setCsrfToken(login.csrf_token);
    setUser(next);
  }, []);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // the session is dropped on the host anyway
    }
    clearSession();
    setCsrfToken(null);
    setUser(null);
  }, []);

  const value = useMemo<AuthValue>(
    () => ({
      user,
      isAdmin: user !== null && user.role === ROLE_ADMIN,
      ready,
      signIn,
      signOut,
    }),
    [user, ready, signIn, signOut],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
