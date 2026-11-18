import { useState, type FormEvent, type ReactNode } from "react";
import { Navigate, useNavigate } from "react-router-dom";
import { ApiError } from "../api/client";
import { useAuth } from "../auth/useAuth";
import { Notice } from "../components/Bits";

export function LoginPage(): ReactNode {
  const { user, ready, signIn } = useAuth();
  const navigate = useNavigate();
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [retryAfter, setRetryAfter] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  if (ready && user !== null) {
    return <Navigate to="/" replace />;
  }

  async function submit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setBusy(true);
    setError(null);
    setRetryAfter(null);
    try {
      await signIn(username, password);
      navigate("/", { replace: true });
    } catch (reason) {
      if (reason instanceof ApiError) {
        setError(reason.message);
        setRetryAfter(reason.retryAfter);
      } else {
        setError("the sign-in failed");
      }
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="login-page">
      <form className="card login-card" onSubmit={submit}>
        <h1>Oracle-HCM</h1>
        <p className="muted">The console of the auto-coding engine.</p>
        {error !== null && (
          <Notice tone="danger">
            {error}
            {retryAfter !== null && <> Try again in {retryAfter} seconds.</>}
          </Notice>
        )}
        <label className="stack">
          <span>User</span>
          <input
            name="username"
            autoComplete="username"
            value={username}
            onChange={(event) => {
              setUsername(event.target.value);
            }}
          />
        </label>
        <label className="stack">
          <span>Password</span>
          <input
            name="password"
            type="password"
            autoComplete="current-password"
            value={password}
            onChange={(event) => {
              setPassword(event.target.value);
            }}
          />
        </label>
        <button type="submit" className="primary" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </div>
  );
}
