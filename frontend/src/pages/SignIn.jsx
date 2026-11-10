import { useState } from "react";
import { api, setAuthToken } from "../api/client.js";
import { Field } from "../components/Widgets.jsx";

/** Shown when the API requires a token (hosted dashboard) and none/invalid is set. */
export default function SignIn({ onSignedIn }) {
  const [token, setToken] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState(null);

  const submit = async (e) => {
    e.preventDefault();
    setBusy(true);
    setError(null);
    setAuthToken(token.trim());
    try {
      const status = await api.systemStatus();
      setToken("");
      onSignedIn(status);
    } catch (err) {
      setAuthToken(null);
      setError(err.status === 401 ? "That token was not accepted." : err.message);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center p-4">
      <form onSubmit={submit} className="card w-full max-w-md space-y-4 p-6" aria-labelledby="signin-h">
        <div>
          <h1 id="signin-h" className="text-xl font-bold">
            SecretSentinel dashboard
          </h1>
          <p className="mt-1 text-sm text-muted">
            This dashboard is private. Enter its API token (the <span className="mono">API_TOKEN</span> value in the
            hosting service's environment settings).
          </p>
        </div>
        <Field label="API token" htmlFor="signin-token">
          <input
            id="signin-token"
            type="password"
            className="input"
            value={token}
            onChange={(e) => setToken(e.target.value)}
            autoComplete="current-password"
            required
          />
        </Field>
        <button type="submit" className="btn btn-primary w-full" disabled={busy || !token.trim()}>
          {busy ? "Checking…" : "Sign in"}
        </button>
        {error && (
          <p role="alert" className="text-sm text-critical">
            {error}
          </p>
        )}
        <p className="text-xs text-muted">The token is kept for this browser tab only and is cleared when you close it.</p>
      </form>
    </div>
  );
}
