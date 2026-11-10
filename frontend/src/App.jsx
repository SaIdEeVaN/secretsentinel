import { useCallback, useEffect, useMemo, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { UNAUTHORIZED_EVENT, api, setAuthToken } from "./api/client.js";
import Sidebar from "./components/Sidebar.jsx";
import { EmptyState, Loading } from "./components/States.jsx";
import { SystemContext } from "./context/system.js";
import Attestations from "./pages/Attestations.jsx";
import FindingDetail from "./pages/FindingDetail.jsx";
import Findings from "./pages/Findings.jsx";
import NewScan from "./pages/NewScan.jsx";
import Overview from "./pages/Overview.jsx";
import Rules from "./pages/Rules.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";
import Scans from "./pages/Scans.jsx";
import Settings from "./pages/Settings.jsx";
import SignIn from "./pages/SignIn.jsx";

const THEME_KEY = "secretsentinel.theme"; // UI preference only - never sensitive data

function initialTheme() {
  try {
    const saved = window.localStorage.getItem(THEME_KEY);
    if (saved === "light" || saved === "dark") return saved;
  } catch {
    /* storage unavailable */
  }
  return window.matchMedia?.("(prefers-color-scheme: light)").matches ? "light" : "dark";
}

export default function App() {
  const [theme, setTheme] = useState(initialTheme);
  const [status, setStatus] = useState(null);
  // "checking" -> "ready" | "signin" (hosted dashboards require an API token)
  const [auth, setAuth] = useState("checking");
  const [authTick, setAuthTick] = useState(0);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  const loadStatus = useCallback(async () => {
    try {
      setStatus(await api.systemStatus());
      setAuth("ready");
    } catch (err) {
      if (err.status === 401) setAuth("signin");
      else setAuth("ready"); // backend unreachable etc.: pages show their own errors
    }
  }, []);

  useEffect(() => {
    loadStatus();
  }, [loadStatus, authTick]);

  useEffect(() => {
    const onUnauthorized = () => setAuth("signin");
    window.addEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
    return () => window.removeEventListener(UNAUTHORIZED_EVENT, onUnauthorized);
  }, []);

  const signOut = useCallback(() => {
    setAuthToken(null);
    setStatus(null);
    setAuth("signin");
  }, []);

  const ctx = useMemo(() => ({ status, reload: loadStatus, signOut }), [status, loadStatus, signOut]);
  const blockchain = Boolean(status?.blockchain_enabled);

  if (auth === "checking") return <Loading label="Connecting to SecretSentinel…" />;
  if (auth === "signin") {
    return (
      <SignIn
        onSignedIn={(s) => {
          setStatus(s);
          setAuth("ready");
          setAuthTick((n) => n + 1);
        }}
      />
    );
  }

  return (
    <SystemContext.Provider value={ctx}>
      <div className="min-h-screen lg:flex">
        <a href="#main" className="skip-link">
          Skip to content
        </a>
        <Sidebar
          blockchainEnabled={blockchain}
          localScanning={status ? status.local_scanning_enabled : true}
          onSignOut={status?.auth_required ? signOut : null}
          theme={theme}
          onToggleTheme={() => setTheme((t) => (t === "light" ? "dark" : "light"))}
        />
        <main id="main" className="min-w-0 flex-1 px-4 py-5 sm:px-6 lg:px-8 lg:py-8">
          <div className="mx-auto max-w-7xl" key={authTick}>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/scan/new" element={<NewScan />} />
              <Route path="/scans" element={<Scans />} />
              <Route path="/scans/:scanId" element={<ScanDetail blockchainEnabled={blockchain} />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/findings/:findingId" element={<FindingDetail />} />
              <Route path="/rules" element={<Rules />} />
              <Route path="/settings" element={<Settings onAuthChanged={() => setAuthTick((n) => n + 1)} />} />
              {blockchain && <Route path="/attestations" element={<Attestations />} />}
              <Route path="*" element={<EmptyState title="Page not found." />} />
            </Routes>
          </div>
        </main>
      </div>
    </SystemContext.Provider>
  );
}
