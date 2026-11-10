import { useEffect, useState } from "react";
import { Route, Routes } from "react-router-dom";
import { api } from "./api/client.js";
import Sidebar from "./components/Sidebar.jsx";
import { EmptyState } from "./components/States.jsx";
import Attestations from "./pages/Attestations.jsx";
import FindingDetail from "./pages/FindingDetail.jsx";
import Findings from "./pages/Findings.jsx";
import NewScan from "./pages/NewScan.jsx";
import Overview from "./pages/Overview.jsx";
import Rules from "./pages/Rules.jsx";
import ScanDetail from "./pages/ScanDetail.jsx";
import Scans from "./pages/Scans.jsx";
import Settings from "./pages/Settings.jsx";

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
  const [blockchain, setBlockchain] = useState(false);
  const [authTick, setAuthTick] = useState(0);

  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);

  useEffect(() => {
    api
      .systemStatus()
      .then((s) => setBlockchain(Boolean(s.blockchain_enabled)))
      .catch(() => setBlockchain(false));
  }, [authTick]);

  return (
    <div className="min-h-screen lg:flex">
      <a href="#main" className="skip-link">
        Skip to content
      </a>
      <Sidebar blockchainEnabled={blockchain} theme={theme} onToggleTheme={() => setTheme((t) => (t === "light" ? "dark" : "light"))} />
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
  );
}
