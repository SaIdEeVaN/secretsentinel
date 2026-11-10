import { useState } from "react";
import { NavLink } from "react-router-dom";

const LINKS = [
  { to: "/", label: "Overview", icon: "▦", end: true },
  { to: "/scan/new", label: "New Scan", icon: "＋" },
  { to: "/findings", label: "Findings", icon: "⚑" },
  { to: "/scans", label: "Scan History", icon: "☰" },
  { to: "/rules", label: "Rules & Policy", icon: "§" },
  { to: "/settings", label: "Settings", icon: "⚙" },
];

function Logo() {
  return (
    <div className="flex items-center gap-2 px-2">
      <svg viewBox="0 0 32 32" className="size-7" aria-hidden="true">
        <path d="M16 2 4 6.5v8.2c0 7.2 5 13.2 12 15.3 7-2.1 12-8.1 12-15.3V6.5Z" fill="var(--accent)" />
        <path d="m11 16 3.5 3.5L21.5 12" fill="none" stroke="var(--accent-ink)" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      <div className="leading-tight">
        <div className="font-bold tracking-tight">SecretSentinel</div>
        <div className="text-[11px] text-muted">local · redacted by design</div>
      </div>
    </div>
  );
}

export default function Sidebar({ blockchainEnabled, theme, onToggleTheme }) {
  const [open, setOpen] = useState(false);
  const links = blockchainEnabled ? [...LINKS.slice(0, 5), { to: "/attestations", label: "Attestations", icon: "⛓" }, LINKS[5]] : LINKS;
  const linkCls = ({ isActive }) =>
    `flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium ${
      isActive ? "bg-surface-2 text-ink border border-line" : "text-muted hover:text-ink hover:bg-surface-2 border border-transparent"
    }`;
  return (
    <>
      {/* Mobile top bar */}
      <header className="lg:hidden sticky top-0 z-30 flex items-center justify-between border-b border-line bg-surface px-4 py-2">
        <Logo />
        <button
          type="button"
          className="btn btn-ghost"
          aria-expanded={open}
          aria-controls="primary-nav"
          onClick={() => setOpen((o) => !o)}
        >
          <span aria-hidden="true">☰</span>
          <span className="sr-only">Toggle navigation</span>
        </button>
      </header>
      <aside
        id="primary-nav"
        className={`${open ? "block" : "hidden"} lg:block lg:sticky lg:top-0 lg:h-screen w-full lg:w-60 shrink-0 border-b lg:border-b-0 lg:border-r border-line bg-surface p-3`}
      >
        <div className="hidden lg:block py-3">
          <Logo />
        </div>
        <nav aria-label="Primary" className="mt-2">
          <ul className="space-y-1">
            {links.map((l) => (
              <li key={l.to}>
                <NavLink to={l.to} end={l.end} className={linkCls} onClick={() => setOpen(false)}>
                  <span aria-hidden="true" className="w-4 text-center">
                    {l.icon}
                  </span>
                  {l.label}
                </NavLink>
              </li>
            ))}
          </ul>
        </nav>
        <div className="mt-6 px-2">
          <button type="button" className="btn btn-ghost w-full text-xs" onClick={onToggleTheme}>
            {theme === "light" ? "☾ Dark theme" : "☀ Light theme"}
          </button>
          <p className="mt-3 text-[11px] leading-snug text-muted">
            Secret values are never stored, returned or displayed. Severity is a detector risk estimate.
          </p>
        </div>
      </aside>
    </>
  );
}
