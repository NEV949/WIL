import { useState, type ReactNode } from "react";
import { NavLink, Outlet } from "react-router-dom";
import { useAuth } from "../auth/useAuth";
import { currentTheme, toggleTheme, type Theme } from "../theme";

export function Layout(): ReactNode {
  const { user, isAdmin, signOut } = useAuth();
  const [menuOpen, setMenuOpen] = useState(false);
  const [theme, setThemeState] = useState<Theme>(currentTheme);

  const items = [
    { to: "/", label: "Dashboard", end: true },
    ...(isAdmin ? [{ to: "/approvals", label: "Approvals", end: false }] : []),
    { to: "/security", label: "Security", end: false },
    { to: "/deployment", label: "Deployment", end: false },
    { to: "/metrics", label: "Metrics", end: false },
  ];

  const close = (): void => {
    setMenuOpen(false);
  };

  return (
    <div className="shell">
      <header className="topbar">
        <button
          type="button"
          className="ghost menu-button"
          aria-expanded={menuOpen}
          aria-controls="main-nav"
          onClick={() => {
            setMenuOpen((open) => !open);
          }}
        >
          Menu
        </button>
        <span className="brand">Oracle-HCM</span>
        <div className="topbar-actions">
          <button
            type="button"
            className="ghost"
            onClick={() => {
              setThemeState(toggleTheme());
            }}
          >
            {theme === "dark" ? "Light theme" : "Dark theme"}
          </button>
          <span className="who">{user?.user_id ?? ""}</span>
          <button
            type="button"
            className="ghost"
            onClick={() => {
              void signOut();
            }}
          >
            Sign out
          </button>
        </div>
      </header>
      <div className="body">
        <nav id="main-nav" className={menuOpen ? "nav nav-open" : "nav"}>
          {items.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              onClick={close}
              className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
            >
              {item.label}
            </NavLink>
          ))}
        </nav>
        <main className="main">
          <Outlet />
        </main>
      </div>
    </div>
  );
}
