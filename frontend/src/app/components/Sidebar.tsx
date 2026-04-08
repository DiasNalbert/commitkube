"use client";

import { useState, useEffect, useLayoutEffect } from "react";
import { usePathname } from "next/navigation";
import KubeLogo from "./KubeLogo";
import ThemeToggle from "./ThemeToggle";
import LogoutButton from "./LogoutButton";

const HIDDEN_ROUTES = ["/login", "/register", "/setup"];

const IconDashboard = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="14" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" />
  </svg>
);
const IconShield = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6L12 2z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);
const IconActivity = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </svg>
);
const IconPlus = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" />
  </svg>
);
const IconDownload = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
    <polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
  </svg>
);
const IconFile = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <line x1="8" y1="13" x2="16" y2="13" /><line x1="8" y1="17" x2="12" y2="17" />
  </svg>
);
const IconGear = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
  </svg>
);
const IconUsers = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" /><circle cx="9" cy="7" r="4" />
    <path d="M23 21v-2a4 4 0 00-3-3.87" /><path d="M16 3.13a4 4 0 010 7.75" />
  </svg>
);
const IconUser = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" />
  </svg>
);
const IconChevronLeft = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <polyline points="15 18 9 12 15 6" />
  </svg>
);
const IconChevronRight = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <polyline points="9 18 15 12 9 6" />
  </svg>
);

const mainItems = [
  { href: "/", label: "Dashboard", icon: <IconDashboard /> },
  { href: "/security", label: "Security", icon: <IconShield /> },
  { href: "/monitoring", label: "Availability", icon: <IconActivity /> },
  { href: "/repositories/new", label: "New Repository", icon: <IconPlus /> },
  { href: "/templates", label: "Templates", icon: <IconFile /> },
  { href: "/settings", label: "Settings", icon: <IconGear /> },
];

const adminItems = [
  { href: "/repositories/import", label: "Import Repository", icon: <IconDownload /> },
  { href: "/users", label: "Users", icon: <IconUsers /> },
];

const bottomItems = [
  { href: "/profile", label: "Profile", icon: <IconUser /> },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [role, setRole] = useState("");

  useLayoutEffect(() => {
    setRole(localStorage.getItem("role") || "");
    const saved = localStorage.getItem("sidebar_collapsed");
    if (saved === "1") setCollapsed(true);
  }, []);

  const toggle = () => {
    setCollapsed(prev => {
      const next = !prev;
      localStorage.setItem("sidebar_collapsed", next ? "1" : "0");
      window.dispatchEvent(new CustomEvent("sidebar-toggle", { detail: { collapsed: next } }));
      return next;
    });
  };

  if (HIDDEN_ROUTES.includes(pathname)) return null;

  const isAdminOrRoot = role === "root" || role === "admin";
  const allItems = [
    ...mainItems,
    ...(isAdminOrRoot ? adminItems : []),
  ];

  const w = collapsed ? "w-16" : "w-60";

  const NavItem = ({ href, label, icon }: { href: string; label: string; icon: React.ReactNode }) => {
    const active = pathname === href;
    return (
      <a
        href={href}
        title={collapsed ? label : undefined}
        className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group relative
          ${active
            ? "bg-brand-green/15 text-brand-green"
            : "text-zinc-400 hover:text-brand-green hover:bg-brand-green/8"
          }`}
      >
        <span className={active ? "text-brand-green" : "text-zinc-500 group-hover:text-brand-green transition-colors"}>
          {icon}
        </span>
        {!collapsed && <span className="truncate">{label}</span>}
        {active && (
          <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-brand-green rounded-full" />
        )}
      </a>
    );
  };

  return (
    <aside
      className={`fixed left-0 top-0 bottom-0 z-50 flex flex-col border-r border-brand-green/20 glass-panel transition-all duration-200 ${w}`}
    >
      {/* Brand */}
      <div className={`flex items-center h-16 px-3 border-b border-brand-green/20 shrink-0 ${collapsed ? "justify-center" : "gap-3"}`}>
        <a href="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-brand-green/10 border border-brand-green/50 flex items-center justify-center tech-glow group-hover:bg-brand-green/20 transition-all duration-200 p-1.5 shrink-0">
            <KubeLogo className="w-full h-full" />
          </div>
          {!collapsed && (
            <span className="text-xl font-black tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold whitespace-nowrap">
              CommitKube
            </span>
          )}
        </a>
      </div>

      {/* Toggle button */}
      <button
        onClick={toggle}
        className={`absolute -right-3 top-[72px] w-6 h-6 rounded-full bg-zinc-800 border border-zinc-600 flex items-center justify-center text-zinc-400 hover:text-white hover:bg-zinc-700 transition-colors z-10`}
        title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {collapsed ? <IconChevronRight /> : <IconChevronLeft />}
      </button>

      {/* Main nav */}
      <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-0.5">
        {allItems.map(item => (
          <NavItem key={item.href} {...item} />
        ))}
      </nav>

      {/* Bottom: profile + actions */}
      <div className="border-t border-brand-green/20 py-3 px-2 space-y-0.5 shrink-0">
        {bottomItems.map(item => (
          <NavItem key={item.href} {...item} />
        ))}
        <div className={`flex items-center px-3 py-2 gap-3 ${collapsed ? "justify-center flex-col" : ""}`}>
          <ThemeToggle />
          <LogoutButton />
        </div>
      </div>
    </aside>
  );
}

export function useSidebarWidth() {
  const [collapsed, setCollapsed] = useState(false);
  useLayoutEffect(() => {
    setCollapsed(localStorage.getItem("sidebar_collapsed") === "1");
  }, []);
  return collapsed ? "ml-16" : "ml-60";
}
