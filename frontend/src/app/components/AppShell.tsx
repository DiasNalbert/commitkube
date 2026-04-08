"use client";

import { useEffect, useLayoutEffect, useState } from "react";
import { usePathname } from "next/navigation";

const HIDDEN_ROUTES = ["/login", "/register", "/setup"];

export default function AppShell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);

  useLayoutEffect(() => {
    setCollapsed(localStorage.getItem("sidebar_collapsed") === "1");
  }, []);

  useEffect(() => {
    const onStorage = () => setCollapsed(localStorage.getItem("sidebar_collapsed") === "1");
    const onToggle = (e: Event) => setCollapsed((e as CustomEvent<{ collapsed: boolean }>).detail.collapsed);
    window.addEventListener("storage", onStorage);
    window.addEventListener("sidebar-toggle", onToggle);
    return () => {
      window.removeEventListener("storage", onStorage);
      window.removeEventListener("sidebar-toggle", onToggle);
    };
  }, []);

  const isSidebarHidden = HIDDEN_ROUTES.includes(pathname);
  const marginClass = isSidebarHidden ? "" : collapsed ? "ml-16" : "ml-60";

  return (
    <div className={`flex-1 flex flex-col min-w-0 transition-all duration-200 ${marginClass}`}>
      {children}
    </div>
  );
}
