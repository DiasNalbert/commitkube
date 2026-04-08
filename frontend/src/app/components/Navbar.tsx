"use client";

import { usePathname } from "next/navigation";
import { useEffect, useState } from "react";
import LogoutButton from "./LogoutButton";
import ThemeToggle from "./ThemeToggle";
import KubeLogo from "./KubeLogo";

const HIDDEN_ROUTES = ["/login", "/register", "/setup"];

export default function Navbar() {
  const pathname = usePathname();
  const [role, setRole] = useState("");

  useEffect(() => {
    setRole(localStorage.getItem("role") || "");
  }, []);

  if (HIDDEN_ROUTES.includes(pathname)) return null;

  const isAdminOrRoot = role === "root" || role === "admin";

  const links = [
    { href: "/", label: "Dashboard" },
    { href: "/security", label: "Security" },
    { href: "/monitoring", label: "Availability" },
    { href: "/repositories/new", label: "New Repository" },
    { href: "/repositories/import", label: "Import Repository" },
    { href: "/templates", label: "Templates" },
    { href: "/settings", label: "Settings" },
    ...(isAdminOrRoot ? [
      { href: "/golden-paths", label: "Golden Paths" },
      { href: "/users", label: "Users" },
    ] : []),
    { href: "/profile", label: "Profile" },
  ];

  return (
    <nav className="border-b border-brand-green/20 glass-panel sticky top-0 z-50">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          <a href="/" className="flex items-center gap-3 group">
            <div className="w-9 h-9 rounded-lg bg-brand-green/10 border border-brand-green/50 flex items-center justify-center tech-glow group-hover:bg-brand-green/20 transition-all duration-200 p-1.5">
              <KubeLogo className="w-full h-full" />
            </div>
            <span className="text-2xl font-black tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold group-hover:opacity-90 transition-opacity">
              CommitKube
            </span>
          </a>

          <div className="hidden md:flex items-center gap-1">
            {links.map(link => (
              <a
                key={link.href}
                href={link.href}
                className={`relative px-3 py-2 rounded-md text-sm font-medium transition-all duration-150 hover:text-brand-green hover:bg-brand-green/5 ${pathname === link.href ? "text-brand-green" : "text-zinc-400"}`}
              >
                {link.label}
                {pathname === link.href && (
                  <span className="absolute bottom-0 left-1/2 -translate-x-1/2 w-4 h-0.5 bg-brand-green rounded-full" />
                )}
              </a>
            ))}
            <div className="ml-3 flex items-center gap-2">
              <ThemeToggle />
              <LogoutButton />
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
