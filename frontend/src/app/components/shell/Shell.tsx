"use client";

import { Suspense, useEffect, useLayoutEffect, useState } from "react";
import { usePathname } from "next/navigation";
import Rail from "./Rail";
import TopBar from "./TopBar";
import { useBadges } from "./useBadges";
import { usePermissions } from "../usePermissions";
import { useSessionUser } from "../SessionGate";
import { PERMISSIONS as P } from "@/lib/permissions";
import { isPublicRoute } from "@/lib/auth";

const COLLAPSED_KEY = "sidebar_collapsed";

/** The frame every signed-in page sits in: the rail on the left, the header
 *  across the top, the page in what is left. Below md the rail becomes a
 *  drawer behind the header's menu button. */
export default function Shell({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  // Sign-in and setup get the bare page. Nothing below runs there: the rail
  // asks the API for permissions and counts, which without a session would
  // only be refused.
  if (isPublicRoute(pathname)) return <>{children}</>;
  return <SignedInShell pathname={pathname}>{children}</SignedInShell>;
}

function SignedInShell({ children, pathname }: { children: React.ReactNode; pathname: string }) {
  const { can } = usePermissions();
  const user = useSessionUser();
  const isAdmin = user?.role === "root" || user?.role === "admin";
  const badges = useBadges(can, { k8s: P.k8sRead, security: P.securityRead, cloudflare: P.cloudflareRead });

  const [collapsed, setCollapsed] = useState(false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const [desktop, setDesktop] = useState(true);

  useLayoutEffect(() => {
    try { setCollapsed(localStorage.getItem(COLLAPSED_KEY) === "1"); } catch { /* default open */ }
    const mq = window.matchMedia("(min-width: 768px)");
    const read = () => setDesktop(mq.matches);
    read();
    mq.addEventListener("change", read);
    return () => mq.removeEventListener("change", read);
  }, []);

  // The drawer closes when a link is followed, on Escape, and when the
  // screen grows past the breakpoint.
  useEffect(() => { setMobileOpen(false); }, [pathname, desktop]);
  useEffect(() => {
    if (!mobileOpen) return;
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") setMobileOpen(false); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [mobileOpen]);

  const toggleCollapsed = () => {
    setCollapsed(prev => {
      const next = !prev;
      try { localStorage.setItem(COLLAPSED_KEY, next ? "1" : "0"); } catch { /* not remembered */ }
      return next;
    });
  };

  const rail = (
    <Rail
      collapsed={collapsed}
      onToggleCollapsed={toggleCollapsed}
      can={can}
      isAdmin={isAdmin}
      badges={badges}
      mobile={!desktop}
      onNavigate={() => setMobileOpen(false)}
    />
  );

  return (
    <div
      className="min-h-screen md:grid"
      style={{
        gridTemplateColumns: `${collapsed ? "60px" : "248px"} minmax(0,1fr)`,
        transition: "grid-template-columns .18s ease",
        background: "var(--bg)",
        color: "var(--text)",
      }}
    >
      {desktop ? rail : (
        <>
          {mobileOpen && <div className="fixed inset-0 z-40 bg-black/50" onClick={() => setMobileOpen(false)} aria-hidden="true" />}
          <div className={`fixed left-0 top-0 bottom-0 z-50 w-[264px] transition-transform duration-200 ${mobileOpen ? "translate-x-0" : "-translate-x-full"}`}>
            {rail}
          </div>
        </>
      )}

      <div className="flex flex-col min-w-0 min-h-screen">
        <Suspense fallback={<div className="h-14" style={{ borderBottom: "1px solid var(--rule)" }} />}>
          <TopBar can={can} isAdmin={isAdmin} onMenu={() => setMobileOpen(true)} />
        </Suspense>
        <main className="flex-1 min-w-0 px-4 py-6 md:px-8 md:py-8">
          {children}
        </main>
      </div>
    </div>
  );
}
