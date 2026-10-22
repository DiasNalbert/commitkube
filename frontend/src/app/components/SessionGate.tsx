"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import {
  ensureSession, getSessionUser, goToLogin, isPublicRoute, onSessionChange,
  refreshSession, watchSignOut, type SessionUser,
} from "@/lib/auth";

/** Every route but sign-in and setup renders only after the server has
 *  confirmed the session. Before this, a page drew itself if localStorage
 *  held something shaped like a token -- which it did for thirty days, across
 *  reboots, whatever had happened to the account in between. */
export default function SessionGate({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const isPublic = isPublicRoute(pathname);
  const [ok, setOk] = useState(false);

  useEffect(() => {
    if (isPublic) return;
    let cancelled = false;
    ensureSession().then(token => {
      if (cancelled) return;
      if (token) setOk(true);
      else goToLogin();
    });
    return () => { cancelled = true; };
  }, [isPublic]);

  // While the tab is in front, keep the session warm: the access token is
  // short, and the server ends a session nobody has used for a while. A tab
  // left in the background stops renewing, so closing the lid ends it.
  useEffect(() => {
    if (isPublic || !ok) return;
    const tick = () => {
      if (document.hidden) return;
      refreshSession().then(t => { if (!t) goToLogin(); });
    };
    const id = setInterval(tick, 4 * 60 * 1000);
    const onVisible = () => {
      if (document.hidden) return;
      ensureSession().then(t => { if (!t) goToLogin(); });
    };
    document.addEventListener("visibilitychange", onVisible);
    const stopWatching = watchSignOut(() => { window.location.href = "/login"; });
    return () => {
      clearInterval(id);
      document.removeEventListener("visibilitychange", onVisible);
      stopWatching();
    };
  }, [isPublic, ok]);

  if (isPublic) return <>{children}</>;
  if (!ok) {
    return (
      <div className="flex-1 min-h-screen grid place-items-center" aria-busy="true">
        <span className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>checking session…</span>
      </div>
    );
  }
  return <>{children}</>;
}

/** The signed-in person, for the parts of the page that show or depend on
 *  who it is. Null until the session has been confirmed. */
export function useSessionUser(): SessionUser | null {
  const [u, setU] = useState<SessionUser | null>(() => getSessionUser());
  useEffect(() => {
    setU(getSessionUser());
    return onSessionChange(setU);
  }, []);
  return u;
}
