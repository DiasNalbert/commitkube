"use client";

import { useEffect, useState } from "react";
import { loadPermissions } from "@/lib/permissions";

/** The permissions the current user holds, plus whether the answer has
 *  arrived. Nothing is hidden while it is still loading: flashing the nav
 *  smaller and then bigger reads as a glitch, and showing one extra item for
 *  a moment costs nothing the backend does not already refuse. */
export function usePermissions() {
  const [held, setHeld] = useState<Set<string> | null>(null);

  useEffect(() => {
    let cancelled = false;
    loadPermissions().then(set => { if (!cancelled) setHeld(set); });
    return () => { cancelled = true; };
  }, []);

  return {
    loaded: held !== null,
    can: (permission?: string) => !permission || held === null || held.size === 0 || held.has(permission),
  };
}
