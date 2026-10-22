"use client";

import { useEffect, useState } from "react";
import { usePathname } from "next/navigation";
import { MODULES, activeModule, itemActive, type BadgeKey, type ModuleKey } from "./nav";
import { LogoMark, ModuleIcon } from "./icons";
import type { Badges } from "./useBadges";
import { useSessionUser } from "../SessionGate";
import { clearPermissions } from "@/lib/permissions";
import { logout } from "@/lib/auth";

const BADGE_COLOR: Record<BadgeKey, string> = {
  failing: "var(--red)",
  security: "var(--gold)",
  edge: "var(--red)",
};

function initials(email: string) {
  const name = email.split("@")[0] ?? "";
  const parts = name.split(/[._-]+/).filter(Boolean);
  const s = parts.length >= 2 ? parts[0][0] + parts[1][0] : name.slice(0, 2);
  return s.toUpperCase();
}

const OPEN_KEY = "rail_open";

/** The navigation rail. 248px with every module's places listed, or 60px of
 *  module icons; a click on a collapsed module opens the rail on it. */
export default function Rail({
  collapsed, onToggleCollapsed, can, isAdmin, badges, mobile, onNavigate,
}: {
  collapsed: boolean;
  onToggleCollapsed: () => void;
  can: (perm?: string) => boolean;
  isAdmin: boolean;
  badges: Badges;
  mobile: boolean;
  onNavigate: () => void;
}) {
  const pathname = usePathname();
  const here = activeModule(pathname);
  const user = useSessionUser();
  const rail = collapsed && !mobile;

  // Which modules are expanded, remembered across visits. The module you are
  // in is always open, so the current page is never hidden.
  const [open, setOpen] = useState<Partial<Record<ModuleKey, boolean>>>({ cluster: true });
  useEffect(() => {
    try {
      const saved = JSON.parse(localStorage.getItem(OPEN_KEY) ?? "null");
      if (saved && typeof saved === "object") setOpen(saved);
    } catch { /* first visit */ }
  }, []);
  const persist = (next: Partial<Record<ModuleKey, boolean>>) => {
    setOpen(next);
    try { localStorage.setItem(OPEN_KEY, JSON.stringify(next)); } catch { /* not remembered */ }
  };

  const modules = MODULES
    .map(m => ({ ...m, items: m.items.filter(i => can(i.perm) && (!i.adminOnly || isAdmin)) }))
    .filter(m => m.items.length > 0);

  return (
    <aside
      className="h-screen sticky top-0 flex flex-col overflow-hidden z-40"
      style={{ background: "var(--side)", borderRight: "1px solid var(--rule)" }}
      aria-label="Navigation"
    >
      <a href="/" className="h-14 flex items-center gap-2.5 px-[17px] shrink-0 no-underline" style={{ borderBottom: "1px solid var(--rule)", color: "var(--text)" }}>
        <LogoMark />
        {!rail && <span className="font-bold text-base tracking-[-0.02em] whitespace-nowrap">CommitKube</span>}
      </a>

      <nav className="flex-1 overflow-y-auto overflow-x-hidden px-2 py-2.5 flex flex-col gap-0.5">
        {modules.map(m => {
          const isHere = here === m.key;
          const isOpen = !!open[m.key] || isHere;
          const count = m.badge ? badges[m.badge] : undefined;
          return (
            <div key={m.key} className="flex flex-col">
              <button
                type="button"
                title={m.label}
                aria-expanded={!rail && isOpen}
                onClick={() => {
                  if (rail) { onToggleCollapsed(); persist({ ...open, [m.key]: true }); return; }
                  persist({ ...open, [m.key]: !isOpen });
                }}
                className="relative w-full flex items-center gap-[11px] h-[38px] px-3 rounded text-left whitespace-nowrap transition-colors hover:bg-[var(--hover)] hover:text-[var(--text)]"
                style={{
                  background: isHere && rail ? "var(--hover)" : "transparent",
                  color: isHere ? "var(--text)" : "var(--t3)",
                }}
              >
                <ModuleIcon module={m.key} />
                {!rail && (
                  <>
                    <span className="flex-1 font-semibold text-[14.5px]">{m.label}</span>
                    {!!count && <span className="font-mono text-[10.5px]" style={{ color: BADGE_COLOR[m.badge!] }}>{count}</span>}
                    <span className="text-[10px] inline-block transition-transform" style={{ color: "var(--m2)", transform: isOpen ? "none" : "rotate(-90deg)" }}>▾</span>
                  </>
                )}
                {rail && !!count && (
                  <span className="absolute top-[9px] left-[28px] w-1.5 h-1.5 rounded-full" style={{ background: BADGE_COLOR[m.badge!] }} />
                )}
              </button>

              {!rail && isOpen && (
                <div className="flex flex-col gap-px mt-0.5 mb-2.5 ml-5 pl-2.5" style={{ borderLeft: "1px solid var(--rule)" }}>
                  {m.items.map(it => {
                    const on = itemActive(it, pathname);
                    const n = it.badge ? badges[it.badge] : undefined;
                    return (
                      <a
                        key={it.href}
                        href={it.href}
                        onClick={onNavigate}
                        aria-current={on ? "page" : undefined}
                        className="flex items-center justify-between gap-2 h-[30px] px-2.5 rounded-[3px] text-[13.5px] whitespace-nowrap no-underline transition-colors hover:bg-[var(--hover)] hover:!text-[var(--text)]"
                        style={{
                          background: on ? "rgba(16,185,129,.12)" : "transparent",
                          color: on ? "var(--green2)" : "var(--m1)",
                          boxShadow: on ? "inset 2px 0 0 var(--green)" : "none",
                        }}
                      >
                        <span className="overflow-hidden text-ellipsis">{it.label}</span>
                        {!!n && <span className="font-mono text-[10.5px]" style={{ color: BADGE_COLOR[it.badge!] }}>{n}</span>}
                      </a>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </nav>

      <div className="shrink-0 px-2 py-2.5 flex flex-col gap-1" style={{ borderTop: "1px solid var(--rule)" }}>
        <a href="/profile" onClick={onNavigate} title={user?.email} className="flex items-center gap-2.5 px-[7px] py-1 rounded whitespace-nowrap no-underline hover:bg-[var(--hover)]" style={{ color: "var(--text)" }}>
          <span className="w-7 h-7 rounded-full grid place-items-center text-[11px] font-semibold shrink-0" style={{ border: "1px solid var(--line2)", background: "var(--chip)" }}>
            {user ? initials(user.email) : "··"}
          </span>
          {!rail && (
            <span className="flex flex-col min-w-0">
              <span className="text-[13px] truncate">{user?.email ?? ""}</span>
              <span className="text-[11.5px]" style={{ color: "var(--m2)" }}>{user?.role ?? ""}</span>
            </span>
          )}
        </a>
        <button
          type="button"
          onClick={() => { clearPermissions(); logout(); }}
          title="Sign out"
          className="flex items-center gap-[11px] h-8 px-3 rounded whitespace-nowrap transition-colors hover:bg-[var(--hover)] hover:!text-[var(--red)]"
          style={{ color: "var(--m1)" }}
        >
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" className="w-[18px] h-[18px] shrink-0" aria-hidden>
            <path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4M16 17l5-5-5-5M21 12H9" />
          </svg>
          {!rail && <span className="text-[13px]">Sign out</span>}
        </button>
        {!mobile && (
          <button
            type="button"
            onClick={onToggleCollapsed}
            title={rail ? "Expand menu" : "Collapse menu"}
            className="flex items-center gap-[11px] h-8 px-3 rounded whitespace-nowrap transition-colors hover:bg-[var(--hover)] hover:!text-[var(--text)]"
            style={{ color: "var(--m1)" }}
          >
            <span className="w-[18px] text-center text-sm shrink-0">{rail ? "»" : "«"}</span>
            {!rail && <span className="text-[13px]">Collapse menu</span>}
          </button>
        )}
      </div>
    </aside>
  );
}
