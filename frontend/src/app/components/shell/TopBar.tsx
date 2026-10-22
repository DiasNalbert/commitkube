"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { usePathname, useSearchParams } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { selectedCluster, setSelectedCluster, type ClusterInfo } from "@/lib/cluster";
import { PERMISSIONS as P } from "@/lib/permissions";
import { MODULES } from "./nav";
import { useShellRefreshState } from "./refresh";

const hhmm = (t: number) => {
  const d = new Date(t);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
};

/** Which cluster the cluster pages read. A chip, not a form control: it is
 *  context for everything on the page, read far more often than changed. */
function ClusterCrumb() {
  const [clusters, setClusters] = useState<ClusterInfo[]>([]);
  const [current, setCurrent] = useState("");
  const [open, setOpen] = useState(false);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    apiFetch("/clusters").then(r => (r.ok ? r.json() : {})).then((body: { clusters?: ClusterInfo[] }) => {
      const list = body.clusters ?? [];
      setClusters(list);
      // A stored id that no longer exists would send every request to an
      // unknown cluster, so fall back to the default.
      const stored = selectedCluster();
      if (!list.some(c => String(c.id) === stored)) {
        const fallback = list.find(c => c.is_default) ?? list[0];
        if (fallback) { setSelectedCluster(fallback.id); setCurrent(String(fallback.id)); }
      } else setCurrent(stored);
    }).catch(() => {});
  }, []);

  useEffect(() => {
    if (!open) return;
    const close = (e: MouseEvent) => { if (!box.current?.contains(e.target as Node)) setOpen(false); };
    window.addEventListener("mousedown", close);
    return () => window.removeEventListener("mousedown", close);
  }, [open]);

  const active = clusters.find(c => String(c.id) === current);
  if (!active) return null;
  const many = clusters.length > 1;

  return (
    <div ref={box} className="relative">
      <button
        type="button"
        onClick={() => many && setOpen(o => !o)}
        title={active.error || active.version || active.name}
        className="flex items-center gap-1.5 h-7 px-2 rounded-[3px] transition-colors hover:bg-[var(--rule)]"
        style={{ background: "var(--chip)", cursor: many ? "pointer" : "default" }}
      >
        <span className="w-1.5 h-1.5" style={{ background: active.reachable ? "var(--green)" : "var(--red)" }} />
        {active.name}
        {many && <span style={{ color: "var(--m2)" }}>▾</span>}
      </button>
      {open && (
        <div className="absolute left-0 top-9 min-w-[220px] p-1 rounded z-50" style={{ background: "var(--hover)", border: "1px solid var(--line2)", boxShadow: "0 18px 40px rgba(0,0,0,.5)" }}>
          {clusters.map(c => (
            <button
              key={c.id}
              type="button"
              onClick={() => { setSelectedCluster(c.id); window.location.reload(); }}
              className="w-full flex items-center justify-between gap-3 px-2.5 py-2 rounded-[3px] text-left hover:bg-[var(--sel)]"
              style={{ background: String(c.id) === current ? "var(--sel)" : "transparent" }}
            >
              <span className="flex items-center gap-2">
                <span className="w-1.5 h-1.5" style={{ background: c.reachable ? "var(--green)" : "var(--red)" }} />
                {c.name}
              </span>
              <span className="text-[10.5px]" style={{ color: "var(--m2)" }}>{c.reachable ? c.version ?? "" : "unreachable"}</span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

interface Suggestion { label: string; kind: string; mono: boolean; href: string }

/** ⌘K: pages, namespaces and pods by name. Pages come from the nav itself;
 *  namespaces and pods are read the first time the box is used and reused
 *  for half a minute, so typing does not cost a cluster call per key. */
function CommandBar({ can, isAdmin }: { can: (p?: string) => boolean; isAdmin: boolean }) {
  const [q, setQ] = useState("");
  const [focused, setFocused] = useState(false);
  const [idx, setIdx] = useState(0);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [pods, setPods] = useState<{ name: string; namespace: string }[]>([]);
  const loadedAt = useRef(0);
  const input = useRef<HTMLInputElement>(null);
  const canK8s = can(P.k8sRead);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); input.current?.focus(); }
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, []);

  const warm = useCallback(() => {
    if (!canK8s || Date.now() - loadedAt.current < 30_000) return;
    loadedAt.current = Date.now();
    apiFetch("/kubernetes/namespaces").then(r => (r.ok ? r.json() : {})).then((d: { namespaces?: string[] }) => setNamespaces(d.namespaces ?? [])).catch(() => {});
    apiFetch("/monitoring/pods").then(r => (r.ok ? r.json() : {})).then((d: { pods?: { name: string; namespace: string }[] }) => setPods((d.pods ?? []).map((p: { name: string; namespace: string }) => ({ name: p.name, namespace: p.namespace })))).catch(() => {});
  }, [canK8s]);

  const pages = useMemo(() => MODULES.flatMap(m =>
    m.items.filter(i => can(i.perm) && (!i.adminOnly || isAdmin)).map(i => ({ label: i.label, module: m.label, href: i.href }))), [can, isAdmin]);

  const suggestions: Suggestion[] = useMemo(() => {
    const s = q.toLowerCase().trim();
    if (!s) {
      return pages.slice(0, 6).map(p => ({ label: p.label, kind: p.module, mono: false, href: p.href }));
    }
    const out: Suggestion[] = [];
    pages.filter(p => p.label.toLowerCase().includes(s) || p.module.toLowerCase().includes(s))
      .forEach(p => out.push({ label: p.label, kind: p.module, mono: false, href: p.href }));
    namespaces.filter(n => n.toLowerCase().includes(s)).slice(0, 5)
      .forEach(n => out.push({ label: n, kind: "Namespace", mono: true, href: `/kubernetes/overview?ns=${encodeURIComponent(n)}` }));
    pods.filter(p => p.name.toLowerCase().includes(s)).slice(0, 6)
      .forEach(p => out.push({ label: p.name, kind: `Pod · ${p.namespace}`, mono: true, href: `/kubernetes/overview?pod=${encodeURIComponent(`${p.namespace}/${p.name}`)}` }));
    return out.slice(0, 10);
  }, [q, pages, namespaces, pods]);

  const at = Math.min(idx, Math.max(0, suggestions.length - 1));
  const go = (s: Suggestion) => { setQ(""); input.current?.blur(); window.location.href = s.href; };

  return (
    <div className="relative flex-1 min-w-[160px] max-w-[620px]">
      <input
        ref={input}
        value={q}
        onChange={e => { setQ(e.target.value); setIdx(0); }}
        onFocus={() => { setFocused(true); warm(); }}
        onBlur={() => setFocused(false)}
        onKeyDown={e => {
          if (e.key === "ArrowDown") { e.preventDefault(); setIdx(Math.min(at + 1, suggestions.length - 1)); }
          else if (e.key === "ArrowUp") { e.preventDefault(); setIdx(Math.max(at - 1, 0)); }
          else if (e.key === "Enter" && suggestions[at]) go(suggestions[at]);
          else if (e.key === "Escape") input.current?.blur();
        }}
        placeholder={canK8s ? "Page, namespace or pod" : "Go to page"}
        aria-label="Search"
        className="w-full h-[34px] pl-3 pr-16 rounded outline-none transition-colors"
        style={{ background: focused ? "var(--inputf)" : "var(--input)", border: `1px solid ${focused ? "var(--green)" : "var(--line)"}` }}
      />
      <span className="absolute right-2.5 top-[9px] font-mono text-[10.5px] pointer-events-none" style={{ color: "var(--m2)" }}>⌘K</span>
      {focused && (
        <div className="absolute left-0 right-0 top-10 p-1 rounded z-50" style={{ background: "var(--hover)", border: "1px solid var(--line2)", boxShadow: "0 18px 40px rgba(0,0,0,.5)" }}>
          {suggestions.map((s, i) => (
            <button
              key={s.kind + s.href}
              type="button"
              onMouseDown={e => { e.preventDefault(); go(s); }}
              onMouseEnter={() => setIdx(i)}
              className="w-full flex justify-between gap-3 px-2.5 py-2 rounded-[3px] text-left"
              style={{ background: i === at ? "var(--sel)" : "transparent" }}
            >
              <span className={s.mono ? "font-mono text-[11.5px] truncate" : "text-sm truncate"}>{s.label}</span>
              <span className="text-xs shrink-0" style={{ color: "var(--m2)" }}>{s.kind}</span>
            </button>
          ))}
          {suggestions.length === 0 && <div className="p-2.5" style={{ color: "var(--t3)" }}>Nothing named “{q}”.</div>}
        </div>
      )}
    </div>
  );
}

function ThemeButton() {
  const [dark, setDark] = useState(true);
  useEffect(() => { setDark(document.documentElement.classList.contains("dark")); }, []);
  const toggle = () => {
    const next = !dark;
    setDark(next);
    try { localStorage.setItem("theme", next ? "dark" : "light"); } catch { /* not remembered */ }
    document.documentElement.classList.toggle("dark", next);
  };
  return (
    <button
      type="button"
      onClick={toggle}
      title={dark ? "Light theme" : "Dark theme"}
      className="w-8 h-8 shrink-0 rounded grid place-items-center transition-colors hover:!text-[var(--gold)] hover:!border-[var(--gold)]"
      style={{ border: "1px solid var(--line2)", color: "var(--t3)" }}
    >
      <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.7" strokeLinecap="round" className="w-4 h-4" aria-hidden>
        <path d={dark
          ? "M16 12a4 4 0 1 1-8 0 4 4 0 0 1 8 0zM12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"
          : "M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"} />
      </svg>
    </button>
  );
}

export default function TopBar({ can, isAdmin, onMenu }: { can: (p?: string) => boolean; isAdmin: boolean; onMenu: () => void }) {
  const pathname = usePathname();
  const params = useSearchParams();
  const refresh = useShellRefreshState();
  const onCluster = pathname.startsWith("/kubernetes") || pathname === "/delivery" || pathname.startsWith("/security/posture") || pathname.startsWith("/security/workloads");
  const ns = pathname === "/kubernetes/overview" ? params.get("ns") : null;

  return (
    <header className="sticky top-0 z-30" style={{ background: "var(--bg)", borderBottom: "1px solid var(--rule)" }}>
      <div className="h-14 flex items-center gap-4 px-4 md:px-6 min-w-0">
        <button type="button" onClick={onMenu} aria-label="Open navigation" className="md:hidden w-8 h-8 -ml-1 grid place-items-center rounded" style={{ color: "var(--t3)" }}>
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" className="w-5 h-5" aria-hidden><path d="M4 7h16M4 12h16M4 17h16" /></svg>
        </button>
        {onCluster && can(P.k8sRead) && (
          <div className="hidden sm:flex items-center gap-1.5 font-mono text-[11.5px] min-w-0 overflow-hidden whitespace-nowrap" style={{ color: "var(--t3)" }}>
            <ClusterCrumb />
            {pathname === "/kubernetes/overview" && (
              <>
                <span style={{ color: "var(--m4)" }}>/</span>
                <a
                  href="/kubernetes/overview"
                  title={ns ? "Show all namespaces" : undefined}
                  className="h-7 px-2 rounded-[3px] flex items-center no-underline hover:bg-[var(--rule)]"
                  style={{ background: "var(--chip)", color: ns ? "var(--green)" : "var(--t3)" }}
                >
                  {ns || "all namespaces"}
                </a>
              </>
            )}
          </div>
        )}
        <CommandBar can={can} isAdmin={isAdmin} />
        <div className="flex-1" />
        {refresh.handler && (
          <button
            type="button"
            onClick={() => refresh.handler?.()}
            title="Refresh"
            className="hidden sm:flex items-center gap-2 font-mono text-[11px] whitespace-nowrap transition-colors hover:!text-[var(--green)]"
            style={{ color: "var(--m2)" }}
          >
            {refresh.syncedAt ? hhmm(refresh.syncedAt) : "--:--"} ↻
          </button>
        )}
        <ThemeButton />
      </div>
    </header>
  );
}
