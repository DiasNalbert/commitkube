"use client";

import React, { useEffect, useState, useCallback, useRef } from "react";
import { apiFetch } from "@/lib/api";
import SecurityTimeline from "./SecurityTimeline";
import SuppressForm, { describeSuppression, type Suppression } from "./FindingTriage";
import { exportFindingsCSV, exportFindingsPDF, type ExportContext } from "@/lib/findings-export";
import { usePermissions } from "@/app/components/usePermissions";
import { PERMISSIONS } from "@/lib/permissions";

interface ScanHistoryEntry {
  id: number;
  scanned_at: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  image_critical: number;
  image_high: number;
  image_medium: number;
  image_low: number;
}

interface RepoResult {
  id: number;
  repo_name: string;
  scanned_at: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  scanned_image: string;
  image_source: string; // "deployed" | "base" | ""
  image_critical: number;
  image_high: number;
  image_medium: number;
  image_low: number;
  image_error: string;
  secrets: number;
  suppressed: number;
}

interface Finding {
  target: string;
  type: string; // vulnerability | misconfiguration | secret
  vuln_id: string;
  pkg: string;
  line?: number;
  version: string;
  fixed: string;
  severity: string;
  title: string;
  /** From the findings table: when this exact finding was first and last
   *  reported, and whether the latest scan is the only one to have seen it. */
  first_seen: string;
  last_seen: string;
  is_new: boolean;
  suppressed: boolean;
  suppression?: Suppression;
}

interface RepoDetail {
  repo_name: string;
  scanned_at: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  secrets: number;
  suppressed: number;
  new_findings: number;
  resolved_30d: number;
  findings: Finding[];
  scanned_image: string;
  image_source: string;
  image_critical: number;
  image_high: number;
  image_medium: number;
  image_low: number;
  image_error: string;
  image_findings: Finding[];
}

interface Totals { critical: number; high: number; medium: number; low: number }
interface Workspace { id: number; alias: string; workspace_id: string; project_key: string }
interface Project { id: number; project_key: string; alias: string }

const sevColor = (s: string) => {
  switch (s?.toUpperCase()) {
    case "CRITICAL": return "text-red-500 font-bold";
    case "HIGH":     return "text-orange-500 font-bold";
    case "MEDIUM":   return "text-yellow-500";
    case "LOW":      return "text-green-500";
    default:         return "text-zinc-400";
  }
};

/** Which image produced these numbers. A base-image result describes what the
 *  Dockerfile inherits, before anything is built; a deployed one describes what
 *  is actually running. Same scanner, different question -- so it is always
 *  said out loud instead of left to the reader to assume. */
const ImageSourceTag = ({ source }: { source: string }) => {
  if (source === "deployed") {
    return (
      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border border-brand-green/40 text-brand-green">
        deployed image
      </span>
    );
  }
  if (source === "base") {
    return (
      <span
        className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium border border-amber-500/40 text-amber-500"
        title="Nothing is deployed yet: these findings are from the base image the Dockerfile declares, not from the final image."
      >
        base image (Dockerfile)
      </span>
    );
  }
  return null;
};

const KIND_LABEL: Record<string, string> = {
  vulnerability: "vuln", misconfiguration: "misconfig", secret: "secret",
};

const SecretsBadge = ({ count }: { count: number }) =>
  count > 0 ? (
    <span
      className="inline-flex flex-col items-center px-3 py-1.5 rounded text-sm font-semibold min-w-[56px] bg-fuchsia-100 text-fuchsia-700 border border-fuchsia-300 dark:bg-fuchsia-900/40 dark:text-fuchsia-300 dark:border-fuchsia-500/40"
      title="Credentials committed to the repository. A leaked key is a different kind of problem from an old library."
    >
      <span className="text-sm font-bold tabular-nums">{count}</span>
      <span className="text-[9px] font-medium opacity-80">SECRETS</span>
    </span>
  ) : null;

const SevBadge = ({ label, count }: { label: string; count: number }) => {
  const styles: Record<string, string> = {
    CRITICAL: "bg-red-100 text-red-700 border border-red-300 dark:bg-red-900/40 dark:text-red-400 dark:border-red-500/40",
    HIGH:     "bg-orange-100 text-orange-700 border border-orange-300 dark:bg-orange-900/40 dark:text-orange-400 dark:border-orange-500/40",
    MEDIUM:   "bg-yellow-100 text-yellow-700 border border-yellow-300 dark:bg-yellow-900/40 dark:text-yellow-400 dark:border-yellow-500/40",
    LOW:      "bg-green-100 text-green-700 border border-green-300 dark:bg-green-900/40 dark:text-green-400 dark:border-green-500/40",
  };
  return (
    <span className={`inline-flex flex-col items-center px-3 py-1.5 rounded text-sm font-semibold min-w-[56px] ${styles[label]}`}>
      <span className="text-sm font-bold tabular-nums">{count}</span>
      <span className="text-[9px] font-medium opacity-80">{label}</span>
    </span>
  );
};

/** Which half of the scan this dashboard reports on. Trivy produces both from
 *  one run -- a filesystem scan of the checked-out repository and a scan of the
 *  image that was built from it -- but they are different problems with
 *  different owners, so they get a page each instead of two rows on one card. */
export type SecurityDomain = "code" | "container";

const DOMAIN_COPY: Record<SecurityDomain, { title: string; subtitle: string; empty: string }> = {
  code: {
    title: "Code Security",
    subtitle: "Vulnerabilities, misconfigurations and secrets found in repository code.",
    empty: "No code scan yet. Run a Security Scan from a repository page.",
  },
  container: {
    title: "Container Security",
    subtitle: "Vulnerabilities in the images published to the registry — the base system and the dependencies that reach production.",
    empty: "No image scanned yet. The image scan runs alongside the repository scan.",
  },
};

export default function SecurityDashboard({ domain }: { domain: SecurityDomain }) {
  const copy = DOMAIN_COPY[domain];
  const isCode = domain === "code";
  const [totals, setTotals] = useState<Totals>({ critical: 0, high: 0, medium: 0, low: 0 });
  const [results, setResults] = useState<RepoResult[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<string | null>(null);
  const [detail, setDetail] = useState<RepoDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);
  const [severityFilter, setSeverityFilter] = useState("ALL");
  const [search, setSearch] = useState("");
  const [repoSearch, setRepoSearch] = useState("");
  const [scanTab, setScanTab] = useState<"code" | "image" | "history">(domain === "code" ? "code" : "image");
  const [scanHistory, setScanHistory] = useState<ScanHistoryEntry[]>([]);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [repoSevFilter, setRepoSevFilter] = useState<string | null>(null);
  const [kindFilter, setKindFilter] = useState("ALL");
  const [showSuppressed, setShowSuppressed] = useState(false);
  // Which finding has the suppress form open, by its position in the list.
  const [triaging, setTriaging] = useState<string | null>(null);
  const [triageError, setTriageError] = useState("");
  const { can } = usePermissions();
  const canTriage = can(PERMISSIONS.securityTriage);

  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [projects, setProjects] = useState<Record<number, Project[]>>({});
  const [selectedWsId, setSelectedWsId] = useState<number | null>(null);
  const [selectedProjectKey, setSelectedProjectKey] = useState<string | null>(null);

  const buildParams = useCallback((wsId: number | null, pk: string | null, p: number, s = "") => {
    const params = new URLSearchParams();
    if (wsId) params.set("workspace_id", String(wsId));
    if (pk) params.set("project_key", pk);
    if (s) params.set("search", s);
    params.set("page", String(p));
    params.set("limit", "20");
    return params.toString();
  }, []);

  const load = useCallback((wsId: number | null, pk: string | null, p: number, s = "", silent = false) => {
    if (!silent) setLoading(true);
    apiFetch(`/scan-dashboard?${buildParams(wsId, pk, p, s)}`)
      .then(r => r.json())
      .then(data => {
        const scoped = isCode ? data.code_totals : data.image_totals;
        setTotals(scoped || data.totals || { critical: 0, high: 0, medium: 0, low: 0 });
        setResults(data.results || []);
        setTotal(data.total || 0);
        setPage(data.page || 1);
        setPages(data.pages || 1);
      })
      .finally(() => { if (!silent) setLoading(false); });
  }, [buildParams, isCode]);

  useEffect(() => {

    apiFetch("/workspaces").then(r => r.json()).then((wsList: Workspace[]) => {
      if (!Array.isArray(wsList)) return;
      setWorkspaces(wsList);
      wsList.forEach(ws => {
        apiFetch(`/workspaces/${ws.id}/projects`).then(r => r.json()).then((ps: Project[]) => {
          setProjects(prev => ({ ...prev, [ws.id]: Array.isArray(ps) ? ps : [] }));
        });
      });
    });

    load(null, null, 1);
  }, [load]);

  const allProjectsForWs = (wsId: number): string[] => {
    const ws = workspaces.find(w => w.id === wsId);
    const registered = (projects[wsId] || []).map(p => p.project_key);
    const keys = new Set<string>(registered);
    if (ws?.project_key) keys.add(ws.project_key);
    return Array.from(keys).sort();
  };

  const handleWsFilter = (wsId: number | null) => {
    setSelectedWsId(wsId);
    setSelectedProjectKey(null);
    setPage(1);
    load(wsId, null, 1, repoSearch);
  };

  const handleProjectFilter = (wsId: number, pk: string | null) => {
    setSelectedWsId(wsId);
    setSelectedProjectKey(pk);
    setPage(1);
    load(wsId, pk, 1, repoSearch);
  };

  const handlePage = (p: number) => {
    setPage(p);
    load(selectedWsId, selectedProjectKey, p, repoSearch);
  };

  useEffect(() => {
    setPage(1);
    load(selectedWsId, selectedProjectKey, 1, repoSearch, true);
  }, [repoSearch]); // eslint-disable-line react-hooks/exhaustive-deps

  // ---- live refresh ----------------------------------------------------
  // The page polls a version stamp that moves whenever a scan result is
  // written (two index lookups on the server), and only then refetches the
  // totals, the current page, the trend and an open detail. Paused while the
  // tab is hidden, and checked again the moment it comes back.
  const [refreshKey, setRefreshKey] = useState(0);
  const [lastChange, setLastChange] = useState<number | null>(null);
  const [now, setNow] = useState(() => Date.now());
  const versionRef = useRef<string | null>(null);
  const liveState = useRef({ selectedWsId, selectedProjectKey, page, repoSearch, selected });
  liveState.current = { selectedWsId, selectedProjectKey, page, repoSearch, selected };

  useEffect(() => {
    let stopped = false;
    const check = async () => {
      if (document.hidden) return;
      try {
        const res = await apiFetch("/scan-status");
        if (!res.ok) return;
        const { version, last_scan_at } = await res.json();
        if (stopped || typeof version !== "string") return;
        // SQLite hands the timestamp back with a space before the time.
        const at = Date.parse(String(last_scan_at ?? "").replace(" ", "T"));
        if (!Number.isNaN(at)) setLastChange(at);
        if (versionRef.current === null) { versionRef.current = version; return; }
        if (version === versionRef.current) return;
        versionRef.current = version;
        const st = liveState.current;
        load(st.selectedWsId, st.selectedProjectKey, st.page, st.repoSearch, true);
        setRefreshKey(k => k + 1);
        if (st.selected) {
          const d = await apiFetch(`/scan-dashboard/${st.selected}`).then(r => r.json()).catch(() => null);
          // Only if the same repository is still open.
          if (d && liveState.current.selected === st.selected) setDetail(d);
        }
      } catch { /* a missed poll is retried on the next tick */ }
    };
    check();
    const poll = setInterval(check, 15000);
    const clock = setInterval(() => setNow(Date.now()), 5000);
    const onVisible = () => { if (!document.hidden) check(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => { stopped = true; clearInterval(poll); clearInterval(clock); document.removeEventListener("visibilitychange", onVisible); };
  }, [load]);

  const liveLabel = (() => {
    if (lastChange === null) return "Live";
    const s = Math.max(0, Math.round((now - lastChange) / 1000));
    if (s < 60) return "Live · last scan just now";
    const m = Math.round(s / 60);
    if (m < 60) return `Live · last scan ${m} min ago`;
    const h = Math.round(m / 60);
    return h < 48 ? `Live · last scan ${h} h ago` : `Live · last scan ${Math.round(h / 24)} days ago`;
  })();

  const openDetail = async (repoName: string) => {
    if (selected === repoName) { setSelected(null); setDetail(null); return; }
    setSelected(repoName);
    setDetail(null);
    setDetailLoading(true);
    setSeverityFilter("ALL");
    setKindFilter("ALL");
    setSearch("");
    setTriaging(null);
    setScanTab(isCode ? "code" : "image");
    setScanHistory([]);
    const res = await apiFetch(`/scan-dashboard/${repoName}`);
    setDetail(await res.json());
    setDetailLoading(false);
  };

  // After a triage decision the counts on the cards, the totals and the
  // open detail all moved; refetch them without the loading flash.
  const afterTriage = async () => {
    setTriaging(null);
    setTriageError("");
    const st = liveState.current;
    load(st.selectedWsId, st.selectedProjectKey, st.page, st.repoSearch, true);
    setRefreshKey(k => k + 1);
    if (st.selected) {
      const d = await apiFetch(`/scan-dashboard/${st.selected}`).then(r => r.json()).catch(() => null);
      if (d && liveState.current.selected === st.selected) setDetail(d);
    }
  };

  const unsuppress = async (s: Suppression) => {
    setTriageError("");
    const res = await apiFetch(`/scan-suppressions/${s.id}`, { method: "DELETE" });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setTriageError(body.error || `Request failed (${res.status})`);
      return;
    }
    afterTriage();
  };

  const findingKey = (f: Finding) => `${f.type}|${f.target}|${f.vuln_id}|${f.pkg}|${f.line ?? 0}`;

  const sevCount = (r: RepoResult, sev: string) => {
    const k = sev.toLowerCase() as "critical" | "high" | "medium" | "low";
    if (isCode) return r[k];
    return r[`image_${k}` as "image_critical" | "image_high" | "image_medium" | "image_low"] ?? 0;
  };

  // A repository with no finding in THIS domain is noise on this page, even if
  // the other half of its scan is full of them.
  const filteredResults = results.filter(r => {
    if (repoSevFilter) return sevCount(r, repoSevFilter) > 0;
    if (!isCode && r.image_error) return false;
    return true;
  });

  const allTabFindings = scanTab === "code" ? (detail?.findings || []) : scanTab === "image" ? (detail?.image_findings || []) : [];
  const suppressedCount = allTabFindings.filter(f => f.suppressed).length;
  // Suppressed findings are out of the list by default, the way they are out
  // of the counts; a toggle brings them back, dimmed, with the reason.
  const activeFindings = showSuppressed ? allTabFindings : allTabFindings.filter(f => !f.suppressed);
  const filteredFindings = activeFindings.filter(f => {
    const matchSev = severityFilter === "ALL" || f.severity?.toUpperCase() === severityFilter;
    if (kindFilter !== "ALL" && f.type !== kindFilter) return false;
    const matchSearch = !search || f.title?.toLowerCase().includes(search.toLowerCase()) ||
      f.vuln_id?.toLowerCase().includes(search.toLowerCase()) ||
      f.pkg?.toLowerCase().includes(search.toLowerCase()) ||
      f.target?.toLowerCase().includes(search.toLowerCase());
    return matchSev && matchSearch;
  });

  return (
    <div className="p-4 max-w-[1600px] mx-auto space-y-3">
      <header>
        <div className="flex flex-wrap items-baseline justify-between gap-2">
          <h1 className="text-lg font-semibold">{copy.title}</h1>
          <span className="inline-flex items-center gap-1.5 text-[11px] text-zinc-500" title="Refreshes on its own when a scan finishes">
            <span className="relative flex h-2 w-2" aria-hidden>
              <span className="absolute inline-flex h-full w-full rounded-full bg-brand-green opacity-60 animate-ping" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-brand-green" />
            </span>
            {liveLabel}
          </span>
        </div>
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">{copy.subtitle}</p>
      </header>

      {workspaces.length > 0 && (
        <div className="space-y-2">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="text-xs text-zinc-500 uppercase tracking-wide font-medium w-16 shrink-0">Workspace</span>
            <button
              onClick={() => handleWsFilter(null)}
              className={`px-3 py-1 text-sm rounded-full border transition-colors ${selectedWsId === null ? "bg-brand-green border-brand-green text-black" : "border-zinc-600 text-zinc-400 hover:bg-zinc-800"}`}
            >
              All
            </button>
            {workspaces.map(ws => (
              <button
                key={ws.id}
                onClick={() => handleWsFilter(ws.id)}
                className={`px-3 py-1 text-sm rounded-full border transition-colors ${selectedWsId === ws.id && !selectedProjectKey ? "bg-brand-green border-brand-green text-black" : "border-zinc-600 text-zinc-400 hover:bg-zinc-800"}`}
              >
                {ws.alias}
              </button>
            ))}
          </div>

          {selectedWsId !== null && allProjectsForWs(selectedWsId).length > 0 && (
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-xs text-zinc-500 uppercase tracking-wide font-medium w-16 shrink-0">Project</span>
              <button
                onClick={() => handleProjectFilter(selectedWsId, null)}
                className={`px-3 py-1 text-sm rounded-full border transition-colors ${!selectedProjectKey ? "bg-brand-gold border-brand-gold text-black" : "border-zinc-600 text-zinc-400 hover:bg-zinc-800"}`}
              >
                All projects
              </button>
              {allProjectsForWs(selectedWsId).map(pk => (
                <button
                  key={pk}
                  onClick={() => handleProjectFilter(selectedWsId, pk)}
                  className={`px-3 py-1 text-sm rounded-full border transition-colors ${selectedProjectKey === pk ? "bg-brand-gold border-brand-gold text-black" : "border-zinc-600 text-zinc-400 hover:bg-zinc-800"}`}
                >
                  {pk}
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {(["CRITICAL","HIGH","MEDIUM","LOW"] as const).map(sev => {
          const active = repoSevFilter === sev;
          return (
            <div
              key={sev}
              onClick={() => setRepoSevFilter(active ? null : sev)}
              className={`glass-card p-5 text-center cursor-pointer transition-all hover:border-brand-green/40 ${active ? "border-brand-green/60 bg-brand-green/5 ring-1 ring-brand-green/30" : ""}`}
            >
              <SevBadge label={sev} count={totals[sev.toLowerCase() as keyof Totals]} />
              <p className="text-zinc-400 text-xs mt-2">{active ? "click to clear" : "across all repos"}</p>
            </div>
          );
        })}
      </div>

      <SecurityTimeline domain={domain} wsId={selectedWsId} projectKey={selectedProjectKey} refreshKey={refreshKey} />

      {loading ? (
        <div className="text-center py-10 text-brand-green">Loading...</div>
      ) : results.length === 0 ? (
        <div className="glass-card p-10 text-center text-zinc-500">
          {copy.empty}
        </div>
      ) : (
        <>
          <div className="flex items-center gap-3 flex-wrap">
            <div className="relative flex-1 min-w-48 max-w-sm">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 text-sm">🔍</span>
              <input
                type="text"
                value={repoSearch}
                onChange={e => setRepoSearch(e.target.value)}
                placeholder="Search repository..."
                className="input-tech text-sm pl-8 py-2 w-full"
              />
            </div>
            <span className="text-sm text-zinc-500 whitespace-nowrap">{total} repositories · page {page} of {pages}</span>
          </div>

          <div className="space-y-2">
            {Array.from({ length: Math.ceil(filteredResults.length / 2) }, (_, rowIdx) => {
              const pair = filteredResults.slice(rowIdx * 2, rowIdx * 2 + 2);
              const rowHasSelected = pair.some(r => r.repo_name === selected);
              return (
                <div key={rowIdx}>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                    {pair.map(r => (
                      <div
                        key={r.id}
                        onClick={() => openDetail(r.repo_name)}
                        className={`glass-card p-5 cursor-pointer transition-all hover:border-brand-green/40 ${selected === r.repo_name ? "border-brand-green/60 bg-brand-green/5" : ""}`}
                      >
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0">
                            <h3 className="font-bold text-brand-gold truncate">{r.repo_name}</h3>
                            <p className="text-xs text-zinc-500 mt-1">
                              Scanned {new Date(r.scanned_at).toLocaleString("en-US")}
                            </p>
                            {!isCode && r.scanned_image && (
                              <>
                                <p className="text-xs text-zinc-500 font-mono truncate mt-0.5" title={r.scanned_image}>
                                  {r.scanned_image}
                                </p>
                                <div className="mt-1"><ImageSourceTag source={r.image_source} /></div>
                              </>
                            )}
                          </div>
                          <div className="flex flex-col gap-2 items-end shrink-0">
                            {/* Only this page's domain. The other half of the
                                scan has its own dashboard. */}
                            {isCode ? (
                              <div className="flex gap-1 items-center">
                                <SevBadge label="CRITICAL" count={r.critical} />
                                <SevBadge label="HIGH"     count={r.high} />
                                <SevBadge label="MEDIUM"   count={r.medium} />
                                <SevBadge label="LOW"      count={r.low} />
                                <SecretsBadge count={r.secrets ?? 0} />
                              </div>
                            ) : r.image_error ? (
                              <span className="text-xs text-amber-500/80 italic max-w-[260px] text-right" title={r.image_error}>
                                image not scanned
                              </span>
                            ) : (
                              <div className="flex gap-1 items-center">
                                <SevBadge label="CRITICAL" count={r.image_critical ?? 0} />
                                <SevBadge label="HIGH"     count={r.image_high ?? 0} />
                                <SevBadge label="MEDIUM"   count={r.image_medium ?? 0} />
                                <SevBadge label="LOW"      count={r.image_low ?? 0} />
                              </div>
                            )}
                          </div>
                        </div>
                        <p className="text-xs text-brand-green/60 mt-3">
                          {selected === r.repo_name ? "Click to close ↑" : "Click to view findings →"}
                          {(r.suppressed ?? 0) > 0 && (
                            <span className="text-zinc-500 ml-2" title="Findings a person has triaged away. They are not in the counts.">
                              · {r.suppressed} suppressed
                            </span>
                          )}
                        </p>
                      </div>
                    ))}
                  </div>

                  {rowHasSelected && (
                    <div className="glass-card p-6 space-y-4 mt-4 border-brand-green/40">
                      <div className="flex items-center justify-between flex-wrap gap-3">
                        <div>
                          <button
                            onClick={() => { setSelected(null); setDetail(null); }}
                            className="text-xl font-bold text-brand-gold hover:opacity-70 transition text-left"
                          >
                            {selected}
                          </button>
                          {detail && (
                            <p className="text-xs text-zinc-500 mt-1">
                              scanned {new Date(detail.scanned_at).toLocaleString("en-US")}
                              {detail.new_findings > 0 && (
                                <span className="text-amber-400 ml-2" title="Seen for the first time by the latest scan">· {detail.new_findings} new</span>
                              )}
                              {detail.resolved_30d > 0 && (
                                <span className="text-green-500 ml-2" title="Findings that stopped being reported in the last 30 days">· {detail.resolved_30d} resolved in 30 days</span>
                              )}
                              {detail.suppressed > 0 && (
                                <span className="ml-2">· {detail.suppressed} suppressed</span>
                              )}
                              <span className="ml-2">· click name to close</span>
                            </p>
                          )}
                        </div>
                        <button
                          onClick={() => { setSelected(null); setDetail(null); }}
                          className="text-zinc-500 hover:text-white text-lg px-2"
                        >
                          ✕
                        </button>
                      </div>

                      {detailLoading && <p className="text-zinc-400 text-sm">Loading findings...</p>}

                      {detail && (
                        <>
                          <div className="flex gap-2 border-b border-zinc-700 mb-2">
                            <button
                              onClick={() => { setScanTab("code"); setSeverityFilter("ALL"); setSearch(""); }}
                              className={`px-4 py-2 text-sm font-medium border-b-2 transition -mb-px ${scanTab === "code" ? "border-brand-green text-brand-green" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
                            >
                              Code Scan
                              <span className="ml-2 text-xs opacity-70">C:{detail.critical} H:{detail.high} M:{detail.medium} L:{detail.low}{detail.secrets > 0 ? ` · ${detail.secrets} secrets` : ""}</span>
                            </button>
                            <button
                              onClick={() => { setScanTab("image"); setSeverityFilter("ALL"); setSearch(""); }}
                              className={`px-4 py-2 text-sm font-medium border-b-2 transition -mb-px ${scanTab === "image" ? "border-blue-400 text-blue-400" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
                            >
                              Image Scan
                              {detail.image_source && <span className="ml-2"><ImageSourceTag source={detail.image_source} /></span>}
                              {detail.image_error ? (
                                <span className="ml-2 text-xs text-zinc-600 italic">not available</span>
                              ) : (
                                <span className="ml-2 text-xs opacity-70">C:{detail.image_critical} H:{detail.image_high} M:{detail.image_medium} L:{detail.image_low}</span>
                              )}
                            </button>
                            <button
                              onClick={() => {
                                setScanTab("history");
                                if (!scanHistory.length) {
                                  setHistoryLoading(true);
                                  apiFetch(`/repositories/${selected}/scan-history?limit=10`)
                                    .then(r => r.json())
                                    .then(d => { setScanHistory(Array.isArray(d) ? d : []); })
                                    .finally(() => setHistoryLoading(false));
                                }
                              }}
                              className={`px-4 py-2 text-sm font-medium border-b-2 transition -mb-px ${scanTab === "history" ? "border-purple-400 text-purple-400" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
                            >
                              History
                            </button>
                          </div>

                          {scanTab === "history" ? (
                            <div className="overflow-x-auto">
                              {historyLoading ? (
                                <p className="text-zinc-400 text-sm py-4">Loading history...</p>
                              ) : scanHistory.length === 0 ? (
                                <p className="text-zinc-500 text-sm italic py-4">No scan history yet.</p>
                              ) : (
                                <table className="w-full text-sm border-collapse">
                                  <thead>
                                    <tr className="border-b border-zinc-700">
                                      <th className="text-left py-2 px-3 text-zinc-400 font-medium">Date</th>
                                      <th className="text-left py-2 px-3 text-zinc-400 font-medium">Critical</th>
                                      <th className="text-left py-2 px-3 text-zinc-400 font-medium">High</th>
                                      <th className="text-left py-2 px-3 text-zinc-400 font-medium">Medium</th>
                                      <th className="text-left py-2 px-3 text-zinc-400 font-medium">Low</th>
                                      <th className="text-left py-2 px-3 text-zinc-400 font-medium">Trend</th>
                                    </tr>
                                  </thead>
                                  <tbody>
                                    {scanHistory.map((entry, i) => {
                                      const next = scanHistory[i + 1];
                                      let trend: React.ReactNode = <span className="text-zinc-500">—</span>;
                                      if (next) {
                                        const curr = entry.critical + entry.high;
                                        const prev = next.critical + next.high;
                                        if (curr < prev) trend = <span className="text-green-500 font-bold">↓</span>;
                                        else if (curr > prev) trend = <span className="text-red-500 font-bold">↑</span>;
                                        else trend = <span className="text-zinc-500">—</span>;
                                      }
                                      return (
                                        <tr key={entry.id} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                                          <td className="py-2 px-3 text-zinc-400 text-xs whitespace-nowrap">{new Date(entry.scanned_at).toLocaleString("en-US")}</td>
                                          <td className="py-2 px-3 font-mono text-xs text-red-500 font-bold">{entry.critical}</td>
                                          <td className="py-2 px-3 font-mono text-xs text-orange-500 font-bold">{entry.high}</td>
                                          <td className="py-2 px-3 font-mono text-xs text-yellow-500">{entry.medium}</td>
                                          <td className="py-2 px-3 font-mono text-xs text-green-500">{entry.low}</td>
                                          <td className="py-2 px-3">{trend}</td>
                                        </tr>
                                      );
                                    })}
                                  </tbody>
                                </table>
                              )}
                            </div>
                          ) : (
                            <>
                          {scanTab === "image" && detail.image_error ? (
                            <div className="text-sm text-zinc-500 italic py-4 px-2">
                              Image scan not available: {detail.image_error}
                              {detail.scanned_image && <span className="block mt-1 font-mono text-xs text-zinc-600">{detail.scanned_image}</span>}
                            </div>
                          ) : scanTab === "image" && detail.scanned_image ? (
                            <p className="text-xs text-zinc-500 font-mono mb-3">{detail.scanned_image}</p>
                          ) : null}

                          <div className="flex gap-3 flex-wrap items-center">
                            <div className="flex gap-1">
                              {["ALL","CRITICAL","HIGH","MEDIUM","LOW"].map(s => (
                                <button
                                  key={s}
                                  onClick={() => setSeverityFilter(s)}
                                  className={`px-3 py-1 rounded text-xs font-medium border transition ${severityFilter === s ? "border-brand-green text-brand-green bg-brand-green/10" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}
                                >
                                  {s}
                                </button>
                              ))}
                            </div>
                            {scanTab === "code" && (
                              <select
                                value={kindFilter}
                                onChange={e => setKindFilter(e.target.value)}
                                className="input-tech text-xs py-1"
                                title="Kind of finding"
                              >
                                <option value="ALL">All kinds</option>
                                <option value="vulnerability">Vulnerabilities</option>
                                <option value="misconfiguration">Misconfigurations</option>
                                <option value="secret">Secrets</option>
                              </select>
                            )}
                            <input
                              type="text"
                              placeholder="Search CVE, package, file..."
                              value={search}
                              onChange={e => setSearch(e.target.value)}
                              className="input-tech text-sm py-1 flex-1 min-w-48"
                            />
                            {suppressedCount > 0 && (
                              <label className="flex items-center gap-1.5 text-xs text-zinc-400 whitespace-nowrap">
                                <input type="checkbox" checked={showSuppressed} onChange={e => setShowSuppressed(e.target.checked)} />
                                show {suppressedCount} suppressed
                              </label>
                            )}
                            {(() => {
                              const ctx: ExportContext = {
                                repo: detail.repo_name, kind: scanTab === "image" ? "image" : "code",
                                scannedAt: detail.scanned_at, image: scanTab === "image" ? detail.scanned_image : undefined,
                                severityFilter, search, total: activeFindings.length,
                              };
                              const disabled = filteredFindings.length === 0;
                              const cls = "px-3 py-1 rounded text-xs font-medium border border-zinc-700 text-zinc-300 hover:bg-zinc-800 transition disabled:opacity-40 disabled:cursor-not-allowed";
                              return (
                                <div className="flex gap-1" title="Exports the findings shown, with the current filter and search">
                                  <button type="button" disabled={disabled} className={cls} onClick={() => exportFindingsCSV(filteredFindings, ctx)}>
                                    Export CSV
                                  </button>
                                  <button type="button" disabled={disabled} className={cls} onClick={() => exportFindingsPDF(filteredFindings, ctx)}>
                                    Export PDF
                                  </button>
                                </div>
                              );
                            })()}
                          </div>

                          {triageError && <p className="text-xs text-red-400">{triageError}</p>}

                          {filteredFindings.length === 0 ? (
                            <p className="text-zinc-500 text-sm italic py-4">No findings match the current filter.</p>
                          ) : (
                            <div className="overflow-x-auto">
                              <table className="w-full text-sm border-collapse">
                                <thead>
                                  <tr className="border-b border-zinc-700">
                                    <th className="text-left py-2 px-3 text-zinc-400 font-medium">Severity</th>
                                    <th className="text-left py-2 px-3 text-zinc-400 font-medium">ID / CVE</th>
                                    <th className="text-left py-2 px-3 text-zinc-400 font-medium">Title</th>
                                    <th className="text-left py-2 px-3 text-zinc-400 font-medium">File / Target</th>
                                    <th className="text-left py-2 px-3 text-zinc-400 font-medium">Package</th>
                                    <th className="text-left py-2 px-3 text-zinc-400 font-medium">Fixed in</th>
                                    <th className="text-left py-2 px-3 text-zinc-400 font-medium whitespace-nowrap" title="When this finding was first reported">Since</th>
                                    {canTriage && <th className="py-2 px-3" />}
                                  </tr>
                                </thead>
                                <tbody>
                                  {filteredFindings.map(f => {
                                    const key = findingKey(f);
                                    const where = f.type === "secret" && f.line ? `${f.target}:${f.line}` : f.target;
                                    return (
                                    <React.Fragment key={key}>
                                    <tr className={`border-b border-zinc-800 hover:bg-zinc-800/30 ${f.suppressed ? "opacity-50" : ""}`}>
                                      <td className={`py-2 px-3 font-mono text-xs ${sevColor(f.severity)}`}>
                                        {f.severity}
                                        {f.is_new && !f.suppressed && (
                                          <span className="ml-1.5 px-1 rounded text-[9px] font-bold bg-amber-500/20 text-amber-400 border border-amber-500/40" title="First reported by the latest scan">NEW</span>
                                        )}
                                      </td>
                                      <td className="py-2 px-3 font-mono text-xs">
                                        {f.type === "vulnerability" && /^(CVE|GHSA)-/i.test(f.vuln_id) ? (
                                          <a href={f.vuln_id.toUpperCase().startsWith("GHSA") ? `https://github.com/advisories/${f.vuln_id}` : `https://nvd.nist.gov/vuln/detail/${f.vuln_id}`} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline">
                                            {f.vuln_id}
                                          </a>
                                        ) : (
                                          <span className="text-zinc-300">{f.vuln_id}</span>
                                        )}
                                        {f.type !== "vulnerability" && (
                                          <span className={`ml-1.5 px-1 rounded text-[9px] uppercase border ${f.type === "secret" ? "border-fuchsia-500/40 text-fuchsia-300" : "border-zinc-600 text-zinc-500"}`}>
                                            {KIND_LABEL[f.type] ?? f.type}
                                          </span>
                                        )}
                                      </td>
                                      <td className="py-2 px-3 text-zinc-300 max-w-xs truncate" title={f.suppressed && f.suppression ? describeSuppression(f.suppression) : f.title}>
                                        {f.title}
                                        {f.suppressed && f.suppression && (
                                          <span className="block text-[10px] text-zinc-500 truncate">{describeSuppression(f.suppression)}</span>
                                        )}
                                      </td>
                                      <td className="py-2 px-3 font-mono text-xs text-zinc-500 max-w-[180px] truncate" title={where}>{where}</td>
                                      <td className="py-2 px-3 font-mono text-xs text-zinc-400">{f.pkg || "—"}</td>
                                      <td className="py-2 px-3 font-mono text-xs text-brand-green">{f.fixed || "—"}</td>
                                      <td className="py-2 px-3 text-xs text-zinc-500 whitespace-nowrap" title={`First seen ${new Date(f.first_seen).toLocaleString("en-US")}`}>
                                        {new Date(f.first_seen).toLocaleDateString("en-US")}
                                      </td>
                                      {canTriage && (
                                        <td className="py-2 px-3 text-xs whitespace-nowrap text-right">
                                          {f.suppressed && f.suppression ? (
                                            <button type="button" onClick={() => unsuppress(f.suppression!)} className="text-zinc-400 hover:text-white underline-offset-2 hover:underline">
                                              Unsuppress
                                            </button>
                                          ) : (
                                            <button type="button" onClick={() => { setTriaging(triaging === key ? null : key); setTriageError(""); }} className="text-zinc-400 hover:text-white underline-offset-2 hover:underline">
                                              Suppress
                                            </button>
                                          )}
                                        </td>
                                      )}
                                    </tr>
                                    {triaging === key && detail && (
                                      <tr className="border-b border-zinc-800">
                                        <td colSpan={canTriage ? 8 : 7} className="py-2 px-3">
                                          <SuppressForm
                                            repo={detail.repo_name}
                                            vulnId={f.vuln_id}
                                            pkg={f.pkg}
                                            onDone={afterTriage}
                                            onCancel={() => setTriaging(null)}
                                          />
                                        </td>
                                      </tr>
                                    )}
                                    </React.Fragment>
                                    );
                                  })}
                                </tbody>
                              </table>
                            </div>
                          )}
                            </>
                          )}
                        </>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>

          {pages > 1 && (
            <div className="flex justify-center gap-2 mt-2">
              <button
                onClick={() => handlePage(Math.max(1, page - 1))}
                disabled={page === 1}
                className="px-4 py-2 text-sm rounded border border-zinc-700 text-zinc-300 hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
              >
                ← Previous
              </button>
              {Array.from({ length: Math.min(pages, 7) }, (_, i) => {
                const p = pages <= 7 ? i + 1 : page <= 4 ? i + 1 : page >= pages - 3 ? pages - 6 + i : page - 3 + i;
                return (
                  <button
                    key={p}
                    onClick={() => handlePage(p)}
                    className={`px-3 py-2 text-sm rounded border transition ${p === page ? "border-brand-green text-brand-green bg-brand-green/10" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}
                  >
                    {p}
                  </button>
                );
              })}
              <button
                onClick={() => handlePage(Math.min(pages, page + 1))}
                disabled={page === pages}
                className="px-4 py-2 text-sm rounded border border-zinc-700 text-zinc-300 hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
              >
                Next →
              </button>
            </div>
          )}
        </>
      )}

    </div>
  );
}
