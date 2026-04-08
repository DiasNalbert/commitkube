"use client";

import { useEffect, useState, useCallback } from "react";
import { apiFetch } from "@/lib/api";

interface RepoResult {
  id: number;
  repo_name: string;
  scanned_at: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  scanned_image: string;
  image_critical: number;
  image_high: number;
  image_medium: number;
  image_low: number;
  image_error: string;
}

interface Finding {
  target: string;
  type: string;
  vuln_id: string;
  pkg: string;
  version: string;
  fixed: string;
  severity: string;
  title: string;
}

interface RepoDetail {
  repo_name: string;
  scanned_at: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  findings: Finding[];
  scanned_image: string;
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

const SevBadge = ({ label, count }: { label: string; count: number }) => {
  const styles: Record<string, string> = {
    CRITICAL: "bg-red-100 text-red-700 border border-red-300 dark:bg-red-900/40 dark:text-red-400 dark:border-red-500/40",
    HIGH:     "bg-orange-100 text-orange-700 border border-orange-300 dark:bg-orange-900/40 dark:text-orange-400 dark:border-orange-500/40",
    MEDIUM:   "bg-yellow-100 text-yellow-700 border border-yellow-300 dark:bg-yellow-900/40 dark:text-yellow-400 dark:border-yellow-500/40",
    LOW:      "bg-green-100 text-green-700 border border-green-300 dark:bg-green-900/40 dark:text-green-400 dark:border-green-500/40",
  };
  return (
    <span className={`inline-flex flex-col items-center px-3 py-1.5 rounded text-sm font-semibold min-w-[56px] ${styles[label]}`}>
      <span className="text-lg font-black">{count}</span>
      <span className="text-[10px] font-medium opacity-80">{label}</span>
    </span>
  );
};

export default function SecurityDashboard() {
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
  const [scanTab, setScanTab] = useState<"code" | "image">("code");
  const [repoSevFilter, setRepoSevFilter] = useState<string | null>(null);

  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [projects, setProjects] = useState<Record<number, Project[]>>({});
  const [selectedWsId, setSelectedWsId] = useState<number | null>(null);
  const [selectedProjectKey, setSelectedProjectKey] = useState<string | null>(null);

  const buildParams = useCallback((wsId: number | null, pk: string | null, p: number) => {
    const params = new URLSearchParams();
    if (wsId) params.set("workspace_id", String(wsId));
    if (pk) params.set("project_key", pk);
    params.set("page", String(p));
    params.set("limit", "20");
    return params.toString();
  }, []);

  const load = useCallback((wsId: number | null, pk: string | null, p: number) => {
    setLoading(true);
    apiFetch(`/scan-dashboard?${buildParams(wsId, pk, p)}`)
      .then(r => r.json())
      .then(data => {
        setTotals(data.totals || { critical: 0, high: 0, medium: 0, low: 0 });
        setResults(data.results || []);
        setTotal(data.total || 0);
        setPage(data.page || 1);
        setPages(data.pages || 1);
      })
      .finally(() => setLoading(false));
  }, [buildParams]);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }

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
    load(wsId, null, 1);
  };

  const handleProjectFilter = (wsId: number, pk: string | null) => {
    setSelectedWsId(wsId);
    setSelectedProjectKey(pk);
    setPage(1);
    load(wsId, pk, 1);
  };

  const handlePage = (p: number) => {
    setPage(p);
    load(selectedWsId, selectedProjectKey, p);
  };

  const openDetail = async (repoName: string) => {
    if (selected === repoName) { setSelected(null); setDetail(null); return; }
    setSelected(repoName);
    setDetail(null);
    setDetailLoading(true);
    setSeverityFilter("ALL");
    setSearch("");
    setScanTab("code");
    const res = await apiFetch(`/scan-dashboard/${repoName}`);
    setDetail(await res.json());
    setDetailLoading(false);
  };

  const filteredResults = results.filter(r => {
    if (repoSearch && !r.repo_name.toLowerCase().includes(repoSearch.toLowerCase())) return false;
    if (repoSevFilter) {
      const k = repoSevFilter.toLowerCase() as "critical" | "high" | "medium" | "low";
      const imgKey = `image_${k}` as "image_critical" | "image_high" | "image_medium" | "image_low";
      return (r[k] + r[imgKey]) > 0;
    }
    return true;
  });

  const activeFindings = scanTab === "code" ? (detail?.findings || []) : (detail?.image_findings || []);
  const filteredFindings = activeFindings.filter(f => {
    const matchSev = severityFilter === "ALL" || f.severity?.toUpperCase() === severityFilter;
    const matchSearch = !search || f.title?.toLowerCase().includes(search.toLowerCase()) ||
      f.vuln_id?.toLowerCase().includes(search.toLowerCase()) ||
      f.pkg?.toLowerCase().includes(search.toLowerCase()) ||
      f.target?.toLowerCase().includes(search.toLowerCase());
    return matchSev && matchSearch;
  });

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-3xl font-bold">Security Dashboard</h1>
        <p className="text-zinc-400 mt-1">Aggregated vulnerability findings across all scanned repositories.</p>
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

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
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

      {loading ? (
        <div className="text-center py-10 text-brand-green">Loading...</div>
      ) : results.length === 0 ? (
        <div className="glass-card p-10 text-center text-zinc-500">
          No scan results yet. Run a Security Scan from a repository page.
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

          <div className="space-y-4">
            {Array.from({ length: Math.ceil(filteredResults.length / 2) }, (_, rowIdx) => {
              const pair = filteredResults.slice(rowIdx * 2, rowIdx * 2 + 2);
              const rowHasSelected = pair.some(r => r.repo_name === selected);
              return (
                <div key={rowIdx}>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
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
                          </div>
                          <div className="flex flex-col gap-2 items-end shrink-0">
                            <div className="flex gap-1 items-center">
                              <span className="text-[10px] text-zinc-500 mr-1">Code</span>
                              <SevBadge label="CRITICAL" count={r.critical} />
                              <SevBadge label="HIGH"     count={r.high} />
                              <SevBadge label="MEDIUM"   count={r.medium} />
                              <SevBadge label="LOW"      count={r.low} />
                            </div>
                            <div className="flex gap-1 items-center">
                              <span className="text-[10px] text-zinc-500 mr-1">Image</span>
                              {r.image_error ? (
                                <span className="text-[10px] text-zinc-600 italic">not scanned</span>
                              ) : (
                                <>
                                  <SevBadge label="CRITICAL" count={r.image_critical ?? 0} />
                                  <SevBadge label="HIGH"     count={r.image_high ?? 0} />
                                  <SevBadge label="MEDIUM"   count={r.image_medium ?? 0} />
                                  <SevBadge label="LOW"      count={r.image_low ?? 0} />
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                        <p className="text-xs text-brand-green/60 mt-3">
                          {selected === r.repo_name ? "Click to close ↑" : "Click to view findings →"}
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
                              scanned {new Date(detail.scanned_at).toLocaleString("en-US")} · click name to close
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
                              <span className="ml-2 text-xs opacity-70">C:{detail.critical} H:{detail.high} M:{detail.medium} L:{detail.low}</span>
                            </button>
                            <button
                              onClick={() => { setScanTab("image"); setSeverityFilter("ALL"); setSearch(""); }}
                              className={`px-4 py-2 text-sm font-medium border-b-2 transition -mb-px ${scanTab === "image" ? "border-blue-400 text-blue-400" : "border-transparent text-zinc-400 hover:text-zinc-200"}`}
                            >
                              Image Scan
                              {detail.image_error ? (
                                <span className="ml-2 text-xs text-zinc-600 italic">not available</span>
                              ) : (
                                <span className="ml-2 text-xs opacity-70">C:{detail.image_critical} H:{detail.image_high} M:{detail.image_medium} L:{detail.image_low}</span>
                              )}
                            </button>
                          </div>

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
                            <input
                              type="text"
                              placeholder="Search CVE, package, file..."
                              value={search}
                              onChange={e => setSearch(e.target.value)}
                              className="input-tech text-sm py-1 flex-1 min-w-48"
                            />
                          </div>

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
                                  </tr>
                                </thead>
                                <tbody>
                                  {filteredFindings.map((f, i) => (
                                    <tr key={i} className="border-b border-zinc-800 hover:bg-zinc-800/30">
                                      <td className={`py-2 px-3 font-mono text-xs ${sevColor(f.severity)}`}>{f.severity}</td>
                                      <td className="py-2 px-3 font-mono text-xs">
                                        {f.type === "vulnerability" && f.vuln_id ? (
                                          <a href={`https://nvd.nist.gov/vuln/detail/${f.vuln_id}`} target="_blank" rel="noreferrer" className="text-blue-400 hover:underline">
                                            {f.vuln_id}
                                          </a>
                                        ) : (
                                          <span className="text-zinc-300">{f.vuln_id}</span>
                                        )}
                                      </td>
                                      <td className="py-2 px-3 text-zinc-300 max-w-xs truncate" title={f.title}>{f.title}</td>
                                      <td className="py-2 px-3 font-mono text-xs text-zinc-500 max-w-[180px] truncate" title={f.target}>{f.target}</td>
                                      <td className="py-2 px-3 font-mono text-xs text-zinc-400">{f.pkg || "—"}</td>
                                      <td className="py-2 px-3 font-mono text-xs text-brand-green">{f.fixed || "—"}</td>
                                    </tr>
                                  ))}
                                </tbody>
                              </table>
                            </div>
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
