"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import WorkspaceFilter, { WorkspaceSelection } from "@/app/components/WorkspaceFilter";

interface Repository {
  id: number;
  name: string;
  status: string;
  argo_app: string;
  created_at: string;
}

interface RepoPage {
  data: Repository[];
  total: number;
  page: number;
  pages: number;
  limit: number;
}

interface DashboardSummary {
  repos: number;
  security: { critical: number; high: number; medium: number; low: number };
  monitoring: { total: number; healthy: number; degraded: number; unknown: number };
  pods: { total: number; ready: number; unhealthy_apps: number };
}

export default function Dashboard() {
  const [repoPage, setRepoPage] = useState<RepoPage>({ data: [], total: 0, page: 1, pages: 1, limit: 12 });
  const [summary, setSummary] = useState<DashboardSummary | null>(null);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [deleting, setDeleting] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);
  const [deleteConfirmText, setDeleteConfirmText] = useState("");
  const [selectedWs, setSelectedWs] = useState<WorkspaceSelection | null>(null);

  const buildWsParams = (sel: WorkspaceSelection | null) => {
    if (!sel) return "";
    let p = `&workspace_slug=${encodeURIComponent(sel.slug)}`;
    if (sel.project_key) p += `&project_key=${encodeURIComponent(sel.project_key)}`;
    return p;
  };

  const fetchRepos = async (p: number, sel: WorkspaceSelection | null = null, q = "") => {
    const token = localStorage.getItem("token");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    try {
      const searchParam = q ? `&search=${encodeURIComponent(q)}` : "";
      const res = await apiFetch(`/repositories?page=${p}&limit=12${buildWsParams(sel)}${searchParam}`);
      if (res.status === 401) {
        window.location.href = "/login";
        return;
      }
      const data = await res.json();
      setRepoPage(data);
    } catch (err) {
      console.error(err);
    } finally {
      setLoading(false);
    }
  };

  const fetchSummary = async (sel: WorkspaceSelection | null = null) => {
    try {
      const params = sel
        ? `?workspace_slug=${encodeURIComponent(sel.slug)}${sel.project_key ? `&project_key=${encodeURIComponent(sel.project_key)}` : ""}`
        : "";
      const res = await apiFetch(`/dashboard/summary${params}`);
      if (res.ok) setSummary(await res.json());
    } catch {}
  };

  useEffect(() => {
    fetchRepos(page, selectedWs, search);
    fetchSummary(selectedWs);
    const interval = setInterval(() => { fetchRepos(page, selectedWs, search); fetchSummary(selectedWs); }, 600000);
    return () => clearInterval(interval);
  }, [page, selectedWs]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    setPage(1);
    fetchRepos(1, selectedWs, search);
  }, [search]); // eslint-disable-line react-hooks/exhaustive-deps

  const openDeleteModal = (name: string) => {
    setDeleteTarget(name);
    setDeleteConfirmText("");
  };

  const confirmDelete = async () => {
    if (!deleteTarget || deleteConfirmText !== deleteTarget) return;
    setDeleteTarget(null);
    setDeleteConfirmText("");
    setDeleting(deleteTarget);
    await apiFetch(`/repositories/${deleteTarget}`, { method: "DELETE" });
    setDeleting(null);
    fetchRepos(page, selectedWs, search);
    fetchSummary(selectedWs);
  };

  const repos = repoPage.data || [];
  const failedPipelines = repos.filter(r => r.status === "failed");

  if (loading) return <div className="text-center mt-20 text-brand-green">Loading Dashboard...</div>;

  const role = typeof window !== "undefined" ? localStorage.getItem("role") || "" : "";
  const isAdmin = role === "root" || role === "admin";

  return (
    <div className="space-y-8">

      {/* Delete confirmation modal */}
      {deleteTarget && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="glass-panel border border-red-500/30 rounded-2xl p-8 w-full max-w-md shadow-2xl mx-4">
            <div className="flex items-center gap-3 mb-5">
              <div className="w-10 h-10 rounded-xl bg-red-500/15 border border-red-500/30 flex items-center justify-center text-red-400 text-xl shrink-0">⚠</div>
              <div>
                <h2 className="text-lg font-bold text-zinc-100">Delete Repository</h2>
                <p className="text-xs text-zinc-500 mt-0.5">
                  {isAdmin ? "This will remove it from CommitKube, Bitbucket and ArgoCD." : "This will remove it from CommitKube."}
                </p>
              </div>
            </div>

            <p className="text-sm text-zinc-400 mb-4">
              Type <span className="font-mono font-bold text-red-400">{deleteTarget}</span> to confirm deletion. This action is irreversible.
            </p>

            <input
              type="text"
              value={deleteConfirmText}
              onChange={e => setDeleteConfirmText(e.target.value)}
              onKeyDown={e => e.key === "Enter" && confirmDelete()}
              placeholder={`Type "${deleteTarget}" to confirm`}
              autoFocus
              className="w-full bg-zinc-800/60 border border-zinc-700 rounded-lg px-3 py-2.5 text-sm text-zinc-100 placeholder-zinc-600 focus:outline-none focus:border-red-500/50 font-mono mb-5"
            />

            <div className="flex gap-3 justify-end">
              <button
                onClick={() => { setDeleteTarget(null); setDeleteConfirmText(""); }}
                className="px-4 py-2 text-sm rounded-lg border border-zinc-700 text-zinc-400 hover:bg-zinc-800 transition"
              >
                Cancel
              </button>
              <button
                onClick={confirmDelete}
                disabled={deleteConfirmText !== deleteTarget}
                className="px-4 py-2 text-sm rounded-lg bg-red-600 text-white font-semibold hover:bg-red-500 transition disabled:opacity-40 disabled:cursor-not-allowed"
              >
                {deleting ? "Deleting..." : "Delete Repository"}
              </button>
            </div>
          </div>
        </div>
      )}

      <header>
        <h1 className="text-3xl font-bold">Repositories Dashboard</h1>
        <p className="text-zinc-400 mt-2">Os repositórios geridos pela plataforma — Bitbucket, GitHub e GitLab — com o estado de cada scan e a saúde do que eles entregam.</p>
      </header>

      <WorkspaceFilter
        value={selectedWs}
        onChange={(sel) => { setSelectedWs(sel); setPage(1); fetchRepos(1, sel, search); fetchSummary(sel); }}
      />

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="glass-card p-6 border-l-4 border-l-red-500">
          <h3 className="text-lg font-medium text-zinc-300">Failed Pipelines</h3>
          <p className="text-4xl font-black text-red-400 mt-2">{failedPipelines.length}</p>
          <div className="mt-4 text-xs text-zinc-500">Updates every 10 min</div>
        </div>

        <div className="glass-card p-6 border-l-4 border-l-brand-green">
          <h3 className="text-lg font-medium text-zinc-300">Active Repositories</h3>
          <p className="text-4xl font-black text-brand-green mt-2">{repoPage.total}</p>
        </div>

        <div
          className="glass-card p-6 border-l-4 border-l-yellow-500 cursor-pointer hover:border-yellow-400 transition-colors"
          onClick={() => window.location.href = "/security/code"}
        >
          <h3 className="text-lg font-medium text-zinc-300">Security</h3>
          {summary ? (
            <>
              <div className="flex items-end gap-2 mt-2">
                <span className="text-4xl font-black text-red-400">{summary.security.critical}</span>
                <span className="text-sm text-zinc-500 mb-1">critical</span>
              </div>
              <div className="flex gap-3 text-xs mt-2">
                <span className="text-orange-400">{summary.security.high} HIGH</span>
                <span className="text-yellow-400">{summary.security.medium} MED</span>
                <span className="text-green-400">{summary.security.low} LOW</span>
              </div>
            </>
          ) : <p className="text-4xl font-black text-zinc-500 mt-2">—</p>}
        </div>
      </div>

      <div
        className="glass-card p-6 border-l-4 border-l-emerald-500 cursor-pointer hover:border-emerald-500/70 transition-colors"
        onClick={() => window.location.href = "/kubernetes/workloads"}
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h3 className="text-lg font-medium text-zinc-300">Workload Availability</h3>
          <span className="text-xs text-zinc-500">View details →</span>
        </div>
        {summary ? (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mt-4">
            <div>
              <div className="text-3xl font-black text-emerald-400">{summary.monitoring.healthy}</div>
              <div className="text-xs text-zinc-500 mt-0.5">Healthy</div>
            </div>
            <div>
              <div className={`text-3xl font-black ${summary.monitoring.degraded > 0 ? "text-red-400" : "text-zinc-600"}`}>{summary.monitoring.degraded}</div>
              <div className="text-xs text-zinc-500 mt-0.5">Degraded</div>
            </div>
            <div>
              <div className="text-3xl font-black text-blue-400">{summary.pods.ready}<span className="text-lg text-zinc-500">/{summary.pods.total}</span></div>
              <div className="text-xs text-zinc-500 mt-0.5">Ready pods</div>
            </div>
            <div>
              <div className={`text-3xl font-black ${summary.pods.unhealthy_apps > 0 ? "text-red-400" : "text-zinc-600"}`}>{summary.pods.unhealthy_apps}</div>
              <div className="text-xs text-zinc-500 mt-0.5">Apps with missing pod</div>
            </div>
          </div>
        ) : <p className="text-zinc-500 mt-3 text-sm">No monitoring data yet</p>}
      </div>

      {failedPipelines.length > 0 && (
        <div className="space-y-4">
          <h2 className="text-xl font-bold flex items-center gap-2">
            <span className="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span>
            Recently Failed Pipelines
          </h2>
          {failedPipelines.map(repo => (
            <div
              key={repo.id}
              className="glass-card p-4 flex justify-between items-center hover:bg-surface-hover cursor-pointer"
              onClick={() => window.location.href = `/repositories/${repo.name}`}
            >
              <div>
                <h4 className="font-bold text-red-400">{repo.name} <span className="text-xs ml-2 bg-red-500/10 px-2 py-1 rounded text-red-500">FAILED</span></h4>
                <p className="text-xs text-zinc-400 mt-1">Pipeline sync failed for {repo.name}</p>
              </div>
              <div className="text-right text-xs text-zinc-500">
                Created: {new Date(repo.created_at).toLocaleDateString()}
              </div>
            </div>
          ))}
        </div>
      )}

      <div className="space-y-4">
        <div className="flex items-center justify-between mb-4 gap-4 flex-wrap">
          <h2 className="text-xl font-bold">All Managed Repositories</h2>
          <div className="flex items-center gap-3">
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 text-sm">🔍</span>
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="Search repository..."
                className="input-tech text-sm pl-8 pr-4 py-1.5 w-56"
              />
            </div>
            <span className="text-sm text-zinc-500 whitespace-nowrap">{repoPage.total} repositories · page {repoPage.page} of {repoPage.pages}</span>
          </div>
        </div>

        {repos.length === 0 ? (
          <div className="p-8 text-center text-zinc-500 glass-card">
            No repositories found. Create one using the &apos;New Repository&apos; wizard.
          </div>
        ) : (
          <>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-6">
              {repos.map(repo => (
                <div
                  key={repo.id}
                  className="glass-card p-5 group hover:border-brand-gold/40 transition-colors relative"
                >
                  <div
                    className="cursor-pointer"
                    onClick={() => window.location.href = `/repositories/${repo.name}`}
                  >
                    <div className="flex justify-between items-start pr-6">
                      <h4 className="font-bold text-brand-gold">{repo.name}</h4>
                      <span className={`text-xs px-2 py-1 rounded border ${repo.status === "failed" ? "bg-red-500/10 text-red-400 border-red-500/30" : "bg-brand-green/10 text-brand-green border-brand-green/30"}`}>
                        {repo.status.toUpperCase()}
                      </span>
                    </div>
                    <div className="mt-4 space-y-2">
                      <p className="text-xs text-zinc-400 flex items-center gap-2">
                        <span className="w-4">A:</span> ArgoCD App: {repo.argo_app}
                      </p>
                      <p className="text-xs text-zinc-500">
                        {new Date(repo.created_at).toLocaleDateString("en-US")}
                      </p>
                    </div>
                    <div className="mt-3 text-xs text-brand-green/60 group-hover:text-brand-green transition-colors">
                      Click to view details →
                    </div>
                  </div>
                  <button
                    onClick={e => { e.stopPropagation(); openDeleteModal(repo.name); }}
                    disabled={deleting === repo.name}
                    className="absolute top-3 right-3 text-zinc-500 hover:text-red-400 transition-colors text-sm px-1"
                    title="Remove from CommitKube"
                  >
                    {deleting === repo.name ? "..." : "✕"}
                  </button>
                </div>
              ))}
            </div>

            {repoPage.pages > 1 && (
              <div className="flex justify-center gap-2 mt-6">
                <button
                  onClick={() => setPage(p => { const next = Math.max(1, p - 1); fetchRepos(next, selectedWs, search); return next; })}
                  disabled={page === 1}
                  className="px-4 py-2 text-sm rounded border border-zinc-700 text-zinc-300 hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
                >
                  ← Previous
                </button>
                {Array.from({ length: repoPage.pages }, (_, i) => i + 1).map(p => (
                  <button
                    key={p}
                    onClick={() => { setPage(p); fetchRepos(p, selectedWs, search); }}
                    className={`px-3 py-2 text-sm rounded border transition ${p === page ? "border-brand-green text-brand-green bg-brand-green/10" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}
                  >
                    {p}
                  </button>
                ))}
                <button
                  onClick={() => setPage(p => { const next = Math.min(repoPage.pages, p + 1); fetchRepos(next, selectedWs, search); return next; })}
                  disabled={page === repoPage.pages}
                  className="px-4 py-2 text-sm rounded border border-zinc-700 text-zinc-300 hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
                >
                  Next →
                </button>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  );
}
