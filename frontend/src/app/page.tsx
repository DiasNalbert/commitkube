"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import WorkspaceFilter from "@/app/components/WorkspaceFilter";

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
  const [selectedWs, setSelectedWs] = useState<number | null>(null);

  const fetchRepos = async (p: number, wsId: number | null = null) => {
    const token = localStorage.getItem("token");
    if (!token) {
      window.location.href = "/login";
      return;
    }
    try {
      const wsParam = wsId ? `&workspace_id=${wsId}` : "";
      const res = await apiFetch(`/repositories?page=${p}&limit=12${wsParam}`);
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

  const fetchSummary = async (wsId: number | null = null) => {
    try {
      const wsParam = wsId ? `?workspace_id=${wsId}` : "";
      const res = await apiFetch(`/dashboard/summary${wsParam}`);
      if (res.ok) setSummary(await res.json());
    } catch {}
  };

  useEffect(() => {
    fetchRepos(page, selectedWs);
    fetchSummary(selectedWs);
    const interval = setInterval(() => { fetchRepos(page, selectedWs); fetchSummary(selectedWs); }, 600000);
    return () => clearInterval(interval);
  }, [page]);

  const deleteRepo = async (name: string) => {
    if (!confirm(`Remove "${name}" from CommitKube? (the Bitbucket repository will not be deleted)`)) return;
    setDeleting(name);
    await apiFetch(`/repositories/${name}`, { method: "DELETE" });
    setDeleting(null);
    fetchRepos(page);
  };

  const repos = (repoPage.data || []).filter(r => !search || r.name.toLowerCase().includes(search.toLowerCase()));
  const failedPipelines = repos.filter(r => r.status === "failed");

  if (loading) return <div className="text-center mt-20 text-brand-green">Loading Dashboard...</div>;

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-3xl font-bold">Platform Dashboard</h1>
        <p className="text-zinc-400 mt-2">Overview of repositories, security findings, and Kubernetes service health.</p>
      </header>

      <WorkspaceFilter
        value={selectedWs}
        onChange={(id) => { setSelectedWs(id); setPage(1); fetchRepos(1, id); fetchSummary(id); }}
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
          onClick={() => window.location.href = "/security"}
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
        onClick={() => window.location.href = "/monitoring"}
      >
        <div className="flex flex-wrap items-center justify-between gap-4">
          <h3 className="text-lg font-medium text-zinc-300">Monitoring / Status Page</h3>
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
                    onClick={e => { e.stopPropagation(); deleteRepo(repo.name); }}
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
                  onClick={() => setPage(p => Math.max(1, p - 1))}
                  disabled={page === 1}
                  className="px-4 py-2 text-sm rounded border border-zinc-700 text-zinc-300 hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
                >
                  ← Previous
                </button>
                {Array.from({ length: repoPage.pages }, (_, i) => i + 1).map(p => (
                  <button
                    key={p}
                    onClick={() => setPage(p)}
                    className={`px-3 py-2 text-sm rounded border transition ${p === page ? "border-brand-green text-brand-green bg-brand-green/10" : "border-zinc-700 text-zinc-400 hover:bg-zinc-800"}`}
                  >
                    {p}
                  </button>
                ))}
                <button
                  onClick={() => setPage(p => Math.min(repoPage.pages, p + 1))}
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
