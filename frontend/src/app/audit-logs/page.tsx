"use client";

import { useEffect, useState, useCallback } from "react";
import { apiFetch } from "@/lib/api";

interface AuditLog {
  id: number;
  created_at: string;
  user_id: number;
  user_email: string;
  action: string;
  resource_type: string;
  resource_name: string;
  details: string;
  ip_address: string;
}

const ACTION_LABELS: Record<string, { label: string; color: string; icon: string }> = {
  login:               { label: "Login",              color: "text-brand-green border-brand-green/30 bg-brand-green/10",  icon: "→" },
  create_repository:   { label: "Create Repo",        color: "text-blue-400 border-blue-400/30 bg-blue-400/10",          icon: "+" },
  delete_repository:   { label: "Delete Repo",        color: "text-red-400 border-red-400/30 bg-red-400/10",             icon: "✕" },
  import_repository:   { label: "Import Repo",        color: "text-purple-400 border-purple-400/30 bg-purple-400/10",    icon: "↓" },
  commit_file:         { label: "Commit",             color: "text-yellow-400 border-yellow-400/30 bg-yellow-400/10",    icon: "✎" },
  trigger_pipeline:    { label: "Pipeline",           color: "text-orange-400 border-orange-400/30 bg-orange-400/10",    icon: "▶" },
  run_scan:            { label: "Security Scan",      color: "text-cyan-400 border-cyan-400/30 bg-cyan-400/10",          icon: "⬡" },
  analyze_repository:  { label: "Code Analyze",       color: "text-brand-gold border-brand-gold/30 bg-brand-gold/10",    icon: "✦" },
  create_user:         { label: "Create User",        color: "text-green-400 border-green-400/30 bg-green-400/10",       icon: "+" },
  delete_user:         { label: "Delete User",        color: "text-red-400 border-red-400/30 bg-red-400/10",             icon: "✕" },
};

const ALL_ACTIONS = Object.keys(ACTION_LABELS);

function parseDetails(details: string): string {
  if (!details) return "";
  try {
    const obj = JSON.parse(details);
    return Object.entries(obj)
      .map(([k, v]) => `${k}: ${v}`)
      .join(" · ");
  } catch {
    return details;
  }
}

function timeAgo(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime();
  const s = Math.floor(diff / 1000);
  if (s < 60) return `${s}s ago`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  return `${d}d ago`;
}

export default function AuditLogsPage() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const [pages, setPages] = useState(1);
  const [loading, setLoading] = useState(true);
  const [search, setSearch] = useState("");
  const [actionFilter, setActionFilter] = useState("");

  const load = useCallback((p: number, s: string, a: string, silent = false) => {
    if (!silent) setLoading(true);
    const params = new URLSearchParams({ page: String(p), limit: "50" });
    if (s) params.set("search", s);
    if (a) params.set("action", a);
    apiFetch(`/audit-logs?${params}`)
      .then(r => r.json())
      .then(data => {
        setLogs(data.data || []);
        setTotal(data.total || 0);
        setPage(data.page || 1);
        setPages(data.pages || 1);
      })
      .finally(() => { if (!silent) setLoading(false); });
  }, []);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }
    load(1, "", "");
  }, [load]);

  useEffect(() => {
    setPage(1);
    load(1, search, actionFilter, true);
  }, [search, actionFilter]); // eslint-disable-line react-hooks/exhaustive-deps

  const handlePage = (p: number) => {
    setPage(p);
    load(p, search, actionFilter);
  };

  return (
    <div className="space-y-6">
      <header>
        <h1 className="text-3xl font-bold">Audit Log</h1>
        <p className="text-zinc-400 mt-1">Track all user actions across CommitKube.</p>
      </header>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative flex-1 min-w-48 max-w-sm">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 text-sm">🔍</span>
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search user, resource or details..."
            className="input-tech text-sm pl-8 py-2 w-full"
          />
        </div>

        <select
          value={actionFilter}
          onChange={e => setActionFilter(e.target.value)}
          className="input-tech text-sm py-2 px-3 bg-zinc-900"
        >
          <option value="">All actions</option>
          {ALL_ACTIONS.map(a => (
            <option key={a} value={a}>{ACTION_LABELS[a]?.label ?? a}</option>
          ))}
        </select>

        <span className="text-sm text-zinc-500 whitespace-nowrap">{total} events · page {page} of {pages}</span>
      </div>

      {loading ? (
        <div className="text-center py-16 text-brand-green">Loading...</div>
      ) : logs.length === 0 ? (
        <div className="glass-card p-12 text-center text-zinc-500">
          No audit events found.
        </div>
      ) : (
        <>
          <div className="glass-card overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-zinc-800 text-zinc-500 text-xs uppercase tracking-wide">
                  <th className="text-left px-4 py-3 w-32">Time</th>
                  <th className="text-left px-4 py-3 w-32">Action</th>
                  <th className="text-left px-4 py-3">User</th>
                  <th className="text-left px-4 py-3">Resource</th>
                  <th className="text-left px-4 py-3 hidden lg:table-cell">Details</th>
                  <th className="text-left px-4 py-3 hidden xl:table-cell w-32">IP</th>
                </tr>
              </thead>
              <tbody>
                {logs.map((log, i) => {
                  const meta = ACTION_LABELS[log.action] ?? { label: log.action, color: "text-zinc-400 border-zinc-600 bg-zinc-800/40", icon: "•" };
                  return (
                    <tr
                      key={log.id}
                      className={`border-b border-zinc-800/60 hover:bg-zinc-800/30 transition-colors ${i % 2 === 0 ? "" : "bg-zinc-900/20"}`}
                    >
                      <td className="px-4 py-3 text-zinc-500 whitespace-nowrap" title={new Date(log.created_at).toLocaleString("pt-BR")}>
                        {timeAgo(log.created_at)}
                      </td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded border text-xs font-medium ${meta.color}`}>
                          <span>{meta.icon}</span>
                          {meta.label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-zinc-300 truncate max-w-[160px]">
                        {log.user_email || `user #${log.user_id}`}
                      </td>
                      <td className="px-4 py-3">
                        {log.resource_name ? (
                          <span className="text-brand-gold font-medium truncate block max-w-[180px]">{log.resource_name}</span>
                        ) : (
                          <span className="text-zinc-600">—</span>
                        )}
                      </td>
                      <td className="px-4 py-3 text-zinc-500 hidden lg:table-cell truncate max-w-[220px]">
                        {parseDetails(log.details) || "—"}
                      </td>
                      <td className="px-4 py-3 text-zinc-600 hidden xl:table-cell font-mono text-xs">
                        {log.ip_address || "—"}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
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
