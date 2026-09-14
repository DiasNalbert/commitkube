"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from "recharts";

interface WorkloadSummary {
  namespace: string;
  kind: string;
  name: string;
  desired: number;
  ready: number;
  updated: number;
  available: number;
  image: string;
  status: string;
  uptime_pct: number;
  sample_count: number;
  mini_history: string[];
}

interface WorkloadEvent {
  id: number;
  recorded_at: string;
  namespace: string;
  kind: string;
  name: string;
  event_type: string;
  old_value: string;
  new_value: string;
}

interface WorkloadHistory {
  snapshots: { recorded_at: string; desired: number; ready: number; status: string; image: string }[];
  events: WorkloadEvent[];
  uptime_pct: number;
  samples: number;
}

const STATUS: Record<string, { dot: string; text: string; label: string }> = {
  healthy:     { dot: "bg-brand-green", text: "text-brand-green",                 label: "Healthy" },
  progressing: { dot: "bg-sky-500",     text: "text-sky-600 dark:text-sky-400",   label: "Progressing" },
  degraded:    { dot: "bg-red-500",     text: "text-red-500 dark:text-red-400",   label: "Degraded" },
  scaled_zero: { dot: "bg-zinc-400 dark:bg-zinc-600", text: "text-zinc-500 dark:text-zinc-400", label: "Scaled to zero" },
};
const st = (s: string) => STATUS[s] ?? STATUS.scaled_zero;

const EVENT_STYLE: Record<string, string> = {
  status_change:   "text-amber-600 dark:text-amber-400",
  replicas_change: "text-sky-600 dark:text-sky-400",
  image_change:    "text-brand-green",
};

/** The 90-sample strip: one bar per stored sample, oldest on the left. */
function UptimeStrip({ history }: { history: string[] }) {
  if (history.length === 0) {
    return (
      <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-2">
        No samples yet — the series starts at the first poll.
      </p>
    );
  }
  return (
    <div className="mt-2">
      <div className="flex gap-[2px] h-4">
        {history.map((s, i) => (
          <div key={i} title={st(s).label} className={`flex-1 rounded-sm ${st(s).dot}`} />
        ))}
      </div>
      <div className="flex justify-between text-[10px] text-zinc-500 dark:text-zinc-400 mt-1">
        <span>{history.length} samples ago</span>
        <span>now</span>
      </div>
    </div>
  );
}

export default function WorkloadsPage() {
  const [items, setItems] = useState<WorkloadSummary[]>([]);
  const [totals, setTotals] = useState<Record<string, number> | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [nsFilter, setNsFilter] = useState("");
  const [kindFilter, setKindFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const [expanded, setExpanded] = useState<string | null>(null);
  const [history, setHistory] = useState<Record<string, WorkloadHistory>>({});

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/kubernetes/workloads");
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.error ?? `Request failed (${res.status})`);
        setItems([]);
        return;
      }
      setError("");
      setItems(body.items ?? []);
      setTotals(body.totals ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach the API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadHistory = async (w: WorkloadSummary) => {
    const key = `${w.namespace}/${w.kind}/${w.name}`;
    if (history[key]) return;
    const qs = new URLSearchParams({ namespace: w.namespace, name: w.name, kind: w.kind });
    const res = await apiFetch(`/kubernetes/workloads/history?${qs}`);
    if (!res.ok) return;
    const body = await res.json();
    setHistory(h => ({ ...h, [key]: { ...body, snapshots: (body.snapshots ?? []).slice().reverse() } }));
  };

  const toggle = (w: WorkloadSummary) => {
    const key = `${w.namespace}/${w.kind}/${w.name}`;
    if (expanded === key) { setExpanded(null); return; }
    setExpanded(key);
    loadHistory(w);
  };

  const namespaces = useMemo(
    () => Array.from(new Set(items.map(i => i.namespace))).sort(), [items]
  );
  const kinds = useMemo(
    () => Array.from(new Set(items.map(i => i.kind))).sort(), [items]
  );

  const filtered = useMemo(() => {
    let list = items;
    if (nsFilter) list = list.filter(i => i.namespace === nsFilter);
    if (kindFilter) list = list.filter(i => i.kind === kindFilter);
    if (statusFilter) list = list.filter(i => i.status === statusFilter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(i =>
        i.name.toLowerCase().includes(q) ||
        i.namespace.toLowerCase().includes(q) ||
        i.image.toLowerCase().includes(q)
      );
    }
    const rank = (s: string) =>
      s === "degraded" ? 0 : s === "progressing" ? 1 : s === "healthy" ? 2 : 3;
    return list.slice().sort((a, b) => rank(a.status) - rank(b.status) || a.name.localeCompare(b.name));
  }, [items, nsFilter, kindFilter, statusFilter, search]);

  useEffect(() => { setPage(1); }, [nsFilter, kindFilter, statusFilter, search, pageSize]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageRows = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);

  const scoped = useMemo(() => {
    const base = nsFilter ? items.filter(i => i.namespace === nsFilter) : items;
    const t: Record<string, number> = { total: base.length, healthy: 0, degraded: 0, progressing: 0, scaled_zero: 0 };
    for (const i of base) t[i.status] = (t[i.status] ?? 0) + 1;
    return t;
  }, [items, nsFilter]);

  const cards: [string, string, number, string][] = [
    ["total", "Workloads", scoped.total, "text-zinc-600 dark:text-zinc-300"],
    ["degraded", "Degraded", scoped.degraded, "text-red-500 dark:text-red-400"],
    ["progressing", "Progressing", scoped.progressing, "text-sky-600 dark:text-sky-400"],
    ["healthy", "Healthy", scoped.healthy, "text-brand-green"],
  ];

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Workloads</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
            Availability and change history for every Deployment, StatefulSet and DaemonSet,
            sampled from the Kubernetes API
          </p>
        </div>
        <button
          onClick={load}
          className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition"
        >
          Refresh
        </button>
      </div>

      {error && (
        <div className="glass-card p-4 border-red-500/30 text-sm">
          <p className="text-red-500 dark:text-red-400 font-medium">Cannot read workloads</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1 break-words">{error}</p>
        </div>
      )}

      {totals && totals.total > 0 && items.every(i => i.sample_count === 0) && (
        <div className="glass-card p-4 border-amber-500/30 text-sm">
          <p className="text-amber-600 dark:text-amber-400 font-medium">Uptime history is still building</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1">
            Live state is read straight from the cluster, but uptime and change history need stored
            samples. The poller runs every 5 minutes, so the percentages become meaningful over the
            next few hours.
          </p>
        </div>
      )}

      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        {cards.map(([key, label, value, color]) => {
          const active = statusFilter === key || (key === "total" && statusFilter === null);
          return (
            <button
              key={key}
              onClick={() => setStatusFilter(key === "total" || statusFilter === key ? null : key)}
              className={`glass-card p-4 text-left transition ${active ? "border-brand-green/50 ring-1 ring-brand-green/30" : ""}`}
            >
              <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
              <p className={`text-3xl font-semibold mt-1 ${color}`}>{value}</p>
            </button>
          );
        })}
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search workload, namespace or image…"
          className="flex-1 min-w-[240px] px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] placeholder:text-zinc-400 dark:placeholder:text-zinc-500"
        />
        <select
          value={nsFilter}
          onChange={e => setNsFilter(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]"
        >
          <option value="">All namespaces ({namespaces.length})</option>
          {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
        </select>
        <select
          value={kindFilter}
          onChange={e => setKindFilter(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]"
        >
          <option value="">All kinds</option>
          {kinds.map(k => <option key={k} value={k}>{k}</option>)}
        </select>
        <select
          value={pageSize}
          onChange={e => setPageSize(Number(e.target.value))}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]"
        >
          {[25, 50, 100].map(n => <option key={n} value={n}>{n} per page</option>)}
        </select>
        {(search || nsFilter || kindFilter || statusFilter) && (
          <button
            onClick={() => { setSearch(""); setNsFilter(""); setKindFilter(""); setStatusFilter(null); }}
            className="px-3 py-2 text-sm rounded-lg text-zinc-500 hover:text-brand-green transition"
          >
            Clear filters
          </button>
        )}
      </div>

      {loading ? (
        <div className="glass-card p-12 text-center text-zinc-500">Loading workloads…</div>
      ) : filtered.length === 0 ? (
        <div className="glass-card p-12 text-center text-zinc-500">
          {items.length === 0 ? "No workloads found in this cluster." : "No workloads match the current filters."}
        </div>
      ) : (
        <>
          <div className="space-y-2">
            {pageRows.map(w => {
              const key = `${w.namespace}/${w.kind}/${w.name}`;
              const s = st(w.status);
              const h = history[key];
              return (
                <Fragment key={key}>
                  <div className="glass-card p-4">
                    <div
                      onClick={() => toggle(w)}
                      className="flex flex-wrap items-center gap-3 cursor-pointer"
                    >
                      <span className={`w-2 h-2 rounded-full shrink-0 ${s.dot}`} />
                      <div className="min-w-0 flex-1">
                        <p className="font-medium font-mono truncate">{w.name}</p>
                        <p className="text-xs text-zinc-500 dark:text-zinc-400">
                          {w.kind} · {w.namespace}
                        </p>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded border ${s.text} border-current/30`}>
                        {s.label}
                      </span>
                      <span className="text-xs text-zinc-600 dark:text-zinc-400 tabular-nums">
                        {w.ready}/{w.desired} ready
                      </span>
                      <span className="text-xs text-zinc-500 dark:text-zinc-400 font-mono truncate max-w-[220px] hidden lg:block">
                        {w.image}
                      </span>
                      <span className="text-right">
                        <span className={`text-sm font-semibold tabular-nums ${
                          w.sample_count === 0 ? "text-zinc-500" :
                          w.uptime_pct >= 99 ? "text-brand-green" :
                          w.uptime_pct >= 95 ? "text-amber-600 dark:text-amber-400" :
                          "text-red-500 dark:text-red-400"
                        }`}>
                          {w.sample_count === 0 ? "—" : `${w.uptime_pct.toFixed(1)}%`}
                        </span>
                        <span className="block text-[10px] text-zinc-500 dark:text-zinc-400">uptime</span>
                      </span>
                    </div>
                    <UptimeStrip history={w.mini_history} />
                  </div>

                  {expanded === key && (
                    <div className="glass-card p-5 space-y-5">
                      {!h ? (
                        <p className="text-sm text-zinc-500">Loading history…</p>
                      ) : (
                        <>
                          <div className="grid grid-cols-3 gap-3">
                            <div className="p-3 rounded-lg border border-[var(--card-border)] text-center">
                              <p className="text-2xl font-semibold text-brand-green">
                                {h.samples === 0 ? "—" : `${h.uptime_pct.toFixed(1)}%`}
                              </p>
                              <p className="text-xs text-zinc-500 dark:text-zinc-400">Uptime</p>
                            </div>
                            <div className="p-3 rounded-lg border border-[var(--card-border)] text-center">
                              <p className="text-2xl font-semibold">{h.events.length}</p>
                              <p className="text-xs text-zinc-500 dark:text-zinc-400">Events</p>
                            </div>
                            <div className="p-3 rounded-lg border border-[var(--card-border)] text-center">
                              <p className="text-2xl font-semibold">{h.samples}</p>
                              <p className="text-xs text-zinc-500 dark:text-zinc-400">Samples</p>
                            </div>
                          </div>

                          <div>
                            <h3 className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-2">
                              Replicas over time
                            </h3>
                            {h.snapshots.length < 2 ? (
                              <div className="h-[240px] flex items-center justify-center text-sm text-zinc-500 border border-dashed border-[var(--card-border)] rounded-lg px-6 text-center">
                                Not enough samples yet.
                              </div>
                            ) : (
                              <ResponsiveContainer width="100%" height={240}>
                                <LineChart data={h.snapshots.map(sn => ({
                                  time: new Date(sn.recorded_at).toLocaleString([], {
                                    month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
                                  }),
                                  desired: sn.desired,
                                  ready: sn.ready,
                                }))}>
                                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" />
                                  <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="currentColor" />
                                  <YAxis allowDecimals={false} tick={{ fontSize: 11 }} stroke="currentColor" />
                                  <Tooltip contentStyle={{
                                    background: "var(--color-surface)",
                                    border: "1px solid var(--card-border)",
                                    borderRadius: 8, fontSize: 12,
                                  }} />
                                  <Legend wrapperStyle={{ fontSize: 11 }} />
                                  <Line type="stepAfter" dataKey="desired" name="Desired" stroke="#38bdf8" dot={false} strokeWidth={2} />
                                  <Line type="stepAfter" dataKey="ready" name="Ready" stroke="#10b981" dot={false} strokeWidth={2} />
                                </LineChart>
                              </ResponsiveContainer>
                            )}
                          </div>

                          <div>
                            <h3 className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-2">
                              Change history
                            </h3>
                            {h.events.length === 0 ? (
                              <p className="text-sm text-zinc-500">
                                No changes recorded yet.
                              </p>
                            ) : (
                              <div className="space-y-1">
                                {h.events.map(ev => (
                                  <div
                                    key={ev.id}
                                    className="flex flex-wrap items-baseline gap-x-3 gap-y-1 py-2 border-b border-[var(--card-border)] last:border-0 text-sm"
                                  >
                                    <span className="text-xs text-zinc-500 dark:text-zinc-400 tabular-nums shrink-0">
                                      {new Date(ev.recorded_at).toLocaleString([], {
                                        month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit",
                                      })}
                                    </span>
                                    <span className={EVENT_STYLE[ev.event_type] ?? ""}>
                                      {ev.event_type === "status_change" ? "Status" :
                                       ev.event_type === "replicas_change" ? "Replicas" : "Image"}
                                      : <span className="font-mono text-xs break-all">{ev.old_value || "—"}</span>
                                      {" → "}
                                      <span className="font-mono text-xs break-all">{ev.new_value || "—"}</span>
                                    </span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                        </>
                      )}
                    </div>
                  )}
                </Fragment>
              );
            })}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
            <p className="text-zinc-500 dark:text-zinc-400">
              Showing {(safePage - 1) * pageSize + 1}&ndash;{Math.min(safePage * pageSize, filtered.length)} of {filtered.length}
              {filtered.length !== items.length && ` (filtered from ${items.length})`}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={safePage <= 1}
                className="px-3 py-1.5 rounded-lg border border-[var(--card-border)] hover:bg-[var(--color-surface-hover)] transition disabled:opacity-40"
              >
                Previous
              </button>
              <span className="text-zinc-500 dark:text-zinc-400 px-2">Page {safePage} of {totalPages}</span>
              <button
                onClick={() => setPage(p => Math.min(totalPages, p + 1))}
                disabled={safePage >= totalPages}
                className="px-3 py-1.5 rounded-lg border border-[var(--card-border)] hover:bg-[var(--color-surface-hover)] transition disabled:opacity-40"
              >
                Next
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
