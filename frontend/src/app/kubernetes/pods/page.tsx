"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import PodLogs from "@/app/components/k8s/PodLogs";
import PodActions from "@/app/components/k8s/PodActions";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend,
} from "recharts";

interface DetectedProblem {
  kind: string;
  severity: string;
  title: string;
  detail: string;
  value: number;
}

interface ContainerInfo {
  name: string;
  image: string;
  ready: boolean;
  restart_count: number;
  state: string;
  state_reason: string;
  last_exit_code: number;
  last_reason: string;
  cpu_cores: number;
  cpu_requests: number;
  cpu_limits: number;
  mem_bytes: number;
  mem_requests: number;
  mem_limits: number;
  throttled_pct: number;
}

interface PodInfo {
  name: string;
  namespace: string;
  workload: string;
  workload_kind: string;
  node_name: string;
  phase: string;
  ready: boolean;
  age: string;
  restart_count: number;
  image: string;
  qos_class: string;
  cpu_cores: number;
  cpu_requests: number;
  cpu_limits: number;
  cpu_pct: number;
  mem_bytes: number;
  mem_requests: number;
  mem_limits: number;
  mem_pct: number;
  throttled_pct: number;
  metrics_available: boolean;
  problems: DetectedProblem[];
  containers: ContainerInfo[];
}

interface PodsResponse {
  pods: PodInfo[];
  totals: { total: number; critical: number; warning: number; healthy: number };
  metrics_available: boolean;
}

interface PodSnapshot {
  recorded_at: string;
  cpu_cores: number;
  cpu_limits: number;
  mem_bytes: number;
  mem_limits: number;
  throttled_pct: number;
  restart_count: number;
}

const SEV_STYLES: Record<string, { dot: string; text: string; border: string; bg: string }> = {
  critical: { dot: "bg-red-500",   text: "text-red-400",   border: "border-red-500/30",   bg: "bg-red-500/10" },
  warning:  { dot: "bg-amber-500", text: "text-amber-400", border: "border-amber-500/30", bg: "bg-amber-500/10" },
  info:     { dot: "bg-sky-500",   text: "text-sky-400",   border: "border-sky-500/30",   bg: "bg-sky-500/10" },
};

const sev = (s: string) => SEV_STYLES[s] ?? SEV_STYLES.info;

function worstSeverity(problems: DetectedProblem[]): string | null {
  if (problems.some(p => p.severity === "critical")) return "critical";
  if (problems.some(p => p.severity === "warning")) return "warning";
  if (problems.some(p => p.severity === "info")) return "info";
  return null;
}

function fmtBytes(b: number): string {
  if (!b) return "—";
  if (b >= 1 << 30) return `${(b / (1 << 30)).toFixed(2)} GiB`;
  if (b >= 1 << 20) return `${Math.round(b / (1 << 20))} MiB`;
  return `${b} B`;
}

function fmtCores(c: number): string {
  if (!c) return "—";
  return c < 1 ? `${Math.round(c * 1000)}m` : c.toFixed(2);
}

/** A usage bar measured against the limit, coloured by proximity to it. */
function UsageBar({ pct, hasLimit }: { pct: number; hasLimit: boolean }) {
  const color =
    !hasLimit ? "bg-zinc-400 dark:bg-zinc-600" :
    pct >= 95 ? "bg-red-500" :
    pct >= 85 ? "bg-amber-500" :
    pct >= 60 ? "bg-brand-green" :
                "bg-brand-green/60";
  return (
    <div className="w-full h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
      <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${Math.min(pct, 100)}%` }} />
    </div>
  );
}

export default function PodsPage() {
  const [data, setData] = useState<PodsResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [sevFilter, setSevFilter] = useState<string | null>(null);
  const [nsFilter, setNsFilter] = useState("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [history, setHistory] = useState<Record<string, PodSnapshot[]>>({});
  const [autoRefresh, setAutoRefresh] = useState(true);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [detailTab, setDetailTab] = useState<"overview" | "logs">("overview");

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/monitoring/pods");
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.error ?? `Request failed (${res.status})`);
        setData(null);
        return;
      }
      setError("");
      setData(await res.json());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach the API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // The namespace detail panel links here scoped to one namespace.
  useEffect(() => {
    const ns = new URLSearchParams(window.location.search).get("namespace");
    if (ns) setNsFilter(ns);
  }, []);

  useEffect(() => {
    if (!autoRefresh) return;
    const t = setInterval(load, 30_000);
    return () => clearInterval(t);
  }, [autoRefresh, load]);

  const loadHistory = async (pod: PodInfo) => {
    const key = `${pod.namespace}/${pod.name}`;
    if (history[key]) return;
    const res = await apiFetch(
      `/monitoring/pods/history?namespace=${encodeURIComponent(pod.namespace)}&pod=${encodeURIComponent(pod.name)}`
    );
    if (!res.ok) return;
    const body = await res.json();
    setHistory(h => ({ ...h, [key]: (body.snapshots ?? []).slice().reverse() }));
  };

  const toggle = (pod: PodInfo) => {
    const key = `${pod.namespace}/${pod.name}`;
    if (expanded === key) {
      setExpanded(null);
      return;
    }
    setExpanded(key);
    setDetailTab("overview");
    loadHistory(pod);
  };

  const namespaces = useMemo(
    () => Array.from(new Set((data?.pods ?? []).map(p => p.namespace))).sort(),
    [data]
  );

  const pods = useMemo(() => {
    let list = data?.pods ?? [];
    if (nsFilter) list = list.filter(p => p.namespace === nsFilter);
    if (search) {
      const q = search.toLowerCase();
      list = list.filter(p =>
        p.name.toLowerCase().includes(q) ||
        p.workload.toLowerCase().includes(q) ||
        p.node_name.toLowerCase().includes(q)
      );
    }
    if (sevFilter === "healthy") {
      list = list.filter(p => !["critical", "warning"].includes(worstSeverity(p.problems) ?? ""));
    } else if (sevFilter) {
      list = list.filter(p => worstSeverity(p.problems) === sevFilter);
    }
    // Worst first: the page should open on the problems, not on an alphabet.
    const rank = (p: PodInfo) => {
      const w = worstSeverity(p.problems);
      return w === "critical" ? 0 : w === "warning" ? 1 : w === "info" ? 2 : 3;
    };
    return list.slice().sort((a, b) => rank(a) - rank(b) || b.mem_pct - a.mem_pct);
  }, [data, nsFilter, search, sevFilter]);

  // Problems rolled up by kind, so "12 pods with no limits" reads as one line.
  const problemsByKind = useMemo(() => {
    const map = new Map<string, { problem: DetectedProblem; pods: PodInfo[] }>();
    // Built from the same filtered list as the table, so the panel and the rows
    // below it always describe the same set of pods.
    for (const pod of pods) {
      for (const pr of pod.problems) {
        if (sevFilter && sevFilter !== "healthy" && pr.severity !== sevFilter) continue;
        const entry = map.get(pr.kind);
        if (entry) {
          entry.pods.push(pod);
          if (pr.severity === "critical") entry.problem = pr;
        } else {
          map.set(pr.kind, { problem: pr, pods: [pod] });
        }
      }
    }
    const order: Record<string, number> = { critical: 0, warning: 1, info: 2 };
    return Array.from(map.values()).sort(
      (a, b) => (order[a.problem.severity] ?? 3) - (order[b.problem.severity] ?? 3) || b.pods.length - a.pods.length
    );
  }, [pods, sevFilter]);

  useEffect(() => { setPage(1); }, [nsFilter, search, sevFilter, pageSize]);

  const totalPages = Math.max(1, Math.ceil(pods.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageRows = pods.slice((safePage - 1) * pageSize, safePage * pageSize);

  const totals = data?.totals;

  // Scoped to the selected namespace so the cards agree with the table.
  const scopedTotals = useMemo(() => {
    const base = nsFilter
      ? (data?.pods ?? []).filter(p => p.namespace === nsFilter)
      : (data?.pods ?? []);
    const t = { total: base.length, critical: 0, warning: 0, healthy: 0 };
    for (const p of base) {
      const w = worstSeverity(p.problems);
      if (w === "critical") t.critical++;
      else if (w === "warning") t.warning++;
      else t.healthy++;
    }
    return t;
  }, [data, nsFilter]);

  const cards: [string, string, number, string][] = totals
    ? [
        ["total", "Pods", scopedTotals.total, "text-zinc-600 dark:text-zinc-300"],
        ["critical", "Critical", scopedTotals.critical, "text-red-500 dark:text-red-400"],
        ["warning", "Warning", scopedTotals.warning, "text-amber-600 dark:text-amber-400"],
        ["healthy", "Healthy", scopedTotals.healthy, "text-brand-green"],
      ]
    : [];

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Pods</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
            Live resource usage from{" "}
            <code className="text-xs px-1 py-0.5 rounded bg-zinc-200 dark:bg-zinc-800">metrics.k8s.io</code>,
            read straight from the cluster
          </p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-zinc-500 dark:text-zinc-400">
            <input
              type="checkbox"
              checked={autoRefresh}
              onChange={e => setAutoRefresh(e.target.checked)}
              className="accent-brand-green"
            />
            Auto-refresh
          </label>
          <button
            onClick={load}
            className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition"
          >
            Refresh
          </button>
        </div>
      </div>

      {error && (
        <div className="glass-card p-4 border-red-500/30 text-sm">
          <p className="text-red-400 font-medium">Cannot read cluster metrics</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1">{error}</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-2 text-xs">
            CommitKube needs in-cluster credentials or <code>KUBECONFIG</code> set, plus the RBAC in{" "}
            <code>deploy/rbac.yaml</code>.
          </p>
        </div>
      )}

      {data && !data.metrics_available && (
        <div className="glass-card p-4 border-amber-500/30 text-sm">
          <p className="text-amber-400 font-medium">metrics-server is not answering</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1">
            Pod state is shown, but CPU and memory usage are unavailable. Install metrics-server to
            populate them.
          </p>
        </div>
      )}

      {cards.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {cards.map(([key, label, value, color]) => {
            const active = sevFilter === key || (key === "total" && sevFilter === null);
            return (
              <button
                key={key}
                onClick={() => setSevFilter(key === "total" || sevFilter === key ? null : key)}
                className={`glass-card p-4 text-left transition ${active ? "border-brand-green/50 ring-1 ring-brand-green/30" : ""}`}
              >
                <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
                <p className={`text-3xl font-semibold mt-1 ${color}`}>{value}</p>
              </button>
            );
          })}
        </div>
      )}

      {problemsByKind.length > 0 && (
        <div className="glass-card p-5">
          <h2 className="text-sm font-semibold uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-3">
            Open problems
          </h2>
          <div className="space-y-2">
            {problemsByKind.map(({ problem, pods: affected }) => {
              const s = sev(problem.severity);
              return (
                <div key={problem.kind} className={`flex items-start gap-3 p-3 rounded-lg border ${s.border} ${s.bg}`}>
                  <span className={`mt-1.5 w-2 h-2 rounded-full shrink-0 ${s.dot}`} />
                  <div className="min-w-0 flex-1">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`font-medium ${s.text}`}>{problem.title}</span>
                      <span className="text-xs px-1.5 py-0.5 rounded bg-black/10 dark:bg-white/10 text-zinc-600 dark:text-zinc-300">
                        {affected.length} pod{affected.length > 1 ? "s" : ""}
                      </span>
                    </div>
                    <p className="text-sm text-zinc-600 dark:text-zinc-400 mt-0.5 truncate">
                      {affected.slice(0, 4).map(p => p.name).join(", ")}
                      {affected.length > 4 && ` +${affected.length - 4} more`}
                    </p>
                  </div>
                  <button
                    onClick={() => { setSevFilter(problem.severity); setSearch(""); }}
                    className="text-xs text-zinc-500 hover:text-brand-green shrink-0"
                  >
                    Filter
                  </button>
                </div>
              );
            })}
          </div>
        </div>
      )}

      <div className="flex flex-wrap gap-3">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search pod, workload or node…"
          className="flex-1 min-w-[220px] px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]"
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
          value={pageSize}
          onChange={e => setPageSize(Number(e.target.value))}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]"
        >
          {[25, 50, 100].map(n => <option key={n} value={n}>{n} per page</option>)}
        </select>
        {(search || nsFilter || sevFilter) && (
          <button
            onClick={() => { setSearch(""); setNsFilter(""); setSevFilter(null); }}
            className="px-3 py-2 text-sm rounded-lg text-zinc-500 hover:text-brand-green transition"
          >
            Clear filters
          </button>
        )}
      </div>

      {loading && !data ? (
        <div className="glass-card p-12 text-center text-zinc-500">Loading pods…</div>
      ) : pods.length === 0 ? (
        <div className="glass-card p-12 text-center text-zinc-500">No pods match the current filters.</div>
      ) : (
        <>
        <div className="glass-card overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b border-[var(--card-border)]">
                <tr>
                  <th className="text-left font-medium px-4 py-3">Pod</th>
                  <th className="text-left font-medium px-4 py-3">Namespace</th>
                  <th className="text-left font-medium px-4 py-3 w-44">CPU</th>
                  <th className="text-left font-medium px-4 py-3 w-44">Memory</th>
                  <th className="text-right font-medium px-4 py-3">Throttle</th>
                  <th className="text-right font-medium px-4 py-3">Restarts</th>
                  <th className="text-left font-medium px-4 py-3">Node</th>
                  <th className="text-right font-medium px-4 py-3">Age</th>
                </tr>
              </thead>
              <tbody>
                {pageRows.map(pod => {
                  const key = `${pod.namespace}/${pod.name}`;
                  const worst = worstSeverity(pod.problems);
                  const s = worst ? sev(worst) : null;
                  const snaps = history[key] ?? [];

                  return (
                    <Fragment key={key}>
                      <tr
                        onClick={() => toggle(pod)}
                        className="border-b border-[var(--card-border)] hover:bg-[var(--color-surface-hover)] cursor-pointer"
                      >
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full shrink-0 ${s ? s.dot : "bg-brand-green"}`} />
                            <div className="min-w-0">
                              <p className="font-medium truncate max-w-[280px]">{pod.name}</p>
                              <p className="text-xs text-zinc-500 dark:text-zinc-400">
                                {pod.workload_kind} · {pod.workload} · {pod.phase}
                                {!pod.ready && pod.phase === "Running" && " · not ready"}
                              </p>
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3 text-zinc-500 dark:text-zinc-400">{pod.namespace}</td>
                        <td className="px-4 py-3">
                          <div className="flex items-baseline justify-between gap-2 text-xs">
                            <span>{fmtCores(pod.cpu_cores)}</span>
                            <span className="text-zinc-500">
                              {pod.cpu_limits > 0 ? `/ ${fmtCores(pod.cpu_limits)}` : "no limit"}
                            </span>
                          </div>
                          <div className="mt-1"><UsageBar pct={pod.cpu_pct} hasLimit={pod.cpu_limits > 0} /></div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-baseline justify-between gap-2 text-xs">
                            <span>{fmtBytes(pod.mem_bytes)}</span>
                            <span className="text-zinc-500">
                              {pod.mem_limits > 0 ? `/ ${fmtBytes(pod.mem_limits)}` : "no limit"}
                            </span>
                          </div>
                          <div className="mt-1"><UsageBar pct={pod.mem_pct} hasLimit={pod.mem_limits > 0} /></div>
                        </td>
                        <td className={`px-4 py-3 text-right tabular-nums ${
                          pod.throttled_pct >= 50 ? "text-red-400" :
                          pod.throttled_pct >= 25 ? "text-amber-400" : "text-zinc-500"
                        }`}>
                          {pod.throttled_pct > 0 ? `${pod.throttled_pct.toFixed(1)}%` : "—"}
                        </td>
                        <td className={`px-4 py-3 text-right tabular-nums ${pod.restart_count > 5 ? "text-amber-400" : ""}`}>
                          {pod.restart_count}
                        </td>
                        <td className="px-4 py-3 text-zinc-500 dark:text-zinc-400 truncate max-w-[160px]">
                          {pod.node_name || "—"}
                        </td>
                        <td className="px-4 py-3 text-right text-zinc-500 dark:text-zinc-400 tabular-nums">{pod.age}</td>
                      </tr>

                      {expanded === key && (
                        <tr className="border-b border-[var(--card-border)] bg-black/[0.02] dark:bg-white/[0.02]">
                          <td colSpan={8} className="px-4 py-5 space-y-4">
                            <PodActions
                              namespace={pod.namespace}
                              pod={pod.name}
                              onChanged={load}
                            />

                            <div className="flex gap-1 border-b border-[var(--card-border)]">
                              {(["overview", "logs"] as const).map(t => (
                                <button
                                  key={t}
                                  onClick={() => setDetailTab(t)}
                                  className={`px-3 py-2 text-xs font-medium capitalize border-b-2 -mb-px transition ${
                                    detailTab === t
                                      ? "border-brand-green text-brand-green"
                                      : "border-transparent text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300"
                                  }`}
                                >
                                  {t}
                                </button>
                              ))}
                            </div>

                            {detailTab === "logs" ? (
                              <PodLogs
                                namespace={pod.namespace}
                                pod={pod.name}
                                containers={pod.containers.map(c => c.name)}
                              />
                            ) : (
                            <div className="grid lg:grid-cols-2 gap-6">
                              <div className="space-y-4">
                                {pod.problems.length > 0 && (
                                  <div>
                                    <h3 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">Problems</h3>
                                    <div className="space-y-2">
                                      {pod.problems.map(pr => {
                                        const ps = sev(pr.severity);
                                        return (
                                          <div key={pr.kind} className={`p-3 rounded-lg border ${ps.border} ${ps.bg}`}>
                                            <p className={`text-sm font-medium ${ps.text}`}>{pr.title}</p>
                                            <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-1">{pr.detail}</p>
                                          </div>
                                        );
                                      })}
                                    </div>
                                  </div>
                                )}

                                <div>
                                  <h3 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
                                    Containers · QoS {pod.qos_class || "unknown"}
                                  </h3>
                                  <div className="space-y-2">
                                    {pod.containers.map(c => (
                                      <div key={c.name} className="p-3 rounded-lg border border-[var(--card-border)]">
                                        <div className="flex items-center justify-between gap-2">
                                          <span className="font-medium text-sm">{c.name}</span>
                                          <span className={`text-xs ${c.ready ? "text-brand-green" : "text-amber-400"}`}>
                                            {c.state}{c.state_reason && ` · ${c.state_reason}`}
                                          </span>
                                        </div>
                                        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 truncate">{c.image}</p>
                                        <div className="grid sm:grid-cols-2 gap-x-4 gap-y-1 mt-2 text-xs text-zinc-600 dark:text-zinc-400">
                                          <span>CPU {fmtCores(c.cpu_cores)} · req {fmtCores(c.cpu_requests)} · lim {fmtCores(c.cpu_limits)}</span>
                                          <span>Mem {fmtBytes(c.mem_bytes)} · req {fmtBytes(c.mem_requests)} · lim {fmtBytes(c.mem_limits)}</span>
                                        </div>
                                        {c.last_reason && (
                                          <p className="text-xs text-red-400 mt-1">
                                            Last exit: {c.last_reason} (code {c.last_exit_code}) · {c.restart_count} restarts
                                          </p>
                                        )}
                                      </div>
                                    ))}
                                  </div>
                                </div>
                              </div>

                              <div>
                                <h3 className="text-xs uppercase tracking-wide text-zinc-500 mb-2">
                                  History{" "}
                                  <span className="normal-case tracking-normal">(sampled by CommitKube)</span>
                                </h3>
                                {snaps.length < 2 ? (
                                  <div className="h-[260px] flex items-center justify-center text-sm text-zinc-500 border border-dashed border-[var(--card-border)] rounded-lg text-center px-6">
                                    Not enough samples yet. metrics-server keeps no history, so the series
                                    starts building from the first poll.
                                  </div>
                                ) : (
                                  <ResponsiveContainer width="100%" height={260}>
                                    <AreaChart
                                      data={snaps.map(sn => ({
                                        time: new Date(sn.recorded_at).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }),
                                        cpu: Number((sn.cpu_cores * 1000).toFixed(1)),
                                        mem: Number((sn.mem_bytes / (1 << 20)).toFixed(1)),
                                        throttle: Number(sn.throttled_pct.toFixed(1)),
                                      }))}
                                    >
                                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" />
                                      <XAxis dataKey="time" tick={{ fontSize: 11 }} stroke="currentColor" />
                                      <YAxis yAxisId="l" tick={{ fontSize: 11 }} stroke="currentColor" />
                                      <YAxis yAxisId="r" orientation="right" tick={{ fontSize: 11 }} stroke="currentColor" />
                                      <Tooltip
                                        contentStyle={{
                                          background: "var(--color-surface)",
                                          border: "1px solid var(--card-border)",
                                          borderRadius: 8,
                                          fontSize: 12,
                                        }}
                                      />
                                      <Legend wrapperStyle={{ fontSize: 11 }} />
                                      <Area yAxisId="l" type="monotone" dataKey="mem" name="Memory (MiB)" stroke="#10b981" fill="#10b981" fillOpacity={0.15} />
                                      <Area yAxisId="r" type="monotone" dataKey="cpu" name="CPU (millicores)" stroke="#fbbf24" fill="#fbbf24" fillOpacity={0.12} />
                                      <Area yAxisId="r" type="monotone" dataKey="throttle" name="Throttled (%)" stroke="#ef4444" fill="#ef4444" fillOpacity={0.1} />
                                    </AreaChart>
                                  </ResponsiveContainer>
                                )}
                              </div>
                            </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
          <p className="text-zinc-500 dark:text-zinc-400">
            Showing {(safePage - 1) * pageSize + 1}&ndash;{Math.min(safePage * pageSize, pods.length)} of {pods.length}
            {data && pods.length !== data.pods.length && ` (filtered from ${data.pods.length})`}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={() => setPage(p => Math.max(1, p - 1))}
              disabled={safePage <= 1}
              className="px-3 py-1.5 rounded-lg border border-[var(--card-border)] hover:bg-[var(--color-surface-hover)] transition disabled:opacity-40 disabled:hover:bg-transparent"
            >
              Previous
            </button>
            <span className="text-zinc-500 dark:text-zinc-400 px-2">Page {safePage} of {totalPages}</span>
            <button
              onClick={() => setPage(p => Math.min(totalPages, p + 1))}
              disabled={safePage >= totalPages}
              className="px-3 py-1.5 rounded-lg border border-[var(--card-border)] hover:bg-[var(--color-surface-hover)] transition disabled:opacity-40 disabled:hover:bg-transparent"
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
