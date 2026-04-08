"use client";

import { useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from "recharts";

interface ServiceEvent {
  id: number;
  recorded_at: string;
  app_name: string;
  namespace: string;
  event_type: string;
  old_value: string;
  new_value: string;
}

const UptimeBar = ({ history }: { history: string[] }) => (
  <div className="flex gap-[2px] w-full mt-2 h-5">
    {history.map((s, i) => (
      <div
        key={i}
        title={s || "Unknown"}
        className={`flex-1 rounded-sm ${
          s?.toLowerCase() === "healthy"     ? "bg-green-500" :
          s?.toLowerCase() === "degraded"    ? "bg-red-500" :
          s?.toLowerCase() === "progressing" ? "bg-blue-400" :
          "bg-zinc-400 dark:bg-zinc-600"
        }`}
      />
    ))}
  </div>
);

interface AppSummary {
  app_name: string;
  namespace: string;
  argocd_instance_alias: string;
  argocd_instance_id: number;
  health_status: string;
  sync_status: string;
  replicas: number;
  ready_replicas: number;
  image: string;
  last_seen: string;
  status_since: string;
  recent_events: ServiceEvent[];
  mini_history: string[];
  max_restart_count: number;
  restarting_pods: number;
}

interface DashboardData {
  namespaces: Record<string, AppSummary[]>;
  totals: { healthy: number; degraded: number; missing: number; unknown: number; total: number };
}

interface AppHistory {
  snapshots: { id: number; recorded_at: string; health_status: string; sync_status: string; replicas: number; ready_replicas: number; image: string; cpu_cores: number; memory_bytes: number }[];
  events: ServiceEvent[];
  uptime_pct: number;
  total_snapshots: number;
}

interface LogLine {
  content: string;
  timestamp: string;
  pod_name: string;
}

const healthStyle = (s: string) => {
  switch (s?.toLowerCase()) {
    case "healthy":     return "bg-green-100 text-green-700 border border-green-300 dark:bg-green-900/30 dark:text-green-400 dark:border-green-600/40";
    case "degraded":    return "bg-red-100 text-red-700 border border-red-300 dark:bg-red-900/30 dark:text-red-400 dark:border-red-600/40";
    case "progressing": return "bg-blue-100 text-blue-700 border border-blue-300 dark:bg-blue-900/30 dark:text-blue-400 dark:border-blue-600/40";
    case "missing":     return "bg-zinc-100 text-zinc-600 border border-zinc-300 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-600";
    default:            return "bg-zinc-100 text-zinc-600 border border-zinc-300 dark:bg-zinc-800 dark:text-zinc-400 dark:border-zinc-600";
  }
};

const syncStyle = (s: string) =>
  s === "Synced"
    ? "bg-green-100 text-green-700 border border-green-300 dark:bg-green-900/30 dark:text-green-400 dark:border-green-600/40"
    : "bg-yellow-100 text-yellow-700 border border-yellow-300 dark:bg-yellow-900/30 dark:text-yellow-400 dark:border-yellow-600/40";

const timeSince = (d: string) => {
  if (!d) return "-";
  const diff = Date.now() - new Date(d).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 1) return "just now";
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  return `${Math.floor(h / 24)}d ago`;
};

const durationSince = (d: string) => {
  if (!d) return "-";
  const diff = Date.now() - new Date(d).getTime();
  const m = Math.floor(diff / 60000);
  if (m < 60) return `${m} min`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
};

const eventLabel = (e: ServiceEvent) => {
  switch (e.event_type) {
    case "health_change":   return `Health: ${e.old_value} → ${e.new_value}`;
    case "sync_change":     return `Sync: ${e.old_value} → ${e.new_value}`;
    case "image_change":    return `Image: ...${e.old_value.split(":").pop()} → ...${e.new_value.split(":").pop()}`;
    case "replicas_change": return `Replicas: ${e.old_value} → ${e.new_value}`;
    case "restart_spike":   return `Restart spike: ${e.old_value} → ${e.new_value} restarts`;
    default:                return `${e.event_type}: ${e.old_value} → ${e.new_value}`;
  }
};

const eventColor = (t: string) => {
  if (t === "health_change") return "text-red-500 dark:text-red-400";
  if (t === "image_change")  return "text-blue-500 dark:text-blue-400";
  if (t === "replicas_change") return "text-purple-500 dark:text-purple-400";
  if (t === "restart_spike") return "text-orange-500 dark:text-orange-400";
  return "text-yellow-500 dark:text-yellow-400";
};

export default function MonitoringPage() {
  const [data, setData] = useState<DashboardData | null>(null);
  const [loading, setLoading] = useState(true);
  const [selectedInstance, setSelectedInstance] = useState<string | null>(null);
  const [selectedNs, setSelectedNs] = useState("all");
  const [expandedApp, setExpandedApp] = useState<string | null>(null);
  const [history, setHistory] = useState<AppHistory | null>(null);
  const [historyLoading, setHistoryLoading] = useState(false);
  const [clearing, setClearing] = useState(false);
  const [search, setSearch] = useState("");
  const [logs, setLogs] = useState<LogLine[]>([]);
  const [logsLoading, setLogsLoading] = useState(false);
  const [activeTab, setActiveTab] = useState<"history" | "logs" | "metrics">("history");
  const logsRef = useRef<HTMLDivElement>(null);
  interface MetricsPoint {
    t: string;
    cpu_cores: number;
    memory_bytes: number;
    net_rx_bytes_per_sec: number;
    net_tx_bytes_per_sec: number;
  }
  const [metrics, setMetrics] = useState<MetricsPoint | null>(null);
  const [metricsHistory, setMetricsHistory] = useState<MetricsPoint[]>([]);
  const [metricsLoading, setMetricsLoading] = useState(false);
  const [metricsError, setMetricsError] = useState("");
  const metricsIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const metricsAppRef = useRef<AppSummary | null>(null);
  const [restarting, setRestarting] = useState<string | null>(null);
  const [monPage, setMonPage] = useState(1);
  const MON_PAGE_SIZE = 10;

  useEffect(() => { fetchDashboard(); }, []);

  const fetchDashboard = async () => {
    setLoading(true);
    try {
      const res = await apiFetch("/monitoring/dashboard");
      if (res.ok) setData(await res.json());
    } catch {}
    setLoading(false);
  };

  const fetchLogs = async (app: AppSummary) => {
    setLogsLoading(true);
    setLogs([]);
    try {
      const res = await apiFetch(`/monitoring/logs?app=${encodeURIComponent(app.app_name)}&namespace=${encodeURIComponent(app.namespace)}&argocd_instance_id=${app.argocd_instance_id}&tail=200`);
      if (res.ok) {
        const d = await res.json();
        setLogs(d.logs ?? []);
        setTimeout(() => {
          if (logsRef.current) logsRef.current.scrollTop = logsRef.current.scrollHeight;
        }, 10);
      }
    } catch {}
    setLogsLoading(false);
  };

  const stopMetricsPolling = () => {
    if (metricsIntervalRef.current) {
      clearInterval(metricsIntervalRef.current);
      metricsIntervalRef.current = null;
    }
  };

  const fetchMetrics = async (app: AppSummary, showLoading = true) => {
    if (showLoading) { setMetricsLoading(true); setMetrics(null); setMetricsError(""); }
    try {
      const res = await apiFetch(`/monitoring/metrics?app=${encodeURIComponent(app.app_name)}&namespace=${encodeURIComponent(app.namespace)}&argocd_instance_id=${app.argocd_instance_id}`);
      if (res.ok) {
        const data = await res.json();
        const point: MetricsPoint = {
          ...data,
          t: new Date().toLocaleTimeString("en-US", { hour: "2-digit", minute: "2-digit", second: "2-digit" }),
        };
        setMetrics(point);
        setMetricsHistory(prev => {
          const next = [...prev, point];
          return next.length > 60 ? next.slice(next.length - 60) : next;
        });
      } else {
        const d = await res.json();
        setMetricsError(d.error || "Failed to load metrics");
        stopMetricsPolling();
      }
    } catch {
      setMetricsError("Failed to connect to metrics endpoint");
      stopMetricsPolling();
    }
    if (showLoading) setMetricsLoading(false);
  };

  const startMetricsPolling = (app: AppSummary) => {
    metricsAppRef.current = app;
    if (metricsIntervalRef.current) return;
    fetchMetrics(app, true);
    metricsIntervalRef.current = setInterval(() => {
      if (metricsAppRef.current) fetchMetrics(metricsAppRef.current, false);
    }, 15000);
  };

  const toggleApp = async (app: AppSummary) => {
    const key = `${app.namespace}/${app.app_name}`;
    if (expandedApp === key) {
      stopMetricsPolling();
      setExpandedApp(null);
      setHistory(null);
      setLogs([]);
      setMetrics(null);
      setMetricsHistory([]);
      setActiveTab("history");
      return;
    }
    stopMetricsPolling();
    setHistory(null);
    setLogs([]);
    setMetrics(null);
    setMetricsHistory([]);
    setActiveTab("history");
    setExpandedApp(key);
    setHistoryLoading(true);
    try {
      const res = await apiFetch(`/monitoring/history?app=${encodeURIComponent(app.app_name)}&namespace=${encodeURIComponent(app.namespace)}`);
      if (res.ok) {
        const json = await res.json();
        setExpandedApp(prev => prev === key ? key : prev);
        setHistory(json);
      }
    } catch {}
    setHistoryLoading(false);
  };

  const handleExport = async (format: "csv" | "json") => {
    const token = localStorage.getItem("token");
    const res = await fetch(`/api/monitoring/export?format=${format}`, {
      headers: { Authorization: `Bearer ${token}` },
    });
    const blob = await res.blob();
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `monitoring-history.${format}`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const handleClear = async () => {
    if (!confirm("Delete all monitoring history?")) return;
    setClearing(true);
    await apiFetch("/monitoring/history", { method: "DELETE" });
    setClearing(false);
    setExpandedApp(null);
    setHistory(null);
    fetchDashboard();
  };

  const allApps: AppSummary[] = data ? Object.values(data.namespaces).flat() : [];

  const instanceList = data
    ? [...new Set(allApps.map(a => a.argocd_instance_alias).filter(Boolean))]
    : [];

  const instanceFiltered = selectedInstance
    ? allApps.filter(a => a.argocd_instance_alias === selectedInstance)
    : allApps;

  const nsList = [...new Set(instanceFiltered.map(a => a.namespace))].sort();

  const nsFiltered = selectedNs === "all"
    ? instanceFiltered
    : instanceFiltered.filter(a => a.namespace === selectedNs);

  const visibleApps = search
    ? nsFiltered.filter(a => a.app_name.toLowerCase().includes(search.toLowerCase()))
    : nsFiltered;

  const totalMonPages = Math.max(1, Math.ceil(visibleApps.length / MON_PAGE_SIZE));
  const pagedApps = visibleApps.slice((monPage - 1) * MON_PAGE_SIZE, monPage * MON_PAGE_SIZE);

  const counts = visibleApps.reduce(
    (acc, a) => {
      const s = a.health_status?.toLowerCase();
      if (s === "healthy") acc.healthy++;
      else if (s === "degraded") acc.degraded++;
      else acc.unknown++;
      acc.total++;
      return acc;
    },
    { total: 0, healthy: 0, degraded: 0, unknown: 0 }
  );

  return (
    <div className="min-h-screen bg-zinc-50 dark:bg-zinc-950 px-4 py-8">
      <div className="max-w-7xl mx-auto">

        <div className="flex items-center justify-between mb-6">
          <h1 className="text-2xl font-bold text-zinc-800 dark:text-zinc-100">Availability</h1>
          <div className="flex gap-2">
            <button
              onClick={handleClear}
              disabled={clearing}
              className="px-3 py-1.5 text-sm rounded-md border border-red-300 text-red-600 hover:bg-red-50 dark:border-red-700 dark:text-red-400 dark:hover:bg-red-900/20 transition-colors"
            >
              {clearing ? "Clearing..." : "Clear History"}
            </button>
            <button
              onClick={() => handleExport("csv")}
              className="px-3 py-1.5 text-sm rounded-md border border-zinc-300 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-600 dark:text-zinc-400 dark:hover:bg-zinc-800 transition-colors"
            >
              Export CSV
            </button>
            <button
              onClick={() => handleExport("json")}
              className="px-3 py-1.5 text-sm rounded-md border border-zinc-300 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-600 dark:text-zinc-400 dark:hover:bg-zinc-800 transition-colors"
            >
              Export JSON
            </button>
          </div>
        </div>

        {data && (
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-6">
            {[
              { label: "Total", value: counts.total, cls: "text-zinc-700 dark:text-zinc-200" },
              { label: "Healthy", value: counts.healthy, cls: "text-green-600 dark:text-green-400" },
              { label: "Degraded", value: counts.degraded, cls: "text-red-600 dark:text-red-400" },
              { label: "Unknown", value: counts.unknown, cls: "text-zinc-500 dark:text-zinc-400" },
            ].map(c => (
              <div key={c.label} className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded-lg p-4 text-center">
                <div className={`text-3xl font-bold ${c.cls}`}>{c.value}</div>
                <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">{c.label}</div>
              </div>
            ))}
          </div>
        )}

        {instanceList.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap mb-3">
            <span className="text-xs text-zinc-500 dark:text-zinc-500 uppercase tracking-wide font-medium">ArgoCD:</span>
            {[null, ...instanceList].map(inst => (
              <button
                key={inst ?? "__all__"}
                onClick={() => {
                  setSelectedInstance(inst);
                  setSelectedNs("all");
                  setExpandedApp(null);
                  setHistory(null);
                  setMonPage(1);
                }}
                className={`px-3 py-1 text-sm rounded-full border transition-colors ${
                  selectedInstance === inst
                    ? "bg-emerald-600 border-emerald-600 text-white"
                    : "border-zinc-300 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-600 dark:text-zinc-400 dark:hover:bg-zinc-800"
                }`}
              >
                {inst === null ? "All" : inst}
              </button>
            ))}
          </div>
        )}

        {nsList.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap mb-5">
            <span className="text-xs text-zinc-500 dark:text-zinc-500 uppercase tracking-wide font-medium">Namespace:</span>
            {["all", ...nsList].map(ns => {
              const nsCount = ns === "all"
                ? instanceFiltered.length
                : instanceFiltered.filter(a => a.namespace === ns).length;
              return (
                <button
                  key={ns}
                  onClick={() => { setSelectedNs(ns); setExpandedApp(null); setHistory(null); setMonPage(1); }}
                  className={`px-3 py-1 text-sm rounded-full border transition-colors ${
                    selectedNs === ns
                      ? "bg-emerald-600 border-emerald-600 text-white"
                      : "border-zinc-300 text-zinc-600 hover:bg-zinc-100 dark:border-zinc-600 dark:text-zinc-400 dark:hover:bg-zinc-800"
                  }`}
                >
                  {ns === "all" ? "All" : ns} ({nsCount})
                </button>
              );
            })}
          </div>
        )}

        {data && (
          <div className="flex items-center gap-3 mb-4">
            <div className="relative flex-1 max-w-xs">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 text-sm">🔍</span>
              <input
                type="text"
                value={search}
                onChange={e => { setSearch(e.target.value); setMonPage(1); setExpandedApp(null); setHistory(null); }}
                placeholder="Search application..."
                className="w-full bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded-md text-sm pl-8 pr-4 py-1.5 text-zinc-800 dark:text-zinc-100 placeholder-zinc-400 focus:outline-none focus:ring-1 focus:ring-emerald-500"
              />
            </div>
            <span className="text-sm text-zinc-500 whitespace-nowrap">
              {visibleApps.length} apps · page {monPage} of {totalMonPages}
            </span>
          </div>
        )}

        {loading ? (
          <div className="text-center py-16 text-zinc-400">Loading...</div>
        ) : visibleApps.length === 0 ? (
          <div className="text-center py-16 text-zinc-400">
            <div className="text-lg mb-2">No monitoring data yet</div>
            <div className="text-sm">Data is collected every 5 minutes from your ArgoCD services</div>
          </div>
        ) : (
          <div className="space-y-2">
            {pagedApps.map(app => {
              const key = `${app.namespace}/${app.app_name}`;
              const isOpen = expandedApp === key;
              return (
                <div key={key} className="bg-white dark:bg-zinc-900 border border-zinc-200 dark:border-zinc-700 rounded-lg overflow-hidden">
                  <div
                    className="flex flex-wrap items-center gap-3 px-4 py-3 cursor-pointer hover:bg-zinc-50 dark:hover:bg-zinc-800/50 transition-colors"
                    onClick={() => toggleApp(app)}
                  >
                    <div className="flex-1 min-w-0">
                      <div className="font-medium text-zinc-800 dark:text-zinc-100 truncate">{app.app_name}</div>
                      <div className="text-xs text-zinc-400">{app.namespace}{app.argocd_instance_alias ? ` · ${app.argocd_instance_alias}` : ""}</div>
                    </div>

                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${healthStyle(app.health_status)}`}>
                      {app.health_status || "Unknown"}
                    </span>

                    {app.max_restart_count > 10 && (
                      <span
                        className="text-xs px-2 py-0.5 rounded-full font-medium bg-orange-100 text-orange-700 border border-orange-300 dark:bg-orange-900/30 dark:text-orange-400 dark:border-orange-600/40"
                        title={`Max pod restart count: ${app.max_restart_count}${app.restarting_pods > 0 ? ` · ${app.restarting_pods} pod(s) restarting` : ""}`}
                      >
                        ⚠ {app.max_restart_count} restarts
                      </span>
                    )}

                    <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${syncStyle(app.sync_status)}`}>
                      {app.sync_status || "Unknown"}
                    </span>

                    {app.replicas > 0 && (
                      <span className="text-xs text-zinc-500 dark:text-zinc-400 whitespace-nowrap">
                        {app.ready_replicas}/{app.replicas} replicas
                      </span>
                    )}

                    {app.image && (
                      <span className="text-xs text-zinc-400 truncate max-w-[200px]" title={app.image}>
                        {app.image.split("/").pop()}
                      </span>
                    )}

                    <div className="text-right text-xs text-zinc-400 whitespace-nowrap ml-auto">
                      <div>{timeSince(app.last_seen)}</div>
                      <div className={`${app.health_status?.toLowerCase() === "healthy" ? "text-green-500" : "text-red-400"}`}>
                        {app.health_status || "Unknown"} for {durationSince(app.status_since)}
                      </div>
                    </div>

                    <span className="text-zinc-400 text-sm">{isOpen ? "▲" : "▼"}</span>
                  </div>

                  {app.mini_history?.length > 0 && (
                    <div className="px-4 pb-2 border-t border-zinc-100 dark:border-zinc-800">
                      <UptimeBar history={app.mini_history} />
                      <div className="flex justify-between text-[10px] text-zinc-400 mt-1">
                        <span>{app.mini_history.length} snapshots ago</span>
                        <span>now</span>
                      </div>
                    </div>
                  )}

                  {isOpen && (
                    <div className="border-t border-zinc-100 dark:border-zinc-800 px-4 py-4">
                      <div className="flex items-center justify-between gap-2 mb-4 flex-wrap">
                        <div className="flex gap-1">
                          {(["history", "logs", "metrics"] as const).map(tab => (
                            <button
                              key={tab}
                              onClick={() => {
                                setActiveTab(tab);
                                if (tab === "logs" && logs.length === 0 && !logsLoading) fetchLogs(app);
                                if (tab === "metrics" && metrics === null && !metricsLoading) startMetricsPolling(app);
                                if (tab !== "metrics") stopMetricsPolling();
                              }}
                              className={`px-4 py-1.5 text-sm rounded-md border transition-colors ${
                                activeTab === tab
                                  ? "bg-emerald-600 border-emerald-600 text-white"
                                  : "border-zinc-300 dark:border-zinc-600 text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                              }`}
                            >
                              {tab === "history" ? "History" : tab === "logs" ? "Logs" : "Metrics"}
                            </button>
                          ))}
                        </div>
                        <button
                          disabled={restarting === key}
                          onClick={async () => {
                            if (!confirm(`Restart all pods of "${app.app_name}"?`)) return;
                            setRestarting(key);
                            try {
                              await apiFetch(
                                `/monitoring/restart?app=${encodeURIComponent(app.app_name)}&namespace=${encodeURIComponent(app.namespace)}&argocd_instance_id=${app.argocd_instance_id}`,
                                { method: "POST" }
                              );
                            } catch {}
                            setRestarting(null);
                          }}
                          className="px-3 py-1.5 text-xs rounded-md border border-orange-400 text-orange-500 hover:bg-orange-50 dark:hover:bg-orange-900/20 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
                        >
                          {restarting === key ? "Restarting..." : "↺ Restart"}
                        </button>
                      </div>

                      {activeTab === "logs" && (
                        <div>
                          <div className="flex items-center gap-3 mb-2">
                            <button
                              onClick={() => fetchLogs(app)}
                              disabled={logsLoading}
                              className="text-xs text-emerald-500 hover:text-emerald-400 disabled:opacity-40 transition-colors"
                            >
                              ↻ Refresh
                            </button>
                          </div>
                          {logsLoading ? (
                            <div className="text-sm text-zinc-400 py-4 text-center">Loading logs...</div>
                          ) : logs.length === 0 ? (
                            <div className="text-sm text-zinc-400 py-4 text-center">No logs found.</div>
                          ) : (
                            <div ref={logsRef} className="bg-zinc-950 rounded-lg p-3 h-96 overflow-y-auto font-mono text-xs space-y-0.5">
                              {logs.map((line, i) => (
                                <div key={i} className="flex gap-2">
                                  {line.pod_name && (
                                    <span className="text-blue-400 shrink-0 truncate max-w-[180px]" title={line.pod_name}>
                                      [{line.pod_name.split("-").slice(-2).join("-")}]
                                    </span>
                                  )}
                                  <span className="text-zinc-300 break-all">{line.content}</span>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      )}

                      {activeTab === "history" && historyLoading ? (
                        <div className="text-sm text-zinc-400 py-4 text-center">Loading history...</div>
                      ) : activeTab === "history" && history ? (
                        <div className="space-y-5">
                          <div className="flex gap-4 text-sm flex-wrap">
                            {[
                              { label: "Uptime", value: `${history.uptime_pct.toFixed(1)}%`, cls: "text-emerald-600 dark:text-emerald-400" },
                              { label: "Events", value: String(history.events.length), cls: "text-zinc-700 dark:text-zinc-200" },
                              { label: "Snapshots", value: String(history.total_snapshots), cls: "text-zinc-700 dark:text-zinc-200" },
                            ].map(c => (
                              <div key={c.label} className="bg-zinc-50 dark:bg-zinc-800 rounded-md px-4 py-2 text-center">
                                <div className={`text-lg font-bold ${c.cls}`}>{c.value}</div>
                                <div className="text-xs text-zinc-400">{c.label}</div>
                              </div>
                            ))}
                            {app.max_restart_count > 0 && (
                              <div className={`rounded-md px-4 py-2 text-center ${app.max_restart_count > 10 ? "bg-orange-50 dark:bg-orange-900/20" : "bg-zinc-50 dark:bg-zinc-800"}`}>
                                <div className={`text-lg font-bold ${app.max_restart_count > 10 ? "text-orange-600 dark:text-orange-400" : "text-zinc-700 dark:text-zinc-200"}`}>
                                  {app.max_restart_count}
                                </div>
                                <div className="text-xs text-zinc-400">Max Restarts</div>
                              </div>
                            )}
                            {app.restarting_pods > 0 && (
                              <div className="bg-orange-50 dark:bg-orange-900/20 rounded-md px-4 py-2 text-center">
                                <div className="text-lg font-bold text-orange-600 dark:text-orange-400">{app.restarting_pods}</div>
                                <div className="text-xs text-zinc-400">Restarting Pods</div>
                              </div>
                            )}
                          </div>

                          {history.snapshots.some((s: AppHistory["snapshots"][0]) => s.replicas > 0) && (
                            <div>
                              <div className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide mb-3">Replicas Over Time</div>
                              <ResponsiveContainer width="100%" height={200}>
                                <LineChart
                                  data={[...history.snapshots].reverse().map((s: AppHistory["snapshots"][0]) => ({
                                    t: new Date(s.recorded_at).toLocaleString("en-US", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }),
                                    Desired: s.replicas,
                                    Ready: s.ready_replicas,
                                  }))}
                                  margin={{ top: 4, right: 8, left: -20, bottom: 0 }}
                                >
                                  <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                                  <XAxis dataKey="t" tick={{ fontSize: 10, fill: "#9ca3af" }} interval="preserveStartEnd" />
                                  <YAxis tick={{ fontSize: 10, fill: "#9ca3af" }} allowDecimals={false} />
                                  <Tooltip
                                    contentStyle={{ background: "#1f2937", border: "1px solid #374151", borderRadius: 6, fontSize: 12 }}
                                    labelStyle={{ color: "#e5e7eb" }}
                                  />
                                  <Legend wrapperStyle={{ fontSize: 12 }} />
                                  <Line type="monotone" dataKey="Desired" stroke="#10b981" dot={false} strokeWidth={2} />
                                  <Line type="monotone" dataKey="Ready" stroke="#3b82f6" dot={false} strokeWidth={2} />
                                </LineChart>
                              </ResponsiveContainer>
                            </div>
                          )}

                          {history.events.length > 0 ? (
                            <div>
                              <div className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide mb-2">Change History</div>
                              <div className="space-y-1 max-h-56 overflow-y-auto">
                                {history.events.map((e: ServiceEvent) => (
                                  <div key={e.id} className="flex items-center gap-3 text-sm py-1 border-b border-zinc-100 dark:border-zinc-800">
                                    <span className="text-xs text-zinc-400 whitespace-nowrap">
                                      {new Date(e.recorded_at).toLocaleString("en-US", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" })}
                                    </span>
                                    <span className={`font-medium ${eventColor(e.event_type)}`}>{eventLabel(e)}</span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          ) : (
                            <div className="text-sm text-zinc-400">No changes recorded yet</div>
                          )}
                        </div>
                      ) : activeTab === "history" ? null : null}

                      {activeTab === "metrics" && (
                        <div>
                          {metricsLoading ? (
                            <div className="text-sm text-zinc-400 py-4 text-center">Fetching metrics...</div>
                          ) : metricsError ? (
                            <div className="text-sm text-red-400 py-4 text-center">{metricsError}</div>
                          ) : metrics ? (
                            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                              {[
                                {
                                  label: "CPU",
                                  value: metrics.cpu_cores < 1
                                    ? `${(metrics.cpu_cores * 1000).toFixed(1)}m`
                                    : `${metrics.cpu_cores.toFixed(2)}`,
                                  unit: metrics.cpu_cores < 1 ? "millicores" : "cores",
                                  cls: "text-blue-500 dark:text-blue-400",
                                },
                                {
                                  label: "Memory",
                                  value: metrics.memory_bytes >= 1073741824
                                    ? `${(metrics.memory_bytes / 1073741824).toFixed(1)}`
                                    : `${(metrics.memory_bytes / 1048576).toFixed(0)}`,
                                  unit: metrics.memory_bytes >= 1073741824 ? "GiB" : "MiB",
                                  cls: "text-purple-500 dark:text-purple-400",
                                },
                                {
                                  label: "Net In",
                                  value: metrics.net_rx_bytes_per_sec >= 1048576
                                    ? `${(metrics.net_rx_bytes_per_sec / 1048576).toFixed(1)}`
                                    : `${(metrics.net_rx_bytes_per_sec / 1024).toFixed(1)}`,
                                  unit: metrics.net_rx_bytes_per_sec >= 1048576 ? "MB/s" : "KB/s",
                                  cls: "text-emerald-500 dark:text-emerald-400",
                                },
                                {
                                  label: "Net Out",
                                  value: metrics.net_tx_bytes_per_sec >= 1048576
                                    ? `${(metrics.net_tx_bytes_per_sec / 1048576).toFixed(1)}`
                                    : `${(metrics.net_tx_bytes_per_sec / 1024).toFixed(1)}`,
                                  unit: metrics.net_tx_bytes_per_sec >= 1048576 ? "MB/s" : "KB/s",
                                  cls: "text-orange-500 dark:text-orange-400",
                                },
                              ].map(m => (
                                <div key={m.label} className="bg-zinc-50 dark:bg-zinc-800 rounded-lg p-4 text-center">
                                  <div className={`text-2xl font-bold ${m.cls}`}>{m.value}</div>
                                  <div className="text-xs text-zinc-500 mt-0.5">{m.unit}</div>
                                  <div className="text-xs text-zinc-400 mt-1">{m.label}</div>
                                </div>
                              ))}
                            </div>
                          ) : null}
                          {(() => {
                            const histPoints = history?.snapshots
                              .filter(s => s.cpu_cores > 0 || s.memory_bytes > 0)
                              .map(s => ({
                                t: new Date(s.recorded_at).toLocaleString("en-US", { day: "2-digit", month: "2-digit", hour: "2-digit", minute: "2-digit" }),
                                cpu_cores: s.cpu_cores,
                                memory_bytes: s.memory_bytes,
                              }))
                              .reverse() ?? [];
                            const chartData = histPoints.length > 0 ? histPoints : metricsHistory;
                            if (chartData.length === 0) return null;
                            return (
                              <div className="mt-4 space-y-4">
                                <div>
                                  <div className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide mb-2">CPU Over Time (millicores)</div>
                                  <ResponsiveContainer width="100%" height={160}>
                                    <LineChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                                      <XAxis dataKey="t" tick={{ fontSize: 10, fill: "#9ca3af" }} interval="preserveStartEnd" />
                                      <YAxis tick={{ fontSize: 10, fill: "#9ca3af" }} tickFormatter={v => `${(v * 1000).toFixed(0)}m`} />
                                      <Tooltip
                                        contentStyle={{ background: "#1f2937", border: "1px solid #374151", borderRadius: 6, fontSize: 12 }}
                                        formatter={(v: any) => [`${((Number(v) || 0) * 1000).toFixed(1)}m`, "CPU"]}
                                      />
                                      <Line type="monotone" dataKey="cpu_cores" stroke="#3b82f6" dot={false} strokeWidth={2} name="CPU" />
                                    </LineChart>
                                  </ResponsiveContainer>
                                </div>
                                <div>
                                  <div className="text-xs font-semibold text-zinc-500 dark:text-zinc-400 uppercase tracking-wide mb-2">Memory Over Time (MiB)</div>
                                  <ResponsiveContainer width="100%" height={160}>
                                    <LineChart data={chartData} margin={{ top: 4, right: 8, left: -20, bottom: 0 }}>
                                      <CartesianGrid strokeDasharray="3 3" stroke="#374151" />
                                      <XAxis dataKey="t" tick={{ fontSize: 10, fill: "#9ca3af" }} interval="preserveStartEnd" />
                                      <YAxis tick={{ fontSize: 10, fill: "#9ca3af" }} tickFormatter={v => `${(v / 1048576).toFixed(0)}`} />
                                      <Tooltip
                                        contentStyle={{ background: "#1f2937", border: "1px solid #374151", borderRadius: 6, fontSize: 12 }}
                                        formatter={(v: any) => [`${((Number(v) || 0) / 1048576).toFixed(0)} MiB`, "Memory"]}
                                      />
                                      <Line type="monotone" dataKey="memory_bytes" stroke="#a855f7" dot={false} strokeWidth={2} name="Memory" />
                                    </LineChart>
                                  </ResponsiveContainer>
                                </div>
                              </div>
                            );
                          })()}
                          <div className="flex items-center gap-3 mt-2">
                            <span className="text-xs flex items-center gap-1 text-emerald-400">
                              <span className="inline-block w-1.5 h-1.5 rounded-full bg-emerald-400 animate-pulse" />
                              Auto-refresh every 15s
                            </span>
                            <button
                              onClick={() => startMetricsPolling(app)}
                              className="text-xs text-emerald-500 hover:text-emerald-400 transition-colors"
                            >
                              ↻ Refresh now
                            </button>
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              );
            })}

            {totalMonPages > 1 && (
              <div className="flex justify-center gap-2 mt-4">
                <button
                  onClick={() => { setMonPage(p => Math.max(1, p - 1)); setExpandedApp(null); setHistory(null); }}
                  disabled={monPage === 1}
                  className="px-4 py-2 text-sm rounded-md border border-zinc-300 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
                >
                  ← Previous
                </button>
                {Array.from({ length: totalMonPages }, (_, i) => i + 1)
                  .filter(p => p === 1 || p === totalMonPages || Math.abs(p - monPage) <= 2)
                  .reduce<(number | "...")[]>((acc, p, i, arr) => {
                    if (i > 0 && p - (arr[i - 1] as number) > 1) acc.push("...");
                    acc.push(p);
                    return acc;
                  }, [])
                  .map((p, i) =>
                    p === "..." ? (
                      <span key={`ellipsis-${i}`} className="px-2 py-2 text-sm text-zinc-500">…</span>
                    ) : (
                      <button
                        key={p}
                        onClick={() => { setMonPage(p as number); setExpandedApp(null); setHistory(null); }}
                        className={`px-3 py-2 text-sm rounded-md border transition ${
                          p === monPage
                            ? "border-emerald-600 text-emerald-600 bg-emerald-600/10"
                            : "border-zinc-300 dark:border-zinc-700 text-zinc-500 dark:text-zinc-400 hover:bg-zinc-100 dark:hover:bg-zinc-800"
                        }`}
                      >
                        {p}
                      </button>
                    )
                  )}
                <button
                  onClick={() => { setMonPage(p => Math.min(totalMonPages, p + 1)); setExpandedApp(null); setHistory(null); }}
                  disabled={monPage === totalMonPages}
                  className="px-4 py-2 text-sm rounded-md border border-zinc-300 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800 disabled:opacity-40 disabled:cursor-not-allowed transition"
                >
                  Next →
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
