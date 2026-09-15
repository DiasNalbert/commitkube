"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface NodePodUsage {
  name: string;
  namespace: string;
  workload: string;
  phase: string;
  restart_count: number;
  cpu_cores: number;
  cpu_limits: number;
  cpu_node_pct: number;
  mem_bytes: number;
  mem_limits: number;
  mem_node_pct: number;
  problem_count: number;
  worst_problem: string;
}

interface NodePods {
  pod_count: number;
  metrics_available: boolean;
  top_cpu: NodePodUsage[];
  top_memory: NodePodUsage[];
  pods_cpu_cores: number;
  pods_mem_bytes: number;
  node_cpu_cores: number;
  node_mem_bytes: number;
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

interface NodeCondition {
  type: string;
  status: string;
  message: string;
}

interface NodeInfo {
  name: string;
  status: string;
  roles: string[];
  age: string;
  version: string;
  os: string;
  arch: string;
  cpu_cap_cores: number;
  cpu_usage_cores: number;
  cpu_pct: number;
  mem_cap_gb: number;
  mem_usage_gb: number;
  mem_pct: number;
  disk_cap_gb: number;
  metrics_available: boolean;
  conditions: NodeCondition[];
}

/** Ranked list of the pods consuming most of one resource on a node. */
function TopPods({ pods, metric }: { pods: NodePodUsage[]; metric: "cpu" | "memory" }) {
  if (pods.length === 0) {
    return <p className="text-sm text-zinc-500">No pods with metrics on this node.</p>;
  }
  const max = Math.max(...pods.map(p => (metric === "cpu" ? p.cpu_cores : p.mem_bytes)), 0.0001);

  return (
    <div className="space-y-1.5">
      {pods.map((p, i) => {
        const value = metric === "cpu" ? p.cpu_cores : p.mem_bytes;
        const nodePct = metric === "cpu" ? p.cpu_node_pct : p.mem_node_pct;
        const limit = metric === "cpu" ? p.cpu_limits : p.mem_limits;
        const text = metric === "cpu" ? fmtCores(p.cpu_cores) : fmtBytes(p.mem_bytes);
        const limitText = metric === "cpu" ? fmtCores(p.cpu_limits) : fmtBytes(p.mem_limits);

        return (
          <div key={`${p.namespace}/${p.name}`} className="flex items-center gap-3 text-xs">
            <span className="w-5 text-right text-zinc-500 tabular-nums shrink-0">{i + 1}</span>
            <div className="min-w-0 flex-1">
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-mono truncate">
                  {p.name}
                  {p.worst_problem && (
                    <span
                      title={p.worst_problem}
                      className="ml-2 text-[10px] px-1 py-0.5 rounded border border-amber-500/40 text-amber-600 dark:text-amber-400"
                    >
                      {p.worst_problem}
                    </span>
                  )}
                </span>
                <span className="tabular-nums shrink-0">
                  {text}
                  <span className="text-zinc-500"> · {nodePct.toFixed(1)}% do node</span>
                </span>
              </div>
              <div className="w-full h-1 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden mt-1">
                <div
                  className="h-full rounded-full bg-brand-green"
                  style={{ width: `${(value / max) * 100}%` }}
                />
              </div>
              <p className="text-[10px] text-zinc-500 dark:text-zinc-400 mt-0.5">
                {p.namespace} · {p.workload}
                {limit > 0 ? ` · limit ${limitText}` : " · sem limit"}
                {p.restart_count > 0 && ` · ${p.restart_count} restarts`}
              </p>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function UsageBar({ pct }: { pct: number }) {
  const color =
    pct >= 90 ? "bg-red-500" :
    pct >= 75 ? "bg-amber-500" :
                "bg-brand-green";
  return (
    <div className="w-full h-1.5 rounded-full bg-zinc-200 dark:bg-zinc-800 overflow-hidden">
      <div className={`h-full rounded-full transition-all ${color}`} style={{ width: `${Math.min(pct, 100)}%` }} />
    </div>
  );
}

export default function NodesPage() {
  const [nodes, setNodes] = useState<NodeInfo[]>([]);
  const [metricsAvail, setMetricsAvail] = useState(true);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [nodePods, setNodePods] = useState<Record<string, NodePods>>({});
  const [metric, setMetric] = useState<"cpu" | "memory">("cpu");

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/monitoring/nodes");
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.error ?? `Request failed (${res.status})`);
        setNodes([]);
        return;
      }
      setError("");
      setNodes(body.nodes ?? []);
      setMetricsAvail(body.metrics_available ?? false);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach the API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const toggle = async (name: string) => {
    if (expanded === name) { setExpanded(null); return; }
    setExpanded(name);
    if (nodePods[name]) return;
    const res = await apiFetch(`/monitoring/nodes/pods?node=${encodeURIComponent(name)}&limit=10`);
    if (!res.ok) return;
    const body: NodePods = await res.json();
    setNodePods(m => ({ ...m, [name]: body }));
  };

  const ready = nodes.filter(n => n.status === "Ready").length;

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Nodes</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
            Capacity and live usage per node, from{" "}
            <code className="text-xs px-1 py-0.5 rounded bg-zinc-200 dark:bg-zinc-800">metrics.k8s.io</code>
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
          <p className="text-red-500 dark:text-red-400 font-medium">Cannot read nodes</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1 break-words">{error}</p>
        </div>
      )}

      {!loading && nodes.length > 0 && !metricsAvail && (
        <div className="glass-card p-4 border-amber-500/30 text-sm">
          <p className="text-amber-600 dark:text-amber-400 font-medium">metrics-server is not answering</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1">
            Node capacity and conditions are shown, but live CPU and memory usage are unavailable.
          </p>
        </div>
      )}

      {nodes.length > 0 && (
        <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
          <div className="glass-card p-4">
            <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Nodes</p>
            <p className="text-3xl font-semibold mt-1 text-zinc-600 dark:text-zinc-300">{nodes.length}</p>
          </div>
          <div className="glass-card p-4">
            <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Ready</p>
            <p className="text-3xl font-semibold mt-1 text-brand-green">{ready}</p>
          </div>
          <div className="glass-card p-4">
            <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Not ready</p>
            <p className={`text-3xl font-semibold mt-1 ${nodes.length - ready > 0 ? "text-red-500 dark:text-red-400" : "text-zinc-600 dark:text-zinc-300"}`}>
              {nodes.length - ready}
            </p>
          </div>
        </div>
      )}

      {loading ? (
        <div className="glass-card p-12 text-center text-zinc-500">Loading nodes…</div>
      ) : nodes.length === 0 && !error ? (
        <div className="glass-card p-12 text-center text-zinc-500">No nodes returned by the cluster.</div>
      ) : (
        <div className="space-y-3">
          {nodes.map(n => (
            <div key={n.name} className="glass-card p-4">
              <div
                onClick={() => toggle(n.name)}
                className="flex flex-wrap items-center gap-3 cursor-pointer"
              >
                <span className={`w-2 h-2 rounded-full shrink-0 ${n.status === "Ready" ? "bg-brand-green" : "bg-red-500"}`} />
                <div className="min-w-0 flex-1">
                  <p className="font-medium font-mono truncate">{n.name}</p>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">
                    {n.roles.join(", ")} · {n.version} · {n.os}/{n.arch} · up {n.age}
                  </p>
                </div>
                <span className={`text-xs px-2 py-0.5 rounded border ${
                  n.status === "Ready"
                    ? "text-brand-green border-brand-green/30"
                    : "text-red-500 dark:text-red-400 border-red-500/30"
                }`}>
                  {n.status}
                </span>
              </div>

              <div className="grid sm:grid-cols-3 gap-4 mt-4">
                <div>
                  <div className="flex items-baseline justify-between text-xs mb-1">
                    <span className="text-zinc-500 dark:text-zinc-400">CPU</span>
                    <span className="tabular-nums">
                      {n.cpu_usage_cores.toFixed(2)} / {n.cpu_cap_cores.toFixed(0)} cores
                      {n.metrics_available && ` (${n.cpu_pct.toFixed(0)}%)`}
                    </span>
                  </div>
                  <UsageBar pct={n.cpu_pct} />
                </div>
                <div>
                  <div className="flex items-baseline justify-between text-xs mb-1">
                    <span className="text-zinc-500 dark:text-zinc-400">Memory</span>
                    <span className="tabular-nums">
                      {n.mem_usage_gb.toFixed(1)} / {n.mem_cap_gb.toFixed(1)} GB
                      {n.metrics_available && ` (${n.mem_pct.toFixed(0)}%)`}
                    </span>
                  </div>
                  <UsageBar pct={n.mem_pct} />
                </div>
                <div>
                  <div className="flex items-baseline justify-between text-xs mb-1">
                    <span className="text-zinc-500 dark:text-zinc-400">Ephemeral storage</span>
                    <span className="tabular-nums">{n.disk_cap_gb.toFixed(0)} GB capacity</span>
                  </div>
                  <UsageBar pct={0} />
                </div>
              </div>

              {n.conditions.filter(c => c.type !== "Ready").length > 0 && (
                <div className="flex flex-wrap gap-2 mt-3">
                  {n.conditions.filter(c => c.type !== "Ready").map(c => (
                    <span
                      key={c.type}
                      title={c.message}
                      className="text-xs px-2 py-0.5 rounded border border-amber-500/30 text-amber-600 dark:text-amber-400"
                    >
                      {c.type}
                    </span>
                  ))}
                </div>
              )}

              {expanded === n.name && (
                <div className="mt-4 pt-4 border-t border-[var(--card-border)]">
                  {!nodePods[n.name] ? (
                    <p className="text-sm text-zinc-500">Carregando pods do node…</p>
                  ) : (
                    <>
                      <div className="flex flex-wrap items-center gap-3 mb-3">
                        <div className="flex gap-1">
                          {(["cpu", "memory"] as const).map(m => (
                            <button
                              key={m}
                              onClick={() => setMetric(m)}
                              className={`px-3 py-1.5 text-xs font-medium rounded-lg transition ${
                                metric === m
                                  ? "bg-brand-green/15 text-brand-green"
                                  : "text-zinc-500 hover:text-zinc-700 dark:hover:text-zinc-300"
                              }`}
                            >
                              Top {m === "cpu" ? "CPU" : "memory"}
                            </button>
                          ))}
                        </div>
                        <p className="text-xs text-zinc-500 dark:text-zinc-400 ml-auto">
                          {nodePods[n.name].pod_count} pods · somam{" "}
                          {fmtCores(nodePods[n.name].pods_cpu_cores)} CPU e{" "}
                          {fmtBytes(nodePods[n.name].pods_mem_bytes)}
                        </p>
                      </div>

                      <TopPods
                        pods={metric === "cpu" ? nodePods[n.name].top_cpu : nodePods[n.name].top_memory}
                        metric={metric}
                      />

                      <p className="text-[10px] text-zinc-500 dark:text-zinc-400 mt-3">
                        A soma dos pods fica abaixo do total do node: kubelet, runtime de container e
                        system daemons are not pods and do not show up here.
                      </p>
                    </>
                  )}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
