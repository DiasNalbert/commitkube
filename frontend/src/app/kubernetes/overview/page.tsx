"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { statusStyle } from "@/app/components/k8s/status";
import { fmtBytes, fmtCores, loadStatus } from "@/app/components/k8s/format";

interface ClusterAxis {
  capacity: number; allocatable: number; requests: number; limits: number; usage: number;
}
interface CountedValue { value: string; count: number }
interface NodeSummary {
  name: string; status: string; status_text: string; roles: string; version: string; age: string;
  cpu_usage_cores: number; cpu_cap_cores: number; cpu_pct: number;
  mem_usage_bytes: number; mem_cap_bytes: number; mem_pct: number;
  pods: number; pod_capacity: number; schedulable: boolean;
}
interface NamespaceUsage {
  name: string; cpu_cores: number; cpu_requests: number; mem_bytes: number; mem_requests: number; pods: number;
}
interface PodUsage { name: string; namespace: string; cpu_cores: number; mem_bytes: number; node: string }
interface ProblemSummary { kind: string; title: string; severity: string; count: number }
interface ProblemPod { name: string; namespace: string; title: string; detail: string; severity: string }
interface WorkloadHealth { kind: string; total: number; degraded: number }

interface Overview {
  kubernetes_version: string;
  versions: CountedValue[] | null;
  os_images: CountedValue[] | null;
  oldest_node_age: string;
  nodes_total: number; nodes_ready: number; nodes_not_ready: number;
  nodes_cordoned: number; nodes_under_pressure: number;
  cpu: ClusterAxis; memory: ClusterAxis;
  pods_running: number; pod_capacity: number;
  pods_by_phase: Record<string, number>;
  pods_total: number; pods_ready: number; pods_restarts: number;
  containers: number; namespace_count: number;
  workloads: WorkloadHealth[] | null;
  inventory: Record<string, number>;
  problems: ProblemSummary[] | null;
  problem_pods: ProblemPod[] | null;
  critical_count: number; warning_count: number;
  top_namespaces: NamespaceUsage[] | null;
  top_pods_cpu: PodUsage[] | null;
  top_pods_mem: PodUsage[] | null;
  nodes: NodeSummary[] | null;
  metrics_available: boolean;
  degraded?: string[];
}

function Card({ title, subtitle, children, className = "" }: {
  title?: string; subtitle?: string; children: React.ReactNode; className?: string;
}) {
  return (
    <section className={`glass-card p-4 ${className}`}>
      {title && (
        <div className="mb-3">
          <h2 className="text-sm font-semibold">{title}</h2>
          {subtitle && <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">{subtitle}</p>}
        </div>
      )}
      {children}
    </section>
  );
}

/** A headline number with its own label. No plot, so no legend and no hover. */
function Tile({ label, value, note, tone = "" }: {
  label: string; value: React.ReactNode; note?: React.ReactNode; tone?: string;
}) {
  return (
    <div className="glass-card p-4">
      <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
      <p className={`text-3xl font-semibold mt-1 ${tone}`}>{value}</p>
      {note && <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">{note}</p>}
    </div>
  );
}

/** One measure against the capacity that bounds it. The fill is live usage,
 *  coloured by how close it is to the ceiling and always stated in text too;
 *  requests and limits are marks on the same axis, direct-labelled, so the
 *  chart never depends on telling two hues apart. */
function CapacityMeter({ title, axis, format, metrics }: {
  title: string; axis: ClusterAxis; format: (n: number) => string; metrics: boolean;
}) {
  const scale = Math.max(axis.capacity, axis.limits, axis.usage, axis.requests) || 1;
  const usagePct = axis.allocatable > 0 ? (axis.usage / axis.allocatable) * 100 : 0;
  const reqPct = axis.allocatable > 0 ? (axis.requests / axis.allocatable) * 100 : 0;
  const s = statusStyle(metrics ? loadStatus(usagePct) : "unknown");
  const reqS = statusStyle(loadStatus(reqPct));
  const at = (v: number) => `${Math.min(100, (v / scale) * 100)}%`;

  return (
    <div>
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <h3 className="text-sm font-semibold">{title}</h3>
        <p className="text-xs text-zinc-500 dark:text-zinc-400">
          alocável <span className="font-mono text-zinc-700 dark:text-zinc-200">{format(axis.allocatable)}</span>
          {" de "}
          <span className="font-mono text-zinc-700 dark:text-zinc-200">{format(axis.capacity)}</span>
        </p>
      </div>

      <p className="mt-2 text-3xl font-semibold tabular-nums">
        {metrics ? `${usagePct.toFixed(0)}%` : "—"}
        <span className="text-sm font-normal text-zinc-500 dark:text-zinc-400 ml-2">
          {metrics ? `${format(axis.usage)} em uso` : "metrics-server indisponível"}
        </span>
      </p>

      <div className="relative mt-3 h-4 rounded-full bg-[var(--color-surface-hover)] overflow-hidden">
        {metrics && (
          <div className={`h-full rounded-full ${s.dot}`} style={{ width: at(axis.usage) }} title={`Uso ${format(axis.usage)}`} />
        )}
        {axis.allocatable > 0 && (
          <span className="absolute inset-y-0 w-px bg-zinc-400 dark:bg-zinc-500" style={{ left: at(axis.allocatable) }} />
        )}
        {axis.requests > 0 && (
          <span className="absolute inset-y-0 w-0.5 bg-zinc-600 dark:bg-zinc-200" style={{ left: at(axis.requests) }} title={`Requests ${format(axis.requests)}`} />
        )}
        {axis.limits > 0 && (
          <span className="absolute inset-y-0 w-0.5 bg-zinc-400 dark:bg-zinc-400" style={{ left: at(axis.limits) }} title={`Limits ${format(axis.limits)}`} />
        )}
      </div>

      <dl className="grid grid-cols-3 gap-3 mt-3 text-xs">
        <div>
          <dt className="text-zinc-500 dark:text-zinc-400">Uso</dt>
          <dd className="font-mono mt-0.5">{metrics ? format(axis.usage) : "—"}</dd>
        </div>
        <div>
          <dt className="text-zinc-500 dark:text-zinc-400">Requests (comprometido)</dt>
          <dd className="font-mono mt-0.5">
            {format(axis.requests)}
            <span className={`ml-1 ${reqS.text}`}>{reqPct.toFixed(0)}%</span>
          </dd>
        </div>
        <div>
          <dt className="text-zinc-500 dark:text-zinc-400">Limits (estouro possível)</dt>
          <dd className="font-mono mt-0.5">{format(axis.limits)}</dd>
        </div>
      </dl>
    </div>
  );
}

/** Magnitude inside a table row: one hue, length is the only encoding. */
function RowBar({ value, max }: { value: number; max: number }) {
  return (
    <div className="h-1.5 w-full min-w-[60px] rounded-full bg-[var(--color-surface-hover)] overflow-hidden">
      <div className="h-full rounded-full bg-brand-green" style={{ width: `${max > 0 ? Math.min(100, (value / max) * 100) : 0}%` }} />
    </div>
  );
}

function Table({ head, children }: { head: string[]; children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-sm">
        <thead className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b border-[var(--card-border)]">
          <tr>{head.map(h => <th key={h} className="font-medium px-2 py-2 text-left">{h}</th>)}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

const INVENTORY_LABELS: Record<string, [string, string]> = {
  namespaces: ["Namespaces", "/kubernetes/namespaces"],
  nodes: ["Nodes", "/kubernetes/nodes"],
  pods: ["Pods", "/kubernetes/pods"],
  deployments: ["Deployments", "/kubernetes/deployments"],
  statefulsets: ["StatefulSets", "/kubernetes/statefulsets"],
  daemonsets: ["DaemonSets", "/kubernetes/daemonsets"],
  replicasets: ["ReplicaSets", "/kubernetes/replicasets"],
  services: ["Services", "/kubernetes/services"],
  ingresses: ["Ingresses", "/kubernetes/ingresses"],
  persistentvolumeclaims: ["Volume Claims", "/kubernetes/pvcs"],
  cronjobs: ["CronJobs", ""],
  jobs: ["Jobs", ""],
};

const PHASE_TONE: Record<string, string> = {
  Running: "text-brand-green",
  Pending: "text-amber-600 dark:text-amber-400",
  Failed: "text-red-500 dark:text-red-400",
  Succeeded: "text-zinc-500 dark:text-zinc-400",
};

export default function Page() {
  const [data, setData] = useState<Overview | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/kubernetes/cluster-overview");
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
      setError("");
      setData(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Falha ao falar com a API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <div className="p-6 text-zinc-500">Lendo o cluster…</div>;

  if (error) {
    return (
      <div className="p-6 max-w-[1600px] mx-auto">
        <div className="glass-card p-4 border-red-500/30 text-sm">
          <p className="text-red-500 dark:text-red-400 font-medium">Não consegui ler o cluster</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1 break-words">{error}</p>
        </div>
      </div>
    );
  }
  if (!data) return null;

  const d = data;
  const nodeTone = d.nodes_not_ready > 0 ? "text-red-500 dark:text-red-400" : "text-brand-green";
  const podPct = d.pod_capacity > 0 ? (d.pods_running / d.pod_capacity) * 100 : 0;
  const degradedWorkloads = (d.workloads ?? []).reduce((n, w) => n + w.degraded, 0);
  const maxNsCPU = Math.max(...(d.top_namespaces ?? []).map(n => n.cpu_cores), 0);
  const maxPodCPU = Math.max(...(d.top_pods_cpu ?? []).map(p => p.cpu_cores), 0);
  const maxPodMem = Math.max(...(d.top_pods_mem ?? []).map(p => p.mem_bytes), 0);

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">Cluster Overview</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
            O cluster inteiro numa tela: quanto está comprometido, o que está quebrado agora e onde o consumo se concentra.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-zinc-500 dark:text-zinc-400 font-mono">
            {d.kubernetes_version || "versão desconhecida"}
          </span>
          <button onClick={load} className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition">
            Atualizar
          </button>
        </div>
      </div>

      {!d.metrics_available && (
        <div className="glass-card p-3 border-amber-500/30 text-xs text-amber-600 dark:text-amber-400">
          metrics-server não está respondendo: uso ao vivo indisponível. Requests, limits e contagens continuam corretos.
        </div>
      )}
      {d.degraded && d.degraded.length > 0 && (
        <div className="glass-card p-3 border-amber-500/30 text-xs">
          <p className="text-amber-600 dark:text-amber-400 font-medium">Algumas leituras falharam e foram omitidas</p>
          <ul className="mt-1 space-y-0.5 text-zinc-500 dark:text-zinc-400 font-mono">
            {d.degraded.map(x => <li key={x}>{x}</li>)}
          </ul>
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <Tile label="Nodes prontos" value={`${d.nodes_ready}/${d.nodes_total}`} tone={nodeTone}
          note={[
            d.nodes_not_ready > 0 ? `${d.nodes_not_ready} NotReady` : null,
            d.nodes_cordoned > 0 ? `${d.nodes_cordoned} cordoned` : null,
            d.nodes_under_pressure > 0 ? `${d.nodes_under_pressure} sob pressão` : null,
          ].filter(Boolean).join(" · ") || `cluster com ${d.oldest_node_age}`} />
        <Tile label="Pods rodando" value={d.pods_running}
          note={`${podPct.toFixed(0)}% de ${d.pod_capacity} slots · ${d.pods_ready} prontos`} />
        <Tile label="Problemas críticos" value={d.critical_count}
          tone={d.critical_count > 0 ? "text-red-500 dark:text-red-400" : "text-brand-green"}
          note={`${d.warning_count} avisos`} />
        <Tile label="Workloads degradados" value={degradedWorkloads}
          tone={degradedWorkloads > 0 ? "text-amber-600 dark:text-amber-400" : "text-brand-green"}
          note={(d.workloads ?? []).map(w => `${w.kind.toLowerCase()}s ${w.total}`).join(" · ")} />
      </div>

      <div className="grid lg:grid-cols-2 gap-3">
        <Card><CapacityMeter title="CPU" axis={d.cpu} format={fmtCores} metrics={d.metrics_available} /></Card>
        <Card><CapacityMeter title="Memória" axis={d.memory} format={fmtBytes} metrics={d.metrics_available} /></Card>
      </div>

      <Card title="Pods" subtitle={`${d.pods_total} pods · ${d.containers} containers · ${d.namespace_count} namespaces`}>
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          {["Running", "Pending", "Failed", "Succeeded"].map(phase => (
            <div key={phase} className="rounded-lg border border-[var(--card-border)] bg-[var(--color-surface-hover)] p-3">
              <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{phase}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${PHASE_TONE[phase] ?? ""}`}>{d.pods_by_phase[phase] ?? 0}</p>
            </div>
          ))}
          <div className="rounded-lg border border-[var(--card-border)] bg-[var(--color-surface-hover)] p-3">
            <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Restarts</p>
            <p className="text-2xl font-semibold mt-0.5">{d.pods_restarts}</p>
          </div>
        </div>
      </Card>

      <div className="grid lg:grid-cols-2 gap-3">
        <Card title="Problemas detectados" subtitle="mesma detecção das páginas de Pods e Triage">
          {(d.problems ?? []).length === 0 ? (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Nenhum problema aberto no momento.</p>
          ) : (
            <Table head={["Problema", "Severidade", "Pods"]}>
              {(d.problems ?? []).map(p => {
                const s = statusStyle(p.severity);
                return (
                  <tr key={p.kind} className="border-b border-[var(--card-border)] last:border-0">
                    <td className="px-2 py-2">{p.title}</td>
                    <td className={`px-2 py-2 ${s.text}`}>
                      <span className="inline-flex items-center gap-1.5">
                        <span className={`w-1.5 h-1.5 rounded-full ${s.dot}`} />{p.severity}
                      </span>
                    </td>
                    <td className="px-2 py-2 tabular-nums">{p.count}</td>
                  </tr>
                );
              })}
            </Table>
          )}
        </Card>

        <Card title="Pods em estado crítico" subtitle="os dez primeiros">
          {(d.problem_pods ?? []).length === 0 ? (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">Nenhum pod em estado crítico.</p>
          ) : (
            <Table head={["Pod", "Namespace", "Motivo"]}>
              {(d.problem_pods ?? []).map((p, i) => (
                <tr key={`${p.namespace}/${p.name}-${i}`} className="border-b border-[var(--card-border)] last:border-0">
                  <td className="px-2 py-2 font-mono text-xs truncate max-w-[200px]" title={p.name}>{p.name}</td>
                  <td className="px-2 py-2 text-xs">{p.namespace}</td>
                  <td className="px-2 py-2 text-xs text-red-500 dark:text-red-400" title={p.detail}>{p.title}</td>
                </tr>
              ))}
            </Table>
          )}
        </Card>
      </div>

      <Card title="Namespaces que mais consomem" subtitle="ordenado por CPU em uso">
        <Table head={["Namespace", "CPU", "", "Requests CPU", "Memória", "Pods"]}>
          {(d.top_namespaces ?? []).map(ns => (
            <tr key={ns.name} className="border-b border-[var(--card-border)] last:border-0">
              <td className="px-2 py-2 font-mono text-xs">
                <a href={`/kubernetes/pods?namespace=${encodeURIComponent(ns.name)}`} className="hover:text-brand-green">{ns.name}</a>
              </td>
              <td className="px-2 py-2 font-mono text-xs whitespace-nowrap">{fmtCores(ns.cpu_cores)}</td>
              <td className="px-2 py-2 w-[120px]"><RowBar value={ns.cpu_cores} max={maxNsCPU} /></td>
              <td className="px-2 py-2 font-mono text-xs">{fmtCores(ns.cpu_requests)}</td>
              <td className="px-2 py-2 font-mono text-xs">{fmtBytes(ns.mem_bytes)}</td>
              <td className="px-2 py-2 tabular-nums">{ns.pods}</td>
            </tr>
          ))}
        </Table>
      </Card>

      <div className="grid lg:grid-cols-2 gap-3">
        <Card title="Pods por CPU">
          <Table head={["Pod", "Namespace", "CPU", ""]}>
            {(d.top_pods_cpu ?? []).map(p => (
              <tr key={`${p.namespace}/${p.name}`} className="border-b border-[var(--card-border)] last:border-0">
                <td className="px-2 py-2 font-mono text-xs truncate max-w-[180px]" title={p.name}>{p.name}</td>
                <td className="px-2 py-2 text-xs">{p.namespace}</td>
                <td className="px-2 py-2 font-mono text-xs whitespace-nowrap">{fmtCores(p.cpu_cores)}</td>
                <td className="px-2 py-2 w-[90px]"><RowBar value={p.cpu_cores} max={maxPodCPU} /></td>
              </tr>
            ))}
          </Table>
        </Card>
        <Card title="Pods por memória">
          <Table head={["Pod", "Namespace", "Memória", ""]}>
            {(d.top_pods_mem ?? []).map(p => (
              <tr key={`${p.namespace}/${p.name}`} className="border-b border-[var(--card-border)] last:border-0">
                <td className="px-2 py-2 font-mono text-xs truncate max-w-[180px]" title={p.name}>{p.name}</td>
                <td className="px-2 py-2 text-xs">{p.namespace}</td>
                <td className="px-2 py-2 font-mono text-xs whitespace-nowrap">{fmtBytes(p.mem_bytes)}</td>
                <td className="px-2 py-2 w-[90px]"><RowBar value={p.mem_bytes} max={maxPodMem} /></td>
              </tr>
            ))}
          </Table>
        </Card>
      </div>

      <Card title="Nodes" subtitle="pior primeiro">
        <Table head={["Node", "Estado", "Roles", "CPU", "Memória", "Pods", "Versão", "Idade"]}>
          {(d.nodes ?? []).map(n => {
            const s = statusStyle(n.status);
            const cpuS = statusStyle(loadStatus(n.cpu_pct));
            const memS = statusStyle(loadStatus(n.mem_pct));
            return (
              <tr key={n.name} className="border-b border-[var(--card-border)] last:border-0">
                <td className="px-2 py-2 font-mono text-xs">
                  <span className="flex items-center gap-2">
                    <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${s.dot}`} />
                    <span className="truncate max-w-[200px]" title={n.name}>{n.name}</span>
                  </span>
                </td>
                <td className={`px-2 py-2 text-xs ${s.text}`}>{n.status_text}</td>
                <td className="px-2 py-2 text-xs">{n.roles || "—"}</td>
                <td className="px-2 py-2 font-mono text-xs whitespace-nowrap">
                  {d.metrics_available ? (
                    <><span className={cpuS.text}>{n.cpu_pct.toFixed(0)}%</span>
                    <span className="text-zinc-500 dark:text-zinc-400"> de {fmtCores(n.cpu_cap_cores)}</span></>
                  ) : fmtCores(n.cpu_cap_cores)}
                </td>
                <td className="px-2 py-2 font-mono text-xs whitespace-nowrap">
                  {d.metrics_available ? (
                    <><span className={memS.text}>{n.mem_pct.toFixed(0)}%</span>
                    <span className="text-zinc-500 dark:text-zinc-400"> de {fmtBytes(n.mem_cap_bytes)}</span></>
                  ) : fmtBytes(n.mem_cap_bytes)}
                </td>
                <td className="px-2 py-2 tabular-nums text-xs">{n.pods}/{n.pod_capacity}</td>
                <td className="px-2 py-2 font-mono text-xs">{n.version}</td>
                <td className="px-2 py-2 text-xs">{n.age}</td>
              </tr>
            );
          })}
        </Table>
      </Card>

      <div className="grid lg:grid-cols-3 gap-3">
        <Card title="Inventário" className="lg:col-span-2">
          <div className="grid grid-cols-3 md:grid-cols-4 gap-3">
            {Object.keys(INVENTORY_LABELS)
              .filter(k => d.inventory[k] !== undefined)
              .map(k => {
                const [label, href] = INVENTORY_LABELS[k];
                const body = (
                  <>
                    <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
                    <p className="text-xl font-semibold mt-0.5">{d.inventory[k]}</p>
                  </>
                );
                const cls = "rounded-lg border border-[var(--card-border)] bg-[var(--color-surface-hover)] p-3 block";
                return href
                  ? <a key={k} href={href} className={`${cls} hover:border-brand-green/40 transition`}>{body}</a>
                  : <div key={k} className={cls}>{body}</div>;
              })}
          </div>
        </Card>

        <Card title="Versões em uso" subtitle="kubelet por node">
          <div className="space-y-2">
            {(d.versions ?? []).map(v => (
              <div key={v.value} className="flex items-center justify-between gap-2 text-xs">
                <span className="font-mono truncate" title={v.value}>{v.value}</span>
                <span className="tabular-nums text-zinc-500 dark:text-zinc-400">{v.count} node{v.count === 1 ? "" : "s"}</span>
              </div>
            ))}
            {(d.os_images ?? []).length > 0 && (
              <>
                <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 pt-2">Sistema</p>
                {(d.os_images ?? []).map(v => (
                  <div key={v.value} className="flex items-center justify-between gap-2 text-xs">
                    <span className="truncate" title={v.value}>{v.value}</span>
                    <span className="tabular-nums text-zinc-500 dark:text-zinc-400">{v.count}</span>
                  </div>
                ))}
              </>
            )}
          </div>
        </Card>
      </div>
    </div>
  );
}
