"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import { statusStyle, type ResourceRow } from "./status";
import { fmtBytes, fmtCores, loadStatus } from "./format";

/** Kinds that have a hand-written Overview tab in the backend detail endpoint. */
export const KINDS_WITH_DETAIL = new Set(["services", "namespaces"]);

interface KeyValue { key: string; value: string }

interface ServiceDetail {
  name: string;
  namespace: string;
  type: string;
  created: string;
  age: string;
  uid: string;
  cluster_ips: string[] | null;
  external_ips: string[] | null;
  external_name: string;
  session_affinity: string;
  internal_traffic_policy: string;
  external_traffic_policy: string;
  ip_families: string[] | null;
  ip_family_policy: string;
  ports: { name: string; port: number; protocol: string; target_port: string; node_port: number; app_protocol: string }[];
  labels: KeyValue[] | null;
  annotations: KeyValue[] | null;
  selector: KeyValue[] | null;
  endpoints_ready: number;
  endpoints_not_ready: number;
  endpoints_error?: string;
  pods: { name: string; status: string; phase: string; ready: string; restarts: number; node: string; ip: string; endpoint: boolean }[];
  workloads: { kind: string; name: string; pods: number }[];
  ingresses: { name: string; hosts: string[] | null; paths: string[] | null }[];
  status: string;
  status_text: string;
}

interface NamespaceDetail {
  name: string;
  phase: string;
  created: string;
  age: string;
  uid: string;
  labels: KeyValue[] | null;
  annotations: KeyValue[] | null;
  counts: Record<string, number>;
  pods_running: number;
  pods_pending: number;
  pods_failed: number;
  pods_succeeded: number;
  pods_total: number;
  containers: number;
  cpu: { usage: number; requests: number; limits: number };
  memory: { usage: number; requests: number; limits: number };
  metrics_available: boolean;
  quotas: { name: string; entries: { resource: string; used: string; hard: string }[] }[];
  limit_ranges: { name: string; type: string; resource: string; min: string; max: string; default: string; default_request: string }[];
  top_pods: { name: string; cpu_cores: number; mem_bytes: number }[];
}

const IconClose = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <line x1="18" y1="6" x2="6" y2="18" /><line x1="6" y1="6" x2="18" y2="18" />
  </svg>
);

/** A labelled section; the panel is a stack of these. */
function Card({ title, action, children }: { title: string; action?: React.ReactNode; children: React.ReactNode }) {
  return (
    <section className="glass-card p-4">
      <div className="flex items-center justify-between gap-3 mb-3">
        <h3 className="text-sm font-semibold">{title}</h3>
        {action}
      </div>
      {children}
    </section>
  );
}

function EmptyNote({ children }: { children: React.ReactNode }) {
  return <p className="text-xs text-zinc-500 dark:text-zinc-400">{children}</p>;
}

/** Key/value blocks (labels, annotations, selector) as copyable chips. */
function KeyValueList({ items, empty, mono = true }: { items: KeyValue[] | null; empty: string; mono?: boolean }) {
  const [query, setQuery] = useState("");
  const list = items ?? [];
  const filtered = query.trim()
    ? list.filter(kv => (kv.key + kv.value).toLowerCase().includes(query.trim().toLowerCase()))
    : list;

  if (list.length === 0) return <EmptyNote>{empty}</EmptyNote>;

  return (
    <div className="space-y-2">
      {list.length > 6 && (
        <input
          value={query}
          onChange={e => setQuery(e.target.value)}
          placeholder="Filter…"
          className="w-full px-3 py-1.5 text-xs rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50"
        />
      )}
      <div className="flex flex-wrap gap-1.5">
        {filtered.map(kv => (
          <span
            key={kv.key}
            title={`${kv.key}: ${kv.value}`}
            className={`inline-flex max-w-full items-center gap-1 px-2 py-1 rounded-md border border-[var(--card-border)] bg-[var(--color-surface-hover)] text-xs ${mono ? "font-mono" : ""}`}
          >
            <span className="text-brand-green shrink-0">{kv.key}</span>
            <span className="text-zinc-400 shrink-0">:</span>
            <span className="truncate max-w-[320px] text-zinc-600 dark:text-zinc-300">{kv.value || "—"}</span>
          </span>
        ))}
        {filtered.length === 0 && <EmptyNote>Nothing matches “{query}”.</EmptyNote>}
      </div>
    </div>
  );
}

/** Definition row used by the property grids. */
function Prop({ label, value, mono = false }: { label: string; value?: React.ReactNode; mono?: boolean }) {
  const empty = value === undefined || value === null || value === "" ;
  return (
    <div className="min-w-0">
      <dt className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</dt>
      <dd className={`text-sm mt-0.5 truncate ${mono ? "font-mono text-xs" : ""} ${empty ? "text-zinc-400 dark:text-zinc-600" : ""}`}
          title={typeof value === "string" ? value : undefined}>
        {empty ? "—" : value}
      </dd>
    </div>
  );
}

function Table({ head, children }: { head: string[]; children: React.ReactNode }) {
  return (
    <div className="overflow-x-auto -mx-1">
      <table className="w-full text-sm">
        <thead className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b border-[var(--card-border)]">
          <tr>{head.map((h, i) => (
            <th key={h} className={`font-medium px-2 py-2 ${i === 0 ? "text-left" : "text-left"}`}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>{children}</tbody>
      </table>
    </div>
  );
}

function ServiceOverview({ d }: { d: ServiceDetail }) {
  const s = statusStyle(d.status);
  return (
    <div className="space-y-4">
      <div className={`glass-card p-4 ${s.border}`}>
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <span className={`inline-flex items-center gap-2 text-sm font-medium ${s.text}`}>
            <span className={`w-2 h-2 rounded-full ${s.dot}`} />{d.status_text}
          </span>
          <span className="text-sm text-zinc-500 dark:text-zinc-400">
            Workloads: <span className="text-zinc-800 dark:text-zinc-100 font-medium">{d.workloads.length}</span>
          </span>
          <span className="text-sm text-zinc-500 dark:text-zinc-400">
            Pods: <span className="text-zinc-800 dark:text-zinc-100 font-medium">{d.pods.length}</span>
          </span>
          <span className="text-sm text-zinc-500 dark:text-zinc-400">
            Endpoints: <span className="text-zinc-800 dark:text-zinc-100 font-medium">{d.endpoints_ready}</span>
            {d.endpoints_not_ready > 0 && <span className="text-amber-600 dark:text-amber-400"> +{d.endpoints_not_ready} not ready</span>}
          </span>
          <span className="text-sm text-zinc-500 dark:text-zinc-400">
            Ingresses: <span className="text-zinc-800 dark:text-zinc-100 font-medium">{d.ingresses.length}</span>
          </span>
        </div>
        {d.endpoints_error && (
          <p className="text-xs text-amber-600 dark:text-amber-400 mt-3">Endpoints unreadable: {d.endpoints_error}</p>
        )}
      </div>

      <Card title="Info">
        <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-4 gap-y-3">
          <Prop label="Type" value={d.type} />
          <Prop label="Cluster IP" value={(d.cluster_ips ?? []).join(", ")} mono />
          <Prop label="External IP" value={(d.external_ips ?? []).join(", ")} mono />
          {d.external_name && <Prop label="External name" value={d.external_name} mono />}
          <Prop label="Session affinity" value={d.session_affinity} />
          <Prop label="Internal traffic policy" value={d.internal_traffic_policy} />
          <Prop label="External traffic policy" value={d.external_traffic_policy} />
          <Prop label="IP families" value={`${(d.ip_families ?? []).join(", ")}${d.ip_family_policy ? ` (${d.ip_family_policy})` : ""}`} />
          <Prop label="Age" value={d.age} />
          <Prop label="Created" value={d.created} />
          <Prop label="UID" value={d.uid} mono />
        </dl>
      </Card>

      <Card title={`Ports ${d.ports.length}`}>
        {d.ports.length === 0 ? (
          <EmptyNote>This Service exposes no ports.</EmptyNote>
        ) : (
          <Table head={["Name", "Port", "Protocol", "Target port", "Node port", "App protocol"]}>
            {d.ports.map((p, i) => (
              <tr key={`${p.port}-${i}`} className="border-b border-[var(--card-border)] last:border-0">
                <td className="px-2 py-2">{p.name || "—"}</td>
                <td className="px-2 py-2 font-mono text-xs">{p.port}</td>
                <td className="px-2 py-2">{p.protocol}</td>
                <td className="px-2 py-2 font-mono text-xs">{p.target_port || "—"}</td>
                <td className="px-2 py-2 font-mono text-xs">{p.node_port > 0 ? p.node_port : "—"}</td>
                <td className="px-2 py-2">{p.app_protocol || "—"}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="Selector">
        <KeyValueList items={d.selector} empty="No selector — endpoints for this Service are managed manually." />
      </Card>

      <Card title={`Pods ${d.pods.length}`}>
        {d.pods.length === 0 ? (
          <EmptyNote>No pod matches this selector.</EmptyNote>
        ) : (
          <Table head={["Pod", "State", "Ready", "Restarts", "Node", "IP", "Endpoint"]}>
            {d.pods.map(p => {
              const ps = statusStyle(p.status);
              return (
                <tr key={p.name} className="border-b border-[var(--card-border)] last:border-0">
                  <td className="px-2 py-2 font-mono text-xs">
                    <span className="flex items-center gap-2">
                      <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${ps.dot}`} />
                      <span className="truncate max-w-[220px]" title={p.name}>{p.name}</span>
                    </span>
                  </td>
                  <td className={`px-2 py-2 ${ps.text}`}>{p.phase}</td>
                  <td className="px-2 py-2 font-mono text-xs">{p.ready}</td>
                  <td className="px-2 py-2 tabular-nums">{p.restarts}</td>
                  <td className="px-2 py-2 font-mono text-xs truncate max-w-[160px]" title={p.node}>{p.node || "—"}</td>
                  <td className="px-2 py-2 font-mono text-xs">{p.ip || "—"}</td>
                  <td className="px-2 py-2">
                    {p.endpoint
                      ? <span className="text-brand-green text-xs">serving</span>
                      : <span className="text-zinc-400 dark:text-zinc-600 text-xs">not in rotation</span>}
                  </td>
                </tr>
              );
            })}
          </Table>
        )}
      </Card>

      <Card title={`Workloads ${d.workloads.length}`}>
        {d.workloads.length === 0 ? (
          <EmptyNote>No workload owns the pods behind this Service.</EmptyNote>
        ) : (
          <Table head={["Kind", "Name", "Pods"]}>
            {d.workloads.map(w => (
              <tr key={`${w.kind}/${w.name}`} className="border-b border-[var(--card-border)] last:border-0">
                <td className="px-2 py-2">{w.kind}</td>
                <td className="px-2 py-2 font-mono text-xs">{w.name}</td>
                <td className="px-2 py-2 tabular-nums">{w.pods}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title={`Ingresses ${d.ingresses.length}`}>
        {d.ingresses.length === 0 ? (
          <EmptyNote>No Ingress routes to this Service.</EmptyNote>
        ) : (
          <Table head={["Ingress", "Hosts", "Paths"]}>
            {d.ingresses.map(ing => (
              <tr key={ing.name} className="border-b border-[var(--card-border)] last:border-0">
                <td className="px-2 py-2 font-mono text-xs">{ing.name}</td>
                <td className="px-2 py-2 text-xs">{(ing.hosts ?? []).join(", ") || "—"}</td>
                <td className="px-2 py-2 font-mono text-xs">{(ing.paths ?? []).join(", ") || "—"}</td>
              </tr>
            ))}
          </Table>
        )}
      </Card>

      <Card title="Labels"><KeyValueList items={d.labels} empty="There are no labels for this resource." /></Card>
      <Card title="Annotations"><KeyValueList items={d.annotations} empty="There are no annotations for this resource." /></Card>
    </div>
  );
}

/** One measure, one hue. The track is what the pods asked for (or what they
 *  use, whichever is larger), the fill is live usage, and requests/limits are
 *  labelled marks on the same axis rather than competing series -- three hues
 *  here failed CVD separation, and they were never really three categories. */
function UtilizationMeter({
  title, usage, requests, limits, format, metrics,
}: {
  title: string; usage: number; requests: number; limits: number;
  format: (n: number) => string; metrics: boolean;
}) {
  const scale = Math.max(usage, requests, limits) || 1;
  const pct = requests > 0 ? (usage / requests) * 100 : 0;
  const s = statusStyle(metrics && requests > 0 ? loadStatus(pct) : "unknown");
  const at = (v: number) => `${Math.min(100, (v / scale) * 100)}%`;

  return (
    <div>
      <div className="flex items-baseline justify-between gap-2">
        <p className="text-sm font-medium">{title}</p>
        <p className="text-sm font-mono">
          {metrics ? format(usage) : <span className="text-zinc-400 dark:text-zinc-600">no metrics</span>}
          {metrics && requests > 0 && (
            <span className={`ml-2 ${s.text}`}>{pct.toFixed(0)}% of requests</span>
          )}
        </p>
      </div>

      <div className="relative mt-2 h-3 rounded-full bg-[var(--color-surface-hover)] overflow-hidden">
        {metrics && <div className={`h-full rounded-full ${s.dot}`} style={{ width: at(usage) }} />}
        {requests > 0 && (
          <span className="absolute inset-y-0 w-0.5 bg-zinc-500 dark:bg-zinc-300" style={{ left: at(requests) }} />
        )}
        {limits > 0 && (
          <span className="absolute inset-y-0 w-0.5 bg-zinc-400 dark:bg-zinc-500" style={{ left: at(limits) }} />
        )}
      </div>

      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs text-zinc-500 dark:text-zinc-400">
        <span>Usage <span className="font-mono text-zinc-700 dark:text-zinc-200">{metrics ? format(usage) : "—"}</span></span>
        <span>Requests <span className="font-mono text-zinc-700 dark:text-zinc-200">{format(requests)}</span></span>
        <span>Limits <span className="font-mono text-zinc-700 dark:text-zinc-200">{format(limits)}</span></span>
      </div>
    </div>
  );
}

const COUNT_LABELS: Record<string, string> = {
  pods: "Pods",
  services: "Services",
  deployments: "Deployments",
  statefulsets: "StatefulSets",
  daemonsets: "DaemonSets",
  replicasets: "ReplicaSets",
  ingresses: "Ingresses",
  persistentvolumeclaims: "Volume claims",
  configmaps: "ConfigMaps",
  secrets: "Secrets",
  cronjobs: "CronJobs",
  jobs: "Jobs",
};

// Only pages that honour ?namespace= are linked, so a click always lands on
// the namespace being inspected rather than on the whole cluster.
const COUNT_HREFS: Record<string, string> = {
  pods: "/kubernetes/pods",
  services: "/kubernetes/services",
  deployments: "/kubernetes/deployments",
  statefulsets: "/kubernetes/statefulsets",
  daemonsets: "/kubernetes/daemonsets",
  replicasets: "/kubernetes/replicasets",
  ingresses: "/kubernetes/ingresses",
  persistentvolumeclaims: "/kubernetes/pvcs",
};

function NamespaceOverview({ d }: { d: NamespaceDetail }) {
  const workloads =
    (d.counts.deployments ?? 0) + (d.counts.statefulsets ?? 0) +
    (d.counts.daemonsets ?? 0) + (d.counts.cronjobs ?? 0);

  const podStates: [string, number, string][] = [
    ["Running", d.pods_running, "text-brand-green"],
    ["Pending", d.pods_pending, "text-amber-600 dark:text-amber-400"],
    ["Failed", d.pods_failed, "text-red-500 dark:text-red-400"],
    ["Succeeded", d.pods_succeeded, "text-zinc-500 dark:text-zinc-400"],
  ];

  return (
    <div className="space-y-4">
      <div className="glass-card p-4">
        <div className="flex flex-wrap items-center gap-x-6 gap-y-3">
          <span className={`inline-flex items-center gap-2 text-sm font-medium ${d.phase === "Active" ? "text-brand-green" : "text-amber-600 dark:text-amber-400"}`}>
            <span className={`w-2 h-2 rounded-full ${d.phase === "Active" ? "bg-brand-green" : "bg-amber-500"}`} />{d.phase}
          </span>
          <span className="text-sm text-zinc-500 dark:text-zinc-400">
            Workloads: <span className="text-zinc-800 dark:text-zinc-100 font-medium">{workloads}</span>
          </span>
          <span className="text-sm text-zinc-500 dark:text-zinc-400">
            Pods: <span className="text-zinc-800 dark:text-zinc-100 font-medium">{d.pods_total}</span>
          </span>
          <span className="text-sm text-zinc-500 dark:text-zinc-400">
            Containers: <span className="text-zinc-800 dark:text-zinc-100 font-medium">{d.containers}</span>
          </span>
          <span className="text-sm text-zinc-500 dark:text-zinc-400">Age: <span className="text-zinc-800 dark:text-zinc-100 font-medium">{d.age}</span></span>
        </div>
      </div>

      <Card title="Utilization">
        {!d.metrics_available && (
          <p className="text-xs text-amber-600 dark:text-amber-400 mb-3">
            metrics-server is not answering, so live usage is unavailable. Requests and limits are read from the pod specs.
          </p>
        )}
        <div className="grid md:grid-cols-2 gap-6">
          <UtilizationMeter title="CPU" usage={d.cpu.usage} requests={d.cpu.requests} limits={d.cpu.limits}
            format={fmtCores} metrics={d.metrics_available} />
          <UtilizationMeter title="Memory" usage={d.memory.usage} requests={d.memory.requests} limits={d.memory.limits}
            format={fmtBytes} metrics={d.metrics_available} />
        </div>
      </Card>

      <Card title="Pods">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {podStates.map(([label, value, color]) => (
            <div key={label} className="rounded-lg border border-[var(--card-border)] bg-[var(--color-surface-hover)] p-3">
              <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      </Card>

      <Card title="Resources">
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          {Object.keys(COUNT_LABELS)
            .filter(key => d.counts[key] !== undefined)
            .map(key => {
              const base = COUNT_HREFS[key];
              const href = base ? `${base}?namespace=${encodeURIComponent(d.name)}` : undefined;
              const body = (
                <>
                  <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{COUNT_LABELS[key]}</p>
                  <p className="text-2xl font-semibold mt-0.5">{d.counts[key]}</p>
                </>
              );
              const cls = "rounded-lg border border-[var(--card-border)] bg-[var(--color-surface-hover)] p-3 block";
              return href
                ? <a key={key} href={href} className={`${cls} hover:border-brand-green/40 transition`}>{body}</a>
                : <div key={key} className={cls}>{body}</div>;
            })}
        </div>
      </Card>

      {d.top_pods.length > 0 && (
        <Card title="Top pods by CPU">
          <Table head={["Pod", "CPU", "Memory"]}>
            {d.top_pods.map(p => (
              <tr key={p.name} className="border-b border-[var(--card-border)] last:border-0">
                <td className="px-2 py-2 font-mono text-xs truncate max-w-[280px]" title={p.name}>{p.name}</td>
                <td className="px-2 py-2 font-mono text-xs">{fmtCores(p.cpu_cores)}</td>
                <td className="px-2 py-2 font-mono text-xs">{fmtBytes(p.mem_bytes)}</td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      <Card title={`Resource quotas ${d.quotas.length}`}>
        {d.quotas.length === 0 ? (
          <EmptyNote>No ResourceQuota applies to this namespace — nothing caps what it can request.</EmptyNote>
        ) : (
          <div className="space-y-4">
            {d.quotas.map(q => (
              <div key={q.name}>
                <p className="text-xs font-mono text-zinc-500 dark:text-zinc-400 mb-1">{q.name}</p>
                <Table head={["Resource", "Used", "Hard"]}>
                  {q.entries.map(e => (
                    <tr key={e.resource} className="border-b border-[var(--card-border)] last:border-0">
                      <td className="px-2 py-2 font-mono text-xs">{e.resource}</td>
                      <td className="px-2 py-2 font-mono text-xs">{e.used}</td>
                      <td className="px-2 py-2 font-mono text-xs">{e.hard}</td>
                    </tr>
                  ))}
                </Table>
              </div>
            ))}
          </div>
        )}
      </Card>

      {d.limit_ranges.length > 0 && (
        <Card title="Limit ranges">
          <Table head={["Name", "Type", "Resource", "Min", "Max", "Default", "Default request"]}>
            {d.limit_ranges.map((l, i) => (
              <tr key={`${l.name}-${l.type}-${l.resource}-${i}`} className="border-b border-[var(--card-border)] last:border-0">
                <td className="px-2 py-2 font-mono text-xs">{l.name}</td>
                <td className="px-2 py-2 text-xs">{l.type}</td>
                <td className="px-2 py-2 font-mono text-xs">{l.resource}</td>
                <td className="px-2 py-2 font-mono text-xs">{l.min || "—"}</td>
                <td className="px-2 py-2 font-mono text-xs">{l.max || "—"}</td>
                <td className="px-2 py-2 font-mono text-xs">{l.default || "—"}</td>
                <td className="px-2 py-2 font-mono text-xs">{l.default_request || "—"}</td>
              </tr>
            ))}
          </Table>
        </Card>
      )}

      <Card title="Info">
        <dl className="grid grid-cols-2 md:grid-cols-3 gap-x-4 gap-y-3">
          <Prop label="Phase" value={d.phase} />
          <Prop label="Age" value={d.age} />
          <Prop label="Created" value={d.created} />
          <Prop label="UID" value={d.uid} mono />
        </dl>
      </Card>

      <Card title="Labels"><KeyValueList items={d.labels} empty="There are no labels for this namespace." /></Card>
      <Card title="Annotations"><KeyValueList items={d.annotations} empty="There are no annotations for this namespace." /></Card>
    </div>
  );
}

/** Side panel for one resource: the enriched Overview, plus its YAML. */
export default function ResourceDetailDrawer({
  kind, row, onClose,
}: { kind: string; row: ResourceRow; onClose: () => void }) {
  const hasOverview = KINDS_WITH_DETAIL.has(kind);
  const [tab, setTab] = useState<"overview" | "yaml">(hasOverview ? "overview" : "yaml");

  const [detail, setDetail] = useState<ServiceDetail | NamespaceDetail | null>(null);
  const [detailError, setDetailError] = useState("");
  const [detailLoading, setDetailLoading] = useState(hasOverview);

  const [manifest, setManifest] = useState("");
  const [manifestError, setManifestError] = useState("");
  const [manifestLoading, setManifestLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const qs = row.namespace ? `?namespace=${encodeURIComponent(row.namespace)}` : "";

  useEffect(() => {
    if (!hasOverview) return;
    let cancelled = false;
    setDetailLoading(true);
    setDetailError("");
    setDetail(null);

    apiFetch(`/kubernetes/detail/${kind}/${encodeURIComponent(row.name)}${qs}`)
      .then(async res => {
        const body = await res.json().catch(() => ({}));
        if (cancelled) return;
        if (!res.ok) setDetailError(body.error ?? `Request failed (${res.status})`);
        else setDetail(body.service ?? body.namespace ?? null);
      })
      .catch(e => { if (!cancelled) setDetailError(e instanceof Error ? e.message : "Failed to load details"); })
      .finally(() => { if (!cancelled) setDetailLoading(false); });

    return () => { cancelled = true; };
  }, [hasOverview, kind, row.name, qs]);

  // The manifest is only fetched when its tab is opened: on a large object it
  // is the heaviest part of the panel and most visits never look at it.
  //
  // What has already been fetched is tracked in a ref, not in the dependency
  // list. Depending on the loading flag re-runs the effect the moment the
  // fetch starts, and that re-run's cleanup cancels the very request it just
  // fired -- the response lands and is thrown away, leaving "Loading…" forever.
  const fetchedManifest = useRef("");

  useEffect(() => {
    if (tab !== "yaml") return;
    const key = `${kind}/${row.namespace}/${row.name}`;
    if (fetchedManifest.current === key) return;
    fetchedManifest.current = key;

    let cancelled = false;
    setManifestLoading(true);
    setManifestError("");

    apiFetch(`/kubernetes/manifest/${kind}/${encodeURIComponent(row.name)}${qs}`)
      .then(async res => {
        const body = await res.json().catch(() => ({}));
        if (cancelled) return;
        if (!res.ok) setManifestError(body.error ?? `Request failed (${res.status})`);
        else setManifest(body.manifest ?? "");
      })
      .catch(e => { if (!cancelled) setManifestError(e instanceof Error ? e.message : "Failed to load manifest"); })
      .finally(() => { if (!cancelled) setManifestLoading(false); });

    return () => { cancelled = true; };
  }, [tab, kind, row.name, row.namespace, qs]);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const copy = useCallback(async () => {
    try {
      await navigator.clipboard.writeText(manifest);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      setCopied(false);
    }
  }, [manifest]);

  const tabs: [typeof tab, string][] = hasOverview
    ? [["overview", "Overview"], ["yaml", "Definition (YAML)"]]
    : [["yaml", "Definition (YAML)"]];

  return (
    <div className="fixed inset-0 z-50 flex justify-end">
      <div className="absolute inset-0 bg-black/40" onClick={onClose} />
      <aside className="relative w-full max-w-4xl h-full bg-[var(--color-surface)] border-l border-[var(--card-border)] flex flex-col shadow-2xl">
        <header className="px-5 pt-4 border-b border-[var(--card-border)]">
          <div className="flex items-start justify-between gap-4">
            <div className="min-w-0">
              <p className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{kind}</p>
              <h2 className="font-semibold font-mono truncate text-lg">{row.name}</h2>
              {row.namespace && (
                <p className="text-xs text-zinc-500 dark:text-zinc-400 font-mono">{row.namespace}</p>
              )}
            </div>
            <div className="flex items-center gap-2 shrink-0">
              {tab === "yaml" && (
                <button
                  onClick={copy}
                  disabled={!manifest}
                  className="px-3 py-1.5 text-xs rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-40"
                >
                  {copied ? "Copied" : "Copy YAML"}
                </button>
              )}
              <button
                onClick={onClose}
                aria-label="Close"
                className="p-1.5 rounded-lg text-zinc-500 hover:text-zinc-800 dark:hover:text-zinc-200 hover:bg-[var(--color-surface-hover)] transition"
              >
                <IconClose />
              </button>
            </div>
          </div>

          <nav className="flex gap-1 mt-3">
            {tabs.map(([id, label]) => (
              <button
                key={id}
                onClick={() => setTab(id)}
                className={`px-3 py-2 text-sm border-b-2 -mb-px transition ${
                  tab === id
                    ? "border-brand-green text-brand-green"
                    : "border-transparent text-zinc-500 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200"
                }`}
              >
                {label}
              </button>
            ))}
          </nav>
        </header>

        <div className="flex-1 overflow-auto p-5">
          {tab === "overview" ? (
            detailLoading ? (
              <p className="text-sm text-zinc-500">Loading details…</p>
            ) : detailError ? (
              <div className="glass-card p-4 border-red-500/30">
                <p className="text-sm text-red-500 dark:text-red-400 font-medium">Cannot read details</p>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">{detailError}</p>
              </div>
            ) : detail && kind === "services" ? (
              <ServiceOverview d={detail as ServiceDetail} />
            ) : detail ? (
              <NamespaceOverview d={detail as NamespaceDetail} />
            ) : null
          ) : manifestLoading ? (
            <p className="text-sm text-zinc-500">Loading manifest…</p>
          ) : manifestError ? (
            <div className="glass-card p-4 border-red-500/30">
              <p className="text-sm text-red-500 dark:text-red-400 font-medium">Cannot read manifest</p>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">{manifestError}</p>
            </div>
          ) : (
            <pre className="text-xs font-mono leading-relaxed whitespace-pre overflow-x-auto p-4 rounded-lg bg-zinc-100 dark:bg-zinc-900 border border-[var(--card-border)]">
              {manifest}
            </pre>
          )}
        </div>
      </aside>
    </div>
  );
}
