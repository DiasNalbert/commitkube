"use client";

import { Suspense, useCallback, useEffect, useMemo, useState } from "react";
import { usePathname, useRouter, useSearchParams } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { selectedCluster, type ClusterInfo } from "@/lib/cluster";
import { PERMISSIONS as P } from "@/lib/permissions";
import { usePermissions } from "@/app/components/usePermissions";
import { useShellRefresh } from "@/app/components/shell/refresh";
import PodActions from "@/app/components/k8s/PodActions";
import PodLogs from "@/app/components/k8s/PodLogs";

// ---- data ------------------------------------------------------------------

interface ClusterAxis { capacity: number; allocatable: number; requests: number; limits: number; usage: number }
interface NodeSummary {
  name: string; status: string; age: string; version: string;
  cpu_pct: number; mem_pct: number; pods: number; pod_capacity: number; schedulable: boolean;
}
interface NamespaceUsage { name: string; cpu_cores: number; mem_bytes: number; pods: number }
interface PodUsage { name: string; namespace: string; cpu_cores: number; mem_bytes: number }
interface WorkloadHealth { kind: string; total: number; degraded: number }
interface Overview {
  kubernetes_version: string;
  oldest_node_age: string;
  nodes_total: number; nodes_ready: number;
  cpu: ClusterAxis; memory: ClusterAxis;
  pods_running: number; pod_capacity: number;
  workloads: WorkloadHealth[] | null;
  top_namespaces: NamespaceUsage[] | null;
  top_pods_cpu: PodUsage[] | null;
  nodes: NodeSummary[] | null;
  metrics_available: boolean;
  degraded?: string[];
}
interface Problem { kind: string; severity: string; title: string; detail: string }
interface Pod {
  name: string; namespace: string; workload: string; node_name: string; phase: string; ready: boolean;
  age: string; restart_count: number; image: string; problems: Problem[] | null;
  containers: { name: string }[] | null;
}
interface Change {
  at: string; kind: string; tone: "red" | "gold" | "green" | "muted"; text: string; sub: string;
  namespace?: string; failing?: boolean; workload?: string; image?: string; count?: number;
}

type State = "Running" | "Failed" | "Pending" | "Succeeded";
const STATES: State[] = ["Running", "Failed", "Pending", "Succeeded"];
const STATE_COLOR: Record<State, string> = {
  Running: "var(--run)", Failed: "var(--red)", Pending: "var(--gold)", Succeeded: "var(--m4)",
};
const TONE: Record<Change["tone"], string> = {
  red: "var(--red)", gold: "var(--gold)", green: "var(--green)", muted: "var(--m4)",
};

/** A pod is failing when Kubernetes says so or when the problem detector
 *  found something critical -- a CrashLoopBackOff pod is phase Running. */
function stateOf(p: Pod): State {
  if (p.phase === "Failed" || (p.problems ?? []).some(x => x.severity === "critical")) return "Failed";
  if (p.phase === "Pending") return "Pending";
  if (p.phase === "Succeeded") return "Succeeded";
  return "Running";
}

const loadColor = (pct: number) => (pct >= 90 ? "var(--red)" : pct >= 75 ? "var(--gold)" : "var(--green)");
const hhmm = (iso: string) => {
  const d = new Date(iso);
  return `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
};
const tagOf = (image = "") => {
  const at = image.lastIndexOf("@");
  if (at >= 0) return image.slice(at + 8, at + 15);
  const slash = image.lastIndexOf("/"), colon = image.lastIndexOf(":");
  return colon > slash ? image.slice(colon + 1) : "latest";
};
const plural = (n: number, one: string, many: string) => (n === 1 ? one : many);

// ---- small pieces ------------------------------------------------------------

function Figure({ label, value, of, note, color = "var(--text)" }: { label: string; value: string; of?: string; note?: string; color?: string }) {
  return (
    <div className="flex flex-col gap-1.5 pt-4 pr-5">
      <span className="text-[12.5px]" style={{ color: "var(--t3)" }}>{label}</span>
      <span className="font-mono text-[26px] font-light tracking-[-0.03em]" style={{ color }}>
        {value}<span className="text-[13px]" style={{ color: "var(--m2)" }}>{of}</span>
      </span>
      {note && <span className="text-[12.5px]" style={{ color: "var(--m2)" }}>{note}</span>}
    </div>
  );
}

/** Usage, requests and limits on one axis, against allocatable capacity. The
 *  hatched part is past allocatable: limits there are met only if other pods
 *  stay under theirs. */
function Ruler({ title, unit, axis, metrics, step }: { title: string; unit: string; axis: ClusterAxis; metrics: boolean; step: number }) {
  const max = Math.max(step, Math.ceil(Math.max(axis.capacity, axis.limits, axis.usage) / step) * step);
  const at = (v: number) => `${Math.min(100, (v / max) * 100).toFixed(2)}%`;
  const f = (v: number) => `${Number.isInteger(v) ? v : v.toFixed(1)} ${unit}`;
  const pct = (v: number) => (axis.allocatable > 0 ? `${Math.round((v / axis.allocatable) * 100)}%` : "—");
  const ticks: number[] = [];
  for (let v = 0; v <= max + 1e-9; v += step) ticks.push(v);

  return (
    <div className="flex flex-wrap gap-x-6 gap-y-4 items-end">
      <div className="flex flex-col gap-0.5 w-[200px] shrink-0">
        <span className="text-[12.5px]" style={{ color: "var(--t3)" }}>{title}</span>
        <span className="font-mono text-[34px] font-light tracking-[-0.04em]">{metrics ? pct(axis.usage) : "—"}</span>
        <span className="text-[12.5px]" style={{ color: "var(--m2)" }}>
          {metrics ? `${f(axis.usage)} of ${f(axis.allocatable)}` : "metrics-server unavailable"}
        </span>
        <span className="text-[12.5px]" style={{ color: "var(--gold)" }}>requests {f(axis.requests)} · {pct(axis.requests)}</span>
        <span className="text-[12.5px]" style={{ color: "var(--t3)" }}>limits {f(axis.limits)}</span>
      </div>
      <div className="relative h-[74px] flex-1 min-w-[260px]">
        <span className="absolute top-0 -translate-x-1/2 font-mono text-[10.5px] whitespace-nowrap" style={{ left: at(axis.requests), color: "var(--gold)" }}>req</span>
        <span className="absolute top-0 -translate-x-full font-mono text-[10.5px] whitespace-nowrap" style={{ left: at(axis.limits), color: "var(--t3)" }}>lim</span>
        <div className="absolute inset-x-0 top-[22px] h-[22px]" style={{ background: "var(--chip)" }}>
          {metrics && <div className="absolute left-0 inset-y-0" style={{ width: at(axis.usage), background: "var(--green)" }} />}
          <div className="absolute inset-y-0 right-0" style={{ left: at(axis.allocatable), background: "repeating-linear-gradient(135deg,transparent 0 4px,rgba(251,191,36,.22) 4px 6px)" }} />
          <span className="absolute -top-1.5 -bottom-1.5 w-0.5" style={{ left: at(axis.requests), background: "var(--gold)" }} />
          <span className="absolute -top-1.5 -bottom-1.5 w-px" style={{ left: at(axis.limits), background: "var(--t3)" }} />
        </div>
        <div className="absolute inset-x-0 top-[50px] h-6">
          {ticks.map(v => (
            <span key={v} className="absolute top-0 flex flex-col items-start gap-[3px] font-mono text-[9.5px]" style={{ left: at(v), color: v === 0 ? "var(--m2)" : "var(--m3)" }}>
              <span className="w-px h-[5px]" style={{ background: "var(--m4)" }} />{Number.isInteger(v) ? v : v.toFixed(1)}
            </span>
          ))}
        </div>
      </div>
    </div>
  );
}

/** Roughly six ticks, on a round number. */
function niceStep(max: number) {
  const raw = max / 6 || 1;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const n = raw / pow;
  return (n <= 1 ? 1 : n <= 2 ? 2 : n <= 2.5 ? 2.5 : n <= 5 ? 5 : 10) * pow;
}

// ---- page ------------------------------------------------------------------

export default function Page() {
  // The view lives in the URL (?ns=, ?pod=) so it can be linked and the
  // command bar can open it; reading the URL needs a boundary to render in.
  return (
    <Suspense fallback={null}>
      <ClusterOverview />
    </Suspense>
  );
}

function ClusterOverview() {
  const router = useRouter();
  const pathname = usePathname();
  const params = useSearchParams();
  const { can } = usePermissions();
  const canLogs = can(P.k8sLogs);

  const ns = params.get("ns");
  const podParam = params.get("pod");

  const [ov, setOv] = useState<Overview | null>(null);
  const [pods, setPods] = useState<Pod[] | null>(null);
  const [changes, setChanges] = useState<Change[]>([]);
  const [clusterName, setClusterName] = useState("");
  const [error, setError] = useState("");
  const [stateFilter, setStateFilter] = useState<State | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const [streaming, setStreaming] = useState(false);
  const [lastLines, setLastLines] = useState("");

  const setParam = useCallback((key: "ns" | "pod", value: string | null) => {
    const next = new URLSearchParams(params.toString());
    if (value) next.set(key, value); else next.delete(key);
    const qs = next.toString();
    router.replace(qs ? `${pathname}?${qs}` : pathname, { scroll: false });
  }, [params, pathname, router]);

  const { markSynced } = useShellRefresh(() => load());

  const load = useCallback(async () => {
    setError("");
    const [o, p, c] = await Promise.all([
      apiFetch("/kubernetes/cluster-overview").then(async r => (r.ok ? r.json() : Promise.reject((await r.json().catch(() => ({}))).error || `cluster overview: ${r.status}`))),
      apiFetch("/monitoring/pods").then(r => (r.ok ? r.json() : { pods: [] })).catch(() => ({ pods: [] })),
      apiFetch("/kubernetes/changes?hours=6").then(r => (r.ok ? r.json() : { events: [] })).catch(() => ({ events: [] })),
    ]).catch(e => { setError(String(e)); return [null, null, null]; });
    if (o) setOv(o);
    if (p) setPods(p.pods ?? []);
    if (c) setChanges(c.events ?? []);
    if (o) markSynced();
  }, [markSynced]);

  useEffect(() => {
    load();
    apiFetch("/clusters").then(r => (r.ok ? r.json() : {})).then((b: { clusters?: ClusterInfo[] }) => {
      const id = selectedCluster();
      const list = b.clusters ?? [];
      setClusterName((list.find(c => String(c.id) === id) ?? list.find(c => c.is_default) ?? list[0])?.name ?? "");
    }).catch(() => {});
    const t = setInterval(() => { if (!document.hidden) load(); }, 60_000);
    return () => clearInterval(t);
  }, [load]);

  // ---- derived ----
  const all = useMemo(() => (pods ?? []).map(p => ({ ...p, state: stateOf(p) })), [pods]);
  const counts = useMemo(() => {
    const c: Record<State, number> = { Running: 0, Failed: 0, Pending: 0, Succeeded: 0 };
    for (const p of all) c[p.state]++;
    return c;
  }, [all]);
  const failing = all.filter(p => p.state === "Failed");

  const nsList = useMemo(() => {
    const m = new Map<string, { pods: number; failed: number }>();
    for (const p of all) {
      const e = m.get(p.namespace) ?? { pods: 0, failed: 0 };
      e.pods++; if (p.state === "Failed") e.failed++;
      m.set(p.namespace, e);
    }
    return [...m.entries()].sort((a, b) => b[1].failed - a[1].failed || b[1].pods - a[1].pods).map(([name, v]) => ({ name, ...v }));
  }, [all]);

  const match = (p: { namespace: string; state: State }) => (!ns || p.namespace === ns) && (!stateFilter || p.state === stateFilter);

  const nodes = useMemo(() => {
    const byNode = new Map<string, typeof all>();
    for (const p of all) {
      const k = p.node_name || "";
      byNode.set(k, [...(byNode.get(k) ?? []), p]);
    }
    const known = (ov?.nodes ?? []).map(n => ({ ...n, list: byNode.get(n.name) ?? [] }));
    const unscheduled = byNode.get("") ?? [];
    return { known, unscheduled };
  }, [all, ov]);

  const selected = podParam ? all.find(p => `${p.namespace}/${p.name}` === podParam) ?? null : null;
  const hovered = hover ? all.find(p => `${p.namespace}/${p.name}` === hover) : null;

  // The opening sentence: how many pods are failing, and -- when a rollout
  // landed shortly before the failures began -- which one.
  // "Most began at": the largest group of failures still open, not merely
  // the oldest -- six OOMKills an hour earlier are not where most of it began.
  const firstFailure = changes
    .filter(c => c.kind === "problem" && c.failing)
    .reduce<Change | undefined>((best, c) => (!best || (c.count ?? 0) > (best.count ?? 0) ? c : best), undefined);
  const suspect = firstFailure
    ? changes.find(c => c.kind === "rollout" && new Date(c.at) <= new Date(firstFailure.at)
        && new Date(firstFailure.at).getTime() - new Date(c.at).getTime() <= 20 * 60_000)
    : undefined;
  const failingNamespaces = new Set(failing.map(p => p.namespace)).size;

  useEffect(() => {
    setStreaming(false);
    setLastLines("");
    if (!selected || !canLogs) return;
    const qs = new URLSearchParams({ namespace: selected.namespace, pod: selected.name, tail: "8" });
    apiFetch(`/kubernetes/pods/logs?${qs}`).then(r => (r.ok ? r.json() : null)).then(d => setLastLines(d?.logs ?? "")).catch(() => {});
  }, [selected?.namespace, selected?.name, canLogs]); // eslint-disable-line react-hooks/exhaustive-deps

  if (error && !ov) {
    return (
      <div className="max-w-[980px] flex flex-col gap-4">
        <h1 className="m-0 text-[30px] font-medium tracking-[-0.02em]" style={{ color: "var(--red)" }}>The cluster did not answer.</h1>
        <p style={{ color: "var(--t3)" }}>{error}</p>
        <button type="button" onClick={load} className="btn-secondary self-start">Try again</button>
      </div>
    );
  }
  if (!ov || !pods) {
    return <p className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>Reading the cluster…</p>;
  }

  const wl = ov.workloads ?? [];
  const wlTotal = wl.reduce((s, w) => s + w.total, 0);
  const wlDegraded = wl.reduce((s, w) => s + w.degraded, 0);
  const short: Record<string, string> = { Deployment: "deploy", StatefulSet: "sts", DaemonSet: "ds" };
  const cpuStep = niceStep(Math.max(ov.cpu.capacity, ov.cpu.limits));
  const gib = (a: ClusterAxis): ClusterAxis => ({
    capacity: a.capacity / 2 ** 30, allocatable: a.allocatable / 2 ** 30, requests: a.requests / 2 ** 30,
    limits: a.limits / 2 ** 30, usage: a.usage / 2 ** 30,
  });
  const mem = gib(ov.memory);
  const memStep = niceStep(Math.max(mem.capacity, mem.limits));
  const where = clusterName || "this cluster";

  return (
    <div className="-mx-4 -my-6 md:-mx-8 md:-my-8 flex flex-wrap items-stretch min-h-[calc(100vh-57px)]">
      <div className="flex-[999_1_560px] min-w-0 px-4 py-6 md:px-8 md:pt-8 md:pb-16 flex flex-col gap-9">

        <section className="flex flex-col gap-5 max-w-[980px]">
          <h1 className="m-0 text-[26px] md:text-[30px] leading-[1.25] font-medium tracking-[-0.02em]" style={{ textWrap: "pretty" } as React.CSSProperties}>
            {failing.length > 0 ? (
              <>
                <span style={{ color: "var(--red)" }}>{failing.length} {plural(failing.length, "pod is", "pods are")} failing</span> on {where}.
                {firstFailure && <> Most began at {hhmm(firstFailure.at)}</>}
                {firstFailure && suspect ? (
                  <>, {Math.max(0, Math.round((new Date(firstFailure.at).getTime() - new Date(suspect.at).getTime()) / 60_000))} minutes after{" "}
                    <span className="font-mono text-[22px] md:text-[24px]" style={{ color: "var(--gold)" }}>{suspect.workload} {tagOf(suspect.image)}</span> rolled out.</>
                ) : firstFailure ? "." : null}
              </>
            ) : wlDegraded > 0 ? (
              <><span style={{ color: "var(--gold)" }}>{wlDegraded} {plural(wlDegraded, "workload has", "workloads have")} no ready replicas</span> on {where}. No pod is failing outright.</>
            ) : (
              <>All {counts.Running} running pods on {where} are healthy. {changes.length ? `${changes.length} ${plural(changes.length, "change", "changes")} in the last 6 hours.` : "Nothing changed in the last 6 hours."}</>
            )}
          </h1>
          <div className="flex gap-2.5 flex-wrap">
            {failing.length > 0 && (
              <button type="button" onClick={() => { setStateFilter("Failed"); setParam("ns", null); }} className="btn-primary">Show failing pods</button>
            )}
            {suspect && (
              <a href="/delivery" className="btn-secondary no-underline" style={{ color: "var(--text)" }}>Open {suspect.workload} in Releases</a>
            )}
            {failing.length > 0 && <a href="/kubernetes/triage" className="btn-secondary no-underline" style={{ color: "var(--text)" }}>Triage</a>}
          </div>
          {ov.degraded && ov.degraded.length > 0 && (
            <p className="text-[12.5px] m-0" style={{ color: "var(--gold)" }}>Partial data: {ov.degraded.join(", ")}.</p>
          )}
        </section>

        <section className="grid gap-0" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(170px,1fr))", borderTop: "1px solid var(--rule)" }}>
          <Figure label="Nodes ready" value={String(ov.nodes_ready)} of={` / ${ov.nodes_total}`} note={ov.oldest_node_age ? `oldest ${ov.oldest_node_age} · ${ov.kubernetes_version}` : ov.kubernetes_version}
            color={ov.nodes_ready < ov.nodes_total ? "var(--red)" : "var(--text)"} />
          <Figure label="Pods running" value={String(counts.Running)} of={ov.pod_capacity ? ` / ${ov.pod_capacity}` : ""}
            note={ov.pod_capacity ? `${Math.round((ov.pods_running / ov.pod_capacity) * 100)}% of pod slots` : undefined} />
          <Figure label="Pods failing" value={String(failing.length)} color={failing.length ? "var(--red)" : "var(--text)"}
            note={failing.length ? `in ${failingNamespaces} ${plural(failingNamespaces, "namespace", "namespaces")}` : "none"} />
          <Figure label="Workloads degraded" value={String(wlDegraded)} of={` / ${wlTotal}`} color={wlDegraded ? "var(--gold)" : "var(--text)"}
            note={wl.map(w => `${w.total} ${short[w.kind] ?? w.kind.toLowerCase()}`).join(" · ")} />
        </section>

        <section className="flex flex-col gap-3.5">
          <div className="flex items-baseline justify-between gap-4 flex-wrap">
            <h2 className="m-0 text-lg font-semibold tracking-[-0.01em]">Every pod, by node</h2>
            <div className="flex gap-4 flex-wrap">
              {STATES.map(s => (
                <button key={s} type="button" onClick={() => setStateFilter(stateFilter === s ? null : s)}
                  className="flex items-center gap-[7px] p-0 hover:!text-[var(--text)]"
                  style={{ color: !stateFilter || stateFilter === s ? "var(--t2)" : "var(--m3)" }}>
                  <span className="w-2.5 h-2.5" style={{ background: STATE_COLOR[s] }} />{s}
                  <span className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>{counts[s]}</span>
                </button>
              ))}
            </div>
          </div>
          <div className="flex gap-1.5 flex-wrap">
            {nsList.slice(0, 40).map(n => {
              const on = ns === n.name;
              return (
                <button key={n.name} type="button" onClick={() => setParam("ns", on ? null : n.name)}
                  className="h-[26px] px-[9px] rounded-[3px] font-mono text-[10.5px] flex gap-1.5 items-center hover:!border-[var(--m3)]"
                  style={{ border: `1px solid ${on ? "var(--green)" : "var(--line)"}`, background: on ? "var(--rule)" : "transparent", color: on ? "var(--text)" : "var(--t3)" }}>
                  {n.name}{n.failed > 0 && <span style={{ color: "var(--red)" }}>{n.failed}</span>}
                </button>
              );
            })}
          </div>
          <div className="h-5 font-mono text-[11px] whitespace-nowrap overflow-hidden text-ellipsis" style={{ color: "var(--t3)" }}>
            {hovered
              ? `${hovered.name}  ·  ${hovered.namespace}  ·  ${hovered.state === "Failed" ? (hovered.problems ?? []).find(x => x.severity === "critical")?.title ?? hovered.phase : hovered.state}  ·  ${hovered.restart_count} restarts`
              : "Point at a square to read it. Click to inspect."}
          </div>
          <div className="grid gap-4" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(300px,1fr))" }} onMouseLeave={() => setHover(null)}>
            {[...nodes.known, ...(nodes.unscheduled.length ? [{ name: "", list: nodes.unscheduled, cpu_pct: -1, mem_pct: -1 } as unknown as NodeSummary & { list: typeof all }] : [])].map(nd => (
              <div key={nd.name || "unscheduled"} className="flex flex-col gap-2.5 p-3.5" style={{ background: "var(--card)", border: "1px solid var(--rule)" }}>
                <div className="flex justify-between gap-2.5 items-baseline">
                  <span className="font-mono text-[11px]" style={{ color: nd.name ? "var(--text)" : "var(--gold)" }}>{nd.name || "not scheduled"}</span>
                  <span className="font-mono text-[10.5px]" style={{ color: "var(--m2)" }}>{nd.list.length} pods</span>
                </div>
                <div className="grid gap-[3px]" style={{ gridTemplateColumns: "repeat(auto-fill,11px)" }}>
                  {nd.list.map(p => {
                    const id = `${p.namespace}/${p.name}`;
                    return (
                      <span key={id} role="button" tabIndex={-1} aria-label={`${p.name}, ${p.state}`}
                        onMouseEnter={() => setHover(id)} onClick={() => setParam("pod", id)}
                        className="w-[11px] h-[11px] cursor-pointer"
                        style={{ background: STATE_COLOR[p.state], opacity: match(p) ? 1 : 0.13, outline: podParam === id ? "1.5px solid var(--text)" : "none", outlineOffset: 1 }} />
                    );
                  })}
                </div>
                {nd.cpu_pct >= 0 && ov.metrics_available && (
                  <div className="grid gap-2 items-center font-mono text-[10px]" style={{ gridTemplateColumns: "30px minmax(0,1fr) 34px", color: "var(--m2)" }}>
                    <span>cpu</span>
                    <span className="h-[3px]" style={{ background: "var(--track)" }}><span className="block h-full" style={{ width: `${Math.min(100, nd.cpu_pct)}%`, background: loadColor(nd.cpu_pct) }} /></span>
                    <span className="text-right" style={{ color: loadColor(nd.cpu_pct) }}>{Math.round(nd.cpu_pct)}%</span>
                    <span>mem</span>
                    <span className="h-[3px]" style={{ background: "var(--track)" }}><span className="block h-full" style={{ width: `${Math.min(100, nd.mem_pct)}%`, background: loadColor(nd.mem_pct) }} /></span>
                    <span className="text-right" style={{ color: loadColor(nd.mem_pct) }}>{Math.round(nd.mem_pct)}%</span>
                  </div>
                )}
              </div>
            ))}
          </div>
        </section>

        <section className="flex flex-col gap-[22px]">
          <h2 className="m-0 text-lg font-semibold tracking-[-0.01em]">Capacity</h2>
          <Ruler title="CPU" unit="cores" axis={ov.cpu} metrics={ov.metrics_available} step={cpuStep} />
          <Ruler title="Memory" unit="GiB" axis={mem} metrics={ov.metrics_available} step={memStep} />
          <p className="m-0 text-[12.5px] max-w-[720px]" style={{ color: "var(--m2)" }}>
            Hatched area is past allocatable capacity: limits there can only be met if other pods stay under theirs.
          </p>
        </section>

        {((ov.top_namespaces ?? []).length > 0 || (ov.top_pods_cpu ?? []).length > 0) && ov.metrics_available && (
          <section className="flex flex-col gap-3.5">
            <h2 className="m-0 text-lg font-semibold tracking-[-0.01em]">Where the load sits</h2>
            <div className="grid gap-8" style={{ gridTemplateColumns: "repeat(auto-fit,minmax(280px,1fr))" }}>
              {[
                { title: "Namespaces", rows: (ov.top_namespaces ?? []).slice(0, 6).map(n => ({ key: n.name, label: n.name, cpu: n.cpu_cores, onClick: () => setParam("ns", n.name) })) },
                { title: "Pods", rows: (ov.top_pods_cpu ?? []).slice(0, 6).map(p => ({ key: `${p.namespace}/${p.name}`, label: p.name, cpu: p.cpu_cores, onClick: () => setParam("pod", `${p.namespace}/${p.name}`) })) },
              ].map(block => {
                const max = Math.max(...block.rows.map(r => r.cpu), 0.001);
                return (
                  <div key={block.title} className="flex flex-col">
                    <span className="text-[12.5px] pb-2" style={{ color: "var(--t3)" }}>{block.title}, by CPU</span>
                    {block.rows.map(r => (
                      <button key={r.key} type="button" onClick={r.onClick}
                        className="grid gap-3 items-center py-2 text-left hover:bg-[var(--hover)]"
                        style={{ gridTemplateColumns: "minmax(0,1fr) 90px 64px", borderTop: "1px solid var(--rule2)" }}>
                        <span className="font-mono text-[11.5px] truncate">{r.label}</span>
                        <span className="h-[3px]" style={{ background: "var(--track)" }}><span className="block h-full" style={{ width: `${(r.cpu / max) * 100}%`, background: "var(--green)" }} /></span>
                        <span className="font-mono text-[11px] text-right" style={{ color: "var(--t3)" }}>{r.cpu < 1 ? `${Math.round(r.cpu * 1000)}m` : r.cpu.toFixed(2)}</span>
                      </button>
                    ))}
                  </div>
                );
              })}
            </div>
          </section>
        )}
      </div>

      <aside className="flex-[1_1_320px] max-w-full min-w-0" style={{ borderLeft: "1px solid var(--rule)", borderTop: "1px solid var(--rule)", background: "var(--panel)" }}>
        <div className="sticky top-[57px] max-h-[calc(100vh-57px)] overflow-y-auto px-[22px] pt-6 pb-10 flex flex-col gap-5">
          {!selected ? (
            <>
              <div className="flex justify-between items-baseline">
                <h2 className="m-0 text-[15px] font-semibold">What changed</h2>
                <span className="text-xs" style={{ color: "var(--m2)" }}>last 6 hours</span>
              </div>
              {podParam && <p className="m-0 text-[12.5px]" style={{ color: "var(--t3)" }}>{podParam} is gone: it was replaced or deleted since.</p>}
              {changes.length === 0 ? (
                <p className="m-0 text-[13px]" style={{ color: "var(--t3)" }}>No rollouts, failures or replica changes recorded.</p>
              ) : (
                <div className="flex flex-col">
                  {changes.map((e, i) => (
                    <div key={i} className="grid gap-2.5 pb-[18px]" style={{ gridTemplateColumns: "44px 12px minmax(0,1fr)" }}>
                      <span className="font-mono text-[10.5px] pt-0.5" style={{ color: "var(--m2)" }}>{hhmm(e.at)}</span>
                      <span className="flex flex-col items-center gap-1">
                        <span className="w-2 h-2 mt-1" style={{ background: TONE[e.tone] }} />
                        <span className="flex-1 w-px" style={{ background: "var(--track)" }} />
                      </span>
                      <div className="flex flex-col gap-1 min-w-0">
                        <span className="leading-[1.4]">{e.text}</span>
                        <span className="text-[12.5px] leading-[1.45] break-words" style={{ color: "var(--t3)" }}>{e.sub}</span>
                        {e.failing && (
                          <button type="button" onClick={() => { setStateFilter("Failed"); setParam("ns", e.namespace ?? null); }}
                            className="self-start mt-0.5 p-0 text-[12.5px] hover:!text-[var(--green2)]" style={{ color: "var(--green)" }}>
                            Show in the field →
                          </button>
                        )}
                        {e.kind === "rollout" && (
                          <a href="/delivery" className="self-start mt-0.5 text-[12.5px] no-underline hover:!text-[var(--green2)]" style={{ color: "var(--green)" }}>Open in Releases →</a>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </>
          ) : (
            <>
              <button type="button" onClick={() => setParam("pod", null)} className="self-start p-0 text-[12.5px] hover:!text-[var(--text)]" style={{ color: "var(--t3)" }}>← What changed</button>
              <div className="flex flex-col gap-2">
                {(() => {
                  const reason = (selected.problems ?? []).find(x => x.severity === "critical");
                  const color = selected.state === "Running" ? "var(--green)" : STATE_COLOR[selected.state];
                  return (
                    <span className="flex items-center gap-2 text-[13px]" style={{ color }}>
                      <span className="w-[9px] h-[9px]" style={{ background: color }} />{reason?.title ?? selected.phase}
                    </span>
                  );
                })()}
                <span className="font-mono text-[13px] break-all leading-[1.5]">{selected.name}</span>
              </div>
              <dl className="m-0 grid gap-y-[9px] gap-x-2.5 text-[13px]" style={{ gridTemplateColumns: "80px minmax(0,1fr)" }}>
                <dt style={{ color: "var(--m2)" }}>Namespace</dt><dd className="m-0 font-mono text-[11.5px]">{selected.namespace}</dd>
                <dt style={{ color: "var(--m2)" }}>Node</dt><dd className="m-0 font-mono text-[11.5px]">{selected.node_name || "—"}</dd>
                <dt style={{ color: "var(--m2)" }}>Image</dt><dd className="m-0 font-mono text-[11.5px] break-all">{selected.image}</dd>
                <dt style={{ color: "var(--m2)" }}>Restarts</dt><dd className="m-0">{selected.restart_count}</dd>
                <dt style={{ color: "var(--m2)" }}>Age</dt><dd className="m-0">{selected.age}</dd>
              </dl>
              {(selected.problems ?? []).filter(x => x.severity !== "info").map((x, i) => (
                <div key={i} className="p-3 flex flex-col gap-1"
                  style={{ background: x.severity === "critical" ? "rgba(248,113,113,.07)" : "rgba(251,191,36,.06)", border: `1px solid ${x.severity === "critical" ? "rgba(248,113,113,.25)" : "rgba(251,191,36,.25)"}` }}>
                  <span className="font-semibold" style={{ color: x.severity === "critical" ? "var(--red)" : "var(--gold)" }}>{x.title}</span>
                  <span className="text-[12.5px] leading-[1.45]" style={{ color: "var(--t2)" }}>{x.detail}</span>
                </div>
              ))}
              {canLogs && !streaming && (
                <div className="flex flex-col gap-2">
                  <span className="text-[12.5px]" style={{ color: "var(--t3)" }}>Last lines</span>
                  <pre className="m-0 p-3 font-mono text-[10.5px] leading-[1.7] whitespace-pre-wrap break-all" style={{ background: "var(--side)", border: "1px solid var(--rule)", color: "var(--t2)" }}>
                    {lastLines.trim() || "(no output)"}
                  </pre>
                  <button type="button" onClick={() => setStreaming(true)} className="btn-secondary self-start">Stream logs</button>
                </div>
              )}
              {canLogs && streaming && (
                <PodLogs namespace={selected.namespace} pod={selected.name} containers={(selected.containers ?? []).map(c => c.name)} />
              )}
              <PodActions namespace={selected.namespace} pod={selected.name} onChanged={load} />
            </>
          )}
        </div>
      </aside>
    </div>
  );
}
