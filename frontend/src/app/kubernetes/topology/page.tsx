"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";

interface TopoNode {
  id: string;
  namespace: string;
  kind: string;
  name: string;
  services: string[];
  hosts: string[];
  replicas: number;
  status: string;
  external: boolean;
  entry_point: boolean;
  depth: number;
  in_degree: number;
  out_degree: number;
  first_seen: string;
  last_seen: string;
}

interface TopoEdge {
  from: string;
  to: string;
  port: string;
  protocol: string;
  source: string;
  evidence: string;
  confidence: string;
  observed: boolean;
  first_seen: string;
  last_seen: string;
}

interface TopoResponse {
  nodes: TopoNode[];
  edges: TopoEdge[];
  namespaces: string[];
  stats: {
    nodes: number;
    edges: number;
    isolated: number;
    observed: number;
    by_source: Record<string, number>;
    by_confidence: Record<string, number>;
  };
  last_poll: string | null;
  last_run: string | null;
  last_error: string;
  declared_only: boolean;
}

/** Where an edge was read from. The colour is the legend. */
const SOURCES: Record<string, { label: string; stroke: string; chip: string; hint: string }> = {
  ingress: {
    label: "Ingress", stroke: "stroke-emerald-500", chip: "bg-emerald-500",
    hint: "An Ingress or gateway routes to this workload",
  },
  env: {
    label: "Env var", stroke: "stroke-sky-500", chip: "bg-sky-500",
    hint: "A container env var, command or argument names the target",
  },
  configmap: {
    label: "ConfigMap", stroke: "stroke-indigo-500", chip: "bg-indigo-500",
    hint: "A ConfigMap value loaded as an env var names the target",
  },
  mount: {
    label: "Config file", stroke: "stroke-violet-500", chip: "bg-violet-500",
    hint: "A mounted ConfigMap file names the target",
  },
  networkpolicy: {
    label: "NetworkPolicy", stroke: "stroke-zinc-400", chip: "bg-zinc-400",
    hint: "A NetworkPolicy allows this traffic — permission, not a proven call",
  },
  istio: {
    label: "Istio", stroke: "stroke-amber-500", chip: "bg-amber-500",
    hint: "An Istio VirtualService bound to a gateway routes here",
  },
  externalname: {
    label: "ExternalName", stroke: "stroke-rose-500", chip: "bg-rose-500",
    hint: "An ExternalName Service forwards out of the cluster",
  },
};
const src = (s: string) => SOURCES[s] ?? SOURCES.env;

const STATUS: Record<string, { fill: string; ring: string; label: string }> = {
  healthy:     { fill: "fill-brand-green", ring: "stroke-brand-green",  label: "Healthy" },
  progressing: { fill: "fill-sky-500",     ring: "stroke-sky-500",      label: "Progressing" },
  degraded:    { fill: "fill-red-500",     ring: "stroke-red-500",      label: "Degraded" },
  scaled_zero: { fill: "fill-zinc-400",    ring: "stroke-zinc-400",     label: "Scaled to zero" },
  unknown:     { fill: "fill-zinc-400",    ring: "stroke-zinc-400",     label: "Unknown" },
};
const st = (s: string) => STATUS[s] ?? STATUS.unknown;

const CONFIDENCE: Record<string, { label: string; cls: string; dash?: string }> = {
  high:   { label: "High",   cls: "text-brand-green" },
  medium: { label: "Medium", cls: "text-amber-600 dark:text-amber-400", dash: "6 4" },
  low:    { label: "Low",    cls: "text-zinc-500 dark:text-zinc-400", dash: "2 5" },
};

/** The filter controls use the theme's input variables, the same as every other
 *  filter bar in the app. A transparent background here leaves the browser to
 *  paint the native dropdown popup, which it does in the wrong palette. */
const INPUT_CLS =
  "bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]";

const NODE_W = 200;
const NODE_H = 54;
const COL_GAP = 110;
const ROW_GAP = 24;

export default function TopologyPage() {
  const [data, setData] = useState<TopoResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [error, setError] = useState("");

  const [nsFilter, setNsFilter] = useState("");
  const [minConfidence, setMinConfidence] = useState("");
  const [hiddenSources, setHiddenSources] = useState<Record<string, boolean>>({});
  const [includeExternal, setIncludeExternal] = useState(true);
  const [search, setSearch] = useState("");
  const [selected, setSelected] = useState<string | null>(null);

  const [view, setView] = useState({ x: 40, y: 24, k: 1 });
  const dragRef = useRef<{ x: number; y: number; vx: number; vy: number } | null>(null);
  const svgRef = useRef<SVGSVGElement | null>(null);

  const load = useCallback(async () => {
    const qs = new URLSearchParams();
    if (nsFilter) qs.set("namespace", nsFilter);
    if (minConfidence) qs.set("min_confidence", minConfidence);
    if (!includeExternal) qs.set("include_external", "false");
    try {
      const res = await apiFetch(`/kubernetes/topology?${qs}`);
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.error ?? `Request failed (${res.status})`);
        return;
      }
      setError("");
      setData(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach the API");
    } finally {
      setLoading(false);
    }
  }, [nsFilter, minConfidence, includeExternal]);

  useEffect(() => { load(); }, [load]);

  const refresh = async () => {
    setRefreshing(true);
    const res = await apiFetch("/kubernetes/topology/refresh", { method: "POST" });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setError(body.error ?? "Refresh needs an admin role");
    }
    await load();
    setRefreshing(false);
  };

  /** Client-side filters: source toggles, then the search focus. */
  const filtered = useMemo(() => {
    if (!data) return { nodes: [] as TopoNode[], edges: [] as TopoEdge[] };

    let edges = data.edges.filter(e => !hiddenSources[e.source]);
    let nodeIds = new Set<string>();
    edges.forEach(e => { nodeIds.add(e.from); nodeIds.add(e.to); });

    const q = search.trim().toLowerCase();
    if (q) {
      // Keep what matches plus its direct neighbours, so a search reads as
      // "this service and what it touches" rather than a lone box.
      const hits = new Set(
        data.nodes.filter(n => n.name.toLowerCase().includes(q) || n.namespace.toLowerCase().includes(q)).map(n => n.id)
      );
      edges = edges.filter(e => hits.has(e.from) || hits.has(e.to));
      nodeIds = new Set<string>();
      edges.forEach(e => { nodeIds.add(e.from); nodeIds.add(e.to); });
      data.nodes.forEach(n => { if (hits.has(n.id)) nodeIds.add(n.id); });
    }

    return { nodes: data.nodes.filter(n => nodeIds.has(n.id)), edges };
  }, [data, hiddenSources, search]);

  /** Columns by depth; rows in name order inside each column. */
  const layout = useMemo(() => {
    const columns = new Map<number, TopoNode[]>();
    filtered.nodes.forEach(n => {
      const col = columns.get(n.depth) ?? [];
      col.push(n);
      columns.set(n.depth, col);
    });
    const depths = Array.from(columns.keys()).sort((a, b) => a - b);

    const pos = new Map<string, { x: number; y: number }>();
    let width = 0;
    let height = 0;
    depths.forEach((d, ci) => {
      const col = columns.get(d)!;
      col.sort((a, b) => (a.namespace + a.name).localeCompare(b.namespace + b.name));
      const x = ci * (NODE_W + COL_GAP);
      col.forEach((n, ri) => {
        const y = ri * (NODE_H + ROW_GAP);
        pos.set(n.id, { x, y });
        height = Math.max(height, y + NODE_H);
      });
      width = Math.max(width, x + NODE_W);
    });
    return { pos, width, height, columns: depths.length };
  }, [filtered.nodes]);

  const nodeById = useMemo(() => {
    const m = new Map<string, TopoNode>();
    filtered.nodes.forEach(n => m.set(n.id, n));
    return m;
  }, [filtered.nodes]);

  const selectedEdges = useMemo(() => {
    if (!selected) return { out: [] as TopoEdge[], in: [] as TopoEdge[] };
    return {
      out: filtered.edges.filter(e => e.from === selected),
      in: filtered.edges.filter(e => e.to === selected),
    };
  }, [selected, filtered.edges]);

  const fit = useCallback(() => {
    const el = svgRef.current;
    if (!el || layout.width === 0) return;
    const box = el.getBoundingClientRect();
    const k = Math.min((box.width - 80) / layout.width, (box.height - 60) / layout.height, 1.4);
    setView({ x: 40, y: 24, k: Math.max(0.15, k) });
  }, [layout.width, layout.height]);

  useEffect(() => { fit(); }, [fit]);

  const onWheel = (e: React.WheelEvent) => {
    e.preventDefault();
    setView(v => {
      const k = Math.min(2.5, Math.max(0.12, v.k * (e.deltaY < 0 ? 1.12 : 0.89)));
      const box = svgRef.current?.getBoundingClientRect();
      if (!box) return { ...v, k };
      // Keep the point under the cursor fixed while zooming.
      const cx = e.clientX - box.left;
      const cy = e.clientY - box.top;
      return { k, x: cx - ((cx - v.x) * k) / v.k, y: cy - ((cy - v.y) * k) / v.k };
    });
  };

  const onPointerDown = (e: React.PointerEvent) => {
    dragRef.current = { x: e.clientX, y: e.clientY, vx: view.x, vy: view.y };
    (e.target as Element).setPointerCapture?.(e.pointerId);
  };
  const onPointerMove = (e: React.PointerEvent) => {
    const d = dragRef.current;
    if (!d) return;
    setView(v => ({ ...v, x: d.vx + (e.clientX - d.x), y: d.vy + (e.clientY - d.y) }));
  };
  const onPointerUp = () => { dragRef.current = null; };

  const sourceCounts = data?.stats.by_source ?? {};
  const selectedNode = selected ? nodeById.get(selected) : undefined;

  /**
   * Why the canvas is empty. "Nothing discovered yet" is only true before the
   * first pass finishes — saying it after a failed or fruitless pass sends you
   * to wait for a poll that already happened.
   */
  const emptyReason = (() => {
    if (!data) return "";
    if (data.last_error) return "Discovery failed — see the message above.";
    if (data.edges.length > 0) return "No dependencies match these filters.";
    if (!data.last_run && !data.last_poll) {
      return "Nothing discovered yet — the first pass runs about a minute after startup.";
    }
    if (data.stats.nodes === 0 && data.stats.isolated === 0) {
      return "Discovery ran but found no workloads — check the cluster connection.";
    }
    return "Discovery ran and found no declared dependencies yet.";
  })();

  const EdgeList = ({ items, dir }: { items: TopoEdge[]; dir: "out" | "in" }) => (
    <ul className="space-y-2">
      {items.length === 0 && (
        <li className="text-xs text-zinc-500 dark:text-zinc-400">
          {dir === "out" ? "No known dependencies." : "Nothing known to call this."}
        </li>
      )}
      {items.map((e, i) => {
        const other = nodeById.get(dir === "out" ? e.to : e.from);
        const conf = CONFIDENCE[e.confidence] ?? CONFIDENCE.low;
        return (
          <li key={i} className="rounded-lg border border-zinc-200 dark:border-zinc-800 p-2.5">
            <div className="flex items-center gap-2">
              <span className={`w-2 h-2 rounded-full shrink-0 ${src(e.source).chip}`} />
              <button
                onClick={() => other && setSelected(other.id)}
                className="text-sm font-medium truncate hover:underline text-left"
              >
                {other ? other.name : (dir === "out" ? e.to : e.from)}
              </button>
              {e.port && (
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800 shrink-0">
                  {e.protocol}:{e.port}
                </span>
              )}
            </div>
            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-1 break-all">{e.evidence}</p>
            <p className="text-[10px] mt-1">
              <span className="text-zinc-500 dark:text-zinc-400">{src(e.source).label} · </span>
              <span className={conf.cls}>{conf.label} confidence</span>
            </p>
          </li>
        );
      })}
    </ul>
  );

  return (
    <div className="p-6 max-w-[1800px] mx-auto">
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-lg font-semibold">Service Map</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
            Discovered from the cluster itself — no registration, no instrumentation, no agent.
            Every edge is a declaration the cluster makes about itself: a Service name in an env
            var, an Ingress backend, a NetworkPolicy peer.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={fit}
            className="px-3 py-1.5 text-sm rounded-lg border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800"
          >
            Fit
          </button>
          <button
            onClick={refresh}
            disabled={refreshing}
            className="px-3 py-1.5 text-sm rounded-lg bg-brand-green text-white disabled:opacity-60"
          >
            {refreshing ? "Rediscovering…" : "Rediscover"}
          </button>
        </div>
      </div>

      {data?.declared_only && (
        <div className="mt-4 rounded-lg border border-amber-300/60 dark:border-amber-700/50 bg-amber-50 dark:bg-amber-950/30 p-3 text-xs text-amber-900 dark:text-amber-200">
          <strong className="font-semibold">This map is intent, not traffic.</strong>{" "}
          It says what is wired up to call what. It cannot tell you whether a call ever happens,
          how often, or how slow it is — and it misses any dependency whose address is baked into
          an image instead of declared in the cluster. Measured traffic needs a per-node agent,
          because a pod can only observe its own network namespace.
        </div>
      )}

      {error && (
        <div className="mt-4 rounded-lg border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/30 p-3 text-sm text-red-700 dark:text-red-300">
          {error}
        </div>
      )}

      {data?.last_error && (
        <div className="mt-4 rounded-lg border border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/30 p-3 text-sm text-red-700 dark:text-red-300">
          <strong className="font-semibold">Discovery failed.</strong> {data.last_error}
          <p className="mt-1 text-xs opacity-80">
            The map is whatever the last successful pass found. A failure here is almost always a
            missing RBAC rule or no reachable cluster — the ServiceAccount needs read access to
            deployments, statefulsets, daemonsets and services at minimum.
          </p>
        </div>
      )}

      {/* Filters */}
      <div className="mt-4 flex flex-wrap items-center gap-2">
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Focus a service…"
          className={`px-3 py-1.5 text-sm rounded-lg w-56 ${INPUT_CLS}`}
        />
        <select
          value={nsFilter}
          onChange={e => setNsFilter(e.target.value)}
          className={`px-3 py-1.5 text-sm rounded-lg ${INPUT_CLS}`}
        >
          <option value="">All namespaces</option>
          {(data?.namespaces ?? []).map(ns => <option key={ns} value={ns}>{ns}</option>)}
        </select>
        <select
          value={minConfidence}
          onChange={e => setMinConfidence(e.target.value)}
          className={`px-3 py-1.5 text-sm rounded-lg ${INPUT_CLS}`}
        >
          <option value="">Any confidence</option>
          <option value="medium">Medium and up</option>
          <option value="high">High only</option>
        </select>
        <label className="flex items-center gap-2 text-sm px-2 text-[var(--input-fg)]">
          <input
            type="checkbox"
            checked={includeExternal}
            onChange={e => setIncludeExternal(e.target.checked)}
            className="accent-brand-green w-4 h-4"
          />
          External targets
        </label>

        <span className="w-px h-6 bg-zinc-200 dark:bg-zinc-800 mx-1" />

        {Object.keys(SOURCES).map(key => {
          const count = sourceCounts[key] ?? 0;
          const off = hiddenSources[key];
          return (
            <button
              key={key}
              title={src(key).hint}
              onClick={() => setHiddenSources(h => ({ ...h, [key]: !h[key] }))}
              className={`flex items-center gap-1.5 px-2 py-1 text-xs rounded-lg border transition
                ${off
                  ? "border-[var(--input-border)] text-zinc-400 dark:text-zinc-600 line-through decoration-1"
                  : `${INPUT_CLS} font-medium`}`}
            >
              <span className={`w-2 h-2 rounded-full ${off ? "bg-zinc-300 dark:bg-zinc-700" : src(key).chip}`} />
              {src(key).label}
              <span className="text-zinc-400 dark:text-zinc-500">{count}</span>
            </button>
          );
        })}
      </div>

      {data && !data.last_error && data.last_run && data.edges.length === 0 && (
        <div className="mt-4 rounded-lg border border-zinc-200 dark:border-zinc-800 p-3 text-xs text-zinc-600 dark:text-zinc-300">
          <strong className="font-semibold">Discovery ran, but every source came back empty.</strong>{" "}
          The workloads were read, so the cluster connection is fine — what is missing is the
          evidence. Most edges come from ConfigMaps and container env vars, so the usual cause is
          the ServiceAccount lacking <code className="font-mono">configmaps</code> read access:
          <code className="font-mono ml-1">
            kubectl auth can-i list configmaps -A --as=system:serviceaccount:&lt;ns&gt;:commitkube
          </code>
        </div>
      )}

      {data && (
        <p className="mt-3 text-xs text-zinc-500 dark:text-zinc-400">
          {filtered.nodes.length} services · {filtered.edges.length} dependencies
          {data.stats.isolated > 0 && ` · ${data.stats.isolated} with no known dependency`}
          {(data.last_run ?? data.last_poll) &&
            ` · discovered ${new Date((data.last_run ?? data.last_poll)!).toLocaleString()}`}
        </p>
      )}

      <div className="mt-3 grid grid-cols-1 xl:grid-cols-[1fr_340px] gap-4">
        <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 overflow-hidden bg-zinc-50/60 dark:bg-zinc-900/40">
          <svg
            ref={svgRef}
            className="w-full h-[620px] touch-none cursor-grab active:cursor-grabbing"
            onWheel={onWheel}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerLeave={onPointerUp}
          >
            <defs>
              <marker id="topo-arrow" viewBox="0 0 10 10" refX="9" refY="5"
                markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                <path d="M 0 1 L 9 5 L 0 9 z" fill="context-stroke" />
              </marker>
            </defs>

            <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
              {filtered.edges.map((e, i) => {
                const a = layout.pos.get(e.from);
                const b = layout.pos.get(e.to);
                if (!a || !b) return null;
                const x1 = a.x + NODE_W;
                const y1 = a.y + NODE_H / 2;
                const x2 = b.x;
                const y2 = b.y + NODE_H / 2;
                const dx = Math.max(40, Math.abs(x2 - x1) * 0.45);
                const active = !selected || e.from === selected || e.to === selected;
                const conf = CONFIDENCE[e.confidence] ?? CONFIDENCE.low;
                return (
                  <path
                    key={i}
                    d={`M ${x1} ${y1} C ${x1 + dx} ${y1}, ${x2 - dx} ${y2}, ${x2} ${y2}`}
                    className={`${src(e.source).stroke} ${active ? "opacity-70" : "opacity-10"}`}
                    strokeWidth={e.observed ? 2.2 : 1.4}
                    strokeDasharray={conf.dash}
                    fill="none"
                    markerEnd="url(#topo-arrow)"
                  />
                );
              })}

              {filtered.nodes.map(n => {
                const p = layout.pos.get(n.id);
                if (!p) return null;
                const isSel = selected === n.id;
                const dim = selected
                  && !isSel
                  && !filtered.edges.some(e =>
                    (e.from === selected && e.to === n.id) || (e.to === selected && e.from === n.id))
                  ? "opacity-25" : "";
                return (
                  <g
                    key={n.id}
                    transform={`translate(${p.x},${p.y})`}
                    className={`cursor-pointer ${dim}`}
                    onClick={() => setSelected(isSel ? null : n.id)}
                  >
                    <rect
                      width={NODE_W} height={NODE_H} rx={10}
                      className={`fill-white dark:fill-zinc-900 ${isSel ? st(n.status).ring : "stroke-zinc-300 dark:stroke-zinc-700"}`}
                      strokeWidth={isSel ? 2.2 : 1}
                      strokeDasharray={n.external ? "5 4" : undefined}
                    />
                    <circle cx={14} cy={NODE_H / 2} r={4} className={st(n.status).fill} />
                    <text x={28} y={22} className="fill-zinc-900 dark:fill-zinc-100 text-[12px] font-medium">
                      {n.name.length > 22 ? n.name.slice(0, 21) + "…" : n.name}
                    </text>
                    <text x={28} y={38} className="fill-zinc-500 dark:fill-zinc-400 text-[10px]">
                      {n.external ? "external" : `${n.namespace} · ${n.kind}`}
                    </text>
                    {n.entry_point && (
                      <text x={NODE_W - 10} y={18} textAnchor="end" className="fill-emerald-600 dark:fill-emerald-400 text-[9px]">
                        entry
                      </text>
                    )}
                  </g>
                );
              })}
            </g>

            {!loading && filtered.nodes.length === 0 && (
              <text x="50%" y="50%" textAnchor="middle" className="fill-zinc-500 text-sm">
                {emptyReason}
              </text>
            )}
          </svg>
        </div>

        {/* Detail panel */}
        <div className="rounded-xl border border-zinc-200 dark:border-zinc-800 p-4 h-[620px] overflow-y-auto">
          {!selectedNode && (
            <>
              <h2 className="text-sm font-semibold">Legend</h2>
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
                Click a service to see what it depends on and what depends on it, with the exact
                declaration each edge was read from.
              </p>
              <ul className="mt-4 space-y-2">
                {Object.entries(SOURCES).map(([key, s]) => (
                  <li key={key} className="flex items-start gap-2 text-xs">
                    <span className={`w-2 h-2 rounded-full mt-1 shrink-0 ${s.chip}`} />
                    <span><strong className="font-medium">{s.label}</strong> — {s.hint}</span>
                  </li>
                ))}
              </ul>
              <h3 className="text-xs font-semibold mt-5">Line style</h3>
              <ul className="mt-2 space-y-1.5 text-xs text-zinc-600 dark:text-zinc-300">
                <li>Solid — high confidence: the name resolves exactly as DNS would.</li>
                <li>Dashed — medium: an external host, or a mesh route.</li>
                <li>Dotted — low: a NetworkPolicy allows it; nothing says it happens.</li>
                <li>A dashed box is a target outside the cluster.</li>
              </ul>
            </>
          )}

          {selectedNode && (
            <>
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <h2 className="text-sm font-semibold break-all">{selectedNode.name}</h2>
                  <p className="text-xs text-zinc-500 dark:text-zinc-400">
                    {selectedNode.external ? "External target" : `${selectedNode.namespace} · ${selectedNode.kind}`}
                  </p>
                </div>
                <button onClick={() => setSelected(null)} className="text-xs text-zinc-500 hover:underline shrink-0">
                  clear
                </button>
              </div>

              <div className="mt-3 flex flex-wrap gap-1.5 text-[10px]">
                {!selectedNode.external && (
                  <span className="px-1.5 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800">
                    {st(selectedNode.status).label}
                  </span>
                )}
                {selectedNode.replicas > 0 && (
                  <span className="px-1.5 py-0.5 rounded bg-zinc-100 dark:bg-zinc-800">
                    {selectedNode.replicas} replica{selectedNode.replicas === 1 ? "" : "s"}
                  </span>
                )}
                {selectedNode.services.map(s => (
                  <span key={s} className="px-1.5 py-0.5 rounded bg-sky-100 dark:bg-sky-950/50 text-sky-700 dark:text-sky-300">
                    svc/{s}
                  </span>
                ))}
              </div>

              {selectedNode.hosts.length > 0 && (
                <p className="mt-2 text-[11px] text-zinc-500 dark:text-zinc-400 break-all">
                  {selectedNode.hosts.join(", ")}
                </p>
              )}

              <h3 className="text-xs font-semibold mt-5 mb-2">
                Depends on ({selectedEdges.out.length})
              </h3>
              <EdgeList items={selectedEdges.out} dir="out" />

              <h3 className="text-xs font-semibold mt-5 mb-2">
                Depended on by ({selectedEdges.in.length})
              </h3>
              <EdgeList items={selectedEdges.in} dir="in" />
            </>
          )}
        </div>
      </div>
    </div>
  );
}
