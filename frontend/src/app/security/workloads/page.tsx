"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { statusStyle } from "@/app/components/k8s/status";

interface Finding {
  kind: string; severity: string; title: string; detail: string; container?: string;
}
interface Row {
  namespace: string; pod: string; workload: string; node: string;
  findings: Finding[]; worst: string;
}
interface SummaryRow { kind: string; severity: string; title: string; pods: number }

interface Payload {
  pods: Row[] | null;
  totals: Record<string, number>;
  summary: SummaryRow[] | null;
  scanned: number;
}

const toneOf = (severity: string) =>
  statusStyle(severity === "critical" ? "critical" : severity === "warning" ? "warning" : "unknown");

export default function Page() {
  const [data, setData] = useState<Payload | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [kindFilter, setKindFilter] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/kubernetes/pod-security");
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
      setError("");
      setData(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const rows = useMemo(() => {
    let list = data?.pods ?? [];
    if (kindFilter) list = list.filter(r => r.findings.some(f => f.kind === kindFilter));
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(r =>
        r.pod.toLowerCase().includes(q) || r.namespace.toLowerCase().includes(q) ||
        r.workload.toLowerCase().includes(q));
    }
    return list;
  }, [data, kindFilter, search]);

  if (loading) return <div className="p-6 text-zinc-500">Reading pod specs…</div>;

  if (error) {
    return (
      <div className="p-6 max-w-[1500px] mx-auto">
        <div className="glass-card p-4 border-red-500/30 text-sm">
          <p className="text-red-500 dark:text-red-400 font-medium">Could not read the cluster</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1 break-words">{error}</p>
        </div>
      </div>
    );
  }
  if (!data) return null;

  const t = data.totals ?? {};

  return (
    <div className="p-4 max-w-[1600px] mx-auto space-y-3">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-lg font-semibold">Workload Security</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
            What each pod is <em>permitted</em> to do, read from its spec. A pod can be perfectly healthy and
            still be one YAML line away from being the node — nothing in a health check notices that.
          </p>
        </div>
        <button onClick={load}
          className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition">
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
        {([["critical", "Critical", "text-red-500 dark:text-red-400"],
           ["warning", "Warning", "text-amber-600 dark:text-amber-400"],
           ["info", "Info", "text-zinc-500 dark:text-zinc-400"],
           ["healthy", "Clean", "text-brand-green"]] as [string, string, string][]).map(([k, label, tone]) => (
          <div key={k} className="glass-card p-4">
            <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
            <p className={`text-xl font-semibold mt-0.5 tabular-nums ${tone}`}>{t[k] ?? 0}</p>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">pods</p>
          </div>
        ))}
      </div>

      {/* Grouped first: "forty pods run as root" is one decision, where forty
          rows are forty things to read. */}
      <section className="glass-card p-4">
        <h2 className="text-sm font-semibold mb-3">By finding</h2>
        {(data.summary ?? []).length === 0 ? (
          <p className="text-xs text-zinc-500">Nothing found across {data.scanned} pods.</p>
        ) : (
          <div className="space-y-1">
            {(data.summary ?? []).map(sRow => {
              const s = toneOf(sRow.severity);
              const active = kindFilter === sRow.kind;
              return (
                <button key={sRow.kind}
                  onClick={() => setKindFilter(active ? null : sRow.kind)}
                  className={`w-full flex items-center gap-3 px-3 py-2 rounded-lg text-left transition ${
                    active ? "bg-brand-green/10 ring-1 ring-brand-green/30" : "hover:bg-[var(--color-surface-hover)]"
                  }`}>
                  <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${s.dot}`} />
                  <span className="flex-1 text-sm truncate">{sRow.title}</span>
                  <span className={`text-xs ${s.text}`}>{sRow.severity}</span>
                  <span className="text-sm tabular-nums w-12 text-right">{sRow.pods}</span>
                </button>
              );
            })}
          </div>
        )}
      </section>

      <div className="flex flex-wrap items-center gap-2">
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search pod, namespace or workload…"
          className="flex-1 min-w-[240px] px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
        {kindFilter && (
          <button onClick={() => setKindFilter(null)} className="px-3 py-2 text-sm text-zinc-500 hover:text-brand-green transition">
            Clear filter
          </button>
        )}
        <span className="text-sm text-zinc-500 dark:text-zinc-400">
          {rows.length} of {data.scanned} pods
        </span>
      </div>

      <div className="space-y-2">
        {rows.map(r => {
          const s = toneOf(r.worst);
          const key = `${r.namespace}/${r.pod}`;
          const open = expanded === key;
          return (
            <div key={key} className="glass-card overflow-hidden">
              <button onClick={() => setExpanded(open ? null : key)}
                className="w-full flex flex-wrap items-center gap-3 px-4 py-3 text-left hover:bg-[var(--color-surface-hover)] transition">
                <span className={`w-2 h-2 rounded-full shrink-0 ${s.dot}`} />
                <span className="font-mono text-sm truncate max-w-[300px]">{r.pod}</span>
                <span className="text-xs text-zinc-500 dark:text-zinc-400">{r.namespace}</span>
                <span className="flex-1" />
                <span className="text-xs text-zinc-500 dark:text-zinc-400">
                  {r.findings.length} finding{r.findings.length === 1 ? "" : "s"}
                </span>
                <span className="text-xs text-zinc-500">{open ? "−" : "+"}</span>
              </button>

              {open && (
                <div className="px-4 pb-3 space-y-2 border-t border-[var(--card-border)] pt-3">
                  {r.findings.map((f, i) => {
                    const fs = toneOf(f.severity);
                    return (
                      <div key={`${f.kind}-${i}`} className="flex items-start gap-2">
                        <span className={`w-1.5 h-1.5 rounded-full shrink-0 mt-1.5 ${fs.dot}`} />
                        <div className="min-w-0">
                          <p className="text-sm">
                            {f.title}
                            {f.container && <span className="ml-2 font-mono text-xs text-zinc-500">{f.container}</span>}
                          </p>
                          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">{f.detail}</p>
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>
          );
        })}
      </div>

      <p className="text-xs text-zinc-500 dark:text-zinc-400 max-w-3xl">
        Everything here is read from the pod spec, so it is true before anything goes wrong and costs one
        listing. It does not observe behaviour: a container that actually ran <code>wget</code> at 3am is a
        different question, needing eBPF or an audit webhook rather than a spec scan.
      </p>
    </div>
  );
}
