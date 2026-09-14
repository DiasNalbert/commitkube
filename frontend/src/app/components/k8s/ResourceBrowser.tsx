"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import ResourceDetailDrawer, { KINDS_WITH_DETAIL } from "./ResourceDetailDrawer";
import { statusStyle, type ResourceColumn, type ResourceRow } from "./status";

export { STATUS_STYLES, statusStyle } from "./status";
export type { ResourceColumn, ResourceRow } from "./status";

interface Totals {
  total: number;
  critical: number;
  warning: number;
  healthy: number;
  unknown: number;
}

const PAGE_SIZES = [25, 50, 100];

const IconSearch = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-4 h-4">
    <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

export default function ResourceBrowser({
  kind,
  title,
  subtitle,
  columns,
  namespaced = true,
}: {
  kind: string;
  title: string;
  subtitle: string;
  columns: ResourceColumn[];
  namespaced?: boolean;
}) {
  const [rows, setRows] = useState<ResourceRow[]>([]);
  const [totals, setTotals] = useState<Totals | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [search, setSearch] = useState("");
  const [nsFilter, setNsFilter] = useState("");
  const [statusFilter, setStatusFilter] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [selected, setSelected] = useState<ResourceRow | null>(null);

  // Kinds with an Overview tab get a panel worth calling "Details".
  const hasDetail = KINDS_WITH_DETAIL.has(kind);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch(`/kubernetes/resources/${kind}`);
      const body = await res.json().catch(() => ({}));
      if (!res.ok) {
        setError(body.error ?? `Request failed (${res.status})`);
        setRows([]);
        setTotals(null);
        return;
      }
      setError("");
      setRows(body.items ?? []);
      setTotals(body.totals ?? null);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach the API");
    } finally {
      setLoading(false);
    }
  }, [kind]);

  useEffect(() => { setLoading(true); load(); }, [load]);

  // A namespace may arrive in the URL, which is how the namespace detail panel
  // links to "the Services of this namespace" rather than to all of them. Read
  // from location instead of useSearchParams: this page is client-rendered and
  // the hook would force a Suspense boundary around every list.
  useEffect(() => {
    const ns = new URLSearchParams(window.location.search).get("namespace");
    if (ns) setNsFilter(ns);
  }, []);

  const namespaces = useMemo(
    () => Array.from(new Set(rows.map(r => r.namespace).filter(Boolean))).sort(),
    [rows]
  );

  const filtered = useMemo(() => {
    let list = rows;
    if (nsFilter) list = list.filter(r => r.namespace === nsFilter);
    if (statusFilter) list = list.filter(r => r.status === statusFilter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(r =>
        r.name.toLowerCase().includes(q) ||
        r.namespace.toLowerCase().includes(q) ||
        Object.values(r.fields).some(v => v.toLowerCase().includes(q))
      );
    }
    return list;
  }, [rows, nsFilter, statusFilter, search]);

  // Any filter change invalidates the current page number.
  useEffect(() => { setPage(1); }, [nsFilter, statusFilter, search, pageSize]);

  const totalPages = Math.max(1, Math.ceil(filtered.length / pageSize));
  const safePage = Math.min(page, totalPages);
  const pageRows = filtered.slice((safePage - 1) * pageSize, safePage * pageSize);

  // Counts reflect the namespace in view, so they agree with the rows below.
  const scopedTotals = useMemo(() => {
    const base = nsFilter ? rows.filter(r => r.namespace === nsFilter) : rows;
    const t: Totals = { total: base.length, critical: 0, warning: 0, healthy: 0, unknown: 0 };
    for (const r of base) {
      if (r.status in t) t[r.status as keyof Totals]++;
    }
    return t;
  }, [rows, nsFilter]);

  const cards: [string, string, number, string][] = [
    ["total", "Total", scopedTotals.total, "text-zinc-600 dark:text-zinc-300"],
    ["critical", "Critical", scopedTotals.critical, "text-red-500 dark:text-red-400"],
    ["warning", "Warning", scopedTotals.warning, "text-amber-600 dark:text-amber-400"],
    ["healthy", "Healthy", scopedTotals.healthy, "text-brand-green"],
  ];

  const cellValue = (row: ResourceRow, col: ResourceColumn) => {
    switch (col.id) {
      case "name": return row.name;
      case "namespace": return row.namespace;
      case "age": return row.age;
      case "status": return row.status_text;
      default: return row.fields?.[col.id] ?? "";
    }
  };

  return (
    <div className="p-6 max-w-[1600px] mx-auto space-y-5">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-semibold">{title}</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">{subtitle}</p>
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
          <p className="text-red-500 dark:text-red-400 font-medium">Cannot read {kind}</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1 break-words">{error}</p>
          {error.includes("forbidden") && (
            <p className="text-zinc-500 dark:text-zinc-400 mt-2 text-xs">
              The ServiceAccount is missing RBAC for this resource. Re-apply{" "}
              <code>deploy/rbac.yaml</code> — it was expanded to cover workloads and storage.
            </p>
          )}
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
        <div className="relative flex-1 min-w-[240px]">
          <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 pointer-events-none">
            <IconSearch />
          </span>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder={`Search ${kind} by name, namespace or value…`}
            className="w-full pl-9 pr-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] placeholder:text-zinc-400 dark:placeholder:text-zinc-500 focus:outline-none focus:border-brand-green/50"
          />
        </div>

        {namespaced && (
          <select
            value={nsFilter}
            onChange={e => setNsFilter(e.target.value)}
            className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50"
          >
            <option value="">All namespaces ({namespaces.length})</option>
            {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
          </select>
        )}

        <select
          value={pageSize}
          onChange={e => setPageSize(Number(e.target.value))}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50"
        >
          {PAGE_SIZES.map(n => <option key={n} value={n}>{n} per page</option>)}
        </select>

        {(search || nsFilter || statusFilter) && (
          <button
            onClick={() => { setSearch(""); setNsFilter(""); setStatusFilter(null); }}
            className="px-3 py-2 text-sm rounded-lg text-zinc-500 hover:text-brand-green transition"
          >
            Clear filters
          </button>
        )}
      </div>

      {loading ? (
        <div className="glass-card p-12 text-center text-zinc-500">Loading {kind}…</div>
      ) : filtered.length === 0 ? (
        <div className="glass-card p-12 text-center text-zinc-500">
          {rows.length === 0 ? `No ${kind} found in this cluster.` : `No ${kind} match the current filters.`}
        </div>
      ) : (
        <>
          <div className="glass-card overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-xs uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b border-[var(--card-border)]">
                  <tr>
                    {columns.map(col => (
                      <th
                        key={col.id}
                        style={col.width ? { width: col.width } : undefined}
                        className={`font-medium px-4 py-3 ${col.align === "right" ? "text-right" : "text-left"}`}
                      >
                        {col.label}
                      </th>
                    ))}
                    <th className="px-4 py-3 text-right font-medium">{hasDetail ? "Details" : "Manifest"}</th>
                  </tr>
                </thead>
                <tbody>
                  {pageRows.map(row => {
                    const s = statusStyle(row.status);
                    return (
                      <tr
                        key={`${row.namespace}/${row.name}`}
                        onClick={() => setSelected(row)}
                        className="border-b border-[var(--card-border)] hover:bg-[var(--color-surface-hover)] cursor-pointer"
                      >
                        {columns.map((col, i) => {
                          const value = cellValue(row, col);
                          return (
                            <td
                              key={col.id}
                              className={[
                                "px-4 py-3",
                                col.align === "right" ? "text-right tabular-nums" : "",
                                col.mono ? "font-mono text-xs" : "",
                                col.truncate ? "truncate max-w-[260px]" : "",
                                col.id === "status" ? s.text : "",
                                i === 0 ? "font-medium" : "text-zinc-600 dark:text-zinc-400",
                              ].join(" ")}
                              title={col.truncate ? value : undefined}
                            >
                              {i === 0 ? (
                                <span className="flex items-center gap-2">
                                  <span className={`w-2 h-2 rounded-full shrink-0 ${s.dot}`} />
                                  <span className="truncate">{value || "—"}</span>
                                </span>
                              ) : (
                                value || "—"
                              )}
                            </td>
                          );
                        })}
                        <td className="px-4 py-3 text-right">
                          <span className="text-xs text-zinc-500 hover:text-brand-green">{hasDetail ? "Inspect" : "View YAML"}</span>
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 text-sm">
            <p className="text-zinc-500 dark:text-zinc-400">
              Showing {(safePage - 1) * pageSize + 1}–{Math.min(safePage * pageSize, filtered.length)} of{" "}
              {filtered.length}
              {filtered.length !== rows.length && ` (filtered from ${rows.length})`}
            </p>
            <div className="flex items-center gap-2">
              <button
                onClick={() => setPage(p => Math.max(1, p - 1))}
                disabled={safePage <= 1}
                className="px-3 py-1.5 rounded-lg border border-[var(--card-border)] hover:bg-[var(--color-surface-hover)] transition disabled:opacity-40 disabled:hover:bg-transparent"
              >
                Previous
              </button>
              <span className="text-zinc-500 dark:text-zinc-400 px-2">
                Page {safePage} of {totalPages}
              </span>
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

      {selected && (
        <ResourceDetailDrawer kind={kind} row={selected} onClose={() => setSelected(null)} />
      )}
    </div>
  );
}
