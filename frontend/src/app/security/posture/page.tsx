"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import {
  AreaChart, Area, LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip, Legend, ResponsiveContainer,
} from "recharts";
import { apiFetch } from "@/lib/api";
import { loadPermissions, PERMISSIONS } from "@/lib/permissions";

type Severity = "critical" | "high" | "medium" | "low";
type Result = "passed" | "failed" | "not_relevant";

interface Assessment {
  id: number;
  created_at: string;
  cluster_id: number;
  score: number;
  rules_passed: number;
  rules_failed: number;
  rules_assessed: number;
  rules_not_relevant: number;
  failed_critical: number;
  failed_high: number;
  failed_medium: number;
  failed_low: number;
  resources_failed: number;
  resources_assessed: number;
  trigger: string;
}

interface FailedResource { kind: string; namespace: string; name: string; detail: string }

interface RuleRow {
  rule_id: string;
  title: string;
  description: string;
  remediation: string;
  standard: string;
  severity: Severity;
  category: string;
  result: Result;
  failed: number;
  passed: number;
  failed_resources: FailedResource[];
  truncated: boolean;
}

interface Payload {
  assessment: Assessment;
  rules: RuleRow[];
  restricted: boolean;
  standard: string;
  cluster: string;
  excluded_namespaces: string[];
}

const SEVERITIES: Severity[] = ["critical", "high", "medium", "low"];
const SEVERITY_LABEL: Record<Severity, string> = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };
const SEVERITY_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };

const SEVERITY_BADGE: Record<Severity, string> = {
  critical: "text-red-500 dark:text-red-400 border-red-500/30 bg-red-500/10",
  high: "text-orange-600 dark:text-orange-400 border-orange-500/30 bg-orange-500/10",
  medium: "text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/10",
  low: "text-zinc-500 dark:text-zinc-400 border-zinc-500/30 bg-zinc-500/10",
};
const SEVERITY_TEXT: Record<Severity, string> = {
  critical: "text-red-500 dark:text-red-400",
  high: "text-orange-600 dark:text-orange-400",
  medium: "text-amber-600 dark:text-amber-400",
  low: "text-zinc-500 dark:text-zinc-400",
};
const RESULT_BADGE: Record<Result, { label: string; cls: string }> = {
  failed: { label: "Failed", cls: "text-red-500 dark:text-red-400 border-red-500/30 bg-red-500/10" },
  passed: { label: "Passed", cls: "text-brand-green border-brand-green/30 bg-brand-green/10" },
  not_relevant: { label: "Not relevant", cls: "text-zinc-500 dark:text-zinc-400 border-zinc-500/30 bg-zinc-500/10" },
};

// Series colours for the severity timeline, stepped separately for each theme
// and checked for colour-blind separation. Each line also has its own dash
// pattern, so identity never rests on colour alone.
const SERIES_LIGHT: Record<Severity, string> = { critical: "#e34948", high: "#eda100", medium: "#4a3aa7", low: "#1baf7a" };
const SERIES_DARK: Record<Severity, string> = { critical: "#e34948", high: "#c98500", medium: "#9085e9", low: "#199e70" };
const SERIES_DASH: Record<Severity, string | undefined> = { critical: undefined, high: "6 3", medium: "2 3", low: "8 3 2 3" };

const tooltipStyle = {
  background: "var(--color-surface)",
  border: "1px solid var(--card-border)",
  borderRadius: 8, fontSize: 12,
};

function useIsDark() {
  const [dark, setDark] = useState(true);
  useEffect(() => {
    const el = document.documentElement;
    const read = () => setDark(el.classList.contains("dark"));
    read();
    const obs = new MutationObserver(read);
    obs.observe(el, { attributes: true, attributeFilter: ["class"] });
    return () => obs.disconnect();
  }, []);
  return dark;
}

function relativeTime(iso: string): string {
  const ms = Date.now() - new Date(iso).getTime();
  const min = Math.round(ms / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  const h = Math.round(min / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

function shortDate(iso: string): string {
  return new Date(iso).toLocaleString([], { month: "2-digit", day: "2-digit", hour: "2-digit", minute: "2-digit" });
}

function ScoreRing({ score, assessed }: { score: number; assessed: number }) {
  const r = 34;
  const c = 2 * Math.PI * r;
  const pct = assessed > 0 ? Math.max(0, Math.min(100, score)) : 0;
  const tone = pct >= 90 ? "text-brand-green" : pct >= 70 ? "text-amber-500" : "text-red-500";
  return (
    <svg viewBox="0 0 80 80" className="w-20 h-20 shrink-0" role="img" aria-label={`Score ${pct.toFixed(0)} percent`}>
      <circle cx="40" cy="40" r={r} fill="none" stroke="currentColor" strokeWidth="7" className="text-zinc-500/20" />
      <circle cx="40" cy="40" r={r} fill="none" stroke="currentColor" strokeWidth="7" strokeLinecap="round"
        className={tone} strokeDasharray={`${(pct / 100) * c} ${c}`} transform="rotate(-90 40 40)" />
      <text x="40" y="44" textAnchor="middle" className="fill-current text-[15px] font-semibold tabular-nums">
        {assessed > 0 ? `${pct.toFixed(0)}%` : "—"}
      </text>
    </svg>
  );
}

export default function Page() {
  const [data, setData] = useState<Payload | null>(null);
  const [history, setHistory] = useState<Assessment[]>([]);
  const [days, setDays] = useState(90);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [canScan, setCanScan] = useState(true);

  const [resultFilter, setResultFilter] = useState<"" | Result>("");
  const [severityFilter, setSeverityFilter] = useState<"" | Severity>("");
  const [categoryFilter, setCategoryFilter] = useState("");
  const [search, setSearch] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const dark = useIsDark();
  const series = dark ? SERIES_DARK : SERIES_LIGHT;

  const loadHistory = useCallback(async (d: number) => {
    try {
      const res = await apiFetch(`/security/posture/history?days=${d}`);
      const body = await res.json().catch(() => ({}));
      if (res.ok) setHistory(body.assessments ?? []);
    } catch {
      // The timeline is secondary; the assessment itself still renders.
    }
  }, []);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/security/posture");
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
  // Keyed on the assessment as well as the range: the first visit to a
  // cluster runs its first assessment inside GET /security/posture, so a
  // history fetched alongside it comes back empty and must be fetched again
  // once that assessment exists.
  const assessmentId = data?.assessment?.id;
  useEffect(() => { loadHistory(days); }, [loadHistory, days, assessmentId]);
  useEffect(() => {
    loadPermissions().then(p => setCanScan(p.size === 0 || p.has(PERMISSIONS.securityScan)));
  }, []);

  useEffect(() => {
    const onCluster = () => { setLoading(true); load(); loadHistory(days); };
    window.addEventListener("cluster-change", onCluster);
    return () => window.removeEventListener("cluster-change", onCluster);
  }, [load, loadHistory, days]);

  const runNow = async () => {
    setRunning(true);
    try {
      const res = await apiFetch("/security/posture/assess", { method: "POST" });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
      setError("");
      setData(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    } finally {
      setRunning(false);
    }
  };

  const categories = useMemo(
    () => Array.from(new Set((data?.rules ?? []).map(r => r.category))).sort(),
    [data],
  );

  const rows = useMemo(() => {
    let list = [...(data?.rules ?? [])];
    if (resultFilter) list = list.filter(r => r.result === resultFilter);
    if (severityFilter) list = list.filter(r => r.severity === severityFilter);
    if (categoryFilter) list = list.filter(r => r.category === categoryFilter);
    if (search.trim()) {
      const q = search.trim().toLowerCase();
      list = list.filter(r =>
        r.title.toLowerCase().includes(q) || r.rule_id.toLowerCase().includes(q) ||
        r.failed_resources.some(f => f.name.toLowerCase().includes(q) || f.namespace.toLowerCase().includes(q)));
    }
    const resultRank: Record<string, number> = { failed: 0, passed: 1, not_relevant: 2 };
    list.sort((a, b) =>
      (resultRank[a.result] - resultRank[b.result]) ||
      (SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity]) ||
      (b.failed - a.failed) || a.rule_id.localeCompare(b.rule_id));
    return list;
  }, [data, resultFilter, severityFilter, categoryFilter, search]);

  const chartData = useMemo(() => history.map(h => ({
    time: shortDate(h.created_at),
    score: Math.round(h.score * 10) / 10,
    critical: h.failed_critical, high: h.failed_high, medium: h.failed_medium, low: h.failed_low,
  })), [history]);

  const delta = useMemo(() => {
    if (history.length < 2) return null;
    const first = history[0];
    const last = history[history.length - 1];
    return { first, last };
  }, [history]);

  if (loading) return <div className="p-6 text-zinc-500">Assessing the cluster…</div>;

  if (error && !data) {
    return (
      <div className="p-6 max-w-[1500px] mx-auto">
        <div className="glass-card p-4 border-red-500/30 text-sm">
          <p className="text-red-500 dark:text-red-400 font-medium">Could not assess the cluster</p>
          <p className="text-zinc-500 dark:text-zinc-400 mt-1 break-words">{error}</p>
        </div>
      </div>
    );
  }
  if (!data) return null;

  const a = data.assessment;
  const failedBySeverity: Record<Severity, number> = {
    critical: a.failed_critical, high: a.failed_high, medium: a.failed_medium, low: a.failed_low,
  };

  return (
    <div className="p-4 max-w-[1600px] mx-auto space-y-3 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold">Security Posture</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
            {data.standard} rules assessed against every workload, role and namespace in <span className="font-mono">{data.cluster}</span>.
            A rule passes only when none of the resources it applies to fail.
          </p>
        </div>
        <div className="flex items-center gap-3">
          <span className="text-xs text-zinc-500 dark:text-zinc-400" title={new Date(a.created_at).toLocaleString()}>
            Last assessed {relativeTime(a.created_at)} · {a.trigger}
          </span>
          {canScan && (
            <button onClick={runNow} disabled={running}
              className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-50">
              {running ? "Assessing…" : "Run assessment"}
            </button>
          )}
        </div>
      </div>

      {error && (
        <div className="glass-card p-3 border-red-500/30 text-sm text-red-500 dark:text-red-400 break-words">{error}</div>
      )}
      {data.restricted && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400">
          Your account is scoped to some namespaces: the results and the score cover those namespaces only.
          Cluster-wide resources such as ClusterRoles are not shown.
        </p>
      )}

      {/* ---- overview ---- */}
      <div className="grid grid-cols-1 lg:grid-cols-[minmax(0,1.2fr)_minmax(0,2fr)_minmax(0,1fr)] gap-2">
        <div className="glass-card p-4 flex items-center gap-4">
          <ScoreRing score={a.score} assessed={a.rules_assessed} />
          <div className="min-w-0 flex-1">
            <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Score</p>
            <p className="text-sm mt-1">
              <span className="text-brand-green font-semibold tabular-nums">{a.rules_passed}</span> passed ·{" "}
              <span className="text-red-500 dark:text-red-400 font-semibold tabular-nums">{a.rules_failed}</span> failed
            </p>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
              {a.rules_not_relevant} not relevant · {a.rules_assessed} assessed
            </p>
            <div className="mt-2 h-1.5 rounded-full bg-zinc-500/20 overflow-hidden flex gap-[2px]">
              {a.rules_assessed > 0 && <>
                <div className="bg-brand-green rounded-full" style={{ width: `${(a.rules_passed / a.rules_assessed) * 100}%` }} />
                <div className="bg-red-500 rounded-full" style={{ width: `${(a.rules_failed / a.rules_assessed) * 100}%` }} />
              </>}
            </div>
          </div>
        </div>

        <div className="glass-card p-4">
          <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Failed rules by severity</p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 mt-2">
            {SEVERITIES.map(s => (
              <button key={s} onClick={() => { setSeverityFilter(severityFilter === s ? "" : s); setResultFilter("failed"); }}
                className={`text-left rounded-lg border px-3 py-2 transition ${
                  severityFilter === s ? "ring-1 ring-brand-green/40" : ""
                } border-[var(--card-border)] hover:bg-[var(--color-surface-hover)]`}>
                <p className={`text-xs ${SEVERITY_TEXT[s]}`}>{SEVERITY_LABEL[s]}</p>
                <p className="text-xl font-semibold tabular-nums">{failedBySeverity[s]}</p>
              </button>
            ))}
          </div>
        </div>

        <div className="glass-card p-4">
          <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Failed resources</p>
          <p className="text-xl font-semibold mt-0.5 tabular-nums text-red-500 dark:text-red-400">{a.resources_failed}</p>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
            of {a.resources_assessed} assessed resources fail at least one rule
          </p>
        </div>
      </div>

      {/* ---- timeline ---- */}
      <section className="glass-card p-4">
        <div className="flex flex-wrap items-center justify-between gap-2 mb-3">
          <h2 className="text-sm font-semibold">Timeline</h2>
          <div className="flex items-center gap-1">
            {[30, 90, 365].map(d => (
              <button key={d} onClick={() => setDays(d)}
                className={`px-2 py-1 text-xs rounded-md transition ${
                  days === d ? "bg-brand-green/10 text-brand-green" : "text-zinc-500 hover:text-brand-green"
                }`}>
                {d === 365 ? "1 year" : `${d} days`}
              </button>
            ))}
          </div>
        </div>

        {delta && (
          <div className="flex flex-wrap gap-x-5 gap-y-1 text-xs text-zinc-500 dark:text-zinc-400 mb-3">
            <span>Since {new Date(delta.first.created_at).toLocaleDateString()}:</span>
            <span>Score <span className="tabular-nums text-[var(--color-fg)]">{delta.first.score.toFixed(0)}% → {delta.last.score.toFixed(0)}%</span></span>
            {SEVERITIES.map(s => {
              const key = `failed_${s}` as const;
              return (
                <span key={s}>
                  {SEVERITY_LABEL[s]} failing rules{" "}
                  <span className="tabular-nums text-[var(--color-fg)]">{delta.first[key]} → {delta.last[key]}</span>
                </span>
              );
            })}
            <span>Failed resources <span className="tabular-nums text-[var(--color-fg)]">{delta.first.resources_failed} → {delta.last.resources_failed}</span></span>
          </div>
        )}

        {chartData.length < 2 ? (
          <p className="text-xs text-zinc-500">
            {chartData.length === 0 ? "No assessments in this range yet." : "One assessment so far — the timeline fills in as assessments run (every 6 hours)."}
          </p>
        ) : (
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <div className="min-w-0">
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Score %</p>
              <ResponsiveContainer width="100%" height={200}>
                <AreaChart data={chartData} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="currentColor" minTickGap={24} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11 }} stroke="currentColor" />
                  <Tooltip contentStyle={tooltipStyle} formatter={(v) => [`${v}%`, "Score"]} />
                  <Area type="stepAfter" dataKey="score" name="Score" stroke="#10b981" fill="#10b981" fillOpacity={0.12} strokeWidth={2} dot={false} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
            <div className="min-w-0">
              <p className="text-xs text-zinc-500 dark:text-zinc-400 mb-1">Failed rules by severity</p>
              <ResponsiveContainer width="100%" height={200}>
                <LineChart data={chartData} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(128,128,128,0.15)" vertical={false} />
                  <XAxis dataKey="time" tick={{ fontSize: 10 }} stroke="currentColor" minTickGap={24} />
                  <YAxis allowDecimals={false} tick={{ fontSize: 11 }} stroke="currentColor" />
                  <Tooltip contentStyle={tooltipStyle} />
                  <Legend wrapperStyle={{ fontSize: 11 }} />
                  {SEVERITIES.map(s => (
                    <Line key={s} type="stepAfter" dataKey={s} name={SEVERITY_LABEL[s]} stroke={series[s]}
                      strokeDasharray={SERIES_DASH[s]} strokeWidth={2} dot={false} />
                  ))}
                </LineChart>
              </ResponsiveContainer>
            </div>
          </div>
        )}
      </section>

      {/* ---- results ---- */}
      <section className="glass-card p-4 min-w-0">
        <div className="flex flex-wrap items-center gap-2 mb-3">
          <h2 className="text-sm font-semibold mr-2">Assessment results</h2>
          <input value={search} onChange={e => setSearch(e.target.value)}
            placeholder="Search rule or resource…"
            className="flex-1 min-w-[180px] px-3 py-1.5 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
          <select value={resultFilter} onChange={e => setResultFilter(e.target.value as "" | Result)}
            className="px-2 py-1.5 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]">
            <option value="">All results</option>
            <option value="failed">Failed</option>
            <option value="passed">Passed</option>
            <option value="not_relevant">Not relevant</option>
          </select>
          <select value={severityFilter} onChange={e => setSeverityFilter(e.target.value as "" | Severity)}
            className="px-2 py-1.5 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]">
            <option value="">All severities</option>
            {SEVERITIES.map(s => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}
          </select>
          <select value={categoryFilter} onChange={e => setCategoryFilter(e.target.value)}
            className="px-2 py-1.5 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)]">
            <option value="">All categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          {(resultFilter || severityFilter || categoryFilter || search) && (
            <button onClick={() => { setResultFilter(""); setSeverityFilter(""); setCategoryFilter(""); setSearch(""); }}
              className="px-2 py-1.5 text-sm text-zinc-500 hover:text-brand-green transition">
              Clear
            </button>
          )}
          <span className="text-xs text-zinc-500 dark:text-zinc-400">{rows.length} of {data.rules.length} rules</span>
        </div>

        <div className="overflow-x-auto -mx-4 px-4">
          <table className="w-full min-w-[760px] text-sm">
            <thead>
              <tr className="text-left text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b border-[var(--card-border)]">
                <th className="py-2 pr-3 font-medium w-28">Result</th>
                <th className="py-2 pr-3 font-medium w-24">Severity</th>
                <th className="py-2 pr-3 font-medium">Rule</th>
                <th className="py-2 pr-3 font-medium w-32">Category</th>
                <th className="py-2 pr-3 font-medium w-20 text-right">Failed</th>
                <th className="py-2 font-medium w-20 text-right">Passed</th>
              </tr>
            </thead>
            <tbody>
              {rows.map(r => {
                const open = expanded === r.rule_id;
                const rb = RESULT_BADGE[r.result] ?? RESULT_BADGE.not_relevant;
                return (
                  <Fragment key={r.rule_id}>
                    <tr onClick={() => setExpanded(open ? null : r.rule_id)}
                      className="border-b border-[var(--card-border)] cursor-pointer hover:bg-[var(--color-surface-hover)] transition">
                      <td className="py-2 pr-3">
                        <span className={`inline-block px-2 py-0.5 text-xs rounded-md border ${rb.cls}`}>{rb.label}</span>
                      </td>
                      <td className="py-2 pr-3">
                        <span className={`inline-block px-2 py-0.5 text-xs rounded-md border ${SEVERITY_BADGE[r.severity] ?? SEVERITY_BADGE.low}`}>
                          {SEVERITY_LABEL[r.severity] ?? r.severity}
                        </span>
                      </td>
                      <td className="py-2 pr-3">
                        <span className="mr-2">{r.title}</span>
                        <span className="font-mono text-[11px] text-zinc-500">{r.rule_id}</span>
                      </td>
                      <td className="py-2 pr-3 text-zinc-500 dark:text-zinc-400">{r.category}</td>
                      <td className={`py-2 pr-3 text-right tabular-nums ${r.failed > 0 ? "text-red-500 dark:text-red-400" : "text-zinc-500"}`}>{r.failed}</td>
                      <td className="py-2 text-right tabular-nums text-zinc-500 dark:text-zinc-400">{r.passed}</td>
                    </tr>
                    {open && (
                      <tr className="border-b border-[var(--card-border)]">
                        <td colSpan={6} className="py-3">
                          <div className="space-y-3 max-w-[1100px]">
                            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                              <div>
                                <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Description</p>
                                <p className="text-sm mt-1 whitespace-normal">{r.description || "—"}</p>
                              </div>
                              <div>
                                <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Remediation</p>
                                <p className="text-sm mt-1 whitespace-normal">{r.remediation || "—"}</p>
                              </div>
                            </div>
                            <p className="text-xs text-zinc-500">{r.standard} · {r.rule_id}</p>
                            {r.failed_resources.length > 0 && (
                              <div>
                                <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">
                                  Failing resources
                                  {r.truncated && <span className="normal-case tracking-normal"> — showing {r.failed_resources.length} of {r.failed}</span>}
                                </p>
                                <div className="rounded-lg border border-[var(--card-border)] overflow-hidden">
                                  <table className="w-full text-xs">
                                    <thead>
                                      <tr className="text-left text-zinc-500 dark:text-zinc-400 bg-[var(--surface-sunken)]">
                                        <th className="px-3 py-1.5 font-medium w-32">Kind</th>
                                        <th className="px-3 py-1.5 font-medium w-40">Namespace</th>
                                        <th className="px-3 py-1.5 font-medium w-56">Name</th>
                                        <th className="px-3 py-1.5 font-medium">Detail</th>
                                      </tr>
                                    </thead>
                                    <tbody>
                                      {r.failed_resources.map((f, i) => (
                                        <tr key={`${f.kind}/${f.namespace}/${f.name}/${i}`} className="border-t border-[var(--card-border)] align-top">
                                          <td className="px-3 py-1.5">{f.kind}</td>
                                          <td className="px-3 py-1.5 font-mono text-zinc-500 dark:text-zinc-400">{f.namespace || "—"}</td>
                                          <td className="px-3 py-1.5 font-mono break-all">{f.name}</td>
                                          <td className="px-3 py-1.5 text-zinc-500 dark:text-zinc-400 break-words">{f.detail}</td>
                                        </tr>
                                      ))}
                                    </tbody>
                                  </table>
                                </div>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
              {rows.length === 0 && (
                <tr><td colSpan={6} className="py-6 text-center text-xs text-zinc-500">No rules match these filters.</td></tr>
              )}
            </tbody>
          </table>
        </div>
      </section>

      <p className="text-xs text-zinc-500 dark:text-zinc-400 max-w-3xl">
        Workloads are assessed at the controller (Deployment, StatefulSet, DaemonSet, Job, CronJob, and Pods with no owner),
        not per replica. Not assessed: namespaces {data.excluded_namespaces.join(", ")}, RBAC objects named <code>system:*</code>,
        and the built-in roles the API server recreates on every start. Assessments run every 6 hours and are kept for a year.
      </p>
    </div>
  );
}
