"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";

interface LabelCount { label: string; count: number }

interface WorkloadDelivery {
  namespace: string;
  workload: string;
  kind: string;
  deployments: number;
  failed: number;
  failure_rate: number | null;
  lead_median_sec: number | null;
  repo_name: string;
}

interface Summary {
  window_days: number;
  from: string;
  to: string;
  scope_all_namespaces: boolean;
  namespaces: string[] | null;
  deployments: {
    band: string; total: number; per_day: number; per_week: number;
    workloads: number; rollbacks: number;
  };
  lead_time: {
    band: string; median_sec: number | null; p90_sec: number | null;
    linked: number; unlinked: number; pending: number; coverage_pct: number;
  };
  change_failure: {
    band: string; settled: number; failed: number; rate_pct: number | null;
    pending: number; dependency_excluded: number;
  };
  recovery: {
    band: string; median_sec: number | null; recovered: number; ongoing: number;
  };
  unlinked_reasons: LabelCount[];
  failure_reasons: LabelCount[];
  top_workloads: WorkloadDelivery[];
}

interface Deployment {
  id: number;
  namespace: string;
  workload_kind: string;
  workload: string;
  deployed_at: string;
  image: string;
  prev_image: string;
  repo_name: string;
  commit_sha: string;
  commit_at: string | null;
  lead_time_sec: number | null;
  link_status: string;
  link_detail: string;
  rollback: boolean;
  outcome: string;
  failed_reason: string;
  failed_at: string | null;
  recovered_at: string | null;
  recovery_sec: number | null;
  dependency_incident: boolean;
}

/** A duration read by a person, not a chart axis. Below a day the unit people
 *  think in is hours; above it, days. */
function fmtDuration(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return "—";
  if (seconds < 60) return `${Math.round(seconds)}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  if (seconds < 86400) {
    const h = seconds / 3600;
    return `${h < 10 ? h.toFixed(1) : Math.round(h)}h`;
  }
  const d = seconds / 86400;
  return `${d < 10 ? d.toFixed(1) : Math.round(d)}d`;
}

function fmtDateTime(iso: string | null): string {
  if (!iso) return "—";
  const d = new Date(iso);
  return d.toLocaleString(undefined, {
    month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit",
  });
}

const BAND_STYLE: Record<string, string> = {
  elite: "text-emerald-600 dark:text-emerald-400 border-emerald-500/40 bg-emerald-500/10",
  high: "text-sky-600 dark:text-sky-400 border-sky-500/40 bg-sky-500/10",
  medium: "text-amber-600 dark:text-amber-400 border-amber-500/40 bg-amber-500/10",
  low: "text-red-500 dark:text-red-400 border-red-500/40 bg-red-500/10",
  unknown: "text-zinc-500 dark:text-zinc-400 border-zinc-400/30 bg-zinc-500/10",
};

function Band({ band }: { band: string }) {
  return (
    <span className={`text-[10px] uppercase tracking-wide font-semibold px-1.5 py-0.5 rounded border ${BAND_STYLE[band] ?? BAND_STYLE.unknown}`}>
      {band === "unknown" ? "no data" : band}
    </span>
  );
}

/** A headline number with the band it falls in, and the line underneath that
 *  says what it was computed over. A DORA figure without its denominator is
 *  the part people misread. */
function Metric({ label, value, band, note }: {
  label: string; value: React.ReactNode; band: string; note?: React.ReactNode;
}) {
  return (
    <div className="glass-card px-3 py-2.5">
      <div className="flex items-start justify-between gap-2">
        <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
        <Band band={band} />
      </div>
      <p className="text-xl font-semibold mt-0.5 tabular-nums">{value}</p>
      {note && <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5 leading-snug">{note}</p>}
    </div>
  );
}

function Card({ title, subtitle, children }: {
  title: string; subtitle?: string; children: React.ReactNode;
}) {
  return (
    <section className="glass-card">
      <div className="px-3 py-2 border-b rule flex items-baseline gap-2 flex-wrap">
        <h2 className="text-[13px] font-semibold">{title}</h2>
        {subtitle && <p className="text-[11px] text-zinc-500 dark:text-zinc-400">{subtitle}</p>}
      </div>
      <div className="p-3">{children}</div>
    </section>
  );
}

const OUTCOME_STYLE: Record<string, string> = {
  ok: "text-emerald-600 dark:text-emerald-400",
  failed: "text-red-500 dark:text-red-400",
  pending: "text-zinc-500 dark:text-zinc-400",
};

export default function DeliveryPage() {
  const [summary, setSummary] = useState<Summary | null>(null);
  const [deployments, setDeployments] = useState<Deployment[]>([]);
  const [days, setDays] = useState(30);
  const [tab, setTab] = useState<"overview" | "deployments">("overview");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    setLoading(true);
    setError("");
    try {
      const [s, d] = await Promise.all([
        apiFetch(`/delivery/dora?days=${days}`),
        apiFetch(`/delivery/deployments?days=${days}`),
      ]);
      if (!s.ok) throw new Error((await s.json()).error ?? "failed to load the metrics");
      setSummary(await s.json());
      if (d.ok) setDeployments((await d.json()).items ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [days]);

  useEffect(() => { load(); }, [load]);

  const freq = useMemo(() => {
    if (!summary) return "—";
    const perDay = summary.deployments.per_day;
    if (perDay >= 1) return `${perDay.toFixed(1)}/day`;
    if (summary.deployments.per_week >= 1) return `${summary.deployments.per_week.toFixed(1)}/week`;
    return `${summary.deployments.total} in ${summary.window_days}d`;
  }, [summary]);

  return (
    <div className="p-4 max-w-[1500px] mx-auto">
      <header className="mb-6">
        <h1 className="text-2xl font-black tracking-tight">Delivery</h1>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
          The four DORA metrics, measured from the cluster rather than from the pipeline. A
          deployment here is an image that started running — so a pipeline that passed without
          changing the running image is not one, and an image changed by hand is.
        </p>
      </header>

      {error && (
        <div className="mb-3 rounded border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500 dark:text-red-400">
          {error}
        </div>
      )}

      {summary?.scope_all_namespaces && (
        <div className="mb-3 rounded border border-amber-500/30 bg-amber-500/10 px-3 py-2 text-[12px] text-amber-700 dark:text-amber-300">
          Counting every namespace, staging included. DORA describes production, so until
          production is declared these figures are about the whole cluster.
        </div>
      )}

      <div className="flex flex-wrap gap-2 mb-4 items-center">
        <select
          value={days}
          onChange={e => setDays(Number(e.target.value))}
          className="bg-transparent border border-zinc-300 dark:border-zinc-700 rounded px-2 py-1.5 text-sm"
        >
          <option value={7}>Last 7 days</option>
          <option value={30}>Last 30 days</option>
          <option value={90}>Last 90 days</option>
          <option value={180}>Last 180 days</option>
        </select>
        <button onClick={load} className="btn-secondary" disabled={loading}>
          {loading ? "Loading…" : "Refresh"}
        </button>
      </div>

      {summary && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
            <Metric
              label="Deployment frequency"
              value={freq}
              band={summary.deployments.band}
              note={`${summary.deployments.total} across ${summary.deployments.workloads} workloads${
                summary.deployments.rollbacks > 0 ? `, ${summary.deployments.rollbacks} rollbacks` : ""
              }`}
            />
            <Metric
              label="Lead time for changes"
              value={fmtDuration(summary.lead_time.median_sec)}
              band={summary.lead_time.band}
              note={
                summary.lead_time.linked > 0
                  ? `median over ${summary.lead_time.linked} of ${
                      summary.lead_time.linked + summary.lead_time.unlinked + summary.lead_time.pending
                    } deployments (${Math.round(summary.lead_time.coverage_pct)}% linked to a commit)`
                  : "no deployment could be linked to a commit"
              }
            />
            <Metric
              label="Change failure rate"
              value={summary.change_failure.rate_pct === null ? "—" : `${summary.change_failure.rate_pct.toFixed(0)}%`}
              band={summary.change_failure.band}
              note={`${summary.change_failure.failed} of ${summary.change_failure.settled} settled${
                summary.change_failure.pending > 0 ? `, ${summary.change_failure.pending} still inside the window` : ""
              }`}
            />
            <Metric
              label="Failed deployment recovery"
              value={fmtDuration(summary.recovery.median_sec)}
              band={summary.recovery.band}
              note={
                summary.recovery.ongoing > 0
                  ? `median of ${summary.recovery.recovered} recovered — ${summary.recovery.ongoing} still failing`
                  : `median of ${summary.recovery.recovered} recovered`
              }
            />
          </div>

          {summary.change_failure.dependency_excluded > 0 && (
            <div className="mb-4 rounded border rule px-3 py-2 text-[12px] text-zinc-600 dark:text-zinc-300">
              <span className="font-semibold">
                {summary.change_failure.dependency_excluded} deployment
                {summary.change_failure.dependency_excluded === 1 ? "" : "s"} had a problem in the
                window that Triage attributed to a dependency.
              </span>{" "}
              They are not counted as change failures: a third party going down is not a fault of
              the release that happened to be recent.
            </div>
          )}

          <div className="flex gap-1 mb-4 border-b border-zinc-200 dark:border-zinc-800">
            {(["overview", "deployments"] as const).map(t => (
              <button
                key={t}
                onClick={() => setTab(t)}
                className={`px-4 py-2 text-sm font-semibold border-b-2 -mb-px transition ${
                  tab === t
                    ? "border-brand-green text-brand-green"
                    : "border-transparent text-zinc-500 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200"
                }`}
              >
                {t === "overview" ? "Overview" : `Deployments (${deployments.length})`}
              </button>
            ))}
          </div>
        </>
      )}

      {tab === "overview" && summary && (
        <div className="space-y-3">
          <div className="grid lg:grid-cols-2 gap-3">
            <Card
              title="Why lead time covers what it covers"
              subtitle="a deployment with no commit is left out, never given a guessed value"
            >
              {summary.unlinked_reasons.length === 0 ? (
                <p className="text-[12px] text-zinc-500 dark:text-zinc-400">
                  Every deployment in the window is linked to a commit.
                </p>
              ) : (
                <ul className="space-y-1.5">
                  {summary.unlinked_reasons.map(r => (
                    <li key={r.label} className="flex items-baseline justify-between gap-3 text-[12px]">
                      <span className="text-zinc-600 dark:text-zinc-300">{r.label}</span>
                      <span className="tabular-nums font-semibold shrink-0">{r.count}</span>
                    </li>
                  ))}
                </ul>
              )}
              {summary.lead_time.p90_sec !== null && (
                <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-3 pt-3 border-t rule">
                  p90 {fmtDuration(summary.lead_time.p90_sec)} — the slow tail, where the median hides it.
                </p>
              )}
            </Card>

            <Card title="What failed" subtitle="the signal that settled each failed deployment">
              {summary.failure_reasons.length === 0 ? (
                <p className="text-[12px] text-zinc-500 dark:text-zinc-400">
                  No deployment in the window was followed by a problem on its workload.
                </p>
              ) : (
                <ul className="space-y-1.5">
                  {summary.failure_reasons.map(r => (
                    <li key={r.label} className="flex items-baseline justify-between gap-3 text-[12px]">
                      <span className="text-zinc-600 dark:text-zinc-300">{r.label}</span>
                      <span className="tabular-nums font-semibold shrink-0">{r.count}</span>
                    </li>
                  ))}
                </ul>
              )}
            </Card>
          </div>

          <Card title="By workload" subtitle="where the deployments and the failures actually are">
            <div className="overflow-x-auto">
              <table className="w-full text-[13px]">
                <thead>
                  <tr className="text-left text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b rule">
                    <th className="font-medium py-1.5 pr-3">Workload</th>
                    <th className="font-medium py-1.5 pr-3">Namespace</th>
                    <th className="font-medium py-1.5 pr-3">Repository</th>
                    <th className="font-medium py-1.5 pr-3 text-right">Deploys</th>
                    <th className="font-medium py-1.5 pr-3 text-right">Failed</th>
                    <th className="font-medium py-1.5 pr-3 text-right">Failure rate</th>
                    <th className="font-medium py-1.5 text-right">Lead time</th>
                  </tr>
                </thead>
                <tbody>
                  {summary.top_workloads.length === 0 && (
                    <tr><td colSpan={7} className="py-3 text-zinc-500 dark:text-zinc-400 text-[12px]">
                      No deployment recorded in this window. The workload poller writes one when a
                      workload starts running a different image.
                    </td></tr>
                  )}
                  {summary.top_workloads.map(w => (
                    <tr key={`${w.namespace}/${w.workload}`} className="border-b rule last:border-0">
                      <td className="py-1.5 pr-3 font-medium">{w.workload}</td>
                      <td className="py-1.5 pr-3 text-zinc-500 dark:text-zinc-400">{w.namespace}</td>
                      <td className="py-1.5 pr-3 text-zinc-500 dark:text-zinc-400">{w.repo_name || "—"}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{w.deployments}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">{w.failed || "—"}</td>
                      <td className="py-1.5 pr-3 text-right tabular-nums">
                        {w.failure_rate === null ? "—" : `${w.failure_rate.toFixed(0)}%`}
                      </td>
                      <td className="py-1.5 text-right tabular-nums">{fmtDuration(w.lead_median_sec)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>
      )}

      {tab === "deployments" && (
        <Card title="Deployments" subtitle="every image change behind the numbers above, newest first">
          <div className="overflow-x-auto">
            <table className="w-full text-[13px]">
              <thead>
                <tr className="text-left text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 border-b rule">
                  <th className="font-medium py-1.5 pr-3">When</th>
                  <th className="font-medium py-1.5 pr-3">Workload</th>
                  <th className="font-medium py-1.5 pr-3">Image</th>
                  <th className="font-medium py-1.5 pr-3">Commit</th>
                  <th className="font-medium py-1.5 pr-3 text-right">Lead time</th>
                  <th className="font-medium py-1.5 pr-3">Outcome</th>
                  <th className="font-medium py-1.5 text-right">Recovered in</th>
                </tr>
              </thead>
              <tbody>
                {deployments.length === 0 && (
                  <tr><td colSpan={7} className="py-3 text-zinc-500 dark:text-zinc-400 text-[12px]">
                    Nothing recorded yet.
                  </td></tr>
                )}
                {deployments.map(d => (
                  <tr key={d.id} className="border-b rule last:border-0 align-top">
                    <td className="py-1.5 pr-3 tabular-nums whitespace-nowrap text-zinc-500 dark:text-zinc-400">
                      {fmtDateTime(d.deployed_at)}
                    </td>
                    <td className="py-1.5 pr-3">
                      <span className="font-medium">{d.workload}</span>
                      <span className="text-zinc-500 dark:text-zinc-400"> · {d.namespace}</span>
                      {d.rollback && (
                        <span className="ml-1.5 text-[10px] uppercase tracking-wide px-1 py-0.5 rounded border border-amber-500/40 bg-amber-500/10 text-amber-700 dark:text-amber-300">
                          rollback
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 font-mono text-[11px] break-all max-w-[22ch]">{d.image}</td>
                    <td className="py-1.5 pr-3 text-[11px]">
                      {d.link_status === "linked" ? (
                        <span className="font-mono">{d.commit_sha.slice(0, 7)}</span>
                      ) : (
                        <span className="text-zinc-500 dark:text-zinc-400" title={d.link_detail}>
                          {d.link_status === "pending" ? "resolving…" : "unlinked"}
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 pr-3 text-right tabular-nums">{fmtDuration(d.lead_time_sec)}</td>
                    <td className={`py-1.5 pr-3 ${OUTCOME_STYLE[d.outcome] ?? ""}`}>
                      {d.outcome}
                      {d.failed_reason && (
                        <span className="text-zinc-500 dark:text-zinc-400 text-[11px]"> · {d.failed_reason}</span>
                      )}
                      {d.dependency_incident && d.outcome === "ok" && (
                        <span className="block text-[10px] text-zinc-500 dark:text-zinc-400 leading-tight">
                          a dependency failed in the window — not counted
                        </span>
                      )}
                    </td>
                    <td className="py-1.5 text-right tabular-nums">
                      {d.outcome === "failed" && d.recovery_sec === null
                        ? <span className="text-red-500 dark:text-red-400">still failing</span>
                        : fmtDuration(d.recovery_sec)}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}
