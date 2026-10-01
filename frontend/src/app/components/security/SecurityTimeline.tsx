"use client";

import { useEffect, useState } from "react";
import { Area, AreaChart, ResponsiveContainer, Tooltip, XAxis, YAxis } from "recharts";
import { apiFetch } from "@/lib/api";
import type { SecurityDomain } from "./SecurityDashboard";

type Sev = "critical" | "high" | "medium" | "low";
interface Counts { critical: number; high: number; medium: number; low: number }
interface Point extends Counts { date: string; repos: number }
interface Mover { repo: string; from: Counts; to: Counts; delta: Counts }
interface Split { baseline_repos: number; baseline_from: Counts; baseline_to: Counts; added_repos: number; added: Counts }
interface Timeline { points: Point[]; improved: Mover[]; regressed: Mover[]; scans: number; split?: Split }

const SEVERITIES: { key: Sev; label: string; stroke: string }[] = [
  { key: "critical", label: "Critical", stroke: "#ef4444" },
  { key: "high",     label: "High",     stroke: "#f97316" },
  { key: "medium",   label: "Medium",   stroke: "#eab308" },
  { key: "low",      label: "Low",      stroke: "#22c55e" },
];

const RANGES = [7, 30, 90, 180, 365];

const fmtDate = (d: string) =>
  new Date(d + "T12:00:00").toLocaleDateString([], { day: "2-digit", month: "short" });

/** Signed change, written so that down reads as the good direction. Only
 *  the difference: callers that show a starting value also show where it
 *  ended, because "765 → ▲ 660" reads as a fall to 660 when it is a rise of
 *  660. */
const Delta = ({ from, to }: { from: number; to: number }) => {
  const d = to - from;
  if (d === 0) return <span className="text-zinc-500">no change</span>;
  const pct = from > 0 ? `, ${d > 0 ? "+" : ""}${Math.round((d / from) * 100)}%` : "";
  return (
    <span className={d < 0 ? "text-brand-green" : "text-red-500 dark:text-red-400"}>
      {d < 0 ? "▼" : "▲"} {d > 0 ? "+" : "−"}{Math.abs(d).toLocaleString()}{pct}
    </span>
  );
};

const FromTo = ({ from, to }: { from: number; to: number }) => (
  <>
    <span className="text-zinc-500">{from.toLocaleString()} → {to.toLocaleString()} </span>
    <span className="text-zinc-500">(</span><Delta from={from} to={to} /><span className="text-zinc-500">)</span>
  </>
);

/** How the totals moved over time, for the repositories the dashboard is
 *  filtered to. One small chart per severity rather than one shared chart:
 *  medium findings outnumber critical ones by an order of magnitude or more,
 *  and on a shared axis the line that matters most would be flat. */
export default function SecurityTimeline({ domain, wsId, projectKey, refreshKey = 0 }: {
  domain: SecurityDomain; wsId: number | null; projectKey: string | null;
  /** Bumped by the dashboard when a scan finished; refetches without a spinner. */
  refreshKey?: number;
}) {
  const [days, setDays] = useState(90);
  const [data, setData] = useState<Timeline | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const params = new URLSearchParams({ domain, days: String(days) });
    try { params.set("tz", Intl.DateTimeFormat().resolvedOptions().timeZone); } catch { /* server falls back to UTC */ }
    if (wsId) params.set("workspace_id", String(wsId));
    if (projectKey) params.set("project_key", projectKey);
    setLoading(true);
    apiFetch(`/scan-timeline?${params}`)
      .then(r => r.json())
      .then(d => setData(Array.isArray(d?.points) ? d : null))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  }, [domain, days, wsId, projectKey]);

  // A live refresh keeps what is on screen until the new numbers arrive,
  // instead of flashing "Loading history…" every time a scan lands.
  useEffect(() => {
    if (!refreshKey) return;
    const params = new URLSearchParams({ domain, days: String(days) });
    try { params.set("tz", Intl.DateTimeFormat().resolvedOptions().timeZone); } catch { /* UTC */ }
    if (wsId) params.set("workspace_id", String(wsId));
    if (projectKey) params.set("project_key", projectKey);
    apiFetch(`/scan-timeline?${params}`)
      .then(r => r.json())
      .then(d => { if (Array.isArray(d?.points)) setData(d); })
      .catch(() => { /* keep the last good data */ });
  }, [refreshKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const points = data?.points ?? [];
  // The line starts on the first day anything had been scanned; days before
  // that are not zero vulnerabilities, they are no data.
  const firstIdx = points.findIndex(p => p.repos > 0);
  const series = firstIdx >= 0 ? points.slice(firstIdx) : [];
  const first = series[0];
  const last = series[series.length - 1];
  // Yesterday's closing numbers, so a fix made today is visible on its own
  // instead of disappearing into a three-month line.
  const yesterday = series.length >= 2 ? series[series.length - 2] : undefined;
  const split = data?.split;

  return (
    <section className="glass-card p-3 space-y-3 min-w-0">
      <div className="flex flex-wrap sm:flex-nowrap items-start justify-between gap-2">
        <div className="min-w-0">
          <h2 className="text-sm font-semibold">Trend</h2>
          <p className="text-xs text-zinc-500">
            Each day counts every repository at its most recent scan up to that day.
            {first && split && first.date !== last.date && (
              <> The change below compares the {split.baseline_repos} repositories tracked since {fmtDate(first.date)} with themselves
                {split.added_repos > 0 && <>; {split.added_repos} more started being scanned in this period and raise the total without anything getting worse</>}.</>
            )}
          </p>
        </div>
        <div className="flex gap-1 shrink-0" role="group" aria-label="Time range">
          {RANGES.map(r => (
            <button
              key={r}
              onClick={() => setDays(r)}
              className={`px-2.5 py-1 text-xs rounded border transition-colors ${days === r ? "bg-brand-green border-brand-green text-black" : "border-zinc-300 dark:border-zinc-700 text-zinc-500 hover:bg-zinc-100 dark:hover:bg-zinc-800"}`}
            >
              {r === 365 ? "1y" : `${r}d`}
            </button>
          ))}
        </div>
      </div>

      {loading ? (
        <p className="text-xs text-zinc-500 py-6 text-center">Loading history…</p>
      ) : series.length === 0 ? (
        <p className="text-xs text-zinc-500 py-6 text-center">No scans recorded in this period yet. The trend fills in as scans run.</p>
      ) : (
        <>
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-2">
            {SEVERITIES.map(s => (
              <div key={s.key} className="rounded-md border border-zinc-200 dark:border-zinc-800 p-2.5 min-w-0">
                <div className="flex items-baseline justify-between gap-2">
                  <span className="text-xs text-zinc-500 flex items-center gap-1.5">
                    <span className="inline-block w-2 h-2 rounded-full" style={{ background: s.stroke }} aria-hidden />
                    {s.label}
                  </span>
                  <span className="text-lg font-semibold tabular-nums text-zinc-800 dark:text-zinc-100">{last[s.key].toLocaleString()}</span>
                </div>
                {split ? (
                  <div className="text-[11px] text-right tabular-nums space-y-0.5">
                    {yesterday && (
                      <div title="Change since the end of yesterday, all repositories">
                        <span className="text-zinc-500">since yesterday </span>
                        <Delta from={yesterday[s.key]} to={last[s.key]} />
                      </div>
                    )}
                    <div title={`The ${split.baseline_repos} repositories tracked since the start of the period, compared with themselves`}>
                      <span className="text-zinc-500">same {split.baseline_repos} repos </span>
                      <FromTo from={split.baseline_from[s.key]} to={split.baseline_to[s.key]} />
                    </div>
                    {split.added_repos > 0 && (
                      <div className="text-zinc-500" title={`Brought in by the ${split.added_repos} repositories first scanned in this period`}>
                        +{split.added[s.key].toLocaleString()} from {split.added_repos} new repos
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-[11px] text-right tabular-nums">
                    <FromTo from={first[s.key]} to={last[s.key]} />
                  </div>
                )}
                <div className="h-20 mt-1">
                  <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={series} margin={{ top: 4, right: 2, bottom: 0, left: 2 }}>
                      <XAxis dataKey="date" hide />
                      <YAxis hide domain={["auto", "auto"]} />
                      <Tooltip
                        cursor={{ stroke: "rgba(128,128,128,0.4)", strokeWidth: 1 }}
                        contentStyle={{ background: "var(--color-surface)", border: "1px solid var(--card-border)", borderRadius: 8, fontSize: 12 }}
                        labelFormatter={(d) => fmtDate(String(d))}
                        formatter={(v) => [Number(v).toLocaleString(), s.label]}
                      />
                      <Area type="monotone" dataKey={s.key} stroke={s.stroke} strokeWidth={2} fill={s.stroke} fillOpacity={0.12} dot={false} isAnimationActive={false} />
                    </AreaChart>
                  </ResponsiveContainer>
                </div>
              </div>
            ))}
          </div>

          {((data?.improved.length ?? 0) > 0 || (data?.regressed.length ?? 0) > 0) && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
              <MoverList title="Most improved" movers={data?.improved ?? []} />
              <MoverList title="Got worse" movers={data?.regressed ?? []} />
            </div>
          )}
        </>
      )}
    </section>
  );
}

function MoverList({ title, movers }: { title: string; movers: Mover[] }) {
  return (
    <div className="rounded-md border border-zinc-200 dark:border-zinc-800 p-2.5 min-w-0">
      <p className="text-xs font-medium text-zinc-600 dark:text-zinc-300 mb-1.5">{title}</p>
      {movers.length === 0 ? (
        <p className="text-xs text-zinc-500">Nothing in this period.</p>
      ) : (
        <ul className="space-y-1">
          {movers.map(m => (
            <li key={m.repo} className="flex items-center justify-between gap-2 text-xs">
              <span className="font-mono truncate text-zinc-700 dark:text-zinc-300">{m.repo}</span>
              <span className="shrink-0 tabular-nums space-x-2">
                {SEVERITIES.filter(s => m.delta[s.key] !== 0).slice(0, 2).map(s => (
                  <span key={s.key} title={`${s.label}: ${m.from[s.key]} → ${m.to[s.key]}`}>
                    <span className="text-zinc-500">{s.label[0]}</span>{" "}
                    <span className={m.delta[s.key] < 0 ? "text-brand-green" : "text-red-500 dark:text-red-400"}>
                      {m.delta[s.key] > 0 ? "+" : ""}{m.delta[s.key]}
                    </span>
                  </span>
                ))}
              </span>
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
