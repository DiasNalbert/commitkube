"use client";

import { useEffect, useState, type ReactNode } from "react";
import { apiFetch } from "@/lib/api";
import SecurityTimeline from "./SecurityTimeline";

/** The code-weaknesses view of the Code Security page: only what static
 *  analysis found in code the team wrote, across every repository in scope.
 *  The repository cards answer "what is wrong with this repo"; this answers
 *  which kinds of flaw keep turning up, where they concentrate and how long
 *  they stay open. */

interface Counts { critical: number; high: number; medium: number; low: number }
interface Group extends Counts { key: string; name: string; cwe?: string; open: number; repos: number }
interface RepoRow extends Counts { repo: string; open: number; oldest: string }
interface Occurrence {
  repo: string; target: string; line: number; rule: string; cwe?: string;
  severity: string; title: string; first_seen: string;
}
interface Data {
  totals: Counts;
  open: number;
  suppressed: number;
  repos_in_scope: number;
  repos_scanned: number;
  repos_affected: number;
  sast_errors: { repo: string; error: string }[];
  by_cwe: Group[];
  by_rule: Group[];
  by_repo: RepoRow[];
  fix_time: { resolved: number; median_days: number; p90_days: number; open_median_days: number; open_stale: number };
  occurrences?: Occurrence[];
  occurrences_total?: number;
}

type Selection = { by: "cwe" | "rule"; key: string; label: string } | null;

const sevText = (s: string) => {
  switch (s) {
    case "CRITICAL": return "text-red-500 font-bold";
    case "HIGH": return "text-orange-500 font-bold";
    case "MEDIUM": return "text-yellow-500";
    case "LOW": return "text-green-500";
    default: return "text-zinc-400";
  }
};

const days = (d: number) => (d < 1 ? "< 1 day" : `${d.toLocaleString("en-US", { maximumFractionDigits: 1 })} days`);

/** Severity split as words, worst first, zeros left out. Never color alone. */
const SevSplit = ({ c }: { c: Counts }) => (
  <span className="text-[11px] tabular-nums whitespace-nowrap">
    {([["critical", "C", "CRITICAL"], ["high", "H", "HIGH"], ["medium", "M", "MEDIUM"], ["low", "L", "LOW"]] as const)
      .filter(([k]) => c[k] > 0)
      .map(([k, short, sev]) => (
        <span key={k} className={`ml-1.5 ${sevText(sev)}`} title={`${c[k]} ${sev.toLowerCase()}`}>{short}:{c[k]}</span>
      ))}
  </span>
);

const Tile = ({ label, value, detail, title }: { label: string; value: string; detail?: ReactNode; title?: string }) => (
  <div className="glass-card p-4 min-w-0" title={title}>
    <p className="text-xs text-zinc-500">{label}</p>
    <p className="text-2xl font-semibold tabular-nums text-zinc-800 dark:text-zinc-100 mt-1">{value}</p>
    {detail && <div className="text-[11px] text-zinc-500 mt-1">{detail}</div>}
  </div>
);

/** One ranked list: a thin bar per row in a single hue (one measure, so one
 *  color), the number beside it in text ink, the severity split in words. */
function Ranking({ title, hint, rows, selected, onSelect }: {
  title: string; hint: string;
  rows: { key: string; label: string; sub?: string; open: number; counts: Counts; tooltip: string }[];
  selected?: string; onSelect?: (key: string, label: string) => void;
}) {
  const max = Math.max(1, ...rows.map(r => r.open));
  return (
    <section className="glass-card p-3 min-w-0">
      <h2 className="text-sm font-semibold">{title}</h2>
      <p className="text-xs text-zinc-500 mb-2">{hint}</p>
      {rows.length === 0 ? (
        <p className="text-xs text-zinc-500 py-4 text-center">Nothing open.</p>
      ) : (
        <ul className="space-y-0.5">
          {rows.map(r => {
            const active = selected === r.key;
            const Row = onSelect ? "button" : "div";
            return (
              <li key={r.key}>
                <Row
                  type={onSelect ? "button" : undefined}
                  onClick={onSelect ? () => onSelect(r.key, r.label) : undefined}
                  title={r.tooltip}
                  className={`w-full text-left rounded px-2 py-1.5 transition-colors ${onSelect ? "hover:bg-zinc-100 dark:hover:bg-zinc-800/60" : ""} ${active ? "bg-sky-500/10 ring-1 ring-sky-500/40" : ""}`}
                >
                  <div className="flex items-baseline justify-between gap-2 min-w-0">
                    <span className="text-xs text-zinc-700 dark:text-zinc-200 truncate">
                      {r.label}
                      {r.sub && <span className="ml-1.5 text-zinc-500 font-mono text-[10px]">{r.sub}</span>}
                    </span>
                    <span className="shrink-0">
                      <span className="text-xs font-semibold tabular-nums text-zinc-800 dark:text-zinc-100">{r.open}</span>
                      <SevSplit c={r.counts} />
                    </span>
                  </div>
                  <div className="h-1.5 mt-1 rounded-full bg-zinc-200/60 dark:bg-zinc-800">
                    <div className="h-1.5 rounded-full bg-sky-500" style={{ width: `${(r.open / max) * 100}%` }} />
                  </div>
                </Row>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}

export default function WeaknessesPanel({ wsId, projectKey, refreshKey = 0 }: {
  wsId: number | null; projectKey: string | null; refreshKey?: number;
}) {
  const [data, setData] = useState<Data | null>(null);
  const [loading, setLoading] = useState(true);
  const [selection, setSelection] = useState<Selection>(null);
  const [occ, setOcc] = useState<{ rows: Occurrence[]; total: number } | null>(null);
  const [showErrors, setShowErrors] = useState(false);

  const scope = () => {
    const p = new URLSearchParams();
    if (wsId) p.set("workspace_id", String(wsId));
    if (projectKey) p.set("project_key", projectKey);
    return p;
  };

  useEffect(() => {
    setLoading(true);
    apiFetch(`/scan-weaknesses?${scope()}`)
      .then(r => r.json())
      .then(d => setData(d && Array.isArray(d.by_cwe) ? d : null))
      .catch(() => setData(null))
      .finally(() => setLoading(false));
    // A scope change makes the selected row meaningless.
    setSelection(null);
  }, [wsId, projectKey]); // eslint-disable-line react-hooks/exhaustive-deps

  // A finished scan refreshes in place, without the loading state.
  useEffect(() => {
    if (!refreshKey) return;
    apiFetch(`/scan-weaknesses?${scope()}`)
      .then(r => r.json())
      .then(d => { if (d && Array.isArray(d.by_cwe)) setData(d); })
      .catch(() => { /* keep what is shown */ });
  }, [refreshKey]); // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (!selection) { setOcc(null); return; }
    const p = scope();
    p.set(selection.by, selection.key);
    apiFetch(`/scan-weaknesses?${p}`)
      .then(r => r.json())
      .then(d => setOcc({ rows: d.occurrences ?? [], total: d.occurrences_total ?? 0 }))
      .catch(() => setOcc({ rows: [], total: 0 }));
  }, [selection, refreshKey]); // eslint-disable-line react-hooks/exhaustive-deps

  const select = (by: "cwe" | "rule") => (key: string, label: string) =>
    setSelection(s => (s && s.by === by && s.key === key ? null : { by, key, label }));

  if (loading) return <div className="text-center py-10 text-brand-green">Loading...</div>;
  if (!data) return <div className="glass-card p-10 text-center text-zinc-500">Could not load the code weaknesses.</div>;

  const ft = data.fix_time;
  const notCovered = data.repos_in_scope - data.repos_scanned;

  return (
    <div className="space-y-3">
      <p className="text-xs text-zinc-500">
        Static analysis has run on {data.repos_scanned} of {data.repos_in_scope} repositories in scope
        {notCovered > 0 && <> — the other {notCovered} get it on their next code scan</>}.
        {data.suppressed > 0 && <> {data.suppressed} suppressed weaknesses are left out of every number here.</>}
      </p>

      {data.sast_errors.length > 0 && (
        <div className="rounded border border-amber-500/40 bg-amber-500/5 px-3 py-2 text-xs text-amber-600 dark:text-amber-400">
          <button type="button" onClick={() => setShowErrors(v => !v)} className="font-medium hover:underline">
            ⚠ Static analysis did not run on the last scan of {data.sast_errors.length} {data.sast_errors.length === 1 ? "repository" : "repositories"}
            {showErrors ? " ▴" : " ▾"}
          </button>
          <span className="text-zinc-500"> — their earlier weaknesses stay open until it runs again.</span>
          {showErrors && (
            <ul className="mt-1.5 space-y-0.5 font-mono text-[11px]">
              {data.sast_errors.map(e => <li key={e.repo}><span className="text-zinc-700 dark:text-zinc-300">{e.repo}</span>: {e.error}</li>)}
            </ul>
          )}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
        <Tile label="Open weaknesses" value={data.open.toLocaleString()} detail={<SevSplit c={data.totals} />} />
        <Tile
          label="Repositories affected"
          value={data.repos_affected.toLocaleString()}
          detail={`of ${data.repos_scanned} analyzed`}
        />
        <Tile
          label="Median time to fix"
          value={ft.resolved > 0 ? days(ft.median_days) : "—"}
          detail={ft.resolved > 0 ? `${ft.resolved} fixed in 90 days · 90% within ${days(ft.p90_days)}` : "nothing fixed in the last 90 days yet"}
          title="From the scan that first reported a weakness to the one that stopped reporting it"
        />
        <Tile
          label="Open longer than 30 days"
          value={ft.open_stale.toLocaleString()}
          detail={data.open > 0 ? `median open for ${days(ft.open_median_days)}` : undefined}
        />
      </div>

      <SecurityTimeline domain="sast" wsId={wsId} projectKey={projectKey} refreshKey={refreshKey} />

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-3">
        <Ranking
          title="By weakness type"
          hint="Click one to see where it occurs."
          selected={selection?.by === "cwe" ? selection.key : undefined}
          onSelect={select("cwe")}
          rows={data.by_cwe.map(g => ({
            key: g.key, label: g.name, sub: g.cwe && g.cwe !== g.name ? g.cwe : undefined, open: g.open, counts: g,
            tooltip: `${g.open} open in ${g.repos} ${g.repos === 1 ? "repository" : "repositories"}`,
          }))}
        />
        <Ranking
          title="By rule"
          hint="The CommitKube rule that matched. Click one to see where."
          selected={selection?.by === "rule" ? selection.key : undefined}
          onSelect={select("rule")}
          rows={data.by_rule.map(g => ({
            key: g.key, label: g.key, sub: g.cwe, open: g.open, counts: g,
            tooltip: `${g.name}\n\n${g.open} open in ${g.repos} ${g.repos === 1 ? "repository" : "repositories"}`,
          }))}
        />
        <Ranking
          title="By repository"
          hint="Worst first: critical and high, then the total."
          rows={data.by_repo.map(r => ({
            key: r.repo, label: r.repo, open: r.open, counts: r,
            tooltip: `${r.open} open · oldest since ${new Date(r.oldest).toLocaleDateString("en-US")}`,
          }))}
        />
      </div>

      {selection && (
        <section className="glass-card p-3 min-w-0">
          <div className="flex items-baseline justify-between gap-2 mb-2">
            <h2 className="text-sm font-semibold truncate">
              Where: {selection.label}
              {occ && <span className="ml-2 text-xs font-normal text-zinc-500">{occ.total} open</span>}
            </h2>
            <button type="button" onClick={() => setSelection(null)} className="text-zinc-500 hover:text-zinc-200 text-sm px-1" aria-label="Close">✕</button>
          </div>
          {!occ ? (
            <p className="text-xs text-zinc-500 py-3">Loading…</p>
          ) : occ.rows.length === 0 ? (
            <p className="text-xs text-zinc-500 py-3">Nothing open.</p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm border-collapse">
                <thead>
                  <tr className="border-b border-zinc-700 text-left text-zinc-400">
                    <th className="py-1.5 px-2 font-medium">Severity</th>
                    <th className="py-1.5 px-2 font-medium">Repository</th>
                    <th className="py-1.5 px-2 font-medium">File</th>
                    <th className="py-1.5 px-2 font-medium">Rule</th>
                    <th className="py-1.5 px-2 font-medium whitespace-nowrap">Since</th>
                  </tr>
                </thead>
                <tbody>
                  {occ.rows.map(o => (
                    <tr key={`${o.repo}|${o.target}|${o.line}|${o.rule}`} className="border-b border-zinc-800" title={o.title}>
                      <td className={`py-1.5 px-2 font-mono text-xs ${sevText(o.severity)}`}>{o.severity}</td>
                      <td className="py-1.5 px-2 text-xs text-zinc-300">{o.repo}</td>
                      <td className="py-1.5 px-2 font-mono text-xs text-zinc-400 max-w-[280px] truncate">{o.target}:{o.line}</td>
                      <td className="py-1.5 px-2 font-mono text-xs text-zinc-400">{o.rule}</td>
                      <td className="py-1.5 px-2 text-xs text-zinc-500 whitespace-nowrap">{new Date(o.first_seen).toLocaleDateString("en-US")}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
              {occ.total > occ.rows.length && (
                <p className="text-[11px] text-zinc-500 mt-2">Showing the first {occ.rows.length} of {occ.total}, worst first.</p>
              )}
            </div>
          )}
        </section>
      )}
    </div>
  );
}
