"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";

interface ServiceProblem {
  id: number;
  opened_at: string;
  last_seen_at: string;
  closed_at: string | null;
  namespace: string;
  workload_kind: string;
  workload: string;
  kind: string;
  severity: string;
  title: string;
  detail: string;
  value: number;
  requests: number;
  errors: number;
  cause_kind: string;
  cause_source: string;
  cause_namespace: string;
  cause_node_kind: string;
  cause_name: string;
  cause_host: string;
  cause_detail: string;
  occurrences: number;
}

interface LogErrorGroup {
  namespace: string;
  workload_kind: string;
  workload: string;
  fingerprint: string;
  template: string;
  class: string;
  target: string;
  count: number;
  first_seen: string;
  last_seen: string;
  sample: string;
  last_pod: string;
  external: boolean;
}

const SEVERITY: Record<string, { dot: string; text: string; label: string }> = {
  critical: { dot: "bg-red-500", text: "text-red-500 dark:text-red-400", label: "Critical" },
  warning: { dot: "bg-amber-500", text: "text-amber-600 dark:text-amber-400", label: "Warning" },
  info: { dot: "bg-sky-500", text: "text-sky-600 dark:text-sky-400", label: "Info" },
};
const sev = (s: string) => SEVERITY[s] ?? SEVERITY.info;

const PROBLEM_KIND: Record<string, string> = {
  http_5xx: "Server errors",
  error_logs: "Error logs",
  dependency_failure: "Dependency unreachable",
};

const ERROR_CLASS: Record<string, { label: string; style: string }> = {
  dependency_unreachable: {
    label: "Dependency unreachable",
    style: "text-orange-600 dark:text-orange-400 border-orange-500/30 bg-orange-500/10",
  },
  dependency_timeout: {
    label: "Dependency timeout",
    style: "text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/10",
  },
  dependency_http: {
    label: "Dependency error response",
    style: "text-yellow-600 dark:text-yellow-400 border-yellow-500/30 bg-yellow-500/10",
  },
  app_exception: {
    label: "Application exception",
    style: "text-red-500 dark:text-red-400 border-red-500/30 bg-red-500/10",
  },
  unknown: {
    label: "Unclassified",
    style: "text-zinc-500 dark:text-zinc-400 border-zinc-500/30 bg-zinc-500/10",
  },
};
const cls = (c: string) => ERROR_CLASS[c] ?? ERROR_CLASS.unknown;

function shortWhen(iso: string): string {
  const then = new Date(iso).getTime();
  if (!Number.isFinite(then)) return "—";
  const mins = Math.max(0, Math.round((Date.now() - then) / 60000));
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.round(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

/**
 * The verdict banner. This is the part of the page that has to be read
 * correctly at a glance, so the three outcomes are visually distinct and
 * "unknown" is never dressed up as a conclusion -- a workload nobody observed
 * is not a workload that was cleared, and it is not one that was blamed.
 */
function CauseBanner({ p }: { p: ServiceProblem }) {
  const target = p.cause_host || p.cause_name;

  if (p.cause_kind === "dependency") {
    const measured = p.cause_source === "ebpf";
    return (
      <div className="mt-3 rounded border border-orange-500/30 bg-orange-500/5 px-3 py-2">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-xs font-bold uppercase tracking-wide text-orange-600 dark:text-orange-400">
            Not this application
          </span>
          <span className="font-mono text-sm text-zinc-800 dark:text-zinc-200">{target}</span>
          <span
            className={`text-[10px] px-1.5 py-0.5 rounded border ${
              measured
                ? "text-brand-green border-brand-green/30 bg-brand-green/10"
                : "text-zinc-500 dark:text-zinc-400 border-zinc-500/30 bg-zinc-500/10"
            }`}
            title={
              measured
                ? "The traffic layer watched these calls fail."
                : "Read from the application's own log text, not from observed traffic."
            }
          >
            {measured ? "measured" : "inferred from logs"}
          </span>
        </div>
        <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-1.5">{p.cause_detail}</p>
      </div>
    );
  }

  if (p.cause_kind === "self") {
    return (
      <div className="mt-3 rounded border border-red-500/30 bg-red-500/5 px-3 py-2">
        <span className="text-xs font-bold uppercase tracking-wide text-red-500 dark:text-red-400">
          This application
        </span>
        <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-1.5">{p.cause_detail}</p>
      </div>
    );
  }

  return (
    <div className="mt-3 rounded border border-zinc-300 dark:border-zinc-700 bg-zinc-500/5 px-3 py-2">
      <span className="text-xs font-bold uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
        Cause not established
      </span>
      <p className="text-xs text-zinc-600 dark:text-zinc-400 mt-1.5">{p.cause_detail}</p>
    </div>
  );
}

export default function TriagePage() {
  const [tab, setTab] = useState<"problems" | "errors">("problems");

  const [problems, setProblems] = useState<ServiceProblem[]>([]);
  const [groups, setGroups] = useState<LogErrorGroup[]>([]);
  const [byClass, setByClass] = useState<Record<string, number>>({});
  const [externalTotal, setExternalTotal] = useState(0);
  const [errorTotal, setErrorTotal] = useState(0);

  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  const [status, setStatus] = useState<"open" | "all">("open");
  const [causeFilter, setCauseFilter] = useState("");
  const [nsFilter, setNsFilter] = useState("");
  const [classFilter, setClassFilter] = useState("");
  const [externalOnly, setExternalOnly] = useState(false);
  const [hours, setHours] = useState(6);
  const [expanded, setExpanded] = useState<number | null>(null);

  const load = useCallback(async () => {
    try {
      const pq = new URLSearchParams({ status });
      if (causeFilter) pq.set("cause", causeFilter);
      if (nsFilter) pq.set("namespace", nsFilter);

      const gq = new URLSearchParams({ hours: String(hours) });
      if (nsFilter) gq.set("namespace", nsFilter);
      if (classFilter) gq.set("class", classFilter);
      if (externalOnly) gq.set("external", "true");

      const [pRes, gRes] = await Promise.all([
        apiFetch(`/monitoring/services/problems?${pq}`),
        apiFetch(`/monitoring/services/log-errors?${gq}`),
      ]);
      const pBody = await pRes.json().catch(() => ({}));
      const gBody = await gRes.json().catch(() => ({}));

      if (!pRes.ok) {
        setError(pBody.error ?? `Request failed (${pRes.status})`);
        return;
      }
      setError("");
      setProblems(pBody.problems ?? []);
      setGroups(gBody.groups ?? []);
      setByClass(gBody.by_class ?? {});
      setExternalTotal(gBody.external_total ?? 0);
      setErrorTotal(gBody.total ?? 0);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to reach the API");
    } finally {
      setLoading(false);
    }
  }, [status, causeFilter, nsFilter, classFilter, externalOnly, hours]);

  useEffect(() => {
    load();
    const t = setInterval(load, 60000);
    return () => clearInterval(t);
  }, [load]);

  const namespaces = useMemo(() => {
    const set = new Set<string>();
    problems.forEach(p => set.add(p.namespace));
    groups.forEach(g => set.add(g.namespace));
    return [...set].sort();
  }, [problems, groups]);

  const counts = useMemo(() => {
    const open = problems.filter(p => !p.closed_at);
    return {
      total: open.length,
      dependency: open.filter(p => p.cause_kind === "dependency").length,
      self: open.filter(p => p.cause_kind === "self").length,
      unknown: open.filter(p => p.cause_kind === "unknown").length,
    };
  }, [problems]);

  const externalPct = errorTotal > 0 ? Math.round((externalTotal / errorTotal) * 100) : 0;

  return (
    <div className="p-4 max-w-[1500px] mx-auto">
      <header className="mb-6">
        <h1 className="text-2xl font-black tracking-tight">Triage</h1>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
          Applications that are failing while their pods are healthy — and, where the evidence
          allows it, whose fault that is. A pod can be Running and Ready and still answer 500
          because something it depends on is down; nothing in the Kubernetes API reports that.
        </p>
      </header>

      {error && (
        <div className="mb-3 rounded border border-red-500/30 bg-red-500/10 px-3 py-2 text-sm text-red-500 dark:text-red-400">
          {error}
        </div>
      )}

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-6">
        <Tile label="Open problems" value={counts.total} />
        <Tile
          label="Caused by a dependency"
          value={counts.dependency}
          accent="text-orange-600 dark:text-orange-400"
          hint="Something outside the application failed."
        />
        <Tile
          label="In the application"
          value={counts.self}
          accent="text-red-500 dark:text-red-400"
          hint="Dependencies answered normally."
        />
        <Tile
          label="Cause not established"
          value={counts.unknown}
          accent="text-zinc-500 dark:text-zinc-400"
          hint="Nothing observed the outbound calls and the logs named nobody. Deploy the traffic collector to reduce this."
        />
      </div>

      <div className="flex gap-1 mb-4 border-b border-zinc-200 dark:border-zinc-800">
        {(["problems", "errors"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 text-sm font-semibold border-b-2 -mb-px transition ${
              tab === t
                ? "border-brand-green text-brand-green"
                : "border-transparent text-zinc-500 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200"
            }`}
          >
            {t === "problems" ? `Problems (${counts.total})` : `Error catalogue (${groups.length})`}
          </button>
        ))}
      </div>

      <div className="flex flex-wrap gap-2 mb-4 items-center">
        <select
          value={nsFilter}
          onChange={e => setNsFilter(e.target.value)}
          className="bg-transparent border border-zinc-300 dark:border-zinc-700 rounded px-2 py-1.5 text-sm"
        >
          <option value="">All namespaces</option>
          {namespaces.map(ns => (
            <option key={ns} value={ns}>{ns}</option>
          ))}
        </select>

        {tab === "problems" ? (
          <>
            <select
              value={status}
              onChange={e => setStatus(e.target.value as "open" | "all")}
              className="bg-transparent border border-zinc-300 dark:border-zinc-700 rounded px-2 py-1.5 text-sm"
            >
              <option value="open">Open only</option>
              <option value="all">Open and resolved</option>
            </select>
            <select
              value={causeFilter}
              onChange={e => setCauseFilter(e.target.value)}
              className="bg-transparent border border-zinc-300 dark:border-zinc-700 rounded px-2 py-1.5 text-sm"
            >
              <option value="">Any cause</option>
              <option value="dependency">Caused by a dependency</option>
              <option value="self">In the application</option>
              <option value="unknown">Cause not established</option>
            </select>
          </>
        ) : (
          <>
            <select
              value={classFilter}
              onChange={e => setClassFilter(e.target.value)}
              className="bg-transparent border border-zinc-300 dark:border-zinc-700 rounded px-2 py-1.5 text-sm"
            >
              <option value="">Any class</option>
              {Object.keys(ERROR_CLASS).map(c => (
                <option key={c} value={c}>{ERROR_CLASS[c].label}</option>
              ))}
            </select>
            <label className="flex items-center gap-2 text-sm text-zinc-600 dark:text-zinc-400">
              <input
                type="checkbox"
                checked={externalOnly}
                onChange={e => setExternalOnly(e.target.checked)}
                className="accent-brand-green"
              />
              Only what is not the application&apos;s fault
            </label>
            <select
              value={hours}
              onChange={e => setHours(Number(e.target.value))}
              className="bg-transparent border border-zinc-300 dark:border-zinc-700 rounded px-2 py-1.5 text-sm"
            >
              {[1, 6, 24, 72, 168].map(h => (
                <option key={h} value={h}>Last {h < 24 ? `${h}h` : `${h / 24}d`}</option>
              ))}
            </select>
            {errorTotal > 0 && (
              <span className="text-sm text-zinc-500 dark:text-zinc-400 ml-auto">
                {externalPct}% of {errorTotal.toLocaleString()} errors were a dependency failing
              </span>
            )}
          </>
        )}
      </div>

      {loading ? (
        <p className="text-sm text-zinc-500 dark:text-zinc-400">Loading…</p>
      ) : tab === "problems" ? (
        <ProblemList
          problems={problems}
          groups={groups}
          expanded={expanded}
          setExpanded={setExpanded}
        />
      ) : (
        <ErrorCatalogue groups={groups} byClass={byClass} />
      )}
    </div>
  );
}

function Tile({
  label,
  value,
  accent,
  hint,
}: {
  label: string;
  value: number;
  accent?: string;
  hint?: string;
}) {
  return (
    <div
      className="rounded border border-zinc-200 dark:border-zinc-800 p-4 bg-white dark:bg-zinc-900/40"
      title={hint}
    >
      <div className={`text-xl font-semibold tabular-nums ${accent ?? ""}`}>{value}</div>
      <div className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">{label}</div>
    </div>
  );
}

function ProblemList({
  problems,
  groups,
  expanded,
  setExpanded,
}: {
  problems: ServiceProblem[];
  groups: LogErrorGroup[];
  expanded: number | null;
  setExpanded: (id: number | null) => void;
}) {
  if (problems.length === 0) {
    // An empty list has two very different meanings and the page must not let
    // them be confused: nothing is wrong, or nothing has been measured yet.
    return (
      <div className="rounded border border-zinc-200 dark:border-zinc-800 p-8 text-center">
        <p className="font-semibold">No application problems open.</p>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-2 max-w-xl mx-auto">
          If this cluster has just started collecting, an empty list here means the first poll
          has not completed rather than that everything is well. The error catalogue tab shows
          whether anything is being read at all.
        </p>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {problems.map(p => {
        const s = sev(p.severity);
        const related = groups.filter(
          g => g.namespace === p.namespace && g.workload === p.workload
        );
        const isOpen = expanded === p.id;
        return (
          <div
            key={p.id}
            className={`rounded border p-4 bg-white dark:bg-zinc-900/40 ${
              p.closed_at
                ? "border-zinc-200 dark:border-zinc-800 opacity-60"
                : "border-zinc-300 dark:border-zinc-700"
            }`}
          >
            <div className="flex items-start gap-2">
              <span className={`w-2.5 h-2.5 rounded-full mt-1.5 shrink-0 ${s.dot}`} />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2 flex-wrap">
                  <h3 className="font-bold">{p.title}</h3>
                  <span className={`text-[10px] px-1.5 py-0.5 rounded border ${s.text} border-current/30`}>
                    {s.label}
                  </span>
                  <span className="text-[10px] px-1.5 py-0.5 rounded border border-zinc-400/30 text-zinc-500 dark:text-zinc-400">
                    {PROBLEM_KIND[p.kind] ?? p.kind}
                  </span>
                  {p.closed_at && (
                    <span className="text-[10px] px-1.5 py-0.5 rounded border border-brand-green/30 text-brand-green">
                      Resolved
                    </span>
                  )}
                </div>
                <p className="text-xs font-mono text-zinc-500 dark:text-zinc-400 mt-1">
                  {p.namespace} / {p.workload_kind} / {p.workload}
                </p>
                <p className="text-sm text-zinc-700 dark:text-zinc-300 mt-2 whitespace-pre-line">
                  {p.detail}
                </p>

                <CauseBanner p={p} />

                <div className="flex gap-4 text-xs text-zinc-500 dark:text-zinc-400 mt-3 flex-wrap">
                  <span>Opened {shortWhen(p.opened_at)}</span>
                  <span>Last seen {shortWhen(p.last_seen_at)}</span>
                  <span>{p.occurrences} occurrence{p.occurrences === 1 ? "" : "s"}</span>
                  {p.requests > 0 && (
                    <span>
                      {p.errors.toLocaleString()} of {p.requests.toLocaleString()} requests
                    </span>
                  )}
                  {related.length > 0 && (
                    <button
                      onClick={() => setExpanded(isOpen ? null : p.id)}
                      className="text-brand-green hover:underline"
                    >
                      {isOpen ? "Hide" : `Show ${related.length} error group${related.length === 1 ? "" : "s"}`}
                    </button>
                  )}
                </div>

                {isOpen && (
                  <div className="mt-3 space-y-2">
                    {related.map(g => (
                      <GroupRow key={g.fingerprint} g={g} compact />
                    ))}
                  </div>
                )}
              </div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

function ErrorCatalogue({
  groups,
  byClass,
}: {
  groups: LogErrorGroup[];
  byClass: Record<string, number>;
}) {
  if (groups.length === 0) {
    return (
      <div className="rounded border border-zinc-200 dark:border-zinc-800 p-8 text-center">
        <p className="font-semibold">No errors found in the logs for this window.</p>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-2 max-w-xl mx-auto">
          Widen the time range before concluding the applications are quiet. Detection reads
          error-level lines from container output, so a workload that logs failures in a format
          without a recognisable level token will not appear here.
        </p>
      </div>
    );
  }

  const classKeys = Object.keys(byClass).sort((a, b) => byClass[b] - byClass[a]);

  return (
    <>
      {classKeys.length > 0 && (
        <div className="flex flex-wrap gap-2 mb-4">
          {classKeys.map(c => (
            <span key={c} className={`text-xs px-2 py-1 rounded border ${cls(c).style}`}>
              {cls(c).label}: {byClass[c].toLocaleString()}
            </span>
          ))}
        </div>
      )}
      <div className="space-y-2">
        {groups.map(g => (
          <GroupRow key={`${g.namespace}/${g.workload}/${g.fingerprint}`} g={g} />
        ))}
      </div>
    </>
  );
}

function GroupRow({ g, compact }: { g: LogErrorGroup; compact?: boolean }) {
  const [open, setOpen] = useState(false);
  const c = cls(g.class);
  return (
    <div className="rounded border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900/40">
      <button
        onClick={() => setOpen(!open)}
        className="w-full text-left px-3 py-2.5 flex items-start gap-3 hover:bg-zinc-500/5"
      >
        <span className="text-lg font-black tabular-nums shrink-0 w-16 text-right">
          {g.count.toLocaleString()}
        </span>
        <span className="min-w-0 flex-1">
          <span className="flex items-center gap-2 flex-wrap">
            <span className={`text-[10px] px-1.5 py-0.5 rounded border ${c.style}`}>{c.label}</span>
            {g.target && (
              <span className="text-xs font-mono text-zinc-700 dark:text-zinc-300">{g.target}</span>
            )}
            {!compact && (
              <span className="text-xs font-mono text-zinc-500 dark:text-zinc-400">
                {g.namespace}/{g.workload}
              </span>
            )}
          </span>
          <span className="block text-sm font-mono text-zinc-700 dark:text-zinc-300 mt-1 truncate">
            {g.template}
          </span>
          <span className="block text-[11px] text-zinc-500 dark:text-zinc-400 mt-1">
            First {shortWhen(g.first_seen)} · last {shortWhen(g.last_seen)}
            {g.last_pod && ` · ${g.last_pod}`}
          </span>
        </span>
      </button>
      {open && (
        <pre className="px-3 pb-3 text-xs font-mono whitespace-pre-wrap break-all text-zinc-600 dark:text-zinc-400 border-t border-zinc-200 dark:border-zinc-800 pt-2">
          {g.sample}
        </pre>
      )}
    </div>
  );
}
