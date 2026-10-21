"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { useParams } from "next/navigation";
import { AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { apiFetch } from "@/lib/api";
import { loadPermissions, PERMISSIONS } from "@/lib/permissions";
import {
  AlertLog, BarList, Card, Modal, SectionError, Stat, Zone, ZoneForm, fmtBytesSI, fmtFull, fmtNum, fmtPct,
  fmtStamp, relativeTime, sourceLabel, zoneToForm,
} from "../shared";
import ExposureTab from "../exposure";
import TrafficMap from "../map";
import WAFTab from "../waf";

// ---- payload --------------------------------------------------------------------

interface Section<T> { data?: T; error?: string }
interface KeyCount { key: string; count: number }
interface Point { t: string; requests?: number; bytes?: number; visits?: number; mitigated?: number; other?: number }

interface Analytics {
  range: string;
  since: string;
  until: string;
  top_since: string;
  fw_since: string;
  bucket_seconds: number;
  cached_at: string;
  notices: string[] | null;
  sections: {
    traffic?: Section<Point[]>;
    mitigation?: Section<Point[]>;
    status?: Section<KeyCount[]>;
    paths?: Section<KeyCount[]>;
    hosts?: Section<KeyCount[]>;
    countries?: Section<KeyCount[]>;
    methods?: Section<KeyCount[]>;
    cache?: Section<KeyCount[]>;
    ips?: Section<{ ip: string; country: string; count: number }[]>;
    probes?: Section<{ path: string; count: number; reason?: string }[]>;
    user_agents?: Section<{ ua: string; class: string; count: number }[]>;
    bot_scores?: Section<Record<"automated" | "likely_automated" | "likely_human" | "not_scored", number>>;
    verified_bots?: Section<KeyCount[]>;
    fw_actions?: Section<{ action: string; count: number; mitigated: boolean }[]>;
    fw_sources?: Section<KeyCount[]>;
    fw_paths?: Section<{ path: string; count: number; reason?: string }[]>;
    fw_countries?: Section<KeyCount[]>;
    fw_ips?: Section<{ ip: string; country: string; asn: string; count: number }[]>;
    fw_rules?: Section<{ rule_id: string; source: string; description: string; count: number }[]>;
    events?: Section<Record<string, unknown>[]>;
  };
}

const RANGES = [
  { key: "30m", label: "30 min" }, { key: "1h", label: "1 hour" }, { key: "6h", label: "6 hours" },
  { key: "24h", label: "24 hours" }, { key: "3d", label: "3 days" }, { key: "7d", label: "7 days" },
];

const TABS = ["overview", "security", "waf", "exposure", "traffic", "bots", "events", "alerts", "settings"] as const;
type Tab = typeof TABS[number];
const TAB_LABEL: Record<Tab, string> = {
  overview: "Overview", security: "Security", waf: "WAF rules", exposure: "Exposure", traffic: "Traffic", bots: "Bots",
  events: "Security events", alerts: "Alerts", settings: "Settings",
};

// Series colours: the project's validated categorical steps, one per theme.
// Each chart carries a single series, so the title names it and no legend is
// needed; requests and threats are kept on separate charts because their
// scales differ by orders of magnitude.
const REQ = { light: "#4a3aa7", dark: "#9085e9" };
const THREAT = { light: "#eda100", dark: "#c98500" };

const tooltipStyle = {
  background: "var(--color-surface)", border: "1px solid var(--card-border)", borderRadius: 8, fontSize: 12,
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

const UA_CLASS_LABEL: Record<string, string> = {
  browser: "Browsers", automated: "Declared automation", scanner: "Vulnerability scanners", empty: "No user agent", other: "Unclassified",
};

const statusClass = (code: string) => (code ? `${code[0]}xx` : "other");

function tickFormatter(bucketSeconds: number) {
  return (t: string) => {
    const d = new Date(t);
    return bucketSeconds >= 3600
      ? d.toLocaleString([], { month: "2-digit", day: "2-digit", hour: "2-digit" })
      : d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
  };
}

function ProbeBadge({ reason }: { reason?: string }) {
  if (!reason) return null;
  return <span className="text-[10px] px-1 py-px rounded border text-red-500 dark:text-red-400 border-red-500/30 bg-red-500/10 shrink-0">{reason}</span>;
}

function sum<T>(rows: T[] | undefined, f: (r: T) => number) {
  return (rows ?? []).reduce((a, r) => a + f(r), 0);
}

// ---- page ------------------------------------------------------------------------

export default function ZonePage() {
  const params = useParams();
  const id = Number(params.id);
  const [zone, setZone] = useState<Zone | null>(null);
  const [zoneError, setZoneError] = useState("");
  const [data, setData] = useState<Analytics | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [range, setRange] = useState("24h");
  const [tab, setTab] = useState<Tab>("overview");
  const [canManage, setCanManage] = useState(false);
  const [canPoll, setCanPoll] = useState(false);
  const [polling, setPolling] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const dark = useIsDark();
  const reqColor = dark ? REQ.dark : REQ.light;
  const threatColor = dark ? THREAT.dark : THREAT.light;

  useEffect(() => {
    try {
      const saved = localStorage.getItem("cloudflare_range");
      if (saved && RANGES.some(r => r.key === saved)) setRange(saved);
      const h = window.location.hash.slice(1) as Tab;
      if (TABS.includes(h)) setTab(h);
    } catch { /* storage blocked: defaults are fine */ }
    loadPermissions().then(p => {
      setCanManage(p.size === 0 || p.has(PERMISSIONS.cloudflareManage));
      setCanPoll(p.size === 0 || p.has(PERMISSIONS.securityScan));
    });
  }, []);

  const selectTab = (t: Tab) => {
    setTab(t);
    history.replaceState(null, "", `#${t}`);
  };
  const selectRange = (r: string) => {
    setRange(r);
    try { localStorage.setItem("cloudflare_range", r); } catch { /* ignore */ }
  };

  const loadZone = useCallback(async () => {
    try {
      const res = await apiFetch(`/cloudflare/zones/${id}`);
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setZoneError(body.error ?? `Request failed (${res.status})`); return; }
      setZoneError(""); setZone(body);
    } catch (e) {
      setZoneError(e instanceof Error ? e.message : "Could not reach the API");
    }
  }, [id]);

  const loadAnalytics = useCallback(async () => {
    setLoading(true);
    try {
      const res = await apiFetch(`/cloudflare/zones/${id}/analytics?range=${range}`);
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
      setError(""); setData(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    } finally { setLoading(false); }
  }, [id, range]);

  useEffect(() => { loadZone(); }, [loadZone]);
  useEffect(() => { loadAnalytics(); }, [loadAnalytics]);

  const pollNow = async () => {
    setPolling(true);
    try {
      await apiFetch(`/cloudflare/zones/${id}/poll`, { method: "POST" });
      await loadZone();
      setRefreshKey(k => k + 1);
    } finally { setPolling(false); }
  };

  const s = useMemo(() => data?.sections ?? {}, [data]);

  // ---- derived numbers ----
  const totals = useMemo(() => {
    const traffic = s.traffic?.data;
    const requests = sum(traffic, p => p.requests ?? 0);
    const bytes = sum(traffic, p => p.bytes ?? 0);
    const visits = sum(traffic, p => p.visits ?? 0);
    const mitigated = sum(s.mitigation?.data, p => p.mitigated ?? 0);
    const statusTotal = sum(s.status?.data, r => r.count);
    const s5xx = sum(s.status?.data?.filter(r => r.key.startsWith("5")), r => r.count);
    const s4xx = sum(s.status?.data?.filter(r => r.key.startsWith("4")), r => r.count);
    const cacheTotal = sum(s.cache?.data, r => r.count);
    const cached = sum(s.cache?.data?.filter(r => ["hit", "stale", "updating", "revalidated"].includes(r.key)), r => r.count);
    let botShare: number | null = null;
    let botBasis = "";
    const scores = s.bot_scores?.data;
    if (scores) {
      const scored = scores.automated + scores.likely_automated + scores.likely_human;
      if (scored > 0) { botShare = ((scores.automated + scores.likely_automated) / scored) * 100; botBasis = "by bot score"; }
    }
    if (botShare == null && s.user_agents?.data) {
      const all = sum(s.user_agents.data, r => r.count);
      const auto = sum(s.user_agents.data.filter(r => r.class !== "browser" && r.class !== "other"), r => r.count);
      if (all > 0) { botShare = (auto / all) * 100; botBasis = "by declared user agent"; }
    }
    return { requests, bytes, visits, mitigated, statusTotal, s5xx, s4xx, cacheTotal, cached, botShare, botBasis };
  }, [s]);

  const statusClasses = useMemo(() => {
    const m = new Map<string, number>();
    s.status?.data?.forEach(r => m.set(statusClass(r.key), (m.get(statusClass(r.key)) ?? 0) + r.count));
    return ["2xx", "3xx", "4xx", "5xx", "other"].filter(k => m.has(k)).map(k => ({ key: k, label: k, value: m.get(k)! }));
  }, [s.status]);

  const uaClasses = useMemo(() => {
    const m = new Map<string, number>();
    s.user_agents?.data?.forEach(r => m.set(r.class, (m.get(r.class) ?? 0) + r.count));
    return Array.from(m.entries()).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ key: k, label: UA_CLASS_LABEL[k] ?? k, value: v }));
  }, [s.user_agents]);

  if (zoneError) {
    return <div className="p-6"><div className="glass-card p-4 text-sm text-red-500 dark:text-red-400">{zoneError}</div></div>;
  }
  if (!zone) return <div className="p-6 text-zinc-500">Loading zone…</div>;

  const fmtTick = tickFormatter(data?.bucket_seconds ?? 900);
  const topWindow = (() => {
    if (!data) return "";
    const h = (new Date(data.until).getTime() - new Date(data.top_since).getTime()) / 3_600_000;
    return h >= 48 ? `last ${Math.round(h / 24)} days` : h >= 1 ? `last ${Math.round(h)} hours` : `last ${Math.round(h * 60)} minutes`;
  })();

  const chartBox = (series: Point[] | undefined, key: "requests" | "mitigated", color: string, label: string) => (
    <div className="h-48">
      <ResponsiveContainer width="100%" height="100%">
        {key === "requests" ? (
          <AreaChart data={series} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--rule)" vertical={false} />
            <XAxis dataKey="t" tickFormatter={fmtTick} tick={{ fontSize: 11, fill: "#71717a" }} stroke="var(--rule)" minTickGap={40} />
            <YAxis tickFormatter={v => fmtNum(v)} tick={{ fontSize: 11, fill: "#71717a" }} stroke="var(--rule)" width={48} />
            <Tooltip contentStyle={tooltipStyle} labelFormatter={l => fmtStamp(String(l))}
              formatter={v => [fmtFull(Number(v)), label]} />
            <Area type="monotone" dataKey="requests" stroke={color} strokeWidth={2} fill={color} fillOpacity={0.15} isAnimationActive={false} />
          </AreaChart>
        ) : (
          <BarChart data={series} margin={{ top: 4, right: 8, left: 0, bottom: 0 }}>
            <CartesianGrid strokeDasharray="3 3" stroke="var(--rule)" vertical={false} />
            <XAxis dataKey="t" tickFormatter={fmtTick} tick={{ fontSize: 11, fill: "#71717a" }} stroke="var(--rule)" minTickGap={40} />
            <YAxis tickFormatter={v => fmtNum(v)} tick={{ fontSize: 11, fill: "#71717a" }} stroke="var(--rule)" width={48} allowDecimals={false} />
            <Tooltip contentStyle={tooltipStyle} labelFormatter={l => fmtStamp(String(l))} cursor={{ fill: "var(--color-surface-hover)" }}
              formatter={v => [fmtFull(Number(v)), label]} />
            <Bar dataKey="mitigated" fill={color} radius={[2, 2, 0, 0]} isAnimationActive={false} />
          </BarChart>
        )}
      </ResponsiveContainer>
    </div>
  );

  return (
    <div className="p-4 max-w-[1600px] mx-auto space-y-3 min-w-0">
      {/* ---- header ---- */}
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <a href="/cloudflare" className="text-xs text-zinc-500 hover:text-brand-green">← Cloudflare</a>
          <h1 className="text-lg font-semibold flex items-center gap-2 flex-wrap">
            {zone.label}
            {zone.open_alerts > 0 && (
              <button onClick={() => selectTab("alerts")}
                className="text-[11px] font-medium px-1.5 py-0.5 rounded border text-red-500 dark:text-red-400 border-red-500/30 bg-red-500/10">
                ● {zone.open_alerts} open alert{zone.open_alerts > 1 ? "s" : ""}
              </button>
            )}
            {!zone.enabled && <span className="text-[11px] px-1.5 py-0.5 rounded border text-zinc-500 border-zinc-500/30">Paused</span>}
          </h1>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5 flex flex-wrap gap-x-3">
            <span className="font-mono">{zone.zone_name}</span>
            <span>{zone.plan}</span>
            <span>account {zone.account_name || zone.account_id}</span>
            <span>checked {relativeTime(zone.last_polled_at)}</span>
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1" role="group" aria-label="Time range">
            {RANGES.map(r => (
              <button key={r.key} onClick={() => selectRange(r.key)}
                className={`px-2 py-1 text-xs rounded-md transition ${range === r.key ? "bg-brand-green/10 text-brand-green" : "text-zinc-500 hover:text-brand-green"}`}>
                {r.label}
              </button>
            ))}
          </div>
          <button onClick={loadAnalytics} disabled={loading} className="btn-secondary text-xs disabled:opacity-50">
            {loading ? "Loading…" : "Refresh"}
          </button>
        </div>
      </div>

      {zone.last_error && (
        <div className="glass-card p-3 border-red-500/30 text-xs text-red-500 dark:text-red-400 break-words">
          Last check failed: {zone.last_error}
        </div>
      )}
      {error && <div className="glass-card p-3 border-red-500/30 text-sm text-red-500 dark:text-red-400 break-words">{error}</div>}
      {data?.notices?.map(n => <p key={n} className="text-xs text-zinc-500 dark:text-zinc-400">{n}</p>)}

      {/* ---- tabs ---- */}
      <div className="flex flex-wrap gap-1 border-b border-[var(--rule)]" role="tablist">
        {TABS.filter(t => t !== "settings" || canManage).map(t => (
          <button key={t} role="tab" aria-selected={tab === t} onClick={() => selectTab(t)}
            className={`px-3 py-1.5 text-sm -mb-px border-b-2 transition ${tab === t ? "border-brand-green text-brand-green" : "border-transparent text-zinc-500 hover:text-brand-green"}`}>
            {TAB_LABEL[t]}
          </button>
        ))}
      </div>

      {!data && loading && !["alerts", "settings", "exposure", "waf"].includes(tab) && <p className="text-sm text-zinc-500">Querying Cloudflare…</p>}

      {/* ---- overview ---- */}
      {tab === "overview" && data && (
        <div className="space-y-3">
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
            <Stat label="Requests" value={fmtNum(totals.requests)} sub={`${fmtNum(totals.visits)} visits`} />
            <Stat label="Mitigated threats" value={fmtNum(totals.mitigated)} tone={totals.mitigated > 0 ? "warn" : undefined}
              sub={totals.requests > 0 ? `${fmtPct((totals.mitigated / totals.requests) * 100)} of requests` : undefined} />
            <Stat label="Server errors (5xx)" value={totals.statusTotal ? fmtPct((totals.s5xx / totals.statusTotal) * 100) : "—"}
              tone={totals.statusTotal && (totals.s5xx / totals.statusTotal) * 100 >= zone.error_rate_threshold ? "bad" : undefined}
              sub={`${fmtNum(totals.s5xx)} responses`} />
            <Stat label="Client errors (4xx)" value={totals.statusTotal ? fmtPct((totals.s4xx / totals.statusTotal) * 100) : "—"}
              sub={`${fmtNum(totals.s4xx)} responses`} />
            <Stat label="Served from cache" value={totals.cacheTotal ? fmtPct((totals.cached / totals.cacheTotal) * 100) : "—"}
              sub={`${fmtBytesSI(totals.bytes)} served`} />
            <Stat label="Automated traffic" value={totals.botShare == null ? "—" : fmtPct(totals.botShare)} sub={totals.botBasis || "no data"} />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-2">
            <Card title="Requests">
              {s.traffic?.error ? <SectionError error={s.traffic.error} /> : chartBox(s.traffic?.data, "requests", reqColor, "Requests")}
            </Card>
            <Card title="Mitigated threats">
              {s.mitigation?.error ? <SectionError error={s.mitigation.error} /> : chartBox(s.mitigation?.data, "mitigated", threatColor, "Mitigated")}
            </Card>
          </div>

          <TrafficMap zoneRefId={zone.id} range={range} />

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-2">
            <Card title="Response status">
              {s.status?.error ? <SectionError error={s.status.error} /> : <BarList rows={statusClasses} total={totals.statusTotal} />}
            </Card>
            <Card title="Mitigated requests by feature">
              {s.fw_sources?.error ? <SectionError error={s.fw_sources.error} /> :
                <BarList color="bg-[#eda100] dark:bg-[#c98500]" empty="No security feature acted in this range."
                  rows={(s.fw_sources?.data ?? []).map(r => ({ key: r.key, label: sourceLabel(r.key), value: r.count }))} />}
            </Card>
            <Card title="Top countries">
              {s.countries?.error ? <SectionError error={s.countries.error} /> :
                <BarList rows={(s.countries?.data ?? []).slice(0, 8).map(r => ({ key: r.key, label: r.key || "Unknown", value: r.count }))} total={totals.statusTotal} />}
            </Card>
            <Card title="Top paths">
              {s.paths?.error ? <SectionError error={s.paths.error} /> :
                <BarList mono rows={(s.paths?.data ?? []).slice(0, 8).map(r => ({ key: r.key, label: r.key, value: r.count }))} total={totals.statusTotal} />}
            </Card>
          </div>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            Charts cover the selected range; lists and percentages cover the {topWindow}. Read from Cloudflare {relativeTime(data.cached_at)}.
          </p>
        </div>
      )}

      {/* ---- security ---- */}
      {tab === "security" && data && (
        <div className="space-y-2">
          <Card title="Mitigated threats over time">
            {s.mitigation?.error ? <SectionError error={s.mitigation.error} /> : chartBox(s.mitigation?.data, "mitigated", threatColor, "Mitigated")}
          </Card>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
            <Card title="Security events by action">
              {s.fw_actions?.error ? <SectionError error={s.fw_actions.error} /> :
                <BarList color="bg-[#eda100] dark:bg-[#c98500]"
                  rows={(s.fw_actions?.data ?? []).map(r => ({
                    key: r.action, label: r.action, value: r.count,
                    badge: r.mitigated ? <span className="text-[10px] text-amber-600 dark:text-amber-400">mitigated</span> : <span className="text-[10px] text-zinc-500">observed</span>,
                  }))} />}
            </Card>
            <Card title="Security events by feature">
              {s.fw_sources?.error ? <SectionError error={s.fw_sources.error} /> :
                <BarList color="bg-[#eda100] dark:bg-[#c98500]" rows={(s.fw_sources?.data ?? []).map(r => ({ key: r.key, label: sourceLabel(r.key), value: r.count }))} />}
            </Card>
            <Card title="Security events by country">
              {s.fw_countries?.error ? <SectionError error={s.fw_countries.error} /> :
                <BarList color="bg-[#eda100] dark:bg-[#c98500]" rows={(s.fw_countries?.data ?? []).map(r => ({ key: r.key, label: r.key || "Unknown", value: r.count }))} />}
            </Card>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-2">
            <Card title="Top offending IPs (security events)">
              {s.fw_ips?.error ? <SectionError error={s.fw_ips.error} /> : (
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-zinc-500 dark:text-zinc-400"><th className="py-1 font-medium">IP</th><th className="font-medium">Country</th><th className="font-medium">ASN</th><th className="font-medium text-right">Events</th></tr></thead>
                  <tbody>
                    {(s.fw_ips?.data ?? []).map(r => (
                      <tr key={r.ip} className="border-t border-[var(--rule)]">
                        <td className="py-1 font-mono">{r.ip}</td><td>{r.country}</td><td className="tabular-nums">{r.asn}</td>
                        <td className="text-right tabular-nums">{fmtFull(r.count)}</td>
                      </tr>
                    ))}
                    {(s.fw_ips?.data ?? []).length === 0 && <tr><td colSpan={4} className="py-2 text-zinc-500">No security events in this range.</td></tr>}
                  </tbody>
                </table>
              )}
            </Card>
            <Card title="Security events by path">
              {s.fw_paths?.error ? <SectionError error={s.fw_paths.error} /> :
                <BarList mono color="bg-[#eda100] dark:bg-[#c98500]" empty="No security events in this range."
                  rows={(s.fw_paths?.data ?? []).map(r => ({ key: r.path, label: r.path, value: r.count, badge: <ProbeBadge reason={r.reason} /> }))} />}
            </Card>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-2">
            <Card title="Probing (paths answered 4xx)">
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 -mt-2 mb-2">
                Requests that got through to a 4xx. Paths flagged in red are what scanners ask every host for.
              </p>
              {s.probes?.error ? <SectionError error={s.probes.error} /> :
                <BarList mono rows={(s.probes?.data ?? []).map(r => ({ key: r.path, label: r.path, value: r.count, badge: <ProbeBadge reason={r.reason} /> }))} />}
            </Card>
            <Card title="Rules that fired (events per rule)">
              {s.fw_rules?.error ? <SectionError error={s.fw_rules.error} /> : (
                <table className="w-full text-xs">
                  <thead><tr className="text-left text-zinc-500 dark:text-zinc-400"><th className="py-1 font-medium">Rule</th><th className="font-medium">Feature</th><th className="font-medium text-right">Events</th></tr></thead>
                  <tbody>
                    {(s.fw_rules?.data ?? []).map(r => (
                      <tr key={r.rule_id + r.source} className="border-t border-[var(--rule)]">
                        <td className="py-1 max-w-0 w-full truncate" title={r.rule_id}>{r.description || <span className="font-mono">{r.rule_id || "—"}</span>}</td>
                        <td className="whitespace-nowrap pr-2">{sourceLabel(r.source)}</td>
                        <td className="text-right tabular-nums">{fmtFull(r.count)}</td>
                      </tr>
                    ))}
                    {(s.fw_rules?.data ?? []).length === 0 && <tr><td colSpan={3} className="py-2 text-zinc-500">No rules fired in this range.</td></tr>}
                  </tbody>
                </table>
              )}
            </Card>
          </div>
        </div>
      )}

      {/* ---- waf ---- */}
      {tab === "waf" && <WAFTab zoneRefId={zone.id} range={range} accountId={zone.account_id} zoneName={zone.zone_name} />}

      {/* ---- exposure ---- */}
      {tab === "exposure" && <ExposureTab zoneRefId={zone.id} canScan={canPoll} />}

      {/* ---- traffic ---- */}
      {tab === "traffic" && data && (
        <div className="space-y-2">
          <Card title="Requests over time">
            {s.traffic?.error ? <SectionError error={s.traffic.error} /> : chartBox(s.traffic?.data, "requests", reqColor, "Requests")}
          </Card>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
            <Card title="Most requested paths" className="xl:col-span-2">
              {s.paths?.error ? <SectionError error={s.paths.error} /> :
                <BarList mono total={totals.statusTotal} rows={(s.paths?.data ?? []).map(r => ({ key: r.key, label: r.key, value: r.count }))} />}
            </Card>
            <Card title="Status codes">
              {s.status?.error ? <SectionError error={s.status.error} /> :
                <BarList total={totals.statusTotal} rows={(s.status?.data ?? []).slice(0, 15).map(r => ({ key: r.key, label: r.key, value: r.count }))} />}
            </Card>
            <Card title="Hostnames">
              {s.hosts?.error ? <SectionError error={s.hosts.error} /> :
                <BarList mono total={totals.statusTotal} rows={(s.hosts?.data ?? []).map(r => ({ key: r.key, label: r.key, value: r.count }))} />}
            </Card>
            <Card title="Countries">
              {s.countries?.error ? <SectionError error={s.countries.error} /> :
                <BarList total={totals.statusTotal} rows={(s.countries?.data ?? []).map(r => ({ key: r.key, label: r.key || "Unknown", value: r.count }))} />}
            </Card>
            <Card title="Top client IPs">
              {s.ips?.error ? <SectionError error={s.ips.error} /> :
                <BarList mono total={totals.statusTotal} rows={(s.ips?.data ?? []).map(r => ({ key: r.ip, label: `${r.ip}  ${r.country}`, value: r.count }))} />}
            </Card>
            <Card title="Methods">
              {s.methods?.error ? <SectionError error={s.methods.error} /> :
                <BarList total={totals.statusTotal} rows={(s.methods?.data ?? []).map(r => ({ key: r.key, label: r.key, value: r.count }))} />}
            </Card>
            <Card title="Cache status">
              {s.cache?.error ? <SectionError error={s.cache.error} /> :
                <BarList total={totals.cacheTotal} rows={(s.cache?.data ?? []).map(r => ({ key: r.key, label: r.key, value: r.count }))} />}
            </Card>
            <Card title="User agents">
              {s.user_agents?.error ? <SectionError error={s.user_agents.error} /> :
                <BarList mono rows={(s.user_agents?.data ?? []).slice(0, 10).map(r => ({ key: r.ua, label: r.ua || "(empty)", value: r.count }))} />}
            </Card>
          </div>
        </div>
      )}

      {/* ---- bots ---- */}
      {tab === "bots" && data && (
        <div className="space-y-2">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
            <Card title="Bot score">
              {s.bot_scores?.error ? (
                <p className="text-xs text-zinc-500 dark:text-zinc-400">
                  Bot scores come with Cloudflare Bot Management, which this zone&apos;s plan does not include. The
                  classification beside this reads the user agent each client declares — useful, but a client can lie about it.
                </p>
              ) : s.bot_scores?.data && (
                <BarList total={Object.values(s.bot_scores.data).reduce((a, b) => a + b, 0)} rows={[
                  { key: "automated", label: "Automated (score 1)", value: s.bot_scores.data.automated },
                  { key: "likely_automated", label: "Likely automated (2–29)", value: s.bot_scores.data.likely_automated },
                  { key: "likely_human", label: "Likely human (30–99)", value: s.bot_scores.data.likely_human },
                  { key: "not_scored", label: "Not scored", value: s.bot_scores.data.not_scored },
                ]} />
              )}
            </Card>
            <Card title="By declared user agent">
              {s.user_agents?.error ? <SectionError error={s.user_agents.error} /> :
                <BarList total={uaClasses.reduce((a, r) => a + r.value, 0)} rows={uaClasses} />}
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-2">Over the 100 most frequent user agents.</p>
            </Card>
            <Card title="Verified bots">
              {s.verified_bots?.error ? <SectionError error={s.verified_bots.error} /> :
                <BarList empty="No verified bots in this range."
                  rows={(s.verified_bots?.data ?? []).filter(r => r.key).map(r => ({ key: r.key, label: r.key, value: r.count }))} />}
            </Card>
          </div>
          <div className="grid grid-cols-1 xl:grid-cols-2 gap-2">
            <Card title="Vulnerability scanners">
              <BarList mono empty="No known scanner user agents in this range."
                rows={(s.user_agents?.data ?? []).filter(r => r.class === "scanner" || r.class === "empty").map(r => ({ key: r.ua, label: r.ua || "(no user agent)", value: r.count }))} />
            </Card>
            <Card title="Declared automation">
              <BarList mono empty="No automated clients in this range."
                rows={(s.user_agents?.data ?? []).filter(r => r.class === "automated").slice(0, 15).map(r => ({ key: r.ua, label: r.ua, value: r.count }))} />
            </Card>
          </div>
        </div>
      )}

      {/* ---- events ---- */}
      {tab === "events" && data && <EventsTable events={s.events} />}

      {/* ---- alerts ---- */}
      {tab === "alerts" && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <p className="text-xs text-zinc-500 dark:text-zinc-400 max-w-3xl">
              Threshold alerts open when a 5-minute window breaches one of the zone&apos;s rules and resolve on the first clean window.
              Alerts Cloudflare itself sent for the account are copied in alongside.
              {zone.history_error && <span className="text-amber-600 dark:text-amber-400"> Cloudflare&apos;s own alerts are not shown: {zone.history_error}.</span>}
            </p>
            {canPoll && (
              <button onClick={pollNow} disabled={polling} className="btn-secondary text-xs disabled:opacity-50">
                {polling ? "Checking…" : "Check now"}
              </button>
            )}
          </div>
          <AlertLog zoneRefId={zone.id} refreshKey={refreshKey} />
        </div>
      )}

      {/* ---- settings ---- */}
      {tab === "settings" && canManage && <ZoneSettings zone={zone} onChanged={loadZone} />}
    </div>
  );
}

// ---- events table -------------------------------------------------------------------

function EventsTable({ events }: { events?: Section<Record<string, unknown>[]> }) {
  const [expanded, setExpanded] = useState<number | null>(null);
  const [onlyMitigated, setOnlyMitigated] = useState(false);
  if (events?.error) return <Card title="Security events"><SectionError error={events.error} /></Card>;
  const rows = (events?.data ?? []).filter(e => !onlyMitigated || e.mitigated);
  const str = (v: unknown) => (v == null ? "" : String(v));
  return (
    <Card title="Latest security events" right={
      <label className="flex items-center gap-1.5 text-xs text-zinc-500">
        <input type="checkbox" checked={onlyMitigated} onChange={e => setOnlyMitigated(e.target.checked)} /> Mitigated only
      </label>
    }>
      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-zinc-500 dark:text-zinc-400 border-b border-[var(--rule)]">
              <th className="w-5" /><th className="py-1.5 pr-3 font-medium">Time</th><th className="pr-3 font-medium">Action</th>
              <th className="pr-3 font-medium">Feature</th><th className="pr-3 font-medium">IP</th><th className="pr-3 font-medium">Country</th>
              <th className="pr-3 font-medium w-full">Request</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 && <tr><td colSpan={7} className="py-4 text-center text-zinc-500">No security events in this range.</td></tr>}
            {rows.map((e, i) => {
              const open = expanded === i;
              const path = str(e.clientRequestPath) + (e.clientRequestQuery ? str(e.clientRequestQuery) : "");
              return (
                <Fragment key={i}>
                  <tr className="border-b border-[var(--rule)] cursor-pointer hover:bg-[var(--color-surface-hover)]" onClick={() => setExpanded(open ? null : i)}>
                    <td className="pl-1 pr-1 text-zinc-500"><span className={`inline-block transition-transform ${open ? "rotate-90" : ""}`}>›</span></td>
                    <td className="py-1.5 pr-3 whitespace-nowrap tabular-nums">{e.datetime ? fmtStamp(str(e.datetime)) : ""}</td>
                    <td className={`pr-3 whitespace-nowrap ${e.mitigated ? "text-amber-600 dark:text-amber-400 font-medium" : "text-zinc-500"}`}>{str(e.action)}</td>
                    <td className="pr-3 whitespace-nowrap">{sourceLabel(str(e.source))}</td>
                    <td className="pr-3 font-mono whitespace-nowrap">{str(e.clientIP)}</td>
                    <td className="pr-3 whitespace-nowrap">{str(e.clientCountryName)}</td>
                    <td className="pr-3 font-mono truncate max-w-0">
                      {e.clientRequestHTTPMethodName ? `${str(e.clientRequestHTTPMethodName)} ` : ""}{e.clientRequestHTTPHost ? str(e.clientRequestHTTPHost) : ""}{path}
                      {e.probe ? <span className="ml-2 font-sans"><ProbeBadge reason={str(e.probe)} /></span> : null}
                    </td>
                  </tr>
                  {open && (
                    <tr className="border-b border-[var(--rule)]">
                      <td />
                      <td colSpan={6} className="py-2 pr-3">
                        <div className="rounded bg-zinc-500/5 p-2 flex flex-wrap gap-x-3 gap-y-1">
                          {Object.entries(e).filter(([, v]) => v !== "" && v != null).map(([k, v]) => (
                            <span key={k} className="break-all"><span className="text-zinc-500 dark:text-zinc-400">{k}:</span> <span className="text-brand-green font-mono">{str(v)}</span></span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              );
            })}
          </tbody>
        </table>
      </div>
      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-2">The 100 most recent events in the range, newest first.</p>
    </Card>
  );
}

// ---- settings -------------------------------------------------------------------------

function ZoneSettings({ zone, onChanged }: { zone: Zone; onChanged: () => void }) {
  const initial = useMemo(() => zoneToForm(zone), [zone]);
  const [saved, setSaved] = useState<string[] | null>(null);
  const [confirmDelete, setConfirmDelete] = useState(false);
  const [deleteError, setDeleteError] = useState("");

  const remove = async () => {
    const res = await apiFetch(`/cloudflare/zones/${zone.id}`, { method: "DELETE" });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setDeleteError(body.error ?? `Request failed (${res.status})`);
      return;
    }
    window.location.href = "/cloudflare";
  };

  return (
    <div className="space-y-3 max-w-3xl">
      <section className="glass-card p-4">
        <ZoneForm initial={initial} zoneRefId={zone.id} onSaved={(_id, w) => { setSaved(w); onChanged(); }} />
        {saved && (
          <div className="mt-3 text-xs space-y-1">
            <p className="text-brand-green">Saved.</p>
            {saved.map(w => <p key={w} className="text-amber-600 dark:text-amber-400">{w}</p>)}
          </div>
        )}
      </section>
      <section className="glass-card p-4 border-red-500/20">
        <h2 className="text-sm font-semibold">Stop monitoring this zone</h2>
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
          Removes the zone, its stored token and its alert history from CommitKube. Nothing changes in Cloudflare.
        </p>
        <button onClick={() => setConfirmDelete(true)} className="mt-3 text-sm px-3 py-1.5 rounded-lg border border-red-500/40 text-red-500 hover:bg-red-500/10">
          Remove zone
        </button>
      </section>
      {confirmDelete && (
        <Modal title={`Remove ${zone.label}?`} onClose={() => setConfirmDelete(false)}>
          <p className="text-sm">The alert history for <span className="font-mono">{zone.zone_name}</span> is deleted with it.</p>
          {deleteError && <p className="text-xs text-red-500 mt-2">{deleteError}</p>}
          <div className="flex justify-end gap-2 mt-4">
            <button onClick={() => setConfirmDelete(false)} className="btn-secondary text-sm">Cancel</button>
            <button onClick={remove} className="text-sm px-3 py-1.5 rounded-lg bg-red-600 text-white hover:bg-red-700">Remove</button>
          </div>
        </Modal>
      )}
    </div>
  );
}
