"use client";

import { Fragment, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";

// ---- types ------------------------------------------------------------------

export interface Zone {
  id: number;
  created_at: string;
  label: string;
  zone_id: string;
  account_id: string;
  zone_name: string;
  account_name: string;
  plan: string;
  status: string;
  enabled: boolean;
  threat_threshold: number;
  ddos_threshold: number;
  error_rate_threshold: number;
  spike_factor: number;
  last_polled_at: string | null;
  last_error: string;
  last_requests: number;
  last_threats: number;
  last_errors_5xx: number;
  history_synced_at: string | null;
  history_error: string;
  open_alerts: number;
  alerts_24h?: number;
}

export interface Alert {
  id: number;
  zone_ref_id: number;
  source: "commitkube" | "cloudflare";
  alert_type: string;
  external_id?: string;
  severity: Severity;
  title: string;
  message: string;
  value: number;
  peak: number;
  threshold: number;
  started_at: string;
  last_seen_at: string;
  resolved_at: string | null;
  details: string;
}

export type Severity = "critical" | "high" | "medium" | "info";

// ---- formatting ---------------------------------------------------------------

const compact = new Intl.NumberFormat("en", { notation: "compact", maximumFractionDigits: 1 });
const full = new Intl.NumberFormat("en");

export const fmtNum = (n: number | undefined | null) => (n == null ? "—" : n < 10000 ? full.format(n) : compact.format(n));
export const fmtFull = (n: number | undefined | null) => (n == null ? "—" : full.format(n));
export const fmtPct = (n: number, digits = 1) => `${n.toFixed(n > 0 && n < 0.1 ? 2 : digits)}%`;

/** Decimal units, as Cloudflare's own dashboard counts bytes served. */
export const fmtBytesSI = (b: number) => {
  if (!b) return "0 B";
  const units = ["B", "kB", "MB", "GB", "TB", "PB"];
  let v = b;
  let i = 0;
  while (v >= 1000 && i < units.length - 1) { v /= 1000; i++; }
  return `${v.toFixed(v >= 100 || i === 0 ? 0 : 1)} ${units[i]}`;
};

export function relativeTime(iso: string | null | undefined): string {
  if (!iso) return "never";
  const ms = Date.now() - new Date(iso).getTime();
  const min = Math.round(ms / 60000);
  if (min < 1) return "just now";
  if (min < 60) return `${min} min ago`;
  const h = Math.round(min / 60);
  if (h < 48) return `${h} h ago`;
  return `${Math.round(h / 24)} days ago`;
}

export const fmtStamp = (iso: string) =>
  new Date(iso).toLocaleString([], { month: "short", day: "2-digit", hour: "2-digit", minute: "2-digit", second: "2-digit" });

// ---- vocabulary ----------------------------------------------------------------

/** Cloudflare's names for the products that act on a request, said the way
 *  its dashboard says them. Unknown sources show as sent. */
export const SOURCE_LABELS: Record<string, string> = {
  l7ddos: "HTTP DDoS protection",
  waf: "WAF managed rules",
  firewallmanaged: "WAF managed rules",
  firewallcustom: "Custom rules",
  firewallrules: "Firewall rules",
  ratelimit: "Rate limiting",
  bic: "Browser integrity check",
  hot: "Hotlink protection",
  securitylevel: "Security level",
  botfight: "Bot fight mode",
  botmanagement: "Bot management",
  validation: "Request validation",
  uablock: "User agent blocking",
  iprules: "IP access rules",
  zonelockdown: "Zone lockdown",
  country: "Country block",
  asn: "ASN block",
  apishield: "API Shield",
  apishieldschemavalidation: "API Shield schema validation",
  dlp: "Data loss prevention",
  filterbasedfirewall: "Firewall rules",
  "": "Unknown",
};
export const sourceLabel = (s: string) => SOURCE_LABELS[s.toLowerCase()] ?? s;

export const ALERT_TYPE_LABELS: Record<string, string> = {
  ddos_l7: "L7 DDoS",
  threat_spike: "Threat spike",
  origin_errors: "Server errors",
  traffic_spike: "Traffic spike",
  origin_exposed: "Origin exposure",
  exposed_port: "Open port",
  known_vulns: "Known vulnerabilities",
  dangling_cname: "Dangling record",
};

/** Rules measured against a number; exposure alerts are about a thing
 *  (an IP, a port, a record) and carry no value or threshold. */
export const THRESHOLD_TYPES = new Set(["ddos_l7", "threat_spike", "origin_errors", "traffic_spike"]);

export const SEVERITY_BADGE: Record<string, string> = {
  critical: "text-red-500 dark:text-red-400 border-red-500/30 bg-red-500/10",
  high: "text-orange-600 dark:text-orange-400 border-orange-500/30 bg-orange-500/10",
  medium: "text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/10",
  info: "text-zinc-500 dark:text-zinc-400 border-zinc-500/30 bg-zinc-500/10",
};

export function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={`inline-block text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border ${SEVERITY_BADGE[severity] ?? SEVERITY_BADGE.info}`}>
      {severity}
    </span>
  );
}

// ---- small pieces --------------------------------------------------------------

export function Stat({ label, value, sub, tone }: { label: string; value: string; sub?: React.ReactNode; tone?: "bad" | "warn" | "good" }) {
  const color = tone === "bad" ? "text-red-500 dark:text-red-400" : tone === "warn" ? "text-amber-600 dark:text-amber-400" : tone === "good" ? "text-brand-green" : "";
  return (
    <div className="glass-card p-3 min-w-0">
      <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
      <p className={`text-xl font-semibold tabular-nums mt-0.5 ${color}`}>{value}</p>
      {sub && <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5 truncate">{sub}</p>}
    </div>
  );
}

export function SectionError({ error }: { error: string }) {
  return (
    <p className="text-xs text-zinc-500 dark:text-zinc-400 break-words">
      Not available for this zone: <span className="text-amber-600 dark:text-amber-400">{error}</span>
    </p>
  );
}

export interface BarRow {
  key: string;
  label: React.ReactNode;
  title?: string;
  value: number;
  badge?: React.ReactNode;
}

/** A ranked list with an inline bar: the label and the number carry the
 *  reading, the bar only shows proportion -- so it never rests on colour. */
export function BarList({ rows, total, color = "bg-[#4a3aa7] dark:bg-[#9085e9]", empty = "Nothing in this range.", mono }: {
  rows: BarRow[]; total?: number; color?: string; empty?: string; mono?: boolean;
}) {
  const max = Math.max(1, ...rows.map(r => r.value));
  if (rows.length === 0) return <p className="text-xs text-zinc-500 dark:text-zinc-400">{empty}</p>;
  return (
    <ul className="space-y-1">
      {rows.map(r => (
        <li key={r.key} className="group" title={r.title ?? (typeof r.label === "string" ? r.label : undefined)}>
          <div className="flex items-center gap-2 text-xs">
            <span className={`truncate flex-1 min-w-0 ${mono ? "font-mono" : ""}`}>{r.label}</span>
            {r.badge}
            <span className="tabular-nums text-zinc-500 dark:text-zinc-400 shrink-0">
              {fmtNum(r.value)}{total ? ` · ${fmtPct((r.value / total) * 100)}` : ""}
            </span>
          </div>
          <div className="h-1 mt-0.5 rounded-full bg-zinc-500/10 overflow-hidden">
            <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.max(1, (r.value / max) * 100)}%` }} />
          </div>
        </li>
      ))}
    </ul>
  );
}

export function Card({ title, children, right, className = "" }: { title: string; children: React.ReactNode; right?: React.ReactNode; className?: string }) {
  return (
    <section className={`glass-card p-4 min-w-0 ${className}`}>
      <div className="flex items-center justify-between gap-2 mb-3">
        <h2 className="text-sm font-semibold">{title}</h2>
        {right}
      </div>
      {children}
    </section>
  );
}

export function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      onClick={() => { navigator.clipboard?.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1200); }); }}
      className="text-[11px] px-1.5 py-0.5 rounded border border-[var(--card-border)] text-zinc-500 hover:text-brand-green shrink-0"
      title="Copy">
      {done ? "Copied" : "Copy"}
    </button>
  );
}

// ---- zone form -------------------------------------------------------------------

export interface ZoneFormValues {
  label: string;
  zone_id: string;
  account_id: string;
  api_token: string;
  threat_threshold: number;
  ddos_threshold: number;
  error_rate_threshold: number;
  spike_factor: number;
  enabled: boolean;
}

export const emptyZoneForm: ZoneFormValues = {
  label: "", zone_id: "", account_id: "", api_token: "",
  threat_threshold: 1000, ddos_threshold: 1, error_rate_threshold: 5, spike_factor: 3, enabled: true,
};

export function zoneToForm(z: Zone): ZoneFormValues {
  return {
    label: z.label, zone_id: z.zone_id, account_id: z.account_id, api_token: "",
    threat_threshold: z.threat_threshold, ddos_threshold: z.ddos_threshold,
    error_rate_threshold: z.error_rate_threshold, spike_factor: z.spike_factor, enabled: z.enabled,
  };
}

/** Add or edit a zone. Editing never shows the stored token: leaving the
 *  field empty keeps it, typing a new one replaces it after it is verified. */
export function ZoneForm({ initial, zoneRefId, onSaved, onCancel }: {
  initial: ZoneFormValues; zoneRefId?: number; onSaved: (id: number, warnings: string[]) => void; onCancel?: () => void;
}) {
  const [form, setForm] = useState(initial);
  const [busy, setBusy] = useState<"" | "verify" | "save">("");
  const [error, setError] = useState("");
  const [verified, setVerified] = useState<{ zone_name: string; account_name: string; plan: string; status: string; warnings?: string[] } | null>(null);
  const editing = zoneRefId != null;

  useEffect(() => { setForm(initial); }, [initial]);

  const set = <K extends keyof ZoneFormValues>(k: K, v: ZoneFormValues[K]) => {
    setForm(f => ({ ...f, [k]: v }));
    if (k === "zone_id" || k === "account_id" || k === "api_token") setVerified(null);
  };

  const body = () => {
    const b: Record<string, unknown> = {
      label: form.label, account_id: form.account_id.trim(), enabled: form.enabled,
      threat_threshold: Number(form.threat_threshold), ddos_threshold: Number(form.ddos_threshold),
      error_rate_threshold: Number(form.error_rate_threshold), spike_factor: Number(form.spike_factor),
    };
    if (!editing) b.zone_id = form.zone_id.trim();
    if (form.api_token.trim()) b.api_token = form.api_token.trim();
    return b;
  };

  const verify = async () => {
    setBusy("verify"); setError("");
    try {
      const res = await apiFetch("/cloudflare/zones/verify", {
        method: "POST",
        body: JSON.stringify({ ...body(), zone_id: form.zone_id.trim(), ...(editing ? { id: zoneRefId } : {}) }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { setError(data.error ?? `Request failed (${res.status})`); setVerified(null); return; }
      setVerified(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    } finally { setBusy(""); }
  };

  const save = async () => {
    setBusy("save"); setError("");
    try {
      const res = await apiFetch(editing ? `/cloudflare/zones/${zoneRefId}` : "/cloudflare/zones", {
        method: editing ? "PUT" : "POST", body: JSON.stringify(body()),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) { setError(data.error ?? `Request failed (${res.status})`); return; }
      onSaved(editing ? zoneRefId! : data.id, data.warnings ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    } finally { setBusy(""); }
  };

  const field = "input-tech w-full text-sm";
  const lbl = "block text-xs text-zinc-500 dark:text-zinc-400 mb-1";

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <label className="block sm:col-span-2">
          <span className={lbl}>Label</span>
          <input className={field} value={form.label} onChange={e => set("label", e.target.value)} placeholder="Defaults to the zone name" />
        </label>
        <label className="block">
          <span className={lbl}>Zone ID</span>
          <input className={`${field} font-mono`} value={form.zone_id} disabled={editing}
            onChange={e => set("zone_id", e.target.value)} placeholder="32 hex characters" spellCheck={false} />
        </label>
        <label className="block">
          <span className={lbl}>Account ID</span>
          <input className={`${field} font-mono`} value={form.account_id}
            onChange={e => set("account_id", e.target.value)} placeholder="32 hex characters" spellCheck={false} />
        </label>
        <label className="block sm:col-span-2">
          <span className={lbl}>API token {editing && <span className="opacity-70">— leave empty to keep the current one</span>}</span>
          <input className={`${field} font-mono`} type="password" autoComplete="off" value={form.api_token}
            onChange={e => set("api_token", e.target.value)} placeholder={editing ? "••••••••" : "Cloudflare API token"} />
          <span className="block text-[11px] text-zinc-500 dark:text-zinc-400 mt-1">
            Needs <span className="font-mono">Zone › Zone: Read</span> and <span className="font-mono">Zone › Analytics: Read</span>.
            Add <span className="font-mono">Zone › DNS: Read</span> for the exposure check (origin IPs, open ports, dangling records),
            and <span className="font-mono">Account › Notifications: Read</span> to see the alerts Cloudflare itself sends.
            Stored encrypted; never shown again.
          </span>
        </label>
      </div>

      <fieldset>
        <legend className="text-xs font-semibold mb-2">Alert thresholds <span className="font-normal text-zinc-500 dark:text-zinc-400">— each over a 5-minute window; 0 turns the rule off</span></legend>
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <label className="block">
            <span className={lbl}>Threats (mitigated requests)</span>
            <input className={field} type="number" min={0} value={form.threat_threshold} onChange={e => set("threat_threshold", Number(e.target.value))} />
          </label>
          <label className="block">
            <span className={lbl}>L7 DDoS (mitigated requests)</span>
            <input className={field} type="number" min={0} value={form.ddos_threshold} onChange={e => set("ddos_threshold", Number(e.target.value))} />
          </label>
          <label className="block">
            <span className={lbl}>5xx rate (%)</span>
            <input className={field} type="number" min={0} max={100} step={0.5} value={form.error_rate_threshold} onChange={e => set("error_rate_threshold", Number(e.target.value))} />
          </label>
          <label className="block">
            <span className={lbl}>Traffic spike (× last hour)</span>
            <input className={field} type="number" min={0} step={0.5} value={form.spike_factor} onChange={e => set("spike_factor", Number(e.target.value))} />
          </label>
        </div>
      </fieldset>

      <label className="flex items-center gap-2 text-sm">
        <input type="checkbox" checked={form.enabled} onChange={e => set("enabled", e.target.checked)} />
        Monitoring enabled
      </label>

      {verified && (
        <div className="rounded-lg border border-brand-green/30 bg-brand-green/5 p-3 text-xs space-y-1">
          <p className="text-brand-green font-medium">Credentials work</p>
          <p>Zone <span className="font-mono">{verified.zone_name}</span> · {verified.plan} · {verified.status} · account {verified.account_name}</p>
          {verified.warnings?.map(w => <p key={w} className="text-amber-600 dark:text-amber-400">{w}</p>)}
        </div>
      )}
      {error && <div className="rounded-lg border border-red-500/30 bg-red-500/5 p-3 text-xs text-red-500 dark:text-red-400 break-words">{error}</div>}

      <div className="flex flex-wrap justify-end gap-2">
        {onCancel && <button onClick={onCancel} className="btn-secondary text-sm">Cancel</button>}
        <button onClick={verify} disabled={!!busy} className="btn-secondary text-sm disabled:opacity-50">
          {busy === "verify" ? "Testing…" : "Test connection"}
        </button>
        <button onClick={save} disabled={!!busy} className="btn-primary text-sm disabled:opacity-50">
          {busy === "save" ? "Saving…" : editing ? "Save changes" : "Add zone"}
        </button>
      </div>
    </div>
  );
}

export function Modal({ title, children, onClose }: { title: string; children: React.ReactNode; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);
  return (
    <div className="fixed inset-0 z-[60] bg-black/50 flex items-start justify-center p-4 overflow-y-auto" onClick={onClose}>
      <div className="glass-card w-full max-w-2xl p-5 mt-10" style={{ background: "var(--color-surface)" }} onClick={e => e.stopPropagation()}
        role="dialog" aria-modal="true" aria-label={title}>
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-base font-semibold">{title}</h2>
          <button onClick={onClose} className="text-zinc-500 hover:text-[var(--color-fg)] text-lg leading-none" aria-label="Close">×</button>
        </div>
        {children}
      </div>
    </div>
  );
}

// ---- alert log -------------------------------------------------------------------

interface AlertsPayload {
  alerts: Alert[];
  open: number;
  by_severity: Record<string, number>;
  by_source: Record<string, number>;
}

/** The alert log, read like a log: newest first, one line each, expanding to
 *  the full message and every field behind it. Threshold alerts from the
 *  poller and alerts Cloudflare itself sent share it, told apart by source. */
export function AlertLog({ zoneRefId, zones, refreshKey = 0 }: { zoneRefId?: number; zones?: Zone[]; refreshKey?: number }) {
  const [data, setData] = useState<AlertsPayload | null>(null);
  const [error, setError] = useState("");
  const [status, setStatus] = useState("");
  const [source, setSource] = useState("");
  const [severity, setSeverity] = useState("");
  const [q, setQ] = useState("");
  const [days, setDays] = useState(30);
  const [expanded, setExpanded] = useState<number | null>(null);

  useEffect(() => {
    const params = new URLSearchParams({ days: String(days) });
    if (status) params.set("status", status);
    if (source) params.set("source", source);
    if (severity) params.set("severity", severity);
    if (q.trim()) params.set("q", q.trim());
    const path = zoneRefId != null ? `/cloudflare/zones/${zoneRefId}/alerts` : "/cloudflare/alerts";
    const t = setTimeout(async () => {
      try {
        const res = await apiFetch(`${path}?${params}`);
        const body = await res.json().catch(() => ({}));
        if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
        setError(""); setData(body);
      } catch (e) {
        setError(e instanceof Error ? e.message : "Could not reach the API");
      }
    }, q ? 250 : 0);
    return () => clearTimeout(t);
  }, [zoneRefId, status, source, severity, q, days, refreshKey]);

  const zoneName = useMemo(() => {
    const m = new Map<number, string>();
    zones?.forEach(z => m.set(z.id, z.label || z.zone_name));
    return m;
  }, [zones]);

  const sel = "input-tech !w-auto text-xs py-1";

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center gap-2">
        <select className={sel} value={status} onChange={e => setStatus(e.target.value)} aria-label="Status">
          <option value="">Any status</option>
          <option value="open">Open{data ? ` (${data.open})` : ""}</option>
          <option value="resolved">Resolved / delivered</option>
        </select>
        <select className={sel} value={source} onChange={e => setSource(e.target.value)} aria-label="Source">
          <option value="">Any source</option>
          <option value="commitkube">CommitKube thresholds{data?.by_source.commitkube ? ` (${data.by_source.commitkube})` : ""}</option>
          <option value="cloudflare">Sent by Cloudflare{data?.by_source.cloudflare ? ` (${data.by_source.cloudflare})` : ""}</option>
        </select>
        <select className={sel} value={severity} onChange={e => setSeverity(e.target.value)} aria-label="Severity">
          <option value="">Any severity</option>
          {(["critical", "high", "medium", "info"] as const).map(s => (
            <option key={s} value={s}>{s[0].toUpperCase() + s.slice(1)}{data?.by_severity[s] ? ` (${data.by_severity[s]})` : ""}</option>
          ))}
        </select>
        <select className={sel} value={days} onChange={e => setDays(Number(e.target.value))} aria-label="Period">
          {[1, 7, 30, 90].map(d => <option key={d} value={d}>Last {d === 1 ? "24 hours" : `${d} days`}</option>)}
        </select>
        <input className={`input-tech text-xs py-1 flex-1 min-w-[160px]`} placeholder="Search in results" value={q} onChange={e => setQ(e.target.value)} />
        <span className="text-xs px-2 py-1 rounded border border-[var(--card-border)] tabular-nums">
          {data ? `${data.alerts.length} records` : "…"}
        </span>
      </div>

      {error && <p className="text-xs text-red-500 dark:text-red-400">{error}</p>}

      <div className="glass-card overflow-x-auto">
        <table className="w-full text-xs">
          <thead>
            <tr className="text-left text-zinc-500 dark:text-zinc-400 border-b border-[var(--rule)]">
              <th className="w-6" />
              <th className="py-2 pr-3 font-medium whitespace-nowrap">Timestamp</th>
              <th className="py-2 pr-3 font-medium">Severity</th>
              <th className="py-2 pr-3 font-medium">Status</th>
              {zones && <th className="py-2 pr-3 font-medium">Zone</th>}
              <th className="py-2 pr-3 font-medium w-full">Message</th>
            </tr>
          </thead>
          <tbody>
            {data?.alerts.length === 0 && (
              <tr><td colSpan={6} className="py-6 text-center text-zinc-500 dark:text-zinc-400">No alerts match. Quiet is good.</td></tr>
            )}
            {data?.alerts.map(a => {
              const open = expanded === a.id;
              const isOpen = a.source === "commitkube" && !a.resolved_at;
              let details: Record<string, unknown> = {};
              try { details = a.details ? JSON.parse(a.details) : {}; } catch { /* shown raw below */ }
              const fields: [string, React.ReactNode][] = [
                ["timestamp", fmtStamp(a.started_at)],
                ["source", a.source === "cloudflare" ? "Cloudflare notification" : "CommitKube threshold"],
                ["alert_type", a.alert_type],
                ["severity", a.severity],
                ...(zones ? [["zone", zoneName.get(a.zone_ref_id) ?? `#${a.zone_ref_id}`] as [string, React.ReactNode]] : []),
                ...(a.source === "commitkube" && THRESHOLD_TYPES.has(a.alert_type) ? [
                  ["value", a.alert_type === "origin_errors" ? fmtPct(a.value) : a.alert_type === "traffic_spike" ? `${a.value.toFixed(1)}×` : fmtFull(a.value)],
                  ["peak", a.alert_type === "origin_errors" ? fmtPct(a.peak) : a.alert_type === "traffic_spike" ? `${a.peak.toFixed(1)}×` : fmtFull(a.peak)],
                  ["threshold", a.alert_type === "origin_errors" ? fmtPct(a.threshold) : a.alert_type === "traffic_spike" ? `${a.threshold}×` : fmtFull(a.threshold)],
                ] as [string, React.ReactNode][] : []),
                ...(a.source === "commitkube" ? [
                  ["last_seen", fmtStamp(a.last_seen_at)],
                  ["resolved", a.resolved_at ? fmtStamp(a.resolved_at) : "still open"],
                ] as [string, React.ReactNode][] : []),
                ...Object.entries(details)
                  .filter(([k, v]) => v !== "" && v != null && typeof v !== "object" && k !== "alert_type")
                  .map(([k, v]) => [k, String(v)] as [string, React.ReactNode]),
              ];
              const bySource = details.mitigated_by_source as Record<string, number> | undefined;
              return (
                <Fragment key={a.id}>
                  <tr className={`border-b border-[var(--rule)] cursor-pointer hover:bg-[var(--color-surface-hover)] ${open ? "bg-[var(--color-surface-hover)]" : ""}`}
                    onClick={() => setExpanded(open ? null : a.id)}>
                    <td className="pl-2 pr-1 text-zinc-500"><span className={`inline-block transition-transform ${open ? "rotate-90" : ""}`}>›</span></td>
                    <td className="py-1.5 pr-3 whitespace-nowrap tabular-nums">{fmtStamp(a.started_at)}</td>
                    <td className="py-1.5 pr-3"><SeverityBadge severity={a.severity} /></td>
                    <td className="py-1.5 pr-3 whitespace-nowrap">
                      {a.source === "cloudflare"
                        ? <span className="text-zinc-500 dark:text-zinc-400">Sent by Cloudflare</span>
                        : isOpen ? <span className="text-red-500 dark:text-red-400 font-medium">● Open</span>
                          : <span className="text-brand-green">✓ Resolved</span>}
                    </td>
                    {zones && <td className="py-1.5 pr-3 whitespace-nowrap">{zoneName.get(a.zone_ref_id) ?? `#${a.zone_ref_id}`}</td>}
                    <td className="py-1.5 pr-3 font-mono truncate max-w-0">
                      <span className="font-sans font-medium">{a.title}</span>
                      <span className="text-zinc-500 dark:text-zinc-400"> — {a.message}</span>
                    </td>
                  </tr>
                  {open && (
                    <tr className="border-b border-[var(--rule)]">
                      <td />
                      <td colSpan={zones ? 5 : 4} className="py-3 pr-3 space-y-3">
                        <div>
                          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mb-1">Log message</p>
                          <div className="flex items-start gap-2 rounded border border-[var(--card-border)] p-2">
                            <p className="flex-1 font-mono">{a.title}</p><CopyButton text={a.title} />
                          </div>
                        </div>
                        <div>
                          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mb-1">Content</p>
                          <div className="flex items-start gap-2 rounded border border-[var(--card-border)] p-2">
                            <pre className="flex-1 font-mono whitespace-pre-wrap break-words">{a.message || "—"}</pre>
                            <CopyButton text={a.message} />
                          </div>
                        </div>
                        {bySource && Object.keys(bySource).length > 0 && (
                          <div>
                            <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mb-1">Mitigated by</p>
                            <div className="flex flex-wrap gap-x-4 gap-y-1">
                              {Object.entries(bySource).sort((x, y) => y[1] - x[1]).map(([k, v]) => (
                                <span key={k}>{sourceLabel(k)} <span className="tabular-nums text-zinc-500 dark:text-zinc-400">{fmtFull(v)}</span></span>
                              ))}
                            </div>
                          </div>
                        )}
                        <div className="rounded bg-zinc-500/5 p-2 flex flex-wrap gap-x-3 gap-y-1">
                          {fields.map(([k, v]) => (
                            <span key={k}><span className="text-zinc-500 dark:text-zinc-400">{k}:</span> <span className="text-brand-green">{v}</span></span>
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
    </div>
  );
}
