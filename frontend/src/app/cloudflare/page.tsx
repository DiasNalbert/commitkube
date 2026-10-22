"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { loadPermissions, PERMISSIONS } from "@/lib/permissions";
import { useShellRefresh } from "@/app/components/shell/refresh";
import { AlertLog, Modal, ZoneForm, emptyZoneForm, fmtFull, fmtNum, fmtPct, relativeTime, type Alert, type Zone } from "./shared";

interface Port { port: number; service: string; severity: string; closed?: boolean }
interface ExposedIP { ip: string; records: string[]; proxied: boolean; checked: boolean; private: boolean; ports: Port[] | null }
interface Exposure { scanned_at: string | null; error: string; result: { ips: ExposedIP[] | null } | null }

const SEV_COLOR: Record<string, string> = {
  critical: "var(--red)", high: "var(--orange)", medium: "var(--gold)", info: "var(--m3)",
};
const SEV_RANK: Record<string, number> = { critical: 0, high: 1, medium: 2, info: 3 };

const stamp = (iso: string) => {
  const d = new Date(iso);
  const mon = d.toLocaleString("en-US", { month: "short" }).toLowerCase();
  return `${d.getDate()} ${mon} · ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
};

/** Every zone on one page, led by the one thing that is not a dashboard
 *  number: which origin servers answer from the internet without Cloudflare
 *  in front of them. Each zone's own page keeps the deep analytics. */
export default function CloudflarePage() {
  const [zones, setZones] = useState<Zone[] | null>(null);
  const [exposure, setExposure] = useState<Record<number, Exposure>>({});
  const [alerts, setAlerts] = useState<Alert[]>([]);
  const [error, setError] = useState("");
  const [adding, setAdding] = useState(false);
  const [canManage, setCanManage] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [fullLog, setFullLog] = useState(false);
  const [refreshKey, setRefreshKey] = useState(0);

  const { markSynced } = useShellRefresh(() => { load(); setRefreshKey(k => k + 1); });

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/cloudflare/zones");
      const body = await res.json().catch(() => ([]));
      if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
      setError("");
      const list: Zone[] = body;
      setZones(list);
      // Stored scans, not live ones: reading them costs a row each.
      const [exp, al] = await Promise.all([
        Promise.all(list.map(z => apiFetch(`/cloudflare/zones/${z.id}/exposure`).then(r => (r.ok ? r.json() : null)).catch(() => null)
          .then(d => [z.id, d] as const))),
        apiFetch("/cloudflare/alerts?days=7&limit=12").then(r => (r.ok ? r.json() : null)).catch(() => null),
      ]);
      const m: Record<number, Exposure> = {};
      for (const [id, d] of exp) if (d) m[id] = d;
      setExposure(m);
      setAlerts(al?.alerts ?? []);
      markSynced();
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    }
  }, [markSynced]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    loadPermissions().then(p => setCanManage(p.size === 0 || p.has(PERMISSIONS.cloudflareManage)));
  }, []);
  // The poller writes every five minutes; a minute keeps the page current.
  useEffect(() => {
    const t = setInterval(() => { if (!document.hidden) { load(); setRefreshKey(k => k + 1); } }, 60_000);
    return () => clearInterval(t);
  }, [load]);

  const zoneName = useMemo(() => new Map((zones ?? []).map(z => [z.id, z.label || z.zone_name])), [zones]);

  // Origins that answer directly: an address in DNS, not behind the proxy,
  // with something listening that should not be.
  const origins = useMemo(() => {
    const byIP = new Map<string, { ip: string; hosts: Set<string>; ports: Map<number, Port> }>();
    for (const z of zones ?? []) {
      for (const ip of exposure[z.id]?.result?.ips ?? []) {
        if (ip.proxied || ip.private || !ip.checked) continue;
        const ports = (ip.ports ?? []).filter(p => p.severity !== "info" || p.closed);
        if (!ports.length) continue;
        const e = byIP.get(ip.ip) ?? { ip: ip.ip, hosts: new Set<string>(), ports: new Map<number, Port>() };
        (ip.records ?? []).slice(0, 2).forEach(r => e.hosts.add(r));
        ports.forEach(p => e.ports.set(p.port, p));
        byIP.set(ip.ip, e);
      }
    }
    return [...byIP.values()].map(o => ({
      ip: o.ip, host: [...o.hosts].join(", "),
      ports: [...o.ports.values()].sort((a, b) => Number(!!a.closed) - Number(!!b.closed) || (SEV_RANK[a.severity] ?? 9) - (SEV_RANK[b.severity] ?? 9) || a.port - b.port),
    })).sort((a, b) => b.ports.filter(p => !p.closed).length - a.ports.filter(p => !p.closed).length);
  }, [zones, exposure]);

  const openPorts = origins.reduce((n, o) => n + o.ports.filter(p => !p.closed).length, 0);
  const exposedIPs = origins.filter(o => o.ports.some(p => !p.closed)).length;
  const totals = (zones ?? []).reduce((t, z) => ({
    req: t.req + z.last_requests, threats: t.threats + z.last_threats, e5: t.e5 + z.last_errors_5xx, open: t.open + z.open_alerts,
  }), { req: 0, threats: 0, e5: 0, open: 0 });
  const troubled = (zones ?? []).filter(z => z.open_alerts > 0);
  const neverScanned = (zones ?? []).filter(z => !exposure[z.id]?.scanned_at).length;

  if (zones === null && !error) return <p className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>Reading zones…</p>;

  return (
    <div className="max-w-[1280px] flex flex-col gap-9 pb-8">
      {error && <p className="m-0 p-3 text-sm break-words" style={{ color: "var(--red)", border: "1px solid rgba(248,113,113,.3)" }}>{error}</p>}
      {warnings.length > 0 && (
        <div className="p-3 text-xs flex flex-col gap-1" style={{ color: "var(--gold)", border: "1px solid rgba(251,191,36,.3)" }}>
          {warnings.map(w => <p key={w} className="m-0">{w}</p>)}
        </div>
      )}

      {zones && zones.length === 0 ? (
        <section className="flex flex-col gap-5 max-w-[980px]">
          <h1 className="m-0 text-[30px] leading-[1.25] font-medium tracking-[-0.02em]">No Cloudflare zone is being watched yet.</h1>
          <p className="m-0 max-w-[640px]" style={{ color: "var(--t3)" }}>
            Add a zone with its zone ID, account ID and an API token that can read the zone&apos;s analytics and DNS.
            Both IDs are on the zone&apos;s Overview page in the Cloudflare dashboard.
          </p>
          {canManage && <button type="button" onClick={() => setAdding(true)} className="btn-primary self-start">Add zone</button>}
        </section>
      ) : zones && (
        <>
          <section className="flex flex-col gap-5 max-w-[980px]">
            <h1 className="m-0 text-[26px] md:text-[30px] leading-[1.25] font-medium tracking-[-0.02em]" style={{ textWrap: "pretty" } as React.CSSProperties}>
              {openPorts > 0 ? (
                <><span style={{ color: "var(--red)" }}>{openPorts} {openPorts === 1 ? "port" : "ports"}</span> on {exposedIPs} origin {exposedIPs === 1 ? "IP answers" : "IPs answer"} from the internet without Cloudflare in front.</>
              ) : (
                <>No origin answers from the internet outside Cloudflare{neverScanned ? ` (${neverScanned} ${neverScanned === 1 ? "zone has" : "zones have"} not been scanned yet)` : ""}.</>
              )}{" "}
              {troubled.length === 0 ? (
                zones.length === 1
                  ? <>Traffic on <span className="font-mono text-[22px] md:text-[24px]">{zones[0].zone_name}</span> is normal.</>
                  : <>Traffic is normal on all {zones.length} zones.</>
              ) : troubled.length === 1 ? (
                <><span className="font-mono text-[22px] md:text-[24px]" style={{ color: "var(--gold)" }}>{troubled[0].zone_name}</span> has {troubled[0].open_alerts} open {troubled[0].open_alerts === 1 ? "alert" : "alerts"}.</>
              ) : (
                <><span style={{ color: "var(--gold)" }}>{troubled.length} zones</span> have open alerts.</>
              )}
            </h1>
            <div className="flex gap-7 flex-wrap">
              {[
                ["Requests, last 5 min", fmtFull(totals.req)],
                ["Threats blocked", fmtFull(totals.threats)],
                ["5xx rate", totals.req > 0 ? fmtPct((totals.e5 / totals.req) * 100, 2) : "—"],
                ["Open alerts", String(totals.open)],
              ].map(([label, value]) => (
                <div key={label} className="flex flex-col gap-1">
                  <span className="text-[12.5px]" style={{ color: "var(--t3)" }}>{label}</span>
                  <span className="font-mono text-[22px] font-light" style={{ color: label === "Open alerts" && totals.open > 0 ? "var(--red)" : "var(--text)" }}>{value}</span>
                </div>
              ))}
            </div>
          </section>

          <section className="flex flex-col gap-3.5">
            <h2 className="m-0 text-lg font-semibold">Exposure by origin</h2>
            {origins.length === 0 ? (
              <p className="m-0 text-[13px] py-4" style={{ color: "var(--t3)", borderTop: "1px solid var(--rule)" }}>
                Every address in DNS is proxied, private, or has nothing listening that matters.
              </p>
            ) : origins.map(o => (
              <div key={o.ip} className="grid gap-5 items-start py-4" style={{ gridTemplateColumns: "minmax(140px,200px) minmax(0,1fr)", borderTop: "1px solid var(--rule)" }}>
                <div className="flex flex-col gap-1 min-w-0">
                  <span className="font-mono text-[13px]">{o.ip}</span>
                  <span className="text-[12.5px] truncate" style={{ color: "var(--m2)" }} title={o.host}>{o.host || "—"}</span>
                </div>
                <div className="flex gap-2 flex-wrap">
                  {o.ports.map(p => {
                    const c = p.closed ? "var(--m3)" : SEV_COLOR[p.severity] ?? "var(--m3)";
                    return (
                      <div key={p.port} className="flex flex-col gap-[3px] min-w-[132px] px-3 py-2.5"
                        style={{
                          border: `1px solid ${p.closed ? "var(--line)" : `color-mix(in srgb, ${c} 35%, transparent)`}`,
                          background: p.closed ? "transparent" : `color-mix(in srgb, ${c} 6%, transparent)`,
                        }}>
                        <span className="font-mono text-[17px]" style={{ color: c }}>:{p.port}</span>
                        <span className="text-[12.5px]" style={{ color: "var(--t2)" }}>{p.service || "unidentified"}</span>
                        <span className="text-[11.5px]" style={{ color: "var(--m2)" }}>{p.closed ? "closed · resolved" : `${p.severity} · open`}</span>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </section>

          <section className="flex flex-col gap-1.5">
            <div className="flex items-baseline justify-between gap-4 mb-2">
              <h2 className="m-0 text-lg font-semibold">Zones</h2>
              {canManage && <button type="button" onClick={() => setAdding(true)} className="btn-secondary">Add zone</button>}
            </div>
            {zones.map(z => {
              const rate = z.last_requests > 0 ? (z.last_errors_5xx / z.last_requests) * 100 : 0;
              return (
                <a key={z.id} href={`/cloudflare/${z.id}`}
                  className="grid gap-3.5 items-baseline py-2.5 no-underline hover:bg-[var(--hover)]"
                  style={{ gridTemplateColumns: "minmax(0,1.4fr) repeat(3,minmax(70px,.6fr)) minmax(110px,.8fr)", borderTop: "1px solid var(--rule2)", color: "var(--text)" }}>
                  <span className="flex flex-col min-w-0">
                    <span className="truncate">{z.label}</span>
                    <span className="font-mono text-[11px] truncate" style={{ color: "var(--m2)" }}>{z.zone_name}{z.enabled ? "" : " · paused"}</span>
                  </span>
                  <span className="font-mono text-[12px]">{fmtNum(z.last_requests)} <span style={{ color: "var(--m2)" }}>req</span></span>
                  <span className="font-mono text-[12px]" style={{ color: z.last_threats > 0 ? "var(--gold)" : "var(--text)" }}>{fmtNum(z.last_threats)} <span style={{ color: "var(--m2)" }}>threats</span></span>
                  <span className="font-mono text-[12px]" style={{ color: z.error_rate_threshold > 0 && rate >= z.error_rate_threshold ? "var(--red)" : "var(--text)" }}>{fmtPct(rate)} <span style={{ color: "var(--m2)" }}>5xx</span></span>
                  <span className="text-[12.5px] text-right" style={{ color: z.open_alerts > 0 ? "var(--red)" : z.last_error ? "var(--gold)" : "var(--m2)" }} title={z.last_error || undefined}>
                    {z.open_alerts > 0 ? `${z.open_alerts} open` : z.last_error ? "poll failing" : `checked ${relativeTime(z.last_polled_at)}`}
                  </span>
                </a>
              );
            })}
          </section>

          <section className="flex flex-col gap-1.5">
            <div className="flex items-baseline justify-between gap-4 mb-2">
              <h2 className="m-0 text-lg font-semibold">Alert history</h2>
              <button type="button" onClick={() => setFullLog(v => !v)} className="p-0 text-[12.5px]" style={{ color: "var(--green)" }}>
                {fullLog ? "Hide the full log" : "Search the full log →"}
              </button>
            </div>
            {fullLog ? (
              <AlertLog zones={zones} refreshKey={refreshKey} />
            ) : alerts.length === 0 ? (
              <p className="m-0 text-[13px] py-3" style={{ color: "var(--t3)", borderTop: "1px solid var(--rule2)" }}>No alerts in the last 7 days.</p>
            ) : alerts.map(a => {
              const open = !a.resolved_at && a.source === "commitkube";
              return (
                <div key={a.id} className="grid gap-3.5 items-baseline py-2.5" style={{ gridTemplateColumns: "130px 12px minmax(0,1fr) auto", borderTop: "1px solid var(--rule2)" }}>
                  <span className="font-mono text-[10.5px]" style={{ color: "var(--m2)" }}>{stamp(a.started_at)}</span>
                  <span className="w-2 h-2" style={{ background: SEV_COLOR[a.severity] ?? "var(--m3)" }} />
                  <span className="flex flex-col gap-0.5 min-w-0">
                    <span>{a.title}</span>
                    <span className="text-[12.5px] truncate" style={{ color: "var(--t3)" }} title={a.message}>
                      {zones.length > 1 ? `${zoneName.get(a.zone_ref_id) ?? ""} · ` : ""}{a.message}
                    </span>
                  </span>
                  <span className="text-[12.5px]" style={{ color: open ? "var(--red)" : "var(--m2)" }}>{open ? "Open" : "Resolved"}</span>
                </div>
              );
            })}
          </section>
        </>
      )}

      {adding && (
        <Modal title="Add a Cloudflare zone" onClose={() => setAdding(false)}>
          <ZoneForm initial={emptyZoneForm} onCancel={() => setAdding(false)}
            onSaved={(_id, w) => { setAdding(false); setWarnings(w); load(); setTimeout(load, 8000); }} />
        </Modal>
      )}
    </div>
  );
}
