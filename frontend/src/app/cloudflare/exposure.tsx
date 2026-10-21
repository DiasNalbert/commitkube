"use client";

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { Card, SeverityBadge, Stat, relativeTime } from "./shared";

interface Finding { severity: string; type: string; key: string; title: string; detail: string; target: string }
interface Port { port: number; service: string; severity: string }
interface ExposedIP {
  ip: string; records: string[]; proxied: boolean; dns_only: boolean; private: boolean; checked: boolean; seen: boolean;
  ports: Port[] | null; vulns: string[] | null; cpes: string[] | null; tags: string[] | null; hostnames: number; error?: string;
}
interface DNSRecord { id: string; type: string; name: string; content: string; proxied: boolean; ttl: number; comment: string }
interface Result { records: DNSRecord[] | null; ips: ExposedIP[] | null; findings: Finding[] | null; summary: Record<string, number>; notes: string[] | null }
interface Payload { scanned_at: string | null; error: string; result: Result | null }

const TYPE_LABEL: Record<string, string> = {
  origin_exposed: "Origin exposure", exposed_port: "Open port", known_vulns: "Known vulnerabilities",
  dangling_cname: "Dangling record", dns_only_record: "DNS-only record", private_ip_in_dns: "Internal address", email_auth: "Email authentication",
};

const PORT_CHIP: Record<string, string> = {
  critical: "text-red-500 dark:text-red-400 border-red-500/40 bg-red-500/10",
  high: "text-orange-600 dark:text-orange-400 border-orange-500/40 bg-orange-500/10",
  medium: "text-amber-600 dark:text-amber-400 border-amber-500/40 bg-amber-500/10",
  info: "text-zinc-500 dark:text-zinc-400 border-zinc-500/30",
};

function PortChip({ p }: { p: Port }) {
  return (
    <span title={`${p.service || "unidentified service"} · ${p.severity}`}
      className={`inline-block font-mono text-[11px] px-1.5 py-px rounded border ${PORT_CHIP[p.severity] ?? PORT_CHIP.info}`}>
      {p.port}{p.service && p.severity !== "info" ? <span className="font-sans opacity-80"> {p.service}</span> : null}
    </span>
  );
}

function ProxyBadge({ proxied }: { proxied: boolean }) {
  return proxied
    ? <span className="text-[10px] px-1.5 py-px rounded border text-orange-600 dark:text-orange-400 border-orange-500/30 bg-orange-500/10">Proxied</span>
    : <span className="text-[10px] px-1.5 py-px rounded border text-zinc-500 border-zinc-500/30 whitespace-nowrap">DNS only</span>;
}

export default function ExposureTab({ zoneRefId, canScan }: { zoneRefId: number; canScan: boolean }) {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState("");
  const [scanning, setScanning] = useState(false);
  const [sevFilter, setSevFilter] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [recordQuery, setRecordQuery] = useState("");

  const load = useCallback(async (method: "GET" | "POST" = "GET") => {
    try {
      const res = await apiFetch(`/cloudflare/zones/${zoneRefId}/exposure${method === "POST" ? "/scan" : ""}`, { method });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
      setError(""); setData(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    }
  }, [zoneRefId]);

  useEffect(() => { load(); }, [load]);

  const scan = async () => { setScanning(true); await load("POST"); setScanning(false); };

  const r = data?.result;
  const findings = useMemo(() => (r?.findings ?? []).filter(f => !sevFilter || f.severity === sevFilter), [r, sevFilter]);
  const records = useMemo(() => {
    const q = recordQuery.trim().toLowerCase();
    return (r?.records ?? []).filter(x => !q || x.name.toLowerCase().includes(q) || x.content.toLowerCase().includes(q) || x.type.toLowerCase() === q);
  }, [r, recordQuery]);
  const ips = useMemo(() => [...(r?.ips ?? [])].sort((a, b) => {
    const rank = (ip: ExposedIP) => Math.min(9, ...(ip.ports ?? []).map(p => ({ critical: 0, high: 1, medium: 2, info: 3 }[p.severity] ?? 3)));
    return rank(a) - rank(b) || (b.ports?.length ?? 0) - (a.ports?.length ?? 0);
  }), [r]);

  if (!data && !error) return <p className="text-sm text-zinc-500">Loading exposure…</p>;

  const sum = r?.summary ?? {};
  const counts = { critical: sum.findings_critical ?? 0, high: sum.findings_high ?? 0, medium: sum.findings_medium ?? 0, info: sum.findings_info ?? 0 };

  return (
    <div className="space-y-2">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="text-xs text-zinc-500 dark:text-zinc-400 max-w-3xl">
          What the zone exposes underneath Cloudflare: origin IPs reachable directly, open ports, records pointing at nothing.
          Ports are the internet&apos;s view, from Shodan&apos;s InternetDB (passive, refreshed about weekly) — a scan from inside
          the cluster would only see the cluster&apos;s own network. Checked every 6 hours.
          {data?.scanned_at && <> Last check {relativeTime(data.scanned_at)}.</>}
        </p>
        {canScan && (
          <button onClick={scan} disabled={scanning} className="btn-secondary text-xs disabled:opacity-50">
            {scanning ? "Checking…" : "Check now"}
          </button>
        )}
      </div>

      {error && <div className="glass-card p-3 border-red-500/30 text-sm text-red-500 dark:text-red-400 break-words">{error}</div>}
      {data?.error && (
        <div className="glass-card p-3 border-amber-500/30 text-xs text-amber-600 dark:text-amber-400 break-words">
          The last check failed{r ? ", so this is the previous result" : ""}: {data.error}
        </div>
      )}
      {!r && !data?.error && (
        <div className="glass-card p-6 text-center text-sm text-zinc-500">
          No check has run yet.{canScan && " Use Check now to run the first one."}
        </div>
      )}
      {r?.notes?.map(n => <p key={n} className="text-xs text-zinc-500 dark:text-zinc-400">{n}</p>)}

      {r && (
        <>
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-2">
            {(["critical", "high", "medium", "info"] as const).map(s => (
              <button key={s} onClick={() => setSevFilter(sevFilter === s ? "" : s)} className={`text-left ${sevFilter === s ? "ring-1 ring-brand-green/40 rounded-lg" : ""}`}>
                <Stat label={`${s} findings`} value={String(counts[s])}
                  tone={s === "critical" && counts[s] ? "bad" : s === "high" && counts[s] ? "warn" : undefined} />
              </button>
            ))}
            <Stat label="Public IPs" value={String((sum.ips ?? 0) - (r.ips ?? []).filter(i => i.private).length)}
              sub={`${sum.ips_with_ports ?? 0} with open ports`} />
            <Stat label="DNS records" value={String(sum.records ?? 0)}
              sub={`${sum.proxied ?? 0} proxied · ${sum.dns_only ?? 0} DNS only`} />
          </div>

          <Card title={`Findings${sevFilter ? ` · ${sevFilter}` : ""}`}>
            {findings.length === 0 ? (
              <p className="text-xs text-zinc-500 dark:text-zinc-400">{sevFilter ? "None at this severity." : "Nothing exposed that we can see."}</p>
            ) : (
              <ul className="divide-y divide-[var(--rule)]">
                {findings.map(f => {
                  const k = f.type + "|" + f.key;
                  const open = expanded === k;
                  return (
                    <li key={k} className="py-2">
                      <button className="w-full text-left flex items-start gap-2" onClick={() => setExpanded(open ? null : k)}>
                        <span className="w-16 shrink-0"><SeverityBadge severity={f.severity} /></span>
                        <span className="flex-1 min-w-0">
                          <span className="text-sm font-medium">{f.title}</span>
                          <span className="block text-xs text-zinc-500 dark:text-zinc-400 truncate">
                            {TYPE_LABEL[f.type] ?? f.type} · <span className="font-mono">{f.target}</span>
                          </span>
                        </span>
                        <span className={`text-zinc-500 transition-transform ${open ? "rotate-90" : ""}`}>›</span>
                      </button>
                      {open && <p className="text-xs mt-2 ml-[72px] max-w-4xl">{f.detail}</p>}
                    </li>
                  );
                })}
              </ul>
            )}
          </Card>

          <Card title="Addresses and open ports">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="text-left text-zinc-500 dark:text-zinc-400 border-b border-[var(--rule)]">
                    <th className="py-1.5 pr-3 font-medium">IP</th><th className="pr-3 font-medium">Role</th>
                    <th className="pr-3 font-medium">Records</th><th className="pr-3 font-medium">Open ports (internet view)</th>
                    <th className="pr-3 font-medium">Software / CVEs</th>
                  </tr>
                </thead>
                <tbody>
                  {ips.map(ip => (
                    <tr key={ip.ip} className="border-b border-[var(--rule)] align-top">
                      <td className="py-1.5 pr-3 font-mono whitespace-nowrap">{ip.ip}</td>
                      <td className="pr-3 py-1.5 whitespace-nowrap">
                        {ip.private ? <span className="text-zinc-500">Internal</span>
                          : ip.proxied ? <span title="A proxied record points here: this is an origin">Origin{ip.dns_only ? " + public" : ""}</span>
                            : <span>Public</span>}
                      </td>
                      <td className="pr-3 py-1.5 font-mono max-w-[260px]">
                        <span className="block truncate" title={ip.records.join(", ")}>{ip.records.join(", ")}</span>
                      </td>
                      <td className="pr-3 py-1.5">
                        {ip.private ? <span className="text-zinc-500">not looked up</span>
                          : ip.error ? <span className="text-amber-600 dark:text-amber-400" title={ip.error}>lookup failed</span>
                            : !ip.checked ? <span className="text-zinc-500">not looked up</span>
                              : !ip.seen || !ip.ports?.length ? <span className="text-brand-green">none seen</span>
                                : <span className="flex flex-wrap gap-1">{ip.ports.map(p => <PortChip key={p.port} p={p} />)}</span>}
                      </td>
                      <td className="pr-3 py-1.5 max-w-[320px]">
                        {(ip.cpes ?? []).slice(0, 3).map(c => <span key={c} className="block font-mono truncate text-zinc-500 dark:text-zinc-400">{c.replace("cpe:/", "")}</span>)}
                        {(ip.vulns?.length ?? 0) > 0 && (
                          <span className="block text-red-500 dark:text-red-400" title={ip.vulns!.join(", ")}>
                            {ip.vulns!.length} CVE{ip.vulns!.length > 1 ? "s" : ""}: {ip.vulns!.slice(0, 3).join(", ")}{ip.vulns!.length > 3 ? "…" : ""}
                          </span>
                        )}
                      </td>
                    </tr>
                  ))}
                  {ips.length === 0 && <tr><td colSpan={5} className="py-3 text-zinc-500">The zone has no A or AAAA records.</td></tr>}
                </tbody>
              </table>
            </div>
          </Card>

          <Card title="DNS records" right={
            <input className="input-tech !w-48 text-xs py-1" placeholder="Filter by name, content or type" value={recordQuery} onChange={e => setRecordQuery(e.target.value)} />
          }>
            <div className="overflow-x-auto max-h-[480px] overflow-y-auto">
              <table className="w-full text-xs">
                <thead className="sticky top-0" style={{ background: "var(--color-surface)" }}>
                  <tr className="text-left text-zinc-500 dark:text-zinc-400 border-b border-[var(--rule)]">
                    <th className="py-1.5 pr-3 font-medium">Type</th><th className="pr-3 font-medium">Name</th>
                    <th className="pr-3 font-medium w-full">Content</th><th className="pr-3 font-medium">Proxy</th>
                  </tr>
                </thead>
                <tbody>
                  {records.map((x, i) => (
                    <Fragment key={x.id || i}>
                      <tr className="border-b border-[var(--rule)]">
                        <td className="py-1 pr-3 font-mono">{x.type}</td>
                        <td className="pr-3 font-mono whitespace-nowrap">{x.name}</td>
                        <td className="pr-3 font-mono max-w-0 truncate" title={x.content}>{x.content}</td>
                        <td className="pr-3">{["A", "AAAA", "CNAME"].includes(x.type) ? <ProxyBadge proxied={x.proxied} /> : null}</td>
                      </tr>
                    </Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </>
      )}
    </div>
  );
}
