"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { loadPermissions, PERMISSIONS } from "@/lib/permissions";
import { AlertLog, Modal, Zone, ZoneForm, emptyZoneForm, fmtNum, fmtPct, relativeTime } from "./shared";

export default function CloudflarePage() {
  const [zones, setZones] = useState<Zone[] | null>(null);
  const [error, setError] = useState("");
  const [adding, setAdding] = useState(false);
  const [canManage, setCanManage] = useState(false);
  const [warnings, setWarnings] = useState<string[]>([]);
  const [refreshKey, setRefreshKey] = useState(0);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/cloudflare/zones");
      const body = await res.json().catch(() => ([]));
      if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
      setError(""); setZones(body);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Could not reach the API");
    }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    loadPermissions().then(p => setCanManage(p.size === 0 || p.has(PERMISSIONS.cloudflareManage)));
  }, []);
  // The poller writes every five minutes; refreshing on a minute keeps the
  // cards and the log current without anybody reaching for reload.
  useEffect(() => {
    const t = setInterval(() => { load(); setRefreshKey(k => k + 1); }, 60_000);
    return () => clearInterval(t);
  }, [load]);

  return (
    <div className="p-4 max-w-[1600px] mx-auto space-y-4 min-w-0">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <h1 className="text-lg font-semibold">Cloudflare</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
            Security monitoring per zone: traffic, mitigated threats, bots and the paths being probed, read live from
            Cloudflare&apos;s analytics. Every zone is checked every five minutes against its thresholds.
          </p>
        </div>
        {canManage && (
          <button onClick={() => setAdding(true)} className="btn-primary text-sm">Add zone</button>
        )}
      </div>

      {error && <div className="glass-card p-3 border-red-500/30 text-sm text-red-500 dark:text-red-400 break-words">{error}</div>}
      {warnings.length > 0 && (
        <div className="glass-card p-3 border-amber-500/30 text-xs text-amber-600 dark:text-amber-400 space-y-1">
          {warnings.map(w => <p key={w}>{w}</p>)}
        </div>
      )}

      {zones === null && !error && <p className="text-sm text-zinc-500">Loading zones…</p>}

      {zones?.length === 0 && (
        <div className="glass-card p-8 text-center">
          <p className="font-medium">No zones yet</p>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-lg mx-auto">
            Add a zone with its zone ID, account ID and an API token that can read the zone&apos;s analytics.
            Both IDs are on the zone&apos;s Overview page in the Cloudflare dashboard.
          </p>
          {canManage && <button onClick={() => setAdding(true)} className="btn-primary text-sm mt-4">Add zone</button>}
        </div>
      )}

      {zones && zones.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-2">
          {zones.map(z => {
            const rate = z.last_requests > 0 ? (z.last_errors_5xx / z.last_requests) * 100 : 0;
            const threatShare = z.last_requests > 0 ? (z.last_threats / z.last_requests) * 100 : 0;
            return (
              <a key={z.id} href={`/cloudflare/${z.id}`} className="glass-card p-4 block min-w-0">
                <div className="flex items-start justify-between gap-2">
                  <div className="min-w-0">
                    <p className="font-semibold truncate">{z.label}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400 font-mono truncate">{z.zone_name}</p>
                  </div>
                  <div className="flex flex-col items-end gap-1 shrink-0">
                    {z.open_alerts > 0
                      ? <span className="text-[11px] px-1.5 py-0.5 rounded border text-red-500 dark:text-red-400 border-red-500/30 bg-red-500/10">● {z.open_alerts} open alert{z.open_alerts > 1 ? "s" : ""}</span>
                      : z.enabled
                        ? <span className="text-[11px] px-1.5 py-0.5 rounded border text-brand-green border-brand-green/30 bg-brand-green/10">✓ No open alerts</span>
                        : <span className="text-[11px] px-1.5 py-0.5 rounded border text-zinc-500 border-zinc-500/30">Paused</span>}
                    <span className="text-[11px] text-zinc-500 dark:text-zinc-400">{z.plan || "—"}</span>
                  </div>
                </div>

                <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mt-3">Last 5 minutes</p>
                <div className="grid grid-cols-3 gap-2 mt-1">
                  <div>
                    <p className="text-lg font-semibold tabular-nums">{fmtNum(z.last_requests)}</p>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400">requests</p>
                  </div>
                  <div>
                    <p className={`text-lg font-semibold tabular-nums ${z.last_threats > 0 ? "text-amber-600 dark:text-amber-400" : ""}`}>{fmtNum(z.last_threats)}</p>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400">threats{z.last_requests > 0 ? ` · ${fmtPct(threatShare)}` : ""}</p>
                  </div>
                  <div>
                    <p className={`text-lg font-semibold tabular-nums ${rate >= z.error_rate_threshold && z.error_rate_threshold > 0 ? "text-red-500 dark:text-red-400" : ""}`}>{fmtPct(rate)}</p>
                    <p className="text-[11px] text-zinc-500 dark:text-zinc-400">5xx</p>
                  </div>
                </div>

                <div className="mt-3 text-[11px] text-zinc-500 dark:text-zinc-400 flex flex-wrap gap-x-3">
                  <span>Checked {relativeTime(z.last_polled_at)}</span>
                  {(z.alerts_24h ?? 0) > 0 && <span>{z.alerts_24h} alert{z.alerts_24h! > 1 ? "s" : ""} in 24 h</span>}
                </div>
                {z.last_error && <p className="mt-1 text-[11px] text-red-500 dark:text-red-400 truncate" title={z.last_error}>{z.last_error}</p>}
              </a>
            );
          })}
        </div>
      )}

      {zones && zones.length > 0 && (
        <section className="space-y-2">
          <h2 className="text-sm font-semibold">Alerts across all zones</h2>
          <AlertLog zones={zones} refreshKey={refreshKey} />
        </section>
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
