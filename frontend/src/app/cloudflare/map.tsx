"use client";

import { useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import world from "./geo/world.json";
import brazil from "./geo/brazil.json";
import { BarList, SectionError, fmtFull, fmtNum, fmtPct, sourceLabel } from "./shared";

// Where requests come from. The geometry is pre-projected SVG (Natural Earth
// for the world, IBGE's state mesh for Brazil), so the page carries no map
// library. Countries are shaded on a log scale: one country usually has most
// of the traffic, and a linear scale would paint every other one the same.

interface KeyCount { key: string; count: number }
interface Section<T> { data?: T; error?: string }
interface WorldPayload { sections: { countries?: Section<KeyCount[]>; threats?: Section<KeyCount[]> } }
interface CountryPayload {
  country: string;
  region_dim?: string;
  city_dim?: string;
  schema_error?: string;
  sections: {
    regions?: Section<KeyCount[]>; cities?: Section<KeyCount[]>; ips?: Section<KeyCount[]>;
    paths?: Section<KeyCount[]>; threat_sources?: Section<KeyCount[]>;
  };
}

type Mode = "requests" | "threats";

// One hue per measure, light to dark, stepped separately for each theme.
// Requests use the purple of the request charts; threats the amber.
const RAMPS: Record<Mode, { light: string[]; dark: string[] }> = {
  requests: {
    light: ["#e6e2f8", "#c4bbee", "#9d90e0", "#7462cf", "#4a3aa7"],
    dark: ["#2c2650", "#3f3676", "#5a4ea6", "#7a6fd0", "#a39cf0"],
  },
  threats: {
    light: ["#fcefd2", "#f8d68a", "#f1bb47", "#e09a00", "#a86f00"],
    dark: ["#3b2d0c", "#5e4510", "#8c6412", "#c98500", "#f0b43c"],
  },
};
const NO_DATA = { light: "#e4e4e7", dark: "#27272a" };

const regionNames = typeof Intl !== "undefined" && "DisplayNames" in Intl
  ? new Intl.DisplayNames(["en"], { type: "region" }) : null;
export const countryName = (code: string) => {
  try { return regionNames?.of(code) ?? code; } catch { return code; }
};

const fold = (s: string) => s.normalize("NFD").replace(/[̀-ͯ]/g, "").toLowerCase().trim();

/** Cloudflare's region value, whatever its form -- "SP", "BR-SP" or "São
 *  Paulo" -- to the state's UF. */
function toUF(value: string): string | null {
  const states = brazil.states as Record<string, { name: string; d: string }>;
  const v = value.toUpperCase().replace(/^BR-/, "").trim();
  if (states[v]) return v;
  const f = fold(value);
  for (const [uf, s] of Object.entries(states)) if (fold(s.name) === f) return uf;
  return null;
}

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

/** Log-scale buckets over the non-zero values: five steps, the top one only
 *  for the largest values. */
function useScale(values: number[]) {
  return useMemo(() => {
    const pos = values.filter(v => v > 0);
    if (pos.length === 0) return { bucket: () => -1, edges: [] as number[] };
    const lo = Math.log10(Math.min(...pos));
    const hi = Math.log10(Math.max(...pos));
    const span = Math.max(hi - lo, 1e-9);
    const edges = [0, 1, 2, 3, 4, 5].map(i => Math.round(10 ** (lo + (span * i) / 5)));
    const bucket = (v: number) => (v <= 0 ? -1 : Math.min(4, Math.floor(((Math.log10(v) - lo) / span) * 5)));
    return { bucket, edges };
  }, [values]);
}

function Legend({ ramp, edges, label }: { ramp: string[]; edges: number[]; label: string }) {
  if (edges.length === 0) return null;
  return (
    <div className="flex items-center gap-2 text-[11px] text-zinc-500 dark:text-zinc-400">
      <span>{label}</span>
      <span className="flex items-center">
        {ramp.map((c, i) => (
          <span key={c} className="flex flex-col items-center">
            <span className="block w-8 h-2" style={{ background: c, marginRight: 2 }} />
            <span className="tabular-nums mt-0.5">{i === 0 ? fmtNum(edges[0]) : i === ramp.length - 1 ? fmtNum(edges[5]) : ""}</span>
          </span>
        ))}
      </span>
    </div>
  );
}

interface Tip { x: number; y: number; title: string; lines: string[] }

function Tooltip({ tip }: { tip: Tip | null }) {
  if (!tip) return null;
  return (
    <div className="pointer-events-none absolute z-10 rounded-lg border px-2.5 py-1.5 text-xs shadow-lg"
      style={{ left: tip.x + 12, top: tip.y + 12, background: "var(--color-surface)", borderColor: "var(--card-border)" }}>
      <p className="font-medium">{tip.title}</p>
      {tip.lines.map(l => <p key={l} className="text-zinc-500 dark:text-zinc-400 tabular-nums">{l}</p>)}
    </div>
  );
}

export default function TrafficMap({ zoneRefId, range }: { zoneRefId: number; range: string }) {
  const [data, setData] = useState<WorldPayload | null>(null);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<Mode>("requests");
  const [selected, setSelected] = useState<string | null>(null);
  const [tip, setTip] = useState<Tip | null>(null);
  const [hover, setHover] = useState<string | null>(null);
  const box = useRef<HTMLDivElement>(null);
  const dark = useIsDark();

  useEffect(() => {
    let live = true;
    (async () => {
      try {
        const res = await apiFetch(`/cloudflare/zones/${zoneRefId}/geo?range=${range}`);
        const body = await res.json().catch(() => ({}));
        if (!live) return;
        if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
        setError(""); setData(body);
      } catch (e) {
        if (live) setError(e instanceof Error ? e.message : "Could not reach the API");
      }
    })();
    return () => { live = false; };
  }, [zoneRefId, range]);

  const req = useMemo(() => new Map((data?.sections.countries?.data ?? []).map(r => [r.key, r.count])), [data]);
  const thr = useMemo(() => new Map((data?.sections.threats?.data ?? []).map(r => [r.key, r.count])), [data]);
  const totalReq = useMemo(() => Array.from(req.values()).reduce((a, b) => a + b, 0), [req]);
  const totalThr = useMemo(() => Array.from(thr.values()).reduce((a, b) => a + b, 0), [thr]);
  const values = mode === "requests" ? req : thr;
  const scale = useScale(useMemo(() => Array.from(values.values()), [values]));
  const ramp = RAMPS[mode][dark ? "dark" : "light"];
  const empty = dark ? NO_DATA.dark : NO_DATA.light;
  const sectionError = mode === "requests" ? data?.sections.countries?.error : data?.sections.threats?.error;

  const move = (e: React.MouseEvent, code: string) => {
    const r = box.current?.getBoundingClientRect();
    if (!r) return;
    const q = req.get(code) ?? 0;
    const t = thr.get(code) ?? 0;
    setHover(code);
    setTip({
      x: e.clientX - r.left, y: e.clientY - r.top, title: `${countryName(code)} (${code})`,
      lines: [
        `${fmtFull(q)} requests${totalReq ? ` · ${fmtPct((q / totalReq) * 100)}` : ""}`,
        `${fmtFull(t)} security events${q ? ` · ${fmtPct((t / q) * 100)} of its requests` : ""}`,
      ],
    });
  };

  const countries = world.countries as Record<string, string>;
  const ranked = Array.from(values.entries()).sort((a, b) => b[1] - a[1]).slice(0, 10);

  return (
    <section className="glass-card p-4 min-w-0">
      <div className="flex flex-wrap items-center justify-between gap-2 mb-2">
        <h2 className="text-sm font-semibold">Where {mode === "requests" ? "requests" : "security events"} come from</h2>
        <div className="flex items-center gap-3">
          <Legend ramp={ramp} edges={scale.edges} label={mode === "requests" ? "Requests" : "Events"} />
          <div className="flex items-center gap-1" role="group" aria-label="Measure">
            {(["requests", "threats"] as Mode[]).map(m => (
              <button key={m} onClick={() => setMode(m)}
                className={`px-2 py-1 text-xs rounded-md transition ${mode === m ? "bg-brand-green/10 text-brand-green" : "text-zinc-500 hover:text-brand-green"}`}>
                {m === "requests" ? "Requests" : "Security events"}
              </button>
            ))}
          </div>
        </div>
      </div>
      {error && <SectionError error={error} />}
      {sectionError && <SectionError error={sectionError} />}

      <div className={`grid gap-4 ${selected ? "xl:grid-cols-[minmax(0,1.4fr)_minmax(0,1fr)]" : ""}`}>
        <div>
          <div ref={box} className="relative" onMouseLeave={() => { setTip(null); setHover(null); }}>
            <svg viewBox={`0 0 ${world.width} ${world.height}`} className="w-full h-auto" role="img"
              aria-label={`World map of ${mode} by country`}>
              {Object.entries(countries).map(([code, d]) => {
                const b = scale.bucket(values.get(code) ?? 0);
                const isSel = selected === code;
                return (
                  <path key={code} d={d} fill={b < 0 ? empty : ramp[b]}
                    stroke={isSel || hover === code ? (dark ? "#fafafa" : "#0f172a") : (dark ? "#18181b" : "#ffffff")}
                    strokeWidth={isSel ? 1.4 : hover === code ? 1 : 0.4}
                    className="cursor-pointer"
                    onMouseMove={e => move(e, code)}
                    onClick={() => setSelected(isSel ? null : code)} />
                );
              })}
            </svg>
            <Tooltip tip={tip} />
          </div>
          <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-xs">
            {ranked.map(([code, v]) => (
              <button key={code} onClick={() => setSelected(selected === code ? null : code)}
                className={`hover:text-brand-green ${selected === code ? "text-brand-green" : ""}`}>
                {countryName(code)} <span className="tabular-nums text-zinc-500 dark:text-zinc-400">
                  {fmtNum(v)}{(mode === "requests" ? totalReq : totalThr) ? ` · ${fmtPct((v / (mode === "requests" ? totalReq : totalThr)) * 100)}` : ""}
                </span>
              </button>
            ))}
          </div>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-1">Click a country for its regions, cities, clients and paths.</p>
        </div>

        {selected && (
          <CountryDetail zoneRefId={zoneRefId} range={range} code={selected} requests={req.get(selected) ?? 0}
            threats={thr.get(selected) ?? 0} dark={dark} onClose={() => setSelected(null)} />
        )}
      </div>
    </section>
  );
}

function CountryDetail({ zoneRefId, range, code, requests, threats, dark, onClose }: {
  zoneRefId: number; range: string; code: string; requests: number; threats: number; dark: boolean; onClose: () => void;
}) {
  const [data, setData] = useState<CountryPayload | null>(null);
  const [error, setError] = useState("");
  const [tip, setTip] = useState<Tip | null>(null);
  const box = useRef<HTMLDivElement>(null);

  useEffect(() => {
    let live = true;
    setData(null); setError("");
    (async () => {
      try {
        const res = await apiFetch(`/cloudflare/zones/${zoneRefId}/geo?range=${range}&country=${code}`);
        const body = await res.json().catch(() => ({}));
        if (!live) return;
        if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
        setData(body);
      } catch (e) {
        if (live) setError(e instanceof Error ? e.message : "Could not reach the API");
      }
    })();
    return () => { live = false; };
  }, [zoneRefId, range, code]);

  const regions = useMemo(() => data?.sections.regions?.data ?? [], [data]);
  const byUF = useMemo(() => {
    const m = new Map<string, number>();
    if (code === "BR") regions.forEach(r => { const uf = toUF(r.key); if (uf) m.set(uf, (m.get(uf) ?? 0) + r.count); });
    return m;
  }, [regions, code]);
  const scale = useScale(useMemo(() => Array.from(byUF.values()), [byUF]));
  const ramp = RAMPS.requests[dark ? "dark" : "light"];
  const regionTotal = regions.reduce((a, r) => a + r.count, 0);
  const states = brazil.states as Record<string, { name: string; d: string }>;

  return (
    <div className="min-w-0 space-y-3 border-t xl:border-t-0 xl:border-l border-[var(--rule)] pt-3 xl:pt-0 xl:pl-4">
      <div className="flex items-start justify-between gap-2">
        <div>
          <h3 className="text-sm font-semibold">{countryName(code)}</h3>
          <p className="text-xs text-zinc-500 dark:text-zinc-400 tabular-nums">
            {fmtFull(requests)} requests · {fmtFull(threats)} security events
          </p>
        </div>
        <button onClick={onClose} className="text-zinc-500 hover:text-[var(--color-fg)]" aria-label="Close">×</button>
      </div>
      {error && <SectionError error={error} />}
      {!data && !error && <p className="text-xs text-zinc-500">Loading {countryName(code)}…</p>}

      {data && (
        <>
          {!data.region_dim && !data.city_dim && (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Cloudflare&apos;s analytics for this zone have no region or city field
              {data.schema_error ? <> (the schema could not be read: {data.schema_error})</> : null}, so the breakdown stops at the country.
            </p>
          )}

          {code === "BR" && byUF.size > 0 && (
            <div ref={box} className="relative max-w-[420px] mx-auto" onMouseLeave={() => setTip(null)}>
              <svg viewBox={`0 0 ${brazil.width} ${brazil.height}`} className="w-full h-auto" role="img" aria-label="Map of Brazil by state">
                {Object.entries(states).map(([uf, s]) => {
                  const v = byUF.get(uf) ?? 0;
                  const b = scale.bucket(v);
                  return (
                    <path key={uf} d={s.d} fill={b < 0 ? (dark ? NO_DATA.dark : NO_DATA.light) : ramp[b]}
                      stroke={dark ? "#18181b" : "#ffffff"} strokeWidth={0.8}
                      onMouseMove={e => {
                        const r = box.current?.getBoundingClientRect();
                        if (r) setTip({ x: e.clientX - r.left, y: e.clientY - r.top, title: `${s.name} (${uf})`,
                          lines: [`${fmtFull(v)} requests${regionTotal ? ` · ${fmtPct((v / regionTotal) * 100)}` : ""}`] });
                      }} />
                  );
                })}
              </svg>
              <Tooltip tip={tip} />
              <div className="flex justify-center mt-1"><Legend ramp={ramp} edges={scale.edges} label="Requests" /></div>
            </div>
          )}

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {data.region_dim && (
              <div>
                <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Regions</p>
                {data.sections.regions?.error ? <SectionError error={data.sections.regions.error} /> :
                  <BarList total={regionTotal} rows={regions.slice(0, 12).map(r => {
                    const uf = code === "BR" ? toUF(r.key) : null;
                    return { key: r.key, label: uf ? `${states[uf].name} (${uf})` : r.key || "Unknown", value: r.count };
                  })} />}
              </div>
            )}
            {data.city_dim && (
              <div>
                <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Cities</p>
                {data.sections.cities?.error ? <SectionError error={data.sections.cities.error} /> :
                  <BarList rows={(data.sections.cities?.data ?? []).slice(0, 12).map(r => ({ key: r.key, label: r.key || "Unknown", value: r.count }))} />}
              </div>
            )}
            <div>
              <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Top client IPs</p>
              {data.sections.ips?.error ? <SectionError error={data.sections.ips.error} /> :
                <BarList mono rows={(data.sections.ips?.data ?? []).slice(0, 8).map(r => ({ key: r.key, label: r.key, value: r.count }))} />}
            </div>
            <div>
              <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Top paths</p>
              {data.sections.paths?.error ? <SectionError error={data.sections.paths.error} /> :
                <BarList mono rows={(data.sections.paths?.data ?? []).slice(0, 8).map(r => ({ key: r.key, label: r.key, value: r.count }))} />}
            </div>
            <div className="sm:col-span-2">
              <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1">Security events by feature</p>
              {data.sections.threat_sources?.error ? <SectionError error={data.sections.threat_sources.error} /> :
                <BarList color="bg-[#eda100] dark:bg-[#c98500]" empty="No security events from this country."
                  rows={(data.sections.threat_sources?.data ?? []).map(r => ({ key: r.key, label: sourceLabel(r.key), value: r.count }))} />}
            </div>
          </div>
        </>
      )}
    </div>
  );
}
