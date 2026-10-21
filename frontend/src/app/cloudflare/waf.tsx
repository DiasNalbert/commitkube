"use client";

import { Fragment, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { Card, CopyButton, SectionError, fmtFull, relativeTime } from "./shared";

interface Rule {
  id: string; action: string; expression: string; description: string; last_updated: string;
  enabled: boolean; hits: number; ruleset_name?: string; ref?: string;
  ratelimit?: { characteristics: string[]; period: number; requests_per_period: number; mitigation_timeout: number };
}
interface Phase { rules?: Rule[]; error?: string; ruleset_id?: string }
interface Suggestion {
  id: string; priority: "high" | "medium" | "low"; title: string; why: string; evidence: string[] | null;
  phase: "custom" | "ratelimit" | "managed"; action?: string; expression?: string;
  ratelimit?: { characteristics: string[]; period: number; requests_per_period: number; mitigation_timeout: number };
  caveat?: string; covered_by?: string[] | null;
}
interface Payload {
  phases: { custom: Phase; ratelimit: Phase; managed: Phase };
  suggestions: Suggestion[]; suggestions_error?: string; hits_error?: string; plan: string; since: string; until: string;
}

const PRIORITY: Record<string, string> = {
  high: "text-red-500 dark:text-red-400 border-red-500/30 bg-red-500/10",
  medium: "text-amber-600 dark:text-amber-400 border-amber-500/30 bg-amber-500/10",
  low: "text-zinc-500 dark:text-zinc-400 border-zinc-500/30 bg-zinc-500/10",
};
const PHASE_LABEL = { custom: "Custom rule", ratelimit: "Rate limiting rule", managed: "Managed rules" };
const DASH_PAGE = { custom: "custom-rules", ratelimit: "rate-limiting-rules", managed: "managed-rules" };

const ACTION_TONE = (a: string) =>
  ["block", "drop"].includes(a) ? "text-red-500 dark:text-red-400"
    : a.includes("challenge") ? "text-amber-600 dark:text-amber-400"
      : "text-zinc-500 dark:text-zinc-400";

function Expr({ text }: { text: string }) {
  return (
    <div className="flex items-start gap-2 rounded border border-[var(--card-border)] bg-zinc-500/5 p-2">
      <pre className="flex-1 font-mono text-[11px] whitespace-pre-wrap break-all">{text}</pre>
      <CopyButton text={text} />
    </div>
  );
}

function RulesTable({ phase, rules, showRate }: { phase: string; rules: Rule[]; showRate?: boolean }) {
  const [open, setOpen] = useState<string | null>(null);
  if (rules.length === 0) return <p className="text-xs text-zinc-500 dark:text-zinc-400">No {phase} on this zone.</p>;
  return (
    <div className="overflow-x-auto">
      <table className="w-full text-xs">
        <thead>
          <tr className="text-left text-zinc-500 dark:text-zinc-400 border-b border-[var(--rule)]">
            <th className="w-5" /><th className="py-1.5 pr-3 font-medium">Rule</th><th className="pr-3 font-medium">Action</th>
            {showRate && <th className="pr-3 font-medium">Limit</th>}
            <th className="pr-3 font-medium">Status</th><th className="pr-3 font-medium text-right">Events in range</th>
            <th className="pr-3 font-medium">Updated</th>
          </tr>
        </thead>
        <tbody>
          {rules.map(r => {
            const isOpen = open === r.id;
            return (
              <Fragment key={r.id}>
                <tr className="border-b border-[var(--rule)] cursor-pointer hover:bg-[var(--color-surface-hover)]" onClick={() => setOpen(isOpen ? null : r.id)}>
                  <td className="pl-1 pr-1 text-zinc-500"><span className={`inline-block transition-transform ${isOpen ? "rotate-90" : ""}`}>›</span></td>
                  <td className="py-1.5 pr-3 max-w-0 w-full">
                    <span className="block truncate font-medium">{r.ruleset_name || r.description || <span className="font-mono">{r.id}</span>}</span>
                    {!isOpen && r.expression && <span className="block truncate font-mono text-[11px] text-zinc-500 dark:text-zinc-400">{r.expression}</span>}
                  </td>
                  <td className={`pr-3 whitespace-nowrap font-medium ${ACTION_TONE(r.action)}`}>{r.action}</td>
                  {showRate && (
                    <td className="pr-3 whitespace-nowrap tabular-nums">
                      {r.ratelimit ? `${r.ratelimit.requests_per_period} / ${r.ratelimit.period}s` : "—"}
                    </td>
                  )}
                  <td className="pr-3 whitespace-nowrap">
                    {r.enabled ? <span className="text-brand-green">● Enabled</span> : <span className="text-zinc-500">○ Disabled</span>}
                  </td>
                  <td className={`pr-3 text-right tabular-nums ${r.hits ? "" : "text-zinc-500"}`}>{fmtFull(r.hits)}</td>
                  <td className="pr-3 whitespace-nowrap text-zinc-500 dark:text-zinc-400">{r.last_updated ? relativeTime(r.last_updated) : ""}</td>
                </tr>
                {isOpen && (
                  <tr className="border-b border-[var(--rule)]">
                    <td />
                    <td colSpan={showRate ? 6 : 5} className="py-2 pr-3 space-y-2">
                      {r.expression && <Expr text={r.expression} />}
                      {r.ratelimit && (
                        <p className="text-zinc-500 dark:text-zinc-400">
                          Counted per {r.ratelimit.characteristics.join(" + ")}; {r.ratelimit.requests_per_period} requests per {r.ratelimit.period}s,
                          then {r.action} for {r.ratelimit.mitigation_timeout}s.
                        </p>
                      )}
                      <p className="font-mono text-[11px] text-zinc-500">id {r.id}</p>
                    </td>
                  </tr>
                )}
              </Fragment>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

export default function WAFTab({ zoneRefId, range, accountId, zoneName }: { zoneRefId: number; range: string; accountId: string; zoneName: string }) {
  const [data, setData] = useState<Payload | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    let live = true;
    setLoading(true);
    (async () => {
      try {
        const res = await apiFetch(`/cloudflare/zones/${zoneRefId}/waf?range=${range}`);
        const body = await res.json().catch(() => ({}));
        if (!live) return;
        if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
        setError(""); setData(body);
      } catch (e) {
        if (live) setError(e instanceof Error ? e.message : "Could not reach the API");
      } finally { if (live) setLoading(false); }
    })();
    return () => { live = false; };
  }, [zoneRefId, range]);

  const dash = (phase: keyof typeof DASH_PAGE) =>
    `https://dash.cloudflare.com/${accountId}/${zoneName}/security/waf/${DASH_PAGE[phase]}`;

  if (error) return <div className="glass-card p-3 text-sm text-red-500 dark:text-red-400 break-words">{error}</div>;
  if (!data) return <p className="text-sm text-zinc-500">{loading ? "Reading the zone's rules…" : ""}</p>;

  const counts = { high: 0, medium: 0, low: 0 };
  data.suggestions.forEach(s => { counts[s.priority]++; });

  return (
    <div className="space-y-2">
      <Card title="Suggested rules" right={
        <span className="text-xs text-zinc-500 dark:text-zinc-400">
          {counts.high} high · {counts.medium} medium · {counts.low} low
        </span>
      }>
        <p className="text-xs text-zinc-500 dark:text-zinc-400 -mt-2 mb-3 max-w-4xl">
          Worked out from this zone&apos;s traffic in the selected range, leaving out what the enabled rules already cover.
          Nothing is changed in Cloudflare from here: copy the expression into a new rule in the dashboard, and read the caveat first.
        </p>
        {data.suggestions_error && <SectionError error={data.suggestions_error} />}
        {data.suggestions.length === 0 && !data.suggestions_error && (
          <p className="text-xs text-brand-green">Nothing to suggest: the traffic in this range is covered by the rules you have.</p>
        )}
        <ul className="space-y-3">
          {data.suggestions.map(s => (
            <li key={s.id} className="rounded-lg border border-[var(--card-border)] p-3 space-y-2">
              <div className="flex flex-wrap items-start justify-between gap-2">
                <div className="flex items-start gap-2 min-w-0">
                  <span className={`text-[10px] font-semibold uppercase tracking-wide px-1.5 py-0.5 rounded border shrink-0 ${PRIORITY[s.priority]}`}>{s.priority}</span>
                  <div className="min-w-0">
                    <p className="text-sm font-medium">{s.title}</p>
                    <p className="text-xs text-zinc-500 dark:text-zinc-400">
                      {PHASE_LABEL[s.phase]}{s.action ? <> · action <span className={`font-medium ${ACTION_TONE(s.action)}`}>{s.action}</span></> : null}
                    </p>
                  </div>
                </div>
                <a href={dash(s.phase)} target="_blank" rel="noreferrer" className="text-xs text-brand-green hover:underline shrink-0">Open in Cloudflare ↗</a>
              </div>
              <p className="text-xs">{s.why}</p>
              {s.evidence && s.evidence.length > 0 && (
                <ul className="text-xs text-zinc-500 dark:text-zinc-400 list-disc pl-5 space-y-0.5">
                  {s.evidence.slice(0, 8).map(e => <li key={e} className="break-all">{e}</li>)}
                  {s.evidence.length > 8 && <li>and {s.evidence.length - 8} more</li>}
                </ul>
              )}
              {s.expression && <Expr text={s.expression} />}
              {s.ratelimit && (
                <p className="text-xs">
                  Count per <span className="font-mono">{s.ratelimit.characteristics.join(" + ")}</span>: when it exceeds{" "}
                  <span className="font-medium tabular-nums">{s.ratelimit.requests_per_period} requests in {s.ratelimit.period} seconds</span>,{" "}
                  {s.action ?? "block"} for {s.ratelimit.mitigation_timeout} seconds.
                </p>
              )}
              {s.covered_by && s.covered_by.length > 0 && (
                <p className="text-xs text-zinc-500 dark:text-zinc-400">Already covered, so left out: {s.covered_by.join(", ")}.</p>
              )}
              {s.caveat && <p className="text-xs text-amber-600 dark:text-amber-400">Before deploying: {s.caveat}</p>}
            </li>
          ))}
        </ul>
      </Card>

      {data.hits_error && <p className="text-xs text-zinc-500">Event counts per rule are unavailable: {data.hits_error}</p>}

      <Card title="Custom rules" right={<a href={dash("custom")} target="_blank" rel="noreferrer" className="text-xs text-brand-green hover:underline">Open in Cloudflare ↗</a>}>
        {data.phases.custom.error ? <SectionError error={data.phases.custom.error} /> : <RulesTable phase="custom rules" rules={data.phases.custom.rules ?? []} />}
      </Card>
      <Card title="Rate limiting rules" right={<a href={dash("ratelimit")} target="_blank" rel="noreferrer" className="text-xs text-brand-green hover:underline">Open in Cloudflare ↗</a>}>
        {data.phases.ratelimit.error ? <SectionError error={data.phases.ratelimit.error} /> : <RulesTable phase="rate limiting rules" rules={data.phases.ratelimit.rules ?? []} showRate />}
      </Card>
      <Card title="Managed rulesets" right={<a href={dash("managed")} target="_blank" rel="noreferrer" className="text-xs text-brand-green hover:underline">Open in Cloudflare ↗</a>}>
        {data.phases.managed.error ? <SectionError error={data.phases.managed.error} /> : (
          <>
            <RulesTable phase="managed rulesets deployed" rules={data.phases.managed.rules ?? []} />
            {data.plan.toLowerCase().includes("free") && (
              <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-2">The Free plan runs Cloudflare&apos;s Free Managed Ruleset automatically; it may not be listed here.</p>
            )}
          </>
        )}
      </Card>
    </div>
  );
}
