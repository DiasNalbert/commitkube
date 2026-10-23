"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Step = { title: string; command: string };
type Remediation = {
  rule: string; kind: string; namespace: string; name: string;
  steps: Step[]; verified: boolean; managed_by?: string; warnings: string[]; guidance?: string; error?: string;
};

function CopyButton({ text }: { text: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      onClick={async () => {
        try { await navigator.clipboard.writeText(text); setDone(true); setTimeout(() => setDone(false), 1500); } catch { /* clipboard blocked */ }
      }}
      className="text-[11px] px-2 py-0.5 rounded shrink-0"
      style={{ border: "1px solid var(--line2)", color: done ? "var(--green)" : "var(--t3)" }}
    >
      {done ? "Copied" : "Copy"}
    </button>
  );
}

/** The fix for one failing resource, generated from the object as it is in
 *  the cluster now. Nothing is applied from here: the commands are for a
 *  person to read, understand and run. */
export default function RemediationPanel({ rule, kind, namespace, name }: { rule: string; kind: string; namespace: string; name: string }) {
  const [r, setR] = useState<Remediation | null>(null);

  useEffect(() => {
    let cancelled = false;
    const qs = new URLSearchParams({ rule, kind, namespace, name });
    apiFetch(`/security/posture/remediation?${qs}`)
      .then(async res => {
        const body = await res.json().catch(() => ({}));
        if (!cancelled) setR(res.ok ? body : { ...body, steps: [], warnings: [], verified: false, error: body.error ?? `Request failed (${res.status})` });
      })
      .catch(() => { if (!cancelled) setR({ rule, kind, namespace, name, steps: [], warnings: [], verified: false, error: "could not reach the API" }); });
    return () => { cancelled = true; };
  }, [rule, kind, namespace, name]);

  if (!r) return <p className="m-0 text-xs py-2" style={{ color: "var(--m2)" }}>Reading {kind} {name} from the cluster…</p>;
  if (r.error) return <p className="m-0 text-xs py-2" style={{ color: "var(--red)" }}>{r.error}</p>;

  return (
    <div className="flex flex-col gap-3 py-3 px-3" style={{ background: "var(--panel)" }}>
      <div className="flex items-center gap-3 flex-wrap text-xs">
        {r.steps.length > 0 && (
          <span style={{ color: r.verified ? "var(--green)" : "var(--gold)" }}>
            {r.verified ? "✓ Checked: the rule passes after this change" : "Partly automatic: read the notes below"}
          </span>
        )}
        {r.managed_by && <span style={{ color: "var(--gold)" }}>Managed by {r.managed_by}</span>}
      </div>

      {r.warnings.length > 0 && (
        <ul className="m-0 pl-4 flex flex-col gap-1 text-[12.5px]" style={{ color: "var(--t2)" }}>
          {r.warnings.map(w => <li key={w}>{w}</li>)}
        </ul>
      )}

      {r.steps.map((s, i) => (
        <div key={i} className="flex flex-col gap-1">
          <div className="flex items-center justify-between gap-3">
            <span className="text-[12.5px]" style={{ color: "var(--t3)" }}>{i + 1}. {s.title}</span>
            <CopyButton text={s.command} />
          </div>
          <pre className="m-0 p-3 font-mono text-[11px] leading-[1.6] whitespace-pre-wrap break-all" style={{ background: "var(--side)", border: "1px solid var(--rule)", color: "var(--t2)" }}>{s.command}</pre>
        </div>
      ))}

      {r.guidance && (
        <pre className="m-0 p-3 font-sans text-[12.5px] leading-[1.6] whitespace-pre-wrap" style={{ border: "1px solid var(--rule)", color: "var(--t2)" }}>{r.guidance}</pre>
      )}
    </div>
  );
}
