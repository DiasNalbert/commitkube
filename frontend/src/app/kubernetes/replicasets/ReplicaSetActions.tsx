"use client";

import { useState } from "react";
import { apiFetch } from "@/lib/api";
import type { ResourceRow } from "@/app/components/k8s/status";

type Result = { namespace: string; name: string; outcome: string; message: string };

const desired = (r: ResourceRow) => Number(r.fields?.desired ?? "0");

/** Deletes the selected ReplicaSets. Old revisions (scaled to zero) are
 *  cleanup; one that runs pods takes them down with it, so those are only
 *  included when the person ticks the box that says so. */
export function DeleteReplicaSets({ rows, done }: { rows: ResourceRow[]; done: () => void }) {
  const [open, setOpen] = useState(false);
  const [allowRunning, setAllowRunning] = useState(false);
  const [busy, setBusy] = useState(false);
  const [results, setResults] = useState<Result[] | null>(null);
  const [error, setError] = useState("");

  const running = rows.filter(r => desired(r) > 0);
  const retired = rows.length - running.length;

  const submit = async () => {
    setBusy(true);
    setError("");
    const res = await apiFetch("/kubernetes/replicasets/delete", {
      method: "POST",
      body: JSON.stringify({ items: rows.map(r => ({ namespace: r.namespace, name: r.name })), allow_running: allowRunning }),
    });
    const body = await res.json().catch(() => ({}));
    setBusy(false);
    if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
    setResults(body.results ?? []);
  };

  const close = () => {
    const changed = results?.some(r => r.outcome === "deleted");
    setOpen(false); setResults(null); setAllowRunning(false); setError("");
    if (changed) done();
  };

  return (
    <>
      <button type="button" onClick={() => setOpen(true)} className="px-3 py-1.5 text-[13px] rounded"
        style={{ border: "1px solid rgba(248,113,113,.4)", color: "var(--red)" }}>
        Delete {rows.length}
      </button>
      {open && (
        <div className="fixed inset-0 z-[60] bg-black/50 flex items-start justify-center p-4 overflow-y-auto" onClick={close}>
          <div className="w-full max-w-2xl mt-16 p-5 flex flex-col gap-4" style={{ background: "var(--card)", border: "1px solid var(--rule)" }}
            onClick={e => e.stopPropagation()} role="dialog" aria-modal="true" aria-label="Delete ReplicaSets">
            <h2 className="m-0 text-base font-semibold">Delete {rows.length} ReplicaSet{rows.length === 1 ? "" : "s"}</h2>

            {!results ? (
              <>
                <ul className="m-0 pl-4 text-[13px] flex flex-col gap-1" style={{ color: "var(--t2)" }}>
                  {retired > 0 && <li>{retired} old revision{retired === 1 ? "" : "s"} scaled to zero: removed from the rollout history, so a rollback cannot go back to {retired === 1 ? "it" : "them"}. No pod is affected.</li>}
                  {running.length > 0 && (
                    <li style={{ color: "var(--gold)" }}>
                      {running.length} still run{running.length === 1 ? "s" : ""} pods. Deleting {running.length === 1 ? "it" : "them"} deletes those pods; a Deployment recreates its current revision (a restart), anything else stays gone.
                    </li>
                  )}
                </ul>
                <div className="max-h-56 overflow-y-auto text-[12px] font-mono" style={{ border: "1px solid var(--rule)" }}>
                  {rows.map(r => (
                    <div key={`${r.namespace}/${r.name}`} className="flex justify-between gap-3 px-3 py-1.5" style={{ borderTop: "1px solid var(--rule2)" }}>
                      <span className="truncate">{r.namespace}/{r.name}</span>
                      <span style={{ color: desired(r) > 0 ? "var(--gold)" : "var(--m2)" }}>{desired(r) > 0 ? `${desired(r)} running` : "retired"}</span>
                    </div>
                  ))}
                </div>
                {running.length > 0 && (
                  <label className="flex items-start gap-2 text-[13px]">
                    <input type="checkbox" checked={allowRunning} onChange={e => setAllowRunning(e.target.checked)} className="mt-0.5" />
                    <span>Also delete the {running.length} that run pods. Without this they are skipped and only the retired ones go.</span>
                  </label>
                )}
                {error && <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{error}</p>}
                <div className="flex gap-2 justify-end">
                  <button type="button" onClick={close} className="btn-secondary">Cancel</button>
                  <button type="button" disabled={busy} onClick={submit} className="px-3.5 py-1.5 rounded text-[13px] font-semibold disabled:opacity-50"
                    style={{ background: "var(--red)", color: "#1a0505" }}>
                    {busy ? "Deleting…" : allowRunning || running.length === 0 ? `Delete ${rows.length}` : `Delete ${retired} retired`}
                  </button>
                </div>
              </>
            ) : (
              <>
                <div className="max-h-72 overflow-y-auto text-[12.5px]" style={{ border: "1px solid var(--rule)" }}>
                  {results.map(r => (
                    <div key={`${r.namespace}/${r.name}`} className="grid gap-3 px-3 py-1.5" style={{ gridTemplateColumns: "70px minmax(0,1fr)", borderTop: "1px solid var(--rule2)" }}>
                      <span style={{ color: r.outcome === "deleted" ? "var(--green)" : r.outcome === "skipped" ? "var(--gold)" : "var(--red)" }}>{r.outcome}</span>
                      <span className="min-w-0"><span className="font-mono">{r.name}</span> <span style={{ color: "var(--m2)" }}>· {r.message}</span></span>
                    </div>
                  ))}
                </div>
                <div className="flex justify-end"><button type="button" onClick={close} className="btn-primary">Done</button></div>
              </>
            )}
          </div>
        </div>
      )}
    </>
  );
}

/** Scales one ReplicaSet -- or, when a Deployment owns it, the Deployment,
 *  since that is the count Kubernetes keeps. */
export function ScaleReplicaSet({ row, reload }: { row: ResourceRow; reload: () => void }) {
  const [open, setOpen] = useState(false);
  const [value, setValue] = useState(String(desired(row)));
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const viaDeployment = row.fields?.owner_kind === "Deployment" ? row.fields?.owner : "";

  const apply = async () => {
    setBusy(true);
    setMsg(null);
    const res = await apiFetch("/kubernetes/replicasets/scale", {
      method: "POST",
      body: JSON.stringify({ namespace: row.namespace, name: row.name, replicas: Number(value) }),
    });
    const body = await res.json().catch(() => ({}));
    setBusy(false);
    setMsg({ ok: res.ok, text: body.message ?? body.error ?? `Request failed (${res.status})` });
    if (res.ok) setTimeout(() => { setOpen(false); setMsg(null); reload(); }, 1500);
  };

  if (!open) {
    return <button type="button" onClick={() => setOpen(true)} className="text-xs p-0" style={{ color: "var(--green)" }}>Scale</button>;
  }
  return (
    <span className="inline-flex flex-col items-end gap-1">
      <span className="inline-flex items-center gap-2">
        <input type="number" min={0} max={100} value={value} onChange={e => setValue(e.target.value)}
          className="input-tech !w-16 text-xs py-0.5" aria-label="Replicas" />
        <button type="button" disabled={busy} onClick={apply} className="text-xs p-0 disabled:opacity-50" style={{ color: "var(--green)" }}>{busy ? "…" : "Apply"}</button>
        <button type="button" onClick={() => { setOpen(false); setMsg(null); }} className="text-xs p-0" style={{ color: "var(--m2)" }}>Cancel</button>
      </span>
      {viaDeployment && !msg && <span className="text-[11px] whitespace-normal max-w-[260px] text-right" style={{ color: "var(--gold)" }}>Scales Deployment {viaDeployment}: it owns this ReplicaSet and would undo a direct change.</span>}
      {msg && <span className="text-[11px] whitespace-normal max-w-[260px] text-right" style={{ color: msg.ok ? "var(--green)" : "var(--red)" }}>{msg.text}</span>}
    </span>
  );
}
