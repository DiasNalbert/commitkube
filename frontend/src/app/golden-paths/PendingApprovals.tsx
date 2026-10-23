"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Pending = {
  name: string; requested_at: string; requested_by: string; golden_path: string;
  inputs: Record<string, string> | null; project_key: string;
};

/** Requests waiting for someone to say yes. Approving creates the
 *  repository then, checked against its golden path as it stands now. */
export default function PendingApprovals() {
  const [rows, setRows] = useState<Pending[] | null>(null);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const res = await apiFetch("/repositories/pending");
    if (!res.ok) { setRows([]); return; }
    const data = await res.json().catch(() => []);
    setRows(Array.isArray(data) ? data : []);
  }, []);
  useEffect(() => { load(); }, [load]);

  const act = async (name: string, action: "approve" | "reject") => {
    let body = "{}";
    if (action === "reject") {
      const reason = prompt(`Why is ${name} being turned down? The requester will want to know.`);
      if (reason === null) return;
      body = JSON.stringify({ reason });
    }
    setBusy(name);
    setError("");
    const res = await apiFetch(`/repositories/${encodeURIComponent(name)}/${action}`, { method: "POST", body });
    const out = await res.json().catch(() => ({}));
    setBusy("");
    if (!res.ok) { setError(`${name}: ${out.error ?? res.status}`); return; }
    load();
  };

  if (!rows || rows.length === 0) return null;

  return (
    <section className="flex flex-col gap-1.5">
      <h2 className="m-0 mb-2 text-lg font-semibold">Waiting for approval <span className="font-mono text-sm" style={{ color: "var(--gold)" }}>{rows.length}</span></h2>
      {error && <p className="m-0 text-xs whitespace-pre-wrap" style={{ color: "var(--red)" }}>{error}</p>}
      {rows.map(r => (
        <div key={r.name} className="grid gap-4 items-center py-3" style={{ gridTemplateColumns: "minmax(0,1fr) auto", borderTop: "1px solid var(--rule2)" }}>
          <div className="flex flex-col gap-1 min-w-0">
            <span><span className="font-mono">{r.name}</span> <span style={{ color: "var(--t3)" }}>on {r.golden_path || "a golden path"}{r.project_key ? ` · ${r.project_key}` : ""}</span></span>
            <span className="text-[12.5px]" style={{ color: "var(--m2)" }}>
              {r.requested_by || "someone"} · {new Date(r.requested_at).toLocaleString("en-US")}
              {r.inputs && Object.keys(r.inputs).length > 0 && <> · {Object.entries(r.inputs).map(([k, v]) => `${k}=${v}`).join(", ")}</>}
            </span>
          </div>
          <div className="flex gap-2">
            <button type="button" disabled={busy === r.name} onClick={() => act(r.name, "reject")} className="btn-secondary disabled:opacity-50">Reject</button>
            <button type="button" disabled={busy === r.name} onClick={() => act(r.name, "approve")} className="btn-primary disabled:opacity-50">{busy === r.name ? "Working…" : "Approve and create"}</button>
          </div>
        </div>
      ))}
    </section>
  );
}
