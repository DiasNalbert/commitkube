"use client";

import { useState } from "react";
import { apiFetch } from "@/lib/api";

/** Importing a cluster. The token asked for here is the collector identity:
 *  the credential the pollers use, which needs read across the cluster and
 *  nothing more. The user's own access is decided later, by the RBAC bound to
 *  their group. */
export default function AddCluster({ onAdded }: { onAdded: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [apiServer, setApiServer] = useState("");
  const [caCert, setCaCert] = useState("");
  const [token, setToken] = useState("");
  const [insecure, setInsecure] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const submit = async () => {
    setError(""); setBusy(true);
    try {
      const res = await apiFetch("/clusters", {
        method: "POST",
        body: JSON.stringify({
          name, api_server: apiServer, ca_cert: caCert, token, insecure_tls: insecure,
        }),
      });
      const body = await res.json().catch(() => ({}));
      if (!res.ok) { setError(body.error ?? "could not import the cluster"); return; }
      setOpen(false);
      setName(""); setApiServer(""); setCaCert(""); setToken(""); setInsecure(false);
      onAdded();
    } finally {
      setBusy(false);
    }
  };

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition">
        Import cluster
      </button>
    );
  }

  return (
    <div className="glass-card p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold">Import cluster</h3>
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
          The token is that cluster’s <strong>collector identity</strong> — the credential the pollers use.
          Create it there with the same <code>rbac.yaml</code>: read access and nothing more.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 gap-2">
        <input value={name} onChange={e => setName(e.target.value)} placeholder="name (e.g. oke-prod)"
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
        <input value={apiServer} onChange={e => setApiServer(e.target.value)} placeholder="https://1.2.3.4:6443"
          className="px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
      </div>

      <textarea value={token} onChange={e => setToken(e.target.value)} rows={2} placeholder="ServiceAccount token"
        className="w-full px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />

      <textarea value={caCert} onChange={e => setCaCert(e.target.value)} rows={3}
        placeholder="-----BEGIN CERTIFICATE----- (cluster CA)"
        disabled={insecure}
        className="w-full px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50 disabled:opacity-40" />

      <label className="flex items-start gap-3 text-sm cursor-pointer">
        <input type="checkbox" checked={insecure} onChange={e => setInsecure(e.target.checked)}
          className="mt-0.5 accent-amber-500" />
        <span>
          Skip certificate verification
          <span className="block text-xs text-amber-600 dark:text-amber-400">
            The collector token would then be sent to whatever answers at that address. Testing only.
          </span>
        </span>
      </label>

      {error && <p className="text-xs text-red-500 dark:text-red-400">{error}</p>}

      <div className="flex gap-2">
        <button onClick={submit} disabled={busy || !name || !apiServer || !token}
          className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-40">
          {busy ? "Testing…" : "Import"}
        </button>
        <button onClick={() => { setOpen(false); setError(""); }}
          className="px-3 py-1.5 text-sm rounded-lg text-zinc-500 hover:text-zinc-300 transition">
          Cancel
        </button>
      </div>
      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        CommitKube lists namespaces with the token before storing it, so a credential that does not work is
        refused now rather than as a blank page next week.
      </p>
    </div>
  );
}
