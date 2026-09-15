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
      if (!res.ok) { setError(body.error ?? "não foi possível importar o cluster"); return; }
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
        Importar cluster
      </button>
    );
  }

  return (
    <div className="glass-card p-4 space-y-3">
      <div>
        <h3 className="text-sm font-semibold">Importar cluster</h3>
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
          O token é o da <strong>identidade coletora</strong> daquele cluster — a credencial que os coletores
          usam. Crie-a lá com o mesmo <code>rbac.yaml</code>: precisa de leitura e nada além.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 gap-2">
        <input value={name} onChange={e => setName(e.target.value)} placeholder="nome (ex.: oke-prod)"
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
        <input value={apiServer} onChange={e => setApiServer(e.target.value)} placeholder="https://1.2.3.4:6443"
          className="px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
      </div>

      <textarea value={token} onChange={e => setToken(e.target.value)} rows={2} placeholder="token da ServiceAccount"
        className="w-full px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />

      <textarea value={caCert} onChange={e => setCaCert(e.target.value)} rows={3}
        placeholder="-----BEGIN CERTIFICATE----- (CA do cluster)"
        disabled={insecure}
        className="w-full px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50 disabled:opacity-40" />

      <label className="flex items-start gap-3 text-sm cursor-pointer">
        <input type="checkbox" checked={insecure} onChange={e => setInsecure(e.target.checked)}
          className="mt-0.5 accent-amber-500" />
        <span>
          Não verificar o certificado
          <span className="block text-xs text-amber-600 dark:text-amber-400">
            O token da coletora passa a trafegar para qualquer servidor que atenda naquele endereço. Use só
            para testar.
          </span>
        </span>
      </label>

      {error && <p className="text-xs text-red-500 dark:text-red-400">{error}</p>}

      <div className="flex gap-2">
        <button onClick={submit} disabled={busy || !name || !apiServer || !token}
          className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-40">
          {busy ? "Testando…" : "Importar"}
        </button>
        <button onClick={() => { setOpen(false); setError(""); }}
          className="px-3 py-1.5 text-sm rounded-lg text-zinc-500 hover:text-zinc-300 transition">
          Cancelar
        </button>
      </div>
      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        O CommitKube lista os namespaces com esse token antes de guardar: credencial que não funciona é
        recusada agora, e não numa página em branco daqui a uma semana.
      </p>
    </div>
  );
}
