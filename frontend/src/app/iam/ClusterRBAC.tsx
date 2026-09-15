"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface ClusterRow { id: number; name: string; impersonate: boolean; can_manage_rbac: boolean }
interface Group { id: number; name: string }
const ALL_NAMESPACES = "*";

/** Impersonation only decides anything if the cluster holds RBAC naming the
 *  identities being impersonated. This writes that, or hands over the YAML to
 *  apply by hand -- the preview needs no privilege, and is shown before
 *  anything is written, because a product that silently creates RoleBindings
 *  is a product nobody should install. */
export default function ClusterRBAC({ groups, clusters, namespaces, onChanged }: {
  groups: Group[];
  clusters: ClusterRow[];
  namespaces: string[];
  onChanged: () => void;
}) {
  const [derivedFrom, setDerivedFrom] = useState<string[]>([]);
  const [clusterID, setClusterID] = useState<number | null>(null);
  const [group, setGroup] = useState("");
  const [namespace, setNamespace] = useState("");

  const [manifest, setManifest] = useState("");
  const [impersonator, setImpersonator] = useState("");
  const [identity, setIdentity] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    if (clusterID === null && clusters.length > 0) setClusterID(clusters[0].id);
  }, [clusters, clusterID]);

  const cluster = clusters.find(c => c.id === clusterID);

  const preview = useCallback(async () => {
    setError(""); setMessage("");
    if (!group || !namespace) { setError("escolha o grupo e o namespace"); return; }
    const qs = new URLSearchParams({ group, namespace }).toString();
    const res = await apiFetch(`/rbac/preview?${qs}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setError(body.error ?? "não foi possível gerar o manifesto"); return; }
    setManifest(body.manifest ?? "");
    setImpersonator(body.impersonator ?? "");
    setIdentity(body.impersonation_group ?? "");
    setDerivedFrom(body.derived_from ?? []);
  }, [group, namespace]);

  const apply = async () => {
    setError(""); setMessage("");
    const res = await apiFetch("/rbac/apply", {
      method: "POST",
      body: JSON.stringify({ cluster_id: clusterID, group, namespace }),
    });
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setError(body.error ?? "não foi possível aplicar"); return; }
    setMessage(body.message ?? "aplicado");
  };

  const toggle = async (field: "impersonate" | "can_manage_rbac", value: boolean) => {
    setError("");
    const res = await apiFetch(`/clusters/${clusterID}/flags`, {
      method: "PUT",
      body: JSON.stringify({ [field]: value }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setError(body.error ?? "não foi possível alterar o cluster");
      return;
    }
    onChanged();
  };

  return (
    <section className="glass-card p-4 space-y-4">
      <div>
        <h2 className="text-sm font-semibold">RBAC do cluster</h2>
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1">
          O escopo acima decide o que o CommitKube mostra. Isto decide o que o <strong>cluster</strong> deixa
          o grupo fazer quando uma escrita sai com a identidade da pessoa.
        </p>
      </div>

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2">
        <select value={clusterID ?? ""} onChange={e => setClusterID(Number(e.target.value))}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
          {clusters.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <select value={group} onChange={e => setGroup(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
          <option value="">Grupo…</option>
          {groups.map(g => <option key={g.id} value={g.name}>{g.name}</option>)}
        </select>
        <select value={namespace} onChange={e => setNamespace(e.target.value)}
          className="px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
          <option value="">Namespace…</option>
          <option value={ALL_NAMESPACES}>Todos os namespaces</option>
          {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
        </select>
      </div>

      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        As regras vêm das permissões que o grupo já tem acima — você não escolhe duas vezes. Conceder
        <span className="font-mono"> k8s.scale </span> aqui em cima e esquecer o binding aqui embaixo é
        exatamente como as duas metades passam a discordar.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <button onClick={preview}
          className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition">
          Gerar manifesto
        </button>
        <button onClick={apply} disabled={!cluster?.can_manage_rbac || !manifest}
          className="px-3 py-1.5 text-sm rounded-lg border border-amber-500/40 text-amber-500 hover:bg-amber-500/10 transition disabled:opacity-40"
          title={cluster?.can_manage_rbac ? "" : "este cluster não permite que o CommitKube escreva RBAC"}>
          Aplicar no cluster
        </button>
        {!cluster?.can_manage_rbac && (
          <span className="text-xs text-zinc-500">aplique você mesmo, ou libere abaixo</span>
        )}
      </div>

      {error && <p className="text-xs text-red-500 dark:text-red-400">{error}</p>}
      {message && <p className="text-xs text-brand-green">{message}</p>}

      {manifest && (
        <div className="space-y-3">
          {identity && (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Identidade personificada: <span className="font-mono text-brand-green">{identity}</span>
            </p>
          )}
          {derivedFrom.length > 0 && (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Derivado de: {derivedFrom.map(p => <span key={p} className="font-mono text-brand-green mr-2">{p}</span>)}
            </p>
          )}
          {(derivedFrom.includes("k8s.secrets.read") || derivedFrom.includes("k8s.secrets.show")) && (
            <p className="text-xs text-amber-600 dark:text-amber-400">
              O Kubernetes não tem “ler o nome sem o valor”: <code>list</code> em Secrets devolve os objetos
              inteiros. As duas permissões de Secret viram a mesma regra no cluster, e a diferença entre ver a
              chave e ver o valor é o CommitKube que mascara — não o cluster.
            </p>
          )}
          <pre className="text-xs font-mono leading-relaxed whitespace-pre overflow-x-auto p-3 rounded-lg bg-zinc-100 dark:bg-zinc-900 border border-[var(--card-border)]">
{manifest}
          </pre>
          <details>
            <summary className="text-xs text-zinc-500 dark:text-zinc-400 cursor-pointer">
              ClusterRole que a credencial do CommitKube precisa (aplicar uma vez)
            </summary>
            <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
              O <code>resourceNames</code> não é detalhe: sem ele, quem personifica pode virar qualquer usuário do
              cluster, inclusive um cluster-admin.
            </p>
            <pre className="mt-2 text-xs font-mono leading-relaxed whitespace-pre overflow-x-auto p-3 rounded-lg bg-zinc-100 dark:bg-zinc-900 border border-[var(--card-border)]">
{impersonator}
            </pre>
          </details>
        </div>
      )}

      {cluster && (
        <div className="pt-3 border-t border-[var(--card-border)] space-y-3">
          <label className="flex items-start gap-3 text-sm cursor-pointer">
            <input type="checkbox" checked={cluster.impersonate} className="mt-0.5 accent-brand-green"
              onChange={e => toggle("impersonate", e.target.checked)} />
            <span>
              Deixar o cluster decidir
              <span className="block text-xs text-zinc-500 dark:text-zinc-400">
                Sem isto, o CommitKube usa a própria credencial e decide sozinho. Com isto, cada pessoa fala
                com o cluster em nome dela. Marque depois de aplicar o manifesto acima.
              </span>
            </span>
          </label>

          <label className="flex items-start gap-3 text-sm cursor-pointer">
            <input type="checkbox" checked={cluster.can_manage_rbac} className="mt-0.5 accent-amber-500"
              onChange={e => toggle("can_manage_rbac", e.target.checked)} />
            <span>
              Deixar o CommitKube aplicar sozinho
              <span className="block text-xs text-zinc-500 dark:text-zinc-400">
                Sem isto, você aplica o manifesto com <code>kubectl</code>. Com isto, o botão acima faz por você.
              </span>
            </span>
          </label>
        </div>
      )}
    </section>
  );
}
