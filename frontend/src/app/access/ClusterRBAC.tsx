"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface ClusterRow { id: number; name: string; impersonate: boolean; can_manage_rbac: boolean }
interface Group { id: number; name: string }
interface Template { name: string; description: string }

/** Impersonation only decides anything if the cluster holds RBAC naming the
 *  identities being impersonated. This writes that, or hands over the YAML to
 *  apply by hand -- the preview needs no privilege, and is shown before
 *  anything is written, because a product that silently creates RoleBindings
 *  is a product nobody should install. */
export default function ClusterRBAC({ groups, clusters, onChanged }: {
  groups: Group[];
  clusters: ClusterRow[];
  onChanged: () => void;
}) {
  const [templates, setTemplates] = useState<Template[]>([]);
  const [clusterID, setClusterID] = useState<number | null>(null);
  const [group, setGroup] = useState("");
  const [namespace, setNamespace] = useState("");
  const [template, setTemplate] = useState("viewer");

  const [manifest, setManifest] = useState("");
  const [impersonator, setImpersonator] = useState("");
  const [identity, setIdentity] = useState("");
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  useEffect(() => {
    apiFetch("/rbac/templates").then(r => r.json()).then(b => setTemplates(b.templates ?? [])).catch(() => {});
  }, []);
  useEffect(() => {
    if (clusterID === null && clusters.length > 0) setClusterID(clusters[0].id);
  }, [clusters, clusterID]);

  const cluster = clusters.find(c => c.id === clusterID);

  const preview = useCallback(async () => {
    setError(""); setMessage("");
    if (!group || !namespace) { setError("escolha o grupo e o namespace"); return; }
    const qs = new URLSearchParams({ group, namespace, template }).toString();
    const res = await apiFetch(`/rbac/preview?${qs}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setError(body.error ?? "não foi possível gerar o manifesto"); return; }
    setManifest(body.manifest ?? "");
    setImpersonator(body.impersonator ?? "");
    setIdentity(body.impersonation_group ?? "");
  }, [group, namespace, template]);

  const apply = async () => {
    setError(""); setMessage("");
    const res = await apiFetch("/rbac/apply", {
      method: "POST",
      body: JSON.stringify({ cluster_id: clusterID, group, namespace, template }),
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
        <input value={namespace} onChange={e => setNamespace(e.target.value)} placeholder="namespace"
          className="px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
        <select value={template} onChange={e => setTemplate(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
          {templates.map(t => <option key={t.name} value={t.name}>{t.name}</option>)}
        </select>
      </div>

      {templates.find(t => t.name === template) && (
        <p className="text-xs text-zinc-500 dark:text-zinc-400">
          {templates.find(t => t.name === template)!.description}
        </p>
      )}

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
        <div className="pt-3 border-t border-[var(--card-border)] space-y-2">
          <label className="flex items-start gap-3 text-sm cursor-pointer">
            <input type="checkbox" checked={cluster.impersonate} className="mt-0.5 accent-brand-green"
              onChange={e => toggle("impersonate", e.target.checked)} />
            <span>
              Falar com o cluster como a pessoa que pediu
              <span className="block text-xs text-zinc-500 dark:text-zinc-400">
                Listar, ler manifesto, ver log, revelar Secret, deletar, reiniciar e escalar passam a ser
                decididos pelo RBAC de quem pediu, e o audit log do cluster passa a ter nome de gente.
                <strong className="block mt-1 text-amber-600 dark:text-amber-400">
                  Ligue só depois que os RoleBindings existirem: sem binding, as páginas ficam vazias — por
                  política, não por defeito.
                </strong>
                <span className="block mt-1">
                  Não cobre Triage, Service Map nem histórico: esses dados foram colhidos pelo coletor antes da
                  requisição existir, e ali o filtro de namespace do CommitKube é a única cerca.
                </span>
              </span>
            </span>
          </label>
          <label className="flex items-start gap-3 text-sm cursor-pointer">
            <input type="checkbox" checked={cluster.can_manage_rbac} className="mt-0.5 accent-amber-500"
              onChange={e => toggle("can_manage_rbac", e.target.checked)} />
            <span>
              Permitir que o CommitKube escreva RBAC neste cluster
              <span className="block text-xs text-amber-600 dark:text-amber-400">
                É o privilégio mais forte que o produto pode ter: quem escreve RoleBinding escreve um para si.
              </span>
            </span>
          </label>
        </div>
      )}
    </section>
  );
}
