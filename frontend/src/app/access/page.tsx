"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import ClusterRBAC from "./ClusterRBAC";

interface User { id: number; email: string; role: string; is_active: boolean }
interface Group { id: number; name: string; description: string }
interface Grant { id: number; subject_type: string; subject_id: number; permission: string }
interface Scope { id: number; subject_type: string; subject_id: number; cluster_id: number; namespace: string }
interface ClusterRow { id: number; name: string; impersonate: boolean; can_manage_rbac: boolean }

type SubjectType = "user" | "group";

/** What each permission actually lets someone do, in the words a person
 *  granting it would use. A permission list without this is a list of strings
 *  nobody can safely reason about. */
const DESCRIPTIONS: Record<string, string> = {
  "k8s.read": "Ver pods, workloads, nodes, namespaces e manifestos",
  "k8s.logs.read": "Ler log de pod — log costuma conter credencial",
  "k8s.secrets.read": "Listar nomes e chaves de Secrets (sem os valores)",
  "k8s.secrets.show": "Revelar o valor de um Secret",
  "k8s.pod.delete": "Deletar e reiniciar pods",
  "k8s.scale": "Escalar workloads",
  "cluster.manage": "Importar e remover clusters — vê todos os namespaces",
  "scm.read": "Ver repositórios, branches, commits e pipelines",
  "scm.write": "Criar, importar, editar e excluir repositórios",
  "scm.approve": "Aprovar repositórios",
  "template.read": "Ver templates e golden paths",
  "template.write": "Criar e editar templates e golden paths",
  "security.read": "Ver os achados de segurança",
  "security.scan": "Disparar um scan manualmente",
  "settings.read": "Ver configurações, credenciais de registry e notificações",
  "settings.write": "Alterar configurações e credenciais",
  "notify.write": "Criar e editar notificações e webhooks",
  "user.manage": "Gerir usuários, grupos e estas permissões",
  "audit.read": "Ler o log de auditoria",
};

export default function Page() {
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [clusters, setClusters] = useState<ClusterRow[]>([]);
  const [catalog, setCatalog] = useState<string[]>([]);
  const [roles, setRoles] = useState<Record<string, string[]>>({});
  const [grants, setGrants] = useState<Grant[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);

  const [subjectType, setSubjectType] = useState<SubjectType>("user");
  const [subjectID, setSubjectID] = useState<number | null>(null);
  const [newNamespace, setNewNamespace] = useState("");
  const [newCluster, setNewCluster] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const [u, g, cl, cat, gr, sc] = await Promise.all([
        apiFetch("/users").then(r => r.json()).catch(() => []),
        apiFetch("/groups").then(r => r.json()).catch(() => []),
        apiFetch("/clusters").then(r => r.json()).catch(() => ({})),
        apiFetch("/permissions/catalog").then(r => r.json()).catch(() => ({})),
        apiFetch("/permissions/grants").then(r => r.json()).catch(() => ({})),
        apiFetch("/permissions/scopes").then(r => r.json()).catch(() => ({})),
      ]);
      setUsers(Array.isArray(u) ? u : u.users ?? []);
      setGroups(Array.isArray(g) ? g : g.groups ?? []);
      setClusters(cl.clusters ?? []);
      setCatalog(cat.permissions ?? []);
      setRoles(cat.roles ?? {});
      setGrants(gr.grants ?? []);
      setScopes(sc.scopes ?? []);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (newCluster === null && clusters.length > 0) setNewCluster(clusters[0].id);
  }, [clusters, newCluster]);

  const subject = useMemo(() => {
    if (subjectID === null) return null;
    return subjectType === "user"
      ? users.find(u => u.id === subjectID) ?? null
      : groups.find(g => g.id === subjectID) ?? null;
  }, [subjectType, subjectID, users, groups]);

  const roleName = subjectType === "user" ? (subject as User | null)?.role ?? "" : "";
  const fromRole = useMemo(() => new Set(roles[roleName] ?? []), [roles, roleName]);

  const heldGrants = useMemo(
    () => new Set(grants.filter(g => g.subject_type === subjectType && g.subject_id === subjectID).map(g => g.permission)),
    [grants, subjectType, subjectID]
  );
  const mine = useMemo(
    () => scopes.filter(s => s.subject_type === subjectType && s.subject_id === subjectID),
    [scopes, subjectType, subjectID]
  );

  const toggle = async (permission: string, on: boolean) => {
    setError("");
    const res = await apiFetch("/permissions/grants", {
      method: on ? "POST" : "DELETE",
      body: JSON.stringify({ subject_type: subjectType, subject_id: subjectID, permission }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setError(body.error ?? "não foi possível alterar a permissão");
      return;
    }
    load();
  };

  const addScope = async () => {
    if (!newNamespace.trim() || !newCluster) return;
    setError("");
    const res = await apiFetch("/permissions/scopes", {
      method: "POST",
      body: JSON.stringify({
        subject_type: subjectType, subject_id: subjectID,
        cluster_id: newCluster, namespace: newNamespace.trim(),
      }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setError(body.error ?? "não foi possível adicionar o namespace");
      return;
    }
    setNewNamespace("");
    load();
  };

  const removeScope = async (id: number) => {
    await apiFetch(`/permissions/scopes/${id}`, { method: "DELETE" });
    load();
  };

  if (loading) return <div className="p-6 text-zinc-500">Carregando…</div>;

  const subjects = subjectType === "user" ? users : groups;
  const labelOf = (s: User | Group) => ("email" in s ? s.email : s.name);

  return (
    <div className="p-6 max-w-[1400px] mx-auto space-y-5">
      <header>
        <h1 className="text-2xl font-semibold">Acesso</h1>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
          O papel dá o conjunto básico; a concessão adiciona uma capacidade sem promover ninguém. O escopo
          decide de quais namespaces a pessoa vê dados — sem nenhum, ela vê todos os que a permissão já permite.
        </p>
      </header>

      {error && (
        <div className="glass-card p-3 border-red-500/30 text-sm text-red-500 dark:text-red-400">{error}</div>
      )}

      <div className="flex flex-wrap items-center gap-3">
        <div className="flex rounded-lg overflow-hidden border border-[var(--card-border)]">
          {(["user", "group"] as const).map(t => (
            <button
              key={t}
              onClick={() => { setSubjectType(t); setSubjectID(null); }}
              className={`px-3 py-1.5 text-sm transition ${
                subjectType === t ? "bg-brand-green/15 text-brand-green" : "text-zinc-500 hover:text-brand-green"
              }`}
            >
              {t === "user" ? "Usuários" : "Grupos"}
            </button>
          ))}
        </div>

        <select
          value={subjectID ?? ""}
          onChange={e => setSubjectID(e.target.value ? Number(e.target.value) : null)}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50 min-w-[260px]"
        >
          <option value="">Selecione…</option>
          {subjects.map(s => <option key={s.id} value={s.id}>{labelOf(s)}</option>)}
        </select>

        {roleName && (
          <span className="text-xs text-zinc-500 dark:text-zinc-400">
            papel <span className="font-mono text-brand-green">{roleName}</span>
          </span>
        )}
      </div>

      {subjectID === null ? (
        <div className="glass-card p-10 text-center text-zinc-500">
          Escolha um {subjectType === "user" ? "usuário" : "grupo"} para ver o que ele alcança.
        </div>
      ) : (
        <div className="grid lg:grid-cols-2 gap-4">
          <section className="glass-card p-4">
            <h2 className="text-sm font-semibold mb-3">Permissões</h2>
            <div className="space-y-1.5">
              {catalog.map(p => {
                const byRole = fromRole.has(p);
                const byGrant = heldGrants.has(p);
                return (
                  <label
                    key={p}
                    className={`flex items-start gap-3 p-2 rounded-lg transition ${
                      byRole ? "opacity-60" : "hover:bg-[var(--color-surface-hover)] cursor-pointer"
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={byRole || byGrant}
                      disabled={byRole}
                      onChange={e => toggle(p, e.target.checked)}
                      className="mt-0.5 accent-brand-green"
                    />
                    <span className="min-w-0">
                      <span className="font-mono text-xs">{p}</span>
                      {byRole && <span className="ml-2 text-[10px] text-zinc-500">vem do papel</span>}
                      <span className="block text-xs text-zinc-500 dark:text-zinc-400">{DESCRIPTIONS[p] ?? ""}</span>
                    </span>
                  </label>
                );
              })}
            </div>
          </section>

          <section className="glass-card p-4">
            <h2 className="text-sm font-semibold">Namespaces</h2>
            <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 mb-3">
              {mine.length === 0
                ? "Sem restrição: vê todos os namespaces que a permissão permite."
                : `Restrito a ${mine.length} namespace${mine.length === 1 ? "" : "s"}.`}
            </p>

            <div className="flex flex-wrap gap-1.5 mb-3">
              {mine.map(s => (
                <span key={s.id} className="inline-flex items-center gap-2 px-2 py-1 rounded-md border border-[var(--card-border)] bg-[var(--color-surface-hover)] text-xs font-mono">
                  {clusters.find(c => c.id === s.cluster_id)?.name ?? s.cluster_id}
                  <span className="text-zinc-400">/</span>
                  {s.namespace}
                  <button onClick={() => removeScope(s.id)} className="text-zinc-500 hover:text-red-500" aria-label="Remover">×</button>
                </span>
              ))}
            </div>

            <div className="flex flex-wrap gap-2">
              <select
                value={newCluster ?? ""}
                onChange={e => setNewCluster(Number(e.target.value))}
                className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50"
              >
                {clusters.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
              <input
                value={newNamespace}
                onChange={e => setNewNamespace(e.target.value)}
                onKeyDown={e => { if (e.key === "Enter") addScope(); }}
                placeholder="namespace"
                className="flex-1 min-w-[160px] px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50"
              />
              <button
                onClick={addScope}
                className="px-3 py-2 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition"
              >
                Adicionar
              </button>
            </div>
          </section>
        </div>
      )}

      <ClusterRBAC groups={groups} clusters={clusters} onChanged={load} />
    </div>
  );
}
