"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import ClusterRBAC from "./ClusterRBAC";
import AddCluster from "./AddCluster";

interface User { id: number; email: string; role: string; is_active: boolean }
interface Group { id: number; name: string; description: string }
interface Grant { id: number; subject_type: string; subject_id: number; permission: string; denied: boolean }
interface Scope { id: number; subject_type: string; subject_id: number; cluster_id: number; namespace: string }
interface ClusterRow { id: number; name: string; impersonate: boolean; can_manage_rbac: boolean }

type Tab = "users" | "groups" | "clusters";

/** Who each permission is for, said the way the person granting it would say
 *  it. A list of dotted strings is not something anyone can hand out safely. */
const DESCRIPTIONS: Record<string, string> = {
  "k8s.read": "Ver pods, workloads, nodes, namespaces e manifestos",
  "k8s.logs.read": "Ler log de pod — log costuma conter credencial",
  "k8s.secrets.read": "Listar nomes e chaves de Secrets (valores mascarados)",
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
  "user.manage": "Gerir usuários e grupos",
  "audit.read": "Ler o log de auditoria",
};

const GROUPS: [string, string[]][] = [
  ["Kubernetes", ["k8s.read", "k8s.logs.read", "k8s.secrets.read", "k8s.secrets.show", "k8s.pod.delete", "k8s.scale", "cluster.manage"]],
  ["Repositórios", ["scm.read", "scm.write", "scm.approve", "template.read", "template.write"]],
  ["Segurança", ["security.read", "security.scan"]],
  ["Plataforma", ["settings.read", "settings.write", "notify.write", "user.manage", "audit.read"]],
];

export default function Page() {
  const [tab, setTab] = useState<Tab>("users");
  const [users, setUsers] = useState<User[]>([]);
  const [groups, setGroups] = useState<Group[]>([]);
  const [clusters, setClusters] = useState<ClusterRow[]>([]);
  const [catalog, setCatalog] = useState<string[]>([]);
  const [roles, setRoles] = useState<Record<string, string[]>>({});
  const [grants, setGrants] = useState<Grant[]>([]);
  const [scopes, setScopes] = useState<Scope[]>([]);
  const [members, setMembers] = useState<Record<number, number[]>>({});

  const [selected, setSelected] = useState<number | null>(null);
  const [namespaces, setNamespaces] = useState<string[]>([]);
  const [newNamespace, setNewNamespace] = useState("");
  const [newCluster, setNewCluster] = useState<number | null>(null);
  const [error, setError] = useState("");
  const [saved, setSaved] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    const [u, g, cl, cat, gr, sc] = await Promise.all([
      apiFetch("/users").then(r => r.json()).catch(() => []),
      apiFetch("/groups").then(r => r.json()).catch(() => []),
      apiFetch("/clusters").then(r => r.json()).catch(() => ({})),
      apiFetch("/permissions/catalog").then(r => r.json()).catch(() => ({})),
      apiFetch("/permissions/grants").then(r => r.json()).catch(() => ({})),
      apiFetch("/permissions/scopes").then(r => r.json()).catch(() => ({})),
    ]);
    const groupList: Group[] = Array.isArray(g) ? g : g.groups ?? [];
    setUsers(Array.isArray(u) ? u : u.users ?? []);
    setGroups(groupList);
    setClusters(cl.clusters ?? []);
    setCatalog(cat.permissions ?? []);
    setRoles(cat.roles ?? {});
    setGrants(gr.grants ?? []);
    setScopes(sc.scopes ?? []);
    setLoading(false);
  }, []);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (newCluster === null && clusters.length > 0) setNewCluster(clusters[0].id);
  }, [clusters, newCluster]);

  // Namespaces of the selected cluster, so nobody types one from memory and
  // finds the typo only when the page stays empty.
  useEffect(() => {
    if (!newCluster) return;
    apiFetch(`/kubernetes/namespaces?cluster=${newCluster}`)
      .then(r => r.json()).then(b => setNamespaces(b.namespaces ?? [])).catch(() => setNamespaces([]));
  }, [newCluster]);

  const subjectType = tab === "groups" ? "group" : "user";
  const subject = useMemo(() => {
    if (selected === null) return null;
    return subjectType === "user" ? users.find(u => u.id === selected) : groups.find(g => g.id === selected);
  }, [selected, subjectType, users, groups]);

  const roleName = subjectType === "user" ? (subject as User | undefined)?.role ?? "" : "";
  const fromRole = useMemo(() => new Set(roles[roleName] ?? []), [roles, roleName]);
  const myGrants = useMemo(
    () => grants.filter(g => g.subject_type === subjectType && g.subject_id === selected),
    [grants, subjectType, selected]
  );
  const myScopes = useMemo(
    () => scopes.filter(s => s.subject_type === subjectType && s.subject_id === selected),
    [scopes, subjectType, selected]
  );

  /** What the person effectively holds: the role's bundle, then any explicit
   *  decision about them. An explicit row always wins, which is what makes
   *  every box clickable instead of some being greyed out. */
  const effective = (permission: string) => {
    const explicit = myGrants.find(g => g.permission === permission);
    if (explicit) return !explicit.denied;
    return fromRole.has(permission);
  };

  const flash = (msg: string) => { setSaved(msg); setTimeout(() => setSaved(""), 1800); };

  const toggle = async (permission: string, on: boolean) => {
    setError("");
    const fromRoleNow = fromRole.has(permission);
    // Matching the role again means there is nothing to remember, so the
    // explicit row is dropped rather than left as a no-op nobody can read.
    const method = on === fromRoleNow ? "DELETE" : "POST";
    const res = await apiFetch("/permissions/grants", {
      method,
      body: JSON.stringify({ subject_type: subjectType, subject_id: selected, permission, denied: !on }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setError(body.error ?? "não foi possível alterar"); return;
    }
    flash("salvo");
    load();
  };

  const addScope = async () => {
    if (!newNamespace || !newCluster) return;
    setError("");
    const res = await apiFetch("/permissions/scopes", {
      method: "POST",
      body: JSON.stringify({ subject_type: subjectType, subject_id: selected, cluster_id: newCluster, namespace: newNamespace }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setError(body.error ?? "não foi possível adicionar"); return;
    }
    setNewNamespace(""); flash("salvo"); load();
  };

  const removeScope = async (id: number) => {
    await apiFetch(`/permissions/scopes/${id}`, { method: "DELETE" });
    flash("salvo"); load();
  };

  const loadMembers = useCallback(async (groupID: number) => {
    const res = await apiFetch(`/groups`);
    const body = await res.json().catch(() => []);
    const list: { id: number; members?: { user_id: number }[] }[] = Array.isArray(body) ? body : body.groups ?? [];
    const g = list.find(x => x.id === groupID);
    setMembers(prev => ({ ...prev, [groupID]: (g?.members ?? []).map(m => m.user_id) }));
  }, []);

  useEffect(() => {
    if (tab === "groups" && selected !== null) loadMembers(selected);
  }, [tab, selected, loadMembers]);

  const toggleMember = async (userID: number, on: boolean) => {
    if (selected === null) return;
    setError("");
    const res = on
      ? await apiFetch(`/groups/${selected}/members`, { method: "POST", body: JSON.stringify({ user_id: userID }) })
      : await apiFetch(`/groups/${selected}/members/${userID}`, { method: "DELETE" });
    if (!res.ok) { setError("não foi possível alterar o grupo"); return; }
    flash("salvo"); loadMembers(selected);
  };

  if (loading) return <div className="p-6 text-zinc-500">Carregando…</div>;

  const list = tab === "groups" ? groups : users;
  const labelOf = (s: User | Group) => ("email" in s ? s.email : s.name);

  return (
    <div className="p-6 max-w-[1500px] mx-auto space-y-5">
      <header className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold">IAM</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
            Quem é, o que pode fazer, e em quais namespaces. Toda mudança salva na hora.
          </p>
        </div>
        {saved && <span className="text-xs text-brand-green">{saved}</span>}
      </header>

      {error && <div className="glass-card p-3 border-red-500/30 text-sm text-red-500 dark:text-red-400">{error}</div>}

      <div className="flex rounded-lg overflow-hidden border border-[var(--card-border)] w-fit">
        {([["users", "Usuários"], ["groups", "Grupos"], ["clusters", "Clusters"]] as [Tab, string][]).map(([t, label]) => (
          <button key={t} onClick={() => { setTab(t); setSelected(null); }}
            className={`px-4 py-2 text-sm transition ${tab === t ? "bg-brand-green/15 text-brand-green" : "text-zinc-500 hover:text-brand-green"}`}>
            {label}
          </button>
        ))}
      </div>

      {tab === "clusters" ? (
        <div className="space-y-4">
          <section className="glass-card p-4">
            <div className="flex flex-wrap items-center justify-between gap-3">
              <div>
                <h2 className="text-sm font-semibold">Clusters</h2>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-0.5">
                  {clusters.map(c => c.name).join(", ") || "nenhum"}
                </p>
              </div>
              <AddCluster onAdded={load} />
            </div>
          </section>
          <ClusterRBAC groups={groups} clusters={clusters} namespaces={namespaces} onChanged={load} />
        </div>
      ) : (
        <div className="grid lg:grid-cols-[260px_1fr] gap-4">
          <aside className="glass-card p-2 h-fit">
            {list.length === 0 && <p className="p-3 text-xs text-zinc-500">nenhum</p>}
            {list.map(s => (
              <button key={s.id} onClick={() => setSelected(s.id)}
                className={`w-full text-left px-3 py-2 rounded-lg text-sm truncate transition ${
                  selected === s.id ? "bg-brand-green/15 text-brand-green" : "text-zinc-500 hover:text-brand-green hover:bg-brand-green/8"
                }`}>
                {labelOf(s)}
                {"role" in s && <span className="block text-[10px] opacity-70">{s.role}</span>}
              </button>
            ))}
          </aside>

          {selected === null ? (
            <div className="glass-card p-10 text-center text-zinc-500">
              Escolha {tab === "groups" ? "um grupo" : "um usuário"} à esquerda.
            </div>
          ) : (
            <div className="space-y-4">
              <section className="glass-card p-4">
                <div className="flex flex-wrap items-baseline justify-between gap-2 mb-3">
                  <h2 className="text-sm font-semibold">Permissões</h2>
                  {roleName && (
                    <span className="text-xs text-zinc-500 dark:text-zinc-400">
                      papel <span className="font-mono text-brand-green">{roleName}</span> — marque ou desmarque
                      qualquer uma, o papel é só o ponto de partida
                    </span>
                  )}
                </div>

                <div className="grid md:grid-cols-2 gap-x-6 gap-y-4">
                  {GROUPS.map(([section, perms]) => (
                    <div key={section}>
                      <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 mb-1.5">{section}</p>
                      <div className="space-y-1">
                        {perms.filter(p => catalog.includes(p)).map(p => {
                          const on = effective(p);
                          const explicit = myGrants.find(gr => gr.permission === p);
                          return (
                            <label key={p} className="flex items-start gap-2.5 p-1.5 rounded-lg hover:bg-[var(--color-surface-hover)] cursor-pointer">
                              <input type="checkbox" checked={on} onChange={e => toggle(p, e.target.checked)}
                                className="mt-0.5 accent-brand-green" />
                              <span className="min-w-0">
                                <span className="text-sm">{DESCRIPTIONS[p] ?? p}</span>
                                {explicit && (
                                  <span className={`ml-2 text-[10px] ${explicit.denied ? "text-red-500" : "text-brand-green"}`}>
                                    {explicit.denied ? "removida para este" : "adicionada para este"}
                                  </span>
                                )}
                                <span className="block font-mono text-[10px] text-zinc-500">{p}</span>
                              </span>
                            </label>
                          );
                        })}
                      </div>
                    </div>
                  ))}
                </div>
              </section>

              <section className="glass-card p-4">
                <h2 className="text-sm font-semibold">Namespaces</h2>
                <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 mb-3">
                  {myScopes.length === 0
                    ? "Sem restrição: vê todos os namespaces."
                    : `Vê apenas estes ${myScopes.length}.`}
                </p>

                <div className="flex flex-wrap gap-1.5 mb-3">
                  {myScopes.map(s => (
                    <span key={s.id} className="inline-flex items-center gap-2 px-2 py-1 rounded-md border border-[var(--card-border)] bg-[var(--color-surface-hover)] text-xs font-mono">
                      {clusters.find(c => c.id === s.cluster_id)?.name ?? s.cluster_id}
                      <span className="text-zinc-400">/</span>{s.namespace}
                      <button onClick={() => removeScope(s.id)} className="text-zinc-500 hover:text-red-500">×</button>
                    </span>
                  ))}
                </div>

                <div className="flex flex-wrap gap-2">
                  <select value={newCluster ?? ""} onChange={e => setNewCluster(Number(e.target.value))}
                    className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
                    {clusters.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                  </select>
                  <select value={newNamespace} onChange={e => setNewNamespace(e.target.value)}
                    className="flex-1 min-w-[180px] px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
                    <option value="">Namespace…</option>
                    {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
                  </select>
                  <button onClick={addScope} disabled={!newNamespace}
                    className="px-3 py-2 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-40">
                    Adicionar
                  </button>
                </div>
                {namespaces.length === 0 && (
                  <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
                    Nenhum namespace retornou. Se “falar com o cluster como a pessoa” estiver ligado sem
                    RoleBindings, é isso.
                  </p>
                )}
              </section>

              {tab === "groups" && (
                <section className="glass-card p-4">
                  <h2 className="text-sm font-semibold mb-3">Membros</h2>
                  <div className="grid sm:grid-cols-2 gap-1">
                    {users.map(u => (
                      <label key={u.id} className="flex items-center gap-2.5 p-1.5 rounded-lg hover:bg-[var(--color-surface-hover)] cursor-pointer text-sm">
                        <input type="checkbox" checked={(members[selected] ?? []).includes(u.id)}
                          onChange={e => toggleMember(u.id, e.target.checked)} className="accent-brand-green" />
                        <span className="truncate font-mono text-xs">{u.email}</span>
                      </label>
                    ))}
                  </div>
                </section>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
