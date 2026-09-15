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
    if (!group || !namespace) { setError("pick a group and a namespace"); return; }
    const qs = new URLSearchParams({ group, namespace }).toString();
    const res = await apiFetch(`/rbac/preview?${qs}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setError(body.error ?? "could not generate the manifest"); return; }
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
    if (!res.ok) { setError(body.error ?? "could not apply"); return; }
    setMessage(body.message ?? "applied");
  };

  const toggle = async (field: "impersonate" | "can_manage_rbac", value: boolean) => {
    setError("");
    const res = await apiFetch(`/clusters/${clusterID}/flags`, {
      method: "PUT",
      body: JSON.stringify({ [field]: value }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      setError(body.error ?? "could not change the cluster");
      return;
    }
    onChanged();
  };

  return (
    <section className="glass-card p-4 space-y-4">
      <div>
        <h2 className="text-sm font-semibold">Cluster RBAC</h2>
        <p className="text-xs text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
          Everything above is enforced by CommitKube. This is the second fence, enforced by Kubernetes
          itself — so a mistake in ours is not the only thing standing between a team and someone else&apos;s
          workloads. Optional: leave the switches off and CommitKube decides alone, exactly as before.
        </p>
        <ol className="text-xs text-zinc-500 dark:text-zinc-400 mt-2 space-y-1 list-decimal list-inside max-w-3xl">
          <li>Pick a group and a namespace. The rules come from the permissions that group already holds.</li>
          <li><strong>Generate</strong> the manifest and apply it — with kubectl, or let CommitKube do it.</li>
          <li>Only then turn on <em>let the cluster decide</em>. Before the bindings exist, it would answer
              “no” to everything.</li>
        </ol>
      </div>

      <div className="grid sm:grid-cols-2 lg:grid-cols-4 gap-2">
        <select value={clusterID ?? ""} onChange={e => setClusterID(Number(e.target.value))}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
          {clusters.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
        </select>
        <select value={group} onChange={e => setGroup(e.target.value)}
          className="px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
          <option value="">Group…</option>
          {groups.map(g => <option key={g.id} value={g.name}>{g.name}</option>)}
        </select>
        <select value={namespace} onChange={e => setNamespace(e.target.value)}
          className="px-3 py-2 text-sm font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
          <option value="">Namespace…</option>
          <option value={ALL_NAMESPACES}>All namespaces</option>
          {namespaces.map(ns => <option key={ns} value={ns}>{ns}</option>)}
        </select>
      </div>

      <p className="text-xs text-zinc-500 dark:text-zinc-400">
        The rules come from the permissions the group already holds — you do not pick twice. Granting
        <span className="font-mono"> k8s.scale </span> above and forgetting the binding below is exactly how the two halves
        come to disagree.
      </p>

      <div className="flex flex-wrap items-center gap-2">
        <button onClick={preview}
          className="px-3 py-1.5 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition">
          Generate manifest
        </button>
        <button onClick={apply} disabled={!cluster?.can_manage_rbac || !manifest}
          className="px-3 py-1.5 text-sm rounded-lg border border-amber-500/40 text-amber-500 hover:bg-amber-500/10 transition disabled:opacity-40"
          title={cluster?.can_manage_rbac ? "" : "this cluster does not let CommitKube write RBAC"}>
          Apply to cluster
        </button>
        {!cluster?.can_manage_rbac && (
          <span className="text-xs text-zinc-500">apply it yourself, or allow it below</span>
        )}
      </div>

      {error && <p className="text-xs text-red-500 dark:text-red-400">{error}</p>}
      {message && <p className="text-xs text-brand-green">{message}</p>}

      {manifest && (
        <div className="space-y-3">
          {identity && (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Impersonated identity: <span className="font-mono text-brand-green">{identity}</span>
            </p>
          )}
          {derivedFrom.length > 0 && (
            <p className="text-xs text-zinc-500 dark:text-zinc-400">
              Derived from: {derivedFrom.map(p => <span key={p} className="font-mono text-brand-green mr-2">{p}</span>)}
            </p>
          )}
          {(derivedFrom.includes("k8s.secrets.read") || derivedFrom.includes("k8s.secrets.show")) && (
            <p className="text-xs text-amber-600 dark:text-amber-400">
              Kubernetes has no “names without values” for Secrets: <code>list</code> returns whole objects. Both
              Secret permissions become the same cluster rule, and the difference between seeing a key and
              seeing a value is CommitKube masking it — not the cluster refusing.
            </p>
          )}
          <pre className="text-xs font-mono leading-relaxed whitespace-pre overflow-x-auto p-3 rounded-lg bg-zinc-100 dark:bg-zinc-900 border border-[var(--card-border)]">
{manifest}
          </pre>
          <details>
            <summary className="text-xs text-zinc-500 dark:text-zinc-400 cursor-pointer">
              ClusterRole CommitKube’s own credential needs (apply once)
            </summary>
            <p className="text-xs text-amber-600 dark:text-amber-400 mt-2">
              The <code>resourceNames</code> list is not a detail: without it, whoever impersonates can become any
              user in the cluster, cluster-admins included.
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
              Let the cluster decide
              <span className="block text-xs text-zinc-500 dark:text-zinc-400">
                Without this, CommitKube uses its own credential and decides alone. With it, each person talks to
                the cluster as themselves. Turn it on after the manifest above is applied.
              </span>
            </span>
          </label>

          <label className="flex items-start gap-3 text-sm cursor-pointer">
            <input type="checkbox" checked={cluster.can_manage_rbac} className="mt-0.5 accent-amber-500"
              onChange={e => toggle("can_manage_rbac", e.target.checked)} />
            <span>
              Let CommitKube apply it for you
              <span className="block text-xs text-zinc-500 dark:text-zinc-400">
                Without this, you apply the manifest with <code>kubectl</code>. With it, the button above does it.
              </span>
            </span>
          </label>
        </div>
      )}
    </section>
  );
}
