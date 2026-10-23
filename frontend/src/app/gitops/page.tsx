"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PERMISSIONS } from "@/lib/permissions";
import { usePermissions } from "@/app/components/usePermissions";
import { useShellRefresh } from "@/app/components/shell/refresh";
import { Status, ago, shortSha, type GitopsApp } from "./shared";

type Cluster = { id: number; name: string; is_default: boolean };

const emptyForm = {
  name: "", repo_name: "", branch: "main", path: "", namespace: "", cluster_id: 0,
  auto_sync: true, self_heal: false, prune: false,
};

/** The form that puts a repository path under GitOps. Outside the page so
 *  its inputs keep focus while typing. */
function NewApp({ onCreated, onCancel }: { onCreated: (id: number) => void; onCancel: () => void }) {
  const [form, setForm] = useState(emptyForm);
  const [repos, setRepos] = useState<string[]>([]);
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    apiFetch("/repositories?page=1&limit=100").then(r => r.json()).then(d => setRepos((d.data ?? []).map((r: { name: string }) => r.name))).catch(() => {});
    apiFetch("/clusters").then(r => r.json()).then(d => {
      const list: Cluster[] = d.clusters ?? [];
      setClusters(list);
      const def = list.find(c => c.is_default) ?? list[0];
      if (def) setForm(f => ({ ...f, cluster_id: def.id }));
    }).catch(() => {});
  }, []);

  const set = (k: keyof typeof emptyForm, v: string | number | boolean) => setForm(f => ({ ...f, [k]: v }));

  const submit = async () => {
    setBusy(true);
    setError("");
    const res = await apiFetch("/gitops/apps", { method: "POST", body: JSON.stringify(form) });
    const body = await res.json().catch(() => ({}));
    setBusy(false);
    if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
    onCreated(body.id);
  };

  const label = "flex flex-col gap-1 text-xs";
  return (
    <div className="flex flex-col gap-4 p-5" style={{ background: "var(--card)", border: "1px solid var(--rule)" }}>
      <h2 className="m-0 text-base font-semibold">New application</h2>
      <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill,minmax(220px,1fr))" }}>
        <label className={label} style={{ color: "var(--t3)" }}>Name
          <input className="input-tech font-mono" placeholder="orders-api" value={form.name} onChange={e => set("name", e.target.value.toLowerCase())} />
        </label>
        <label className={label} style={{ color: "var(--t3)" }}>Repository
          <input className="input-tech font-mono" list="gitops-repos" value={form.repo_name} onChange={e => set("repo_name", e.target.value)} />
          <datalist id="gitops-repos">{repos.map(r => <option key={r} value={r} />)}</datalist>
        </label>
        <label className={label} style={{ color: "var(--t3)" }}>Branch
          <input className="input-tech font-mono" value={form.branch} onChange={e => set("branch", e.target.value)} />
        </label>
        <label className={label} style={{ color: "var(--t3)" }}>Path in the repository
          <input className="input-tech font-mono" placeholder="k8s (empty is the root)" value={form.path} onChange={e => set("path", e.target.value)} />
        </label>
        <label className={label} style={{ color: "var(--t3)" }}>Cluster
          <select className="input-tech" value={form.cluster_id} onChange={e => set("cluster_id", Number(e.target.value))}>
            {clusters.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>
        </label>
        <label className={label} style={{ color: "var(--t3)" }}>Namespace
          <input className="input-tech font-mono" placeholder="orders" value={form.namespace} onChange={e => set("namespace", e.target.value.toLowerCase())} />
        </label>
      </div>
      <div className="flex gap-5 flex-wrap text-[13px]">
        <label className="flex items-center gap-2"><input type="checkbox" checked={form.auto_sync} onChange={e => { set("auto_sync", e.target.checked); if (!e.target.checked) set("self_heal", false); }} /> Auto-sync new commits</label>
        <label className="flex items-center gap-2" style={{ opacity: form.auto_sync ? 1 : 0.5 }}><input type="checkbox" disabled={!form.auto_sync} checked={form.self_heal} onChange={e => set("self_heal", e.target.checked)} /> Self-heal hand edits</label>
        <label className="flex items-center gap-2"><input type="checkbox" checked={form.prune} onChange={e => set("prune", e.target.checked)} /> Prune what leaves Git</label>
      </div>
      <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>
        Plain manifests, namespaced objects, all in this namespace. Kustomize, Helm and cluster-wide objects are not managed yet.
      </p>
      {error && <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{error}</p>}
      <div className="flex gap-2">
        <button type="button" onClick={submit} disabled={busy} className="btn-primary disabled:opacity-50">{busy ? "Creating…" : "Create"}</button>
        <button type="button" onClick={onCancel} className="btn-secondary">Cancel</button>
      </div>
    </div>
  );
}

export default function GitopsPage() {
  const [apps, setApps] = useState<GitopsApp[] | null>(null);
  const [creating, setCreating] = useState(false);
  const { can } = usePermissions();

  const { markSynced } = useShellRefresh(() => load());
  const load = useCallback(async () => {
    const res = await apiFetch("/gitops/apps");
    const data = await res.json().catch(() => []);
    setApps(Array.isArray(data) ? data : []);
    markSynced();
  }, [markSynced]);

  useEffect(() => {
    load();
    const t = setInterval(() => { if (!document.hidden) load(); }, 20_000);
    return () => clearInterval(t);
  }, [load]);

  if (apps === null) return <p className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>Reading applications…</p>;

  const outOfSync = apps.filter(a => a.sync_status === "OutOfSync").length;
  const degraded = apps.filter(a => a.health === "Degraded" || a.health === "Missing").length;

  return (
    <div className="max-w-[1280px] flex flex-col gap-8">
      <section className="flex flex-col gap-4 max-w-[980px]">
        <h1 className="m-0 text-[26px] md:text-[30px] leading-[1.25] font-medium tracking-[-0.02em]">
          {apps.length === 0 ? "No application is deployed by CommitKube yet." : (
            <>
              {apps.length} {apps.length === 1 ? "application" : "applications"} kept in sync with Git.{" "}
              {outOfSync + degraded === 0 ? "All match their repositories and are healthy." : (
                <>
                  {outOfSync > 0 && <span style={{ color: "var(--gold)" }}>{outOfSync} out of sync</span>}
                  {outOfSync > 0 && degraded > 0 && ", "}
                  {degraded > 0 && <span style={{ color: "var(--red)" }}>{degraded} unhealthy</span>}.
                </>
              )}
            </>
          )}
        </h1>
        <p className="m-0 text-[13px] max-w-[760px]" style={{ color: "var(--t3)" }}>
          A repository path, applied to one namespace and kept there: every few minutes CommitKube compares the branch with the
          cluster using the API server&apos;s own dry run, applies new commits when auto-sync is on, and puts back hand edits when
          self-heal is.
        </p>
        {can(PERMISSIONS.gitopsManage) && !creating && (
          <button type="button" onClick={() => setCreating(true)} className="btn-primary self-start">New application</button>
        )}
      </section>

      {creating && <NewApp onCancel={() => setCreating(false)} onCreated={id => { window.location.href = `/gitops/${id}`; }} />}

      {apps.length > 0 && (
        <section className="flex flex-col">
          <div className="grid gap-4 py-2 text-[11.5px]" style={{ gridTemplateColumns: "minmax(0,1.3fr) minmax(0,1.4fr) 110px 120px 130px", color: "var(--m2)" }}>
            <span>Application</span><span>Source</span><span>Sync</span><span>Health</span><span>Last sync</span>
          </div>
          {apps.map(a => (
            <a key={a.id} href={`/gitops/${a.id}`} className="grid gap-4 items-center py-3 no-underline hover:bg-[var(--hover)]"
              style={{ gridTemplateColumns: "minmax(0,1.3fr) minmax(0,1.4fr) 110px 120px 130px", borderTop: "1px solid var(--rule2)", color: "var(--text)" }}>
              <span className="flex flex-col min-w-0">
                <span className="font-mono text-[13px] truncate">{a.name}</span>
                <span className="text-[11.5px] truncate" style={{ color: "var(--m2)" }}>{a.cluster} / {a.namespace}{a.auto_sync ? " · auto" : ""}{a.self_heal ? " · self-heal" : ""}{a.prune ? " · prune" : ""}</span>
              </span>
              <span className="flex flex-col min-w-0">
                <span className="font-mono text-[12px] truncate">{a.repo_name}{a.path ? `/${a.path}` : ""}</span>
                <span className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>{a.branch} @ {shortSha(a.revision)}</span>
              </span>
              <Status value={a.sync_status} kind="sync" />
              <Status value={a.health} kind="health" />
              <span className="text-[12px]" style={{ color: "var(--m2)" }}>{ago(a.synced_at)}</span>
            </a>
          ))}
        </section>
      )}
    </div>
  );
}
