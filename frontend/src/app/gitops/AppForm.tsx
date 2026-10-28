"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { apiFetch } from "@/lib/api";
import { SOURCE_LABEL, type GitopsApp, type GitopsRepo, type SourceType } from "./shared";

type Cluster = { id: number; name: string; is_default: boolean };
type TreeEntry = { path: string; dir: boolean; kind?: string };
type Tree = { branch: string; revision: string; root_kind: string; entries: TreeEntry[]; truncated: boolean };

type Form = {
  name: string; gitops_repo_id: number; repo_name: string; branch: string; path: string;
  source_type: SourceType; include: string; exclude: string;
  helm_release_name: string; helm_value_files: string; helm_values: string;
  cluster_id: number; namespace: string; cluster_scope: boolean;
  auto_sync: boolean; self_heal: boolean; prune: boolean;
};

const blank: Form = {
  name: "", gitops_repo_id: 0, repo_name: "", branch: "", path: "", source_type: "auto", include: "", exclude: "",
  helm_release_name: "", helm_value_files: "", helm_values: "", cluster_id: 0, namespace: "", cluster_scope: false,
  auto_sync: true, self_heal: false, prune: false,
};

const KIND_COLOR: Record<string, string> = { kustomize: "var(--blue, #60a5fa)", helm: "var(--orange)", directory: "var(--green)" };

function KindTag({ kind }: { kind?: string }) {
  if (!kind) return null;
  const label = kind === "directory" ? "manifests" : kind;
  return <span className="text-[10.5px] px-1.5 py-px rounded font-mono" style={{ border: `1px solid ${KIND_COLOR[kind] ?? "var(--line2)"}`, color: KIND_COLOR[kind] ?? "var(--m2)" }}>{label}</span>;
}

/** The branch's directories and YAML files, so the path is picked rather
 *  than typed. Directories say what auto-detection would read them as. */
function PathPicker({ tree, value, onPick }: { tree: Tree; value: string; onPick: (e: TreeEntry | null) => void }) {
  const [q, setQ] = useState("");
  const shown = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return tree.entries.filter(e => !needle || e.path.toLowerCase().includes(needle)).slice(0, 400);
  }, [tree, q]);
  const row = (key: string, label: string, depth: number, dir: boolean, kind: string | undefined, selected: boolean, pick: () => void) => (
    <button key={key} type="button" onClick={pick}
      className="w-full flex items-center gap-2 px-3 py-1 text-left font-mono text-[12px] hover:bg-[var(--hover)]"
      style={{ paddingLeft: 12 + depth * 14, background: selected ? "var(--hover)" : undefined, color: selected ? "var(--green)" : dir ? "var(--text)" : "var(--t2)" }}>
      <span style={{ color: "var(--m2)" }}>{dir ? "▸" : "·"}</span>
      <span className="truncate">{label}</span>
      <KindTag kind={kind} />
    </button>
  );
  return (
    <div className="flex flex-col" style={{ border: "1px solid var(--rule)" }}>
      <input className="input-tech !border-0 !border-b text-xs" style={{ borderBottom: "1px solid var(--rule)" }} placeholder="Filter paths…" value={q} onChange={e => setQ(e.target.value)} />
      <div className="max-h-72 overflow-y-auto py-1">
        {!q && row("/", "(repository root)", 0, true, tree.root_kind, value === "", () => onPick(null))}
        {shown.map(e => {
          const depth = q ? 0 : e.path.split("/").length - 1;
          const label = q ? e.path : e.path.split("/").pop() ?? e.path;
          return row(e.path, label + (e.dir ? "/" : ""), depth + (q ? 0 : 1), e.dir, e.kind, value === e.path, () => onPick(e));
        })}
        {shown.length === 0 && <p className="m-0 px-3 py-2 text-xs" style={{ color: "var(--m2)" }}>No directory or YAML file matches.</p>}
      </div>
      {tree.truncated && <p className="m-0 px-3 py-1.5 text-[11px]" style={{ color: "var(--gold)", borderTop: "1px solid var(--rule)" }}>The repository is large; only the first 5000 paths are listed. Type the path if yours is missing.</p>}
    </div>
  );
}

/** Creates an application, or (with `app`) edits where an existing one
 *  reads from. Name, cluster and namespace are fixed once created: changing
 *  them would orphan what is already in the cluster. */
export default function AppForm({ app, initialRepo, onDone, onCancel }: {
  app?: GitopsApp; initialRepo?: number; onDone: (id: number) => void; onCancel: () => void;
}) {
  const editing = !!app;
  const [form, setForm] = useState<Form>(() => app ? {
    ...blank, ...app, gitops_repo_id: app.gitops_repo_id ?? 0, helm_values: app.helm_values ?? "",
  } : { ...blank, gitops_repo_id: initialRepo ?? 0 });
  const [repos, setRepos] = useState<GitopsRepo[]>([]);
  const [legacyRepos, setLegacyRepos] = useState<string[]>([]);
  const [clusters, setClusters] = useState<Cluster[]>([]);
  const [branches, setBranches] = useState<string[] | null>(null);
  const [tree, setTree] = useState<Tree | null>(null);
  const [treeState, setTreeState] = useState<"" | "loading" | string>("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const set = <K extends keyof Form>(k: K, v: Form[K]) => setForm(f => ({ ...f, [k]: v }));
  const legacy = form.gitops_repo_id === 0;

  useEffect(() => {
    apiFetch("/gitops/repos").then(r => r.json()).then((d: GitopsRepo[]) => {
      const list = Array.isArray(d) ? d : [];
      setRepos(list);
      if (!app && !initialRepo) {
        const first = list.find(r => r.status === "connected");
        if (first) setForm(f => ({ ...f, gitops_repo_id: first.id }));
      }
    }).catch(() => {});
    apiFetch("/repositories?page=1&limit=100").then(r => r.json()).then(d => setLegacyRepos((d.data ?? []).map((r: { name: string }) => r.name))).catch(() => {});
    if (!app) {
      apiFetch("/clusters").then(r => r.json()).then(d => {
        const list: Cluster[] = d.clusters ?? [];
        setClusters(list);
        const def = list.find(c => c.is_default) ?? list[0];
        if (def) setForm(f => ({ ...f, cluster_id: def.id }));
      }).catch(() => {});
    }
  }, [app, initialRepo]);

  // A connected repository answers with its branches; the default one is
  // preselected unless the application already names one.
  useEffect(() => {
    setBranches(null); setTree(null); setTreeState("");
    if (legacy) return;
    apiFetch(`/gitops/repos/${form.gitops_repo_id}/branches`).then(async r => {
      const d = await r.json().catch(() => ({}));
      if (!r.ok) { setTreeState(d.error ?? `Request failed (${r.status})`); setBranches([]); return; }
      setBranches(d.branches ?? []);
      setForm(f => ({ ...f, branch: f.branch && (d.branches ?? []).includes(f.branch) ? f.branch : (d.default_branch || d.branches?.[0] || "main") }));
    }).catch(() => setBranches([]));
  }, [form.gitops_repo_id, legacy]);

  const loadTree = useCallback(async () => {
    if (legacy || !form.branch) return;
    setTreeState("loading");
    const r = await apiFetch(`/gitops/repos/${form.gitops_repo_id}/tree?branch=${encodeURIComponent(form.branch)}`);
    const d = await r.json().catch(() => ({}));
    if (!r.ok) { setTreeState(d.error ?? `Request failed (${r.status})`); return; }
    setTree(d); setTreeState("");
  }, [legacy, form.gitops_repo_id, form.branch]);

  useEffect(() => { if (branches && branches.length > 0) loadTree(); }, [branches, form.branch, loadTree]);

  const picked = tree?.entries.find(e => e.path === form.path);
  const detected = form.path === "" ? tree?.root_kind : picked?.dir ? picked.kind : picked ? "directory" : undefined;
  const effective: string = form.source_type === "auto" ? (detected || "directory") : form.source_type;
  const isFile = !!picked && !picked.dir;

  const submit = async () => {
    setBusy(true); setError("");
    const body: Record<string, unknown> = { ...form, gitops_repo_id: form.gitops_repo_id || 0 };
    if (!legacy) body.repo_name = "";
    if (editing) { delete body.name; delete body.cluster_id; delete body.namespace; }
    const res = await apiFetch(editing ? `/gitops/apps/${app!.id}` : "/gitops/apps", { method: editing ? "PUT" : "POST", body: JSON.stringify(body) });
    const d = await res.json().catch(() => ({}));
    setBusy(false);
    if (!res.ok) { setError(d.error ?? `Request failed (${res.status})`); return; }
    onDone(d.id ?? app?.id);
  };

  const label = "flex flex-col gap-1 text-xs";
  const muted = { color: "var(--t3)" };
  const connected = repos.filter(r => r.status === "connected");
  const noSource = repos.length === 0 && legacyRepos.length === 0;

  return (
    <div className="flex flex-col gap-5 p-5" style={{ background: "var(--card)", border: "1px solid var(--rule)" }}>
      <h2 className="m-0 text-base font-semibold">{editing ? "Source and options" : "New application"}</h2>

      {noSource && !editing && (
        <p className="m-0 text-[13px]" style={{ color: "var(--gold)" }}>
          No repository yet. <a href="/gitops/repos" style={{ color: "var(--green)" }}>Connect one over SSH</a> first.
        </p>
      )}

      <fieldset className="flex flex-col gap-3 m-0 p-0 border-0">
        <legend className="mb-2 text-[12px] font-semibold" style={muted}>Source</legend>
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill,minmax(220px,1fr))" }}>
          <label className={label} style={muted}>Repository
            <select className="input-tech" value={legacy ? `legacy:${form.repo_name}` : String(form.gitops_repo_id)}
              onChange={e => {
                const v = e.target.value;
                if (v.startsWith("legacy:")) setForm(f => ({ ...f, gitops_repo_id: 0, repo_name: v.slice(7), branch: f.branch || "main", path: "" }));
                else setForm(f => ({ ...f, gitops_repo_id: Number(v), repo_name: "", branch: "", path: "" }));
              }}>
              {legacy && !form.repo_name && <option value="legacy:">Choose…</option>}
              {repos.length > 0 && (
                <optgroup label="Connected over SSH">
                  {repos.map(r => <option key={r.id} value={r.id} disabled={r.status !== "connected"}>{r.name}{r.status !== "connected" ? ` (${r.status})` : ""}</option>)}
                </optgroup>
              )}
              {legacyRepos.length > 0 && (
                <optgroup label="Created by CommitKube">
                  {legacyRepos.map(n => <option key={n} value={`legacy:${n}`}>{n}</option>)}
                </optgroup>
              )}
            </select>
          </label>
          <label className={label} style={muted}>Branch
            {legacy || !branches || branches.length === 0
              ? <input className="input-tech font-mono" value={form.branch} onChange={e => set("branch", e.target.value)} placeholder="main" />
              : <select className="input-tech font-mono" value={form.branch} onChange={e => { set("branch", e.target.value); }}>
                  {branches.map(b => <option key={b} value={b}>{b}</option>)}
                </select>}
          </label>
          <label className={label} style={muted}>Path (directory or file)
            <input className="input-tech font-mono" placeholder="(repository root)" value={form.path} onChange={e => set("path", e.target.value.replace(/^\/+/, ""))} />
          </label>
        </div>
        {connected.length === 0 && repos.length > 0 && !editing && (
          <p className="m-0 text-xs" style={{ color: "var(--gold)" }}>None of the connected repositories has passed its connection test yet.</p>
        )}

        {!legacy && (
          treeState === "loading" ? <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>Reading {form.branch}…</p>
            : treeState ? <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{treeState}</p>
            : tree && <PathPicker tree={tree} value={form.path} onPick={e => set("path", e ? e.path : "")} />
        )}

        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill,minmax(220px,1fr))" }}>
          <label className={label} style={muted}>Read it as
            <select className="input-tech" value={form.source_type} disabled={isFile} onChange={e => set("source_type", e.target.value as SourceType)}>
              {(["auto", "directory", "kustomize", "helm"] as const).map(t => (
                <option key={t} value={t}>{t === "auto" && detected ? `Auto-detect (${SOURCE_LABEL[detected]})` : SOURCE_LABEL[t]}</option>
              ))}
            </select>
          </label>
        </div>
        {isFile && <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>A single file is applied as plain manifests.</p>}

        {!isFile && effective === "directory" && (
          <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))" }}>
            <label className={label} style={muted}>Include (globs, comma-separated)
              <input className="input-tech font-mono" placeholder="all YAML files" value={form.include} onChange={e => set("include", e.target.value)} />
            </label>
            <label className={label} style={muted}>Exclude
              <input className="input-tech font-mono" placeholder="*.test.yaml, drafts/**" value={form.exclude} onChange={e => set("exclude", e.target.value)} />
            </label>
          </div>
        )}
        {!isFile && effective === "directory" && (
          <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>Subdirectories are read too. Kustomization files and Helm charts inside are skipped; point an application at them instead.</p>
        )}

        {!isFile && effective === "helm" && (
          <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill,minmax(260px,1fr))" }}>
            <label className={label} style={muted}>Release name
              <input className="input-tech font-mono" placeholder={form.name || "the application's name"} value={form.helm_release_name} onChange={e => set("helm_release_name", e.target.value.toLowerCase())} />
            </label>
            <label className={label} style={muted}>Values files (one per line, in the chart or from the repository root)
              <textarea className="input-tech font-mono text-xs" rows={3} placeholder={"values-prod.yaml\nenvs/prod/values.yaml"} value={form.helm_value_files} onChange={e => set("helm_value_files", e.target.value)} />
            </label>
            <label className={label + " col-span-full"} style={muted}>Values (YAML, applied last)
              <textarea className="input-tech font-mono text-xs" rows={5} placeholder={"replicaCount: 3\nimage:\n  tag: 1.4.2"} value={form.helm_values} onChange={e => set("helm_values", e.target.value)} spellCheck={false} />
            </label>
          </div>
        )}
        {!isFile && effective === "kustomize" && (
          <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>Rendered with kustomize build. Overlays may reference bases elsewhere in the same repository.</p>
        )}
      </fieldset>

      <fieldset className="flex flex-col gap-3 m-0 p-0 border-0">
        <legend className="mb-2 text-[12px] font-semibold" style={muted}>Destination</legend>
        <div className="grid gap-3" style={{ gridTemplateColumns: "repeat(auto-fill,minmax(220px,1fr))" }}>
          <label className={label} style={muted}>Name
            <input className="input-tech font-mono" placeholder="orders-api" disabled={editing} value={form.name} onChange={e => set("name", e.target.value.toLowerCase())} />
          </label>
          <label className={label} style={muted}>Cluster
            {editing ? <input className="input-tech" disabled value={app?.cluster ?? ""} />
              : <select className="input-tech" value={form.cluster_id} onChange={e => set("cluster_id", Number(e.target.value))}>
                  {clusters.map(c => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>}
          </label>
          <label className={label} style={muted}>Namespace
            <input className="input-tech font-mono" placeholder="orders" disabled={editing} value={form.namespace} onChange={e => set("namespace", e.target.value.toLowerCase())} />
          </label>
        </div>
        <label className="flex items-start gap-2 text-[13px]">
          <input type="checkbox" className="mt-0.5" checked={form.cluster_scope} onChange={e => set("cluster_scope", e.target.checked)} />
          <span>
            Cluster scope: also manage cluster-wide objects (Namespaces, CRDs, ClusterRoles) and objects in other namespaces.
            {form.cluster_scope && <span className="block text-xs mt-1" style={{ color: "var(--gold)" }}>
              CommitKube then needs write access to the whole cluster, and whoever can commit to this path decides what it writes. Leave it off unless the path really holds cluster-wide objects.
            </span>}
          </span>
        </label>
      </fieldset>

      <fieldset className="flex flex-col gap-2 m-0 p-0 border-0">
        <legend className="mb-2 text-[12px] font-semibold" style={muted}>Sync policy</legend>
        <div className="flex gap-5 flex-wrap text-[13px]">
          <label className="flex items-center gap-2"><input type="checkbox" checked={form.auto_sync} onChange={e => setForm(f => ({ ...f, auto_sync: e.target.checked, self_heal: e.target.checked && f.self_heal }))} /> Auto-sync new commits</label>
          <label className="flex items-center gap-2" style={{ opacity: form.auto_sync ? 1 : 0.5 }}><input type="checkbox" disabled={!form.auto_sync} checked={form.self_heal} onChange={e => set("self_heal", e.target.checked)} /> Self-heal hand edits</label>
          <label className="flex items-center gap-2"><input type="checkbox" checked={form.prune} onChange={e => set("prune", e.target.checked)} /> Prune what leaves Git</label>
        </div>
      </fieldset>

      {error && <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{error}</p>}
      <div className="flex gap-2">
        <button type="button" onClick={submit} disabled={busy} className="btn-primary disabled:opacity-50">{busy ? "Saving…" : editing ? "Save" : "Create"}</button>
        <button type="button" onClick={onCancel} className="btn-secondary">Cancel</button>
      </div>
    </div>
  );
}
