"use client";

import { useState, useEffect } from "react";
import { apiFetch } from "@/lib/api";

type Template = { id: number; name: string; path: string; content: string; type: string; is_active: boolean };
type RepoVariable = { key: string; value: string; secured: boolean };
type UploadedFile = { path: string; content: string };
type Workspace = { id: number; alias: string; workspace_id: string; project_key: string };
type ArgoCDInst = { id: number; alias: string; server_url: string };
type Project = { id: number; project_key: string; alias: string };
type RegistryCred = { id: number; alias: string; host: string; type: string };
type RepoEntry = { name: string; projectKey: string; files: UploadedFile[]; editedTmpls: Record<number, string>; skippedTmpls: number[] };
type PreflightFinding = { file: string; type: string; id: string; severity: string; title: string };
type PreflightResult = { files_checked: number; critical: number; high: number; medium: number; low: number; findings: PreflightFinding[]; scan_error: string };
type CreateResult = { name: string; status: "pending" | "creating" | "done" | "error"; message: string };

async function readEntry(entry: FileSystemEntry, basePath = ""): Promise<UploadedFile[]> {
  if (entry.isFile) {
    const fileEntry = entry as FileSystemFileEntry;
    return new Promise(resolve => {
      fileEntry.file(file => {
        const reader = new FileReader();
        reader.onload = () => resolve([{ path: basePath + entry.name, content: reader.result as string }]);
        reader.onerror = () => resolve([]);
        reader.readAsText(file);
      });
    });
  } else {
    const dirEntry = entry as FileSystemDirectoryEntry;
    const reader = dirEntry.createReader();
    return new Promise(resolve => {
      reader.readEntries(async entries => {
        const all: UploadedFile[] = [];
        for (const e of entries) {
          const sub = await readEntry(e, basePath + entry.name + "/");
          all.push(...sub);
        }
        resolve(all);
      });
    });
  }
}

export default function NewRepository() {
  const [step, setStep] = useState(1);

  const [extraBranch, setExtraBranch] = useState("");
  const [useExtraBranch, setUseExtraBranch] = useState(false);
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState("");
  const [createResults, setCreateResults] = useState<CreateResult[]>([]);
  const [preflightLoading, setPreflightLoading] = useState(false);
  const [preflightResult, setPreflightResult] = useState<PreflightResult | null>(null);

  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [argoInstances, setArgoInstances] = useState<ArgoCDInst[]>([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<number>(0);
  const [selectedArgoCDId, setSelectedArgoCDId] = useState<number>(-1);
  const [selectedProjectKey, setSelectedProjectKey] = useState<string>("");
  const [wsProjects, setWsProjects] = useState<Project[]>([]);

  const [registryCreds, setRegistryCreds] = useState<RegistryCred[]>([]);
  const [selectedRegistryId, setSelectedRegistryId] = useState<number>(0);
  const [dockerImagePrivate, setDockerImagePrivate] = useState(true);

  const [provider, setProvider] = useState<"bitbucket" | "github" | "gitlab">("bitbucket");

  const [templates, setTemplates] = useState<Template[]>([]);
  const [activeRepoTab, setActiveRepoTab] = useState(0);

  const loadTemplates = async () => {
    const res = await apiFetch(`/templates`);
    const data = await res.json();
    if (Array.isArray(data)) setTemplates(data.filter((t: Template) => t.is_active));
  };

  const [repoVars, setRepoVars] = useState<RepoVariable[]>([]);
  const [newVar, setNewVar] = useState<RepoVariable>({ key: "", value: "", secured: false });

  const emptyEntry = (projectKey = ""): RepoEntry => ({ name: "", projectKey, files: [], editedTmpls: {}, skippedTmpls: [] });

  const [repoEntries, setRepoEntries] = useState<RepoEntry[]>([emptyEntry()]);
  const [entryDragging, setEntryDragging] = useState<number | null>(null);

  const [extraYamls, setExtraYamls] = useState<{ path: string; content: string }[]>([]);

  const addExtraYaml = () =>
    setExtraYamls(prev => [...prev, { path: "", content: "" }]);
  const removeExtraYaml = (i: number) =>
    setExtraYamls(prev => prev.filter((_, idx) => idx !== i));
  const updateExtraYaml = (i: number, field: "path" | "content", val: string) =>
    setExtraYamls(prev => prev.map((y, idx) => idx === i ? { ...y, [field]: val } : y));

  const loadWsProjects = async (wsId: number, defaultKey: string) => {
    const res = await apiFetch(`/workspaces/${wsId}/projects`);
    const ps: Project[] = await res.json();
    const registered = Array.isArray(ps) ? ps : [];
    const combined: Project[] = [];
    if (defaultKey && !registered.find(p => p.project_key === defaultKey)) {
      combined.push({ id: 0, project_key: defaultKey, alias: "default" });
    }
    combined.push(...registered);
    setWsProjects(combined);
    setSelectedProjectKey(combined[0]?.project_key || defaultKey || "");
  };

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }

    apiFetch("/registry-credentials").then(r => r.json()).then(list => {
      if (Array.isArray(list)) setRegistryCreds(list);
    }).catch(() => {});

    loadTemplates();

    Promise.all([
      apiFetch("/workspaces").then(r => r.json()),
      apiFetch("/argocd-instances").then(r => r.json()),
    ]).then(([wsList, argoList]) => {
      if (Array.isArray(wsList)) {
        setWorkspaces(wsList);
        if (wsList.length > 0) {
          setSelectedWorkspaceId(wsList[0].id);
          loadWsProjects(wsList[0].id, wsList[0].project_key || "");
        }
      }
      if (Array.isArray(argoList)) {
        setArgoInstances(argoList);
        setSelectedArgoCDId(argoList.length > 0 ? argoList[0].id : 0);
      }
    });
  }, []);

  const getContent = (t: Template, entry: RepoEntry) => {
    const base = entry.editedTmpls[t.id] !== undefined ? entry.editedTmpls[t.id] : t.content;
    return base.replace(/\{\{\.ProjectName\}\}/g, entry.name || "project-name");
  };

  const textExt = /\.(ts|tsx|js|jsx|py|go|java|kt|scala|rb|rs|cs|cpp|c|h|sh|bash|yaml|yml|json|json5|md|txt|env|toml|xml|css|scss|html|htm|conf|cfg|ini|sql|graphql|proto|mod|sum|lock|tf|tfvars|hcl|properties|gradle|mvn|pom|Makefile|gitignore|dockerignore|editorconfig)$/i;
  const binaryExt = /\.(png|jpg|jpeg|gif|webp|ico|svg|pdf|zip|tar|gz|tgz|rar|7z|bin|exe|so|dll|class|jar|wasm|mp3|mp4|avi|mov|ttf|woff|woff2|eot)$/i;
  const cacheDir = /(\/__pycache__\/|\/\.mypy_cache\/|\/\.pytest_cache\/|\/node_modules\/|\/\.git\/|\/\.tox\/|\/\.venv\/|\/venv\/|\/dist\/|\/build\/|\/\.next\/)/;

  const filterFiles = (incoming: UploadedFile[]) => incoming.filter(f => {
    if (cacheDir.test("/" + f.path)) return false;
    if (binaryExt.test(f.path)) return false;
    return textExt.test(f.path) || !f.path.includes(".");
  });

  const addEntryFiles = (idx: number, incoming: UploadedFile[]) => {
    const filtered = filterFiles(incoming);
    setRepoEntries(prev => prev.map((e, i) => {
      if (i !== idx) return e;
      const map = new Map(e.files.map(f => [f.path, f]));
      filtered.forEach(f => map.set(f.path, f));
      return { ...e, files: Array.from(map.values()) };
    }));
  };

  const removeEntryFile = (idx: number, path: string) =>
    setRepoEntries(prev => prev.map((e, i) => i !== idx ? e : { ...e, files: e.files.filter(f => f.path !== path) }));

  const updateEntry = (idx: number, patch: Partial<RepoEntry>) =>
    setRepoEntries(prev => prev.map((e, i) => i !== idx ? e : { ...e, ...patch }));

  const addEntry = () =>
    setRepoEntries(prev => [...prev, emptyEntry(selectedProjectKey)]);

  const removeEntry = (idx: number) => {
    setRepoEntries(prev => prev.filter((_, i) => i !== idx));
    setActiveRepoTab(prev => Math.max(0, prev - 1));
  };

  const updateEntryTmpl = (idx: number, tmplId: number, content: string) =>
    setRepoEntries(prev => prev.map((e, i) => i !== idx ? e : { ...e, editedTmpls: { ...e.editedTmpls, [tmplId]: content } }));

  const toggleEntryTmpl = (idx: number, tmplId: number) =>
    setRepoEntries(prev => prev.map((e, i) => {
      if (i !== idx) return e;
      const skipped = e.skippedTmpls.includes(tmplId)
        ? e.skippedTmpls.filter(id => id !== tmplId)
        : [...e.skippedTmpls, tmplId];
      return { ...e, skippedTmpls: skipped };
    }));

  const addVar = () => {
    if (!newVar.key) return;
    setRepoVars(prev => [...prev, newVar]);
    setNewVar({ key: "", value: "", secured: false });
  };
  const removeVar = (i: number) => setRepoVars(prev => prev.filter((_, idx) => idx !== i));

  const buildPayload = (entry: RepoEntry) => ({
    name: entry.name,
    edited_templates: Object.entries(entry.editedTmpls).map(([id, content]) => ({ id: Number(id), content })),
    skipped_template_ids: entry.skippedTmpls,
    repo_variables: repoVars.filter(v => v.key),
    uploaded_files: [
      ...entry.files,
      ...extraYamls.filter(y => y.path && y.content),
    ],
    workspace_id: selectedWorkspaceId > 0 ? selectedWorkspaceId : undefined,
    argocd_instance_id: selectedArgoCDId > 0 ? selectedArgoCDId : undefined,
    project_key: entry.projectKey || selectedProjectKey || undefined,
    extra_branch: useExtraBranch && extraBranch ? extraBranch : undefined,
    registry_id: selectedRegistryId > 0 ? selectedRegistryId : undefined,
    docker_image_private: dockerImagePrivate,
    provider,
  });

  const handlePreflight = async () => {
    setPreflightLoading(true);
    setPreflightResult(null);
    try {
      const res = await apiFetch("/repositories/preflight", {
        method: "POST",
        body: JSON.stringify(buildPayload(repoEntries[0])),
      });
      const data: PreflightResult = await res.json();
      setPreflightResult(data);
    } catch {
      setPreflightResult({ files_checked: 0, critical: 0, high: 0, medium: 0, low: 0, findings: [], scan_error: "Failed to run security check" });
    } finally {
      setPreflightLoading(false);
    }
  };

  const handleCreate = async () => {
    setCreating(true);
    setMessage("");
    const validEntries = repoEntries.filter(e => e.name.trim());
    const results: CreateResult[] = validEntries.map(e => ({ name: e.name, status: "pending", message: "" }));
    setCreateResults(results);

    for (let i = 0; i < validEntries.length; i++) {
      results[i] = { ...results[i], status: "creating" };
      setCreateResults([...results]);
      try {
        const res = await apiFetch("/repositories", {
          method: "POST",
          body: JSON.stringify(buildPayload(validEntries[i])),
        });
        const data = await res.json();
        if (!res.ok) throw new Error(data.error || "Failed to create repo");
        results[i] = { ...results[i], status: "done", message: res.status === 202 ? "Pending approval" : "Created" };
      } catch (err: unknown) {
        results[i] = { ...results[i], status: "error", message: err instanceof Error ? err.message : "Unknown error" };
      }
      setCreateResults([...results]);
    }

    const anyError = results.some(r => r.status === "error");
    if (!anyError) {
      setMessage(results.length > 1 ? `✅ ${results.length} repositories created successfully!` : "✅ Repository created and ArgoCD configured successfully!");
      setTimeout(() => { window.location.href = "/"; }, 2500);
    } else {
      setMessage("⚠️ Some repositories could not be created. Check results below.");
      setCreating(false);
    }
  };

  const manifests = templates.filter(t => t.type === "manifest");
  const pipeline  = templates.find(t => t.type === "pipeline");

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <header>
        <h1 className="text-lg font-semibold bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold">
          New Repository
        </h1>
        <p className="text-zinc-400 mt-2">Bootstrap a repository with Kubernetes manifests and pre-configured pipeline.</p>
      </header>

      {message && (
        <div className={`p-4 rounded border ${message.startsWith("✅") ? "bg-brand-green/10 border-brand-green/50 text-brand-green" : "bg-red-500/10 border-red-500/50 text-red-400"}`}>
          {message}
        </div>
      )}

      {step === 1 && (
        <div className="space-y-6">
          <div className="glass-card p-6">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-xl font-bold">1. Repositories</h2>
              <button
                onClick={addEntry}
                className="text-sm text-zinc-400 hover:text-brand-green border border-zinc-700 hover:border-brand-green px-3 py-1.5 rounded transition-all"
              >
                + Add repository
              </button>
            </div>
            <div className="space-y-4">
              {repoEntries.map((entry, i) => (
                <div key={i} className="rounded-lg border border-zinc-700 bg-zinc-950 p-4 space-y-3">
                  <div className="flex items-center gap-2">
                    {repoEntries.length > 1 && (
                      <span className="text-xs text-zinc-500 font-mono shrink-0 w-5 text-center">#{i + 1}</span>
                    )}
                    <div className="flex-1 space-y-2">
                      <input
                        type="text"
                        value={entry.name}
                        onChange={e => updateEntry(i, { name: e.target.value.toLowerCase().replace(/\s+/g, "-") })}
                        className="input-tech w-full text-lg py-2.5 font-mono"
                        placeholder="repository-name"
                      />
                      {wsProjects.length > 0 && (
                        <div className="flex items-center gap-2">
                          <label className="text-xs text-zinc-500 shrink-0">Project:</label>
                          <select
                            className="input-tech text-sm py-1.5 flex-1"
                            value={entry.projectKey}
                            onChange={e => updateEntry(i, { projectKey: e.target.value })}
                          >
                            <option value="">— default project —</option>
                            {wsProjects.map(p => (
                              <option key={p.id || p.project_key} value={p.project_key}>
                                {p.project_key}{p.alias ? ` — ${p.alias}` : ""}
                              </option>
                            ))}
                          </select>
                        </div>
                      )}
                    </div>
                    {repoEntries.length > 1 && (
                      <button onClick={() => removeEntry(i)} className="text-red-400 hover:text-red-300 px-2 shrink-0 self-start mt-1">✕</button>
                    )}
                  </div>
                  <div
                    onDragOver={e => { e.preventDefault(); setEntryDragging(i); }}
                    onDragLeave={() => setEntryDragging(null)}
                    onDrop={async e => {
                      e.preventDefault();
                      setEntryDragging(null);
                      const items = Array.from(e.dataTransfer.items);
                      const all: UploadedFile[] = [];
                      for (const item of items) {
                        const fsEntry = item.webkitGetAsEntry?.();
                        if (fsEntry) all.push(...await readEntry(fsEntry));
                      }
                      addEntryFiles(i, all);
                    }}
                    className={`border-2 border-dashed rounded-lg px-4 py-3 text-center text-sm transition-all cursor-pointer ${entryDragging === i ? "border-purple-400 bg-purple-500/10" : "border-zinc-800 hover:border-zinc-600"}`}
                  >
                    {entry.files.length === 0
                      ? <span className="text-zinc-500">📁 Drag source code folder here <span className="text-zinc-600">(optional)</span></span>
                      : <span className="text-zinc-400">{entry.files.length} file(s) — drag to replace</span>
                    }
                  </div>
                  {entry.files.length > 0 && (
                    <div className="space-y-0.5 max-h-24 overflow-y-auto">
                      {entry.files.map(f => (
                        <div key={f.path} className="flex items-center gap-2 text-xs font-mono text-zinc-500 group">
                          <span className="text-purple-400">📄</span>
                          <span className="flex-1 truncate">{f.path}</span>
                          <button onClick={() => removeEntryFile(i, f.path)} className="text-red-400 opacity-0 group-hover:opacity-100 px-1">✕</button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              ))}
            </div>
            <p className="text-zinc-500 text-xs mt-3">Lowercase letters, numbers and hyphens only.</p>
          </div>

          <div className="glass-card p-6 border-l-4 border-l-zinc-700">
            <h2 className="text-xl font-bold mb-1">SCM Provider</h2>
            <p className="text-zinc-400 text-sm mb-4">Choose where the repository will be created.</p>
            <div className="flex gap-3 flex-wrap">
              {(["bitbucket", "github", "gitlab"] as const).map(p => (
                <button
                  key={p}
                  onClick={() => setProvider(p)}
                  className={`flex items-center gap-2 px-4 py-2.5 rounded-lg border text-sm font-medium transition-all ${
                    provider === p
                      ? "border-brand-green bg-brand-green/10 text-brand-green"
                      : "border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-white"
                  }`}
                >
                  <span>{p === "bitbucket" ? "🪣" : p === "github" ? "🐙" : "🦊"}</span>
                  <span className="capitalize">{p}</span>
                  {p !== "bitbucket" && (
                    <span className="text-xs text-zinc-600 border border-zinc-700 px-1.5 rounded">preview</span>
                  )}
                </button>
              ))}
            </div>
            {provider !== "bitbucket" && (
              <p className="text-xs text-yellow-500 mt-3 border border-yellow-500/30 bg-yellow-500/10 rounded px-3 py-2">
                ⚠️ {provider === "github" ? "GitHub" : "GitLab"} is in preview — repository creation is not yet implemented. Full support is under development.
              </p>
            )}
          </div>


          <div className="glass-card p-6 border-l-4 border-l-brand-green">
            <h2 className="text-xl font-bold mb-1">Working branch</h2>
            <p className="text-zinc-400 text-sm mb-4">The repository is always created with the <code className="text-brand-green font-mono">main</code> branch. You can define an additional branch for CommitKube to work with.</p>
            <div className="space-y-3">
              <label className="flex items-center gap-3 cursor-pointer group">
                <input
                  type="radio"
                  name="branch-mode"
                  checked={!useExtraBranch}
                  onChange={() => setUseExtraBranch(false)}
                  className="accent-brand-green"
                />
                <span className="text-sm text-zinc-300 group-hover:text-white transition-colors">
                  Use only <code className="text-brand-green font-mono">main</code>
                </span>
              </label>
              <label className="flex items-center gap-3 cursor-pointer group">
                <input
                  type="radio"
                  name="branch-mode"
                  checked={useExtraBranch}
                  onChange={() => setUseExtraBranch(true)}
                  className="accent-brand-green"
                />
                <span className="text-sm text-zinc-300 group-hover:text-white transition-colors">
                  Create a new working branch
                </span>
              </label>
              {useExtraBranch && (
                <div className="ml-6 mt-2 space-y-2">
                  <input
                    type="text"
                    className="input-tech text-sm font-mono"
                    placeholder="e.g. develop"
                    value={extraBranch}
                    onChange={e => setExtraBranch(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
                  />
                  {extraBranch && (
                    <p className="text-xs text-zinc-500">
                      Branch <code className="text-brand-gold font-mono">{extraBranch}</code> created from <code className="text-brand-green font-mono">main</code>. Pipeline and ArgoCD will point to it.
                    </p>
                  )}
                </div>
              )}
            </div>
          </div>

          {(workspaces.length > 0 || argoInstances.length > 0) && (
            <div className="glass-card p-6 border-l-4 border-l-[#0052CC]">
              <h2 className="text-xl font-bold mb-4">2. Workspace & ArgoCD</h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {workspaces.length > 0 && (
                  <div>
                    <label className="block text-sm font-medium text-zinc-400 mb-1">Bitbucket Workspace</label>
                    <select
                      className="input-tech text-sm"
                      value={selectedWorkspaceId}
                      onChange={e => {
                        const id = Number(e.target.value);
                        setSelectedWorkspaceId(id);
                        const ws = workspaces.find(w => w.id === id);
                        loadWsProjects(id, ws?.project_key || "");
                      }}
                    >
                      {workspaces.map(ws => (
                        <option key={ws.id} value={ws.id}>{ws.alias} ({ws.workspace_id})</option>
                      ))}
                    </select>
                  </div>
                )}
                {argoInstances.length > 0 && (
                  <div>
                    <label className="block text-sm font-medium text-zinc-400 mb-1">ArgoCD Instance</label>
                    <select
                      className="input-tech text-sm"
                      value={selectedArgoCDId === -1 ? "" : selectedArgoCDId}
                      onChange={e => setSelectedArgoCDId(Number(e.target.value))}
                    >
                      {argoInstances.map(inst => (
                        <option key={inst.id} value={inst.id}>{inst.alias} ({inst.server_url})</option>
                      ))}
                      <option value={0}>— No ArgoCD —</option>
                    </select>
                  </div>
                )}
              </div>
            </div>
          )}

          {registryCreds.length > 0 && (
            <div className="glass-card p-6 border-l-4 border-l-cyan-500">
              <h2 className="text-xl font-bold mb-1">3. Docker Image Registry <span className="text-sm font-normal text-zinc-400">(optional)</span></h2>
              <p className="text-zinc-400 text-sm mb-4">Select a registry to create a Docker image repository for this project.</p>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <label className="block text-sm font-medium text-zinc-400 mb-1">Registry</label>
                  <select
                    className="input-tech text-sm"
                    value={selectedRegistryId}
                    onChange={e => setSelectedRegistryId(Number(e.target.value))}
                  >
                    <option value={0}>— None —</option>
                    {registryCreds.map(r => (
                      <option key={r.id} value={r.id}>{r.alias} ({r.host})</option>
                    ))}
                  </select>
                </div>
                {selectedRegistryId > 0 && (
                  <div>
                    <label className="block text-sm font-medium text-zinc-400 mb-1">Visibility</label>
                    <div className="flex gap-4 mt-2">
                      <label className="flex items-center gap-2 cursor-pointer text-sm text-zinc-300">
                        <input type="radio" name="docker-visibility" checked={dockerImagePrivate} onChange={() => setDockerImagePrivate(true)} className="accent-brand-green" />
                        Private
                      </label>
                      <label className="flex items-center gap-2 cursor-pointer text-sm text-zinc-300">
                        <input type="radio" name="docker-visibility" checked={!dockerImagePrivate} onChange={() => setDockerImagePrivate(false)} className="accent-brand-green" />
                        Public
                      </label>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          <div className="glass-card p-6 border-l-4 border-l-yellow-500">
            <h2 className="text-xl font-bold mb-1">4. Repository-specific variables <span className="text-sm font-normal text-zinc-400">(optional)</span></h2>
            <p className="text-zinc-400 text-sm mb-4">Variables that will only exist in this repository. Global variables are applied automatically.</p>
            <div className="space-y-2 mb-3">
              {repoVars.map((v, i) => (
                <div key={i} className="flex items-center gap-3 p-2 rounded bg-zinc-900 border border-zinc-800">
                  <span className="font-mono text-brand-green text-sm flex-1">{v.key}</span>
                  <span className="text-zinc-400 text-sm flex-1">{v.secured ? "●●●●●●●" : v.value}</span>
                  {v.secured && <span className="text-xs text-yellow-500 bg-yellow-500/10 px-2 py-0.5 rounded">secured</span>}
                  <button onClick={() => removeVar(i)} className="text-red-400 text-sm px-1">✕</button>
                </div>
              ))}
            </div>
            <div className="flex gap-2 flex-wrap">
              <input className="input-tech flex-1 min-w-28 text-sm" placeholder="KEY" value={newVar.key} onChange={e => setNewVar({...newVar, key: e.target.value})} />
              <input className="input-tech flex-1 min-w-44 text-sm" placeholder="value" type={newVar.secured ? "password" : "text"} value={newVar.value} onChange={e => setNewVar({...newVar, value: e.target.value})} />
              <label className="flex items-center gap-1.5 text-sm text-zinc-400 cursor-pointer">
                <input type="checkbox" checked={newVar.secured} onChange={e => setNewVar({...newVar, secured: e.target.checked})} className="accent-brand-green" />
                Secured
              </label>
              <button onClick={addVar} className="btn-primary px-4 py-2 text-sm">+ Add</button>
            </div>
            {newVar.key && (
              <p className="text-yellow-400 text-xs mt-2">⚠️ Variable &quot;{newVar.key}&quot; has not been added yet. Click &quot;+ Add&quot; before proceeding.</p>
            )}
          </div>


          <div className="flex justify-end">
            <button
              onClick={() => { if (repoEntries.every(e => e.name.trim())) setStep(2); }}
              disabled={!repoEntries.every(e => e.name.trim())}
              className="btn-primary"
            >
              Next: Review Manifests →
            </button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="space-y-6">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <p className="text-zinc-400 text-sm">Review and edit the manifests. Changes apply only to the selected repository.</p>
            {repoEntries.length > 1 && (
              <div className="flex gap-1 flex-wrap">
                {repoEntries.map((e, i) => (
                  <button
                    key={i}
                    onClick={() => setActiveRepoTab(i)}
                    className={`px-3 py-1.5 rounded text-sm font-medium transition-all ${
                      activeRepoTab === i
                        ? "bg-brand-green text-black"
                        : "border border-zinc-700 text-zinc-400 hover:border-zinc-500 hover:text-white"
                    }`}
                  >
                    {e.name || `Repo ${i + 1}`}
                  </button>
                ))}
              </div>
            )}
          </div>

          {manifests.length === 0 && (
            <div className="glass-card p-6 border-l-4 border-l-zinc-600">
              <p className="text-zinc-400 text-sm">
                No manifest templates configured.{" "}
                <a href="/templates" className="text-brand-green underline hover:text-brand-gold">
                  Create your templates in Templates →
                </a>
              </p>
            </div>
          )}
          {manifests.map(t => {
            const entry = repoEntries[activeRepoTab];
            const skipped = entry.skippedTmpls.includes(t.id);
            return (
              <div key={t.id} className={`glass-card p-6 transition-opacity ${skipped ? "opacity-40" : ""}`} style={{ borderLeft: `4px solid ${t.name.includes("deploy") ? "#a855f7" : t.name.includes("service") ? "#3b82f6" : "#f59e0b"}` }}>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-bold text-lg" style={{ color: t.name.includes("deploy") ? "#c084fc" : t.name.includes("service") ? "#60a5fa" : "#fbbf24" }}>
                    {t.name}
                  </h3>
                  <button
                    onClick={() => toggleEntryTmpl(activeRepoTab, t.id)}
                    className={`text-xs px-3 py-1 rounded border transition-all ${skipped ? "border-red-500/50 text-red-400 bg-red-500/10 hover:bg-red-500/20" : "border-zinc-600 text-zinc-400 hover:border-red-500/50 hover:text-red-400"}`}
                  >
                    {skipped ? "✕ Skipped" : "Skip"}
                  </button>
                </div>
                {!skipped && (
                  <textarea
                    className="w-full bg-zinc-950 border border-zinc-800 text-brand-green font-mono text-xs p-4 rounded focus:outline-none focus:border-brand-green"
                    rows={12}
                    value={getContent(t, entry)}
                    onChange={e => updateEntryTmpl(activeRepoTab, t.id, e.target.value)}
                  />
                )}
              </div>
            );
          })}

          {!pipeline && (
            <div className="glass-card p-6 border-l-4 border-l-zinc-600">
              <p className="text-zinc-400 text-sm">
                No pipeline template configured.{" "}
                <a href="/templates" className="text-brand-green underline hover:text-brand-gold">
                  Create your pipeline template in Templates →
                </a>
              </p>
            </div>
          )}
          {pipeline && (() => {
            const entry = repoEntries[activeRepoTab];
            const skipped = entry.skippedTmpls.includes(pipeline.id);
            return (
              <div className={`glass-card p-6 border-l-4 border-l-yellow-500 transition-opacity ${skipped ? "opacity-40" : ""}`}>
                <div className="flex items-center justify-between mb-2">
                  <h3 className="font-bold text-lg text-yellow-400">🔧 bitbucket-pipelines.yml</h3>
                  <button
                    onClick={() => toggleEntryTmpl(activeRepoTab, pipeline.id)}
                    className={`text-xs px-3 py-1 rounded border transition-all ${skipped ? "border-red-500/50 text-red-400 bg-red-500/10 hover:bg-red-500/20" : "border-zinc-600 text-zinc-400 hover:border-red-500/50 hover:text-red-400"}`}
                  >
                    {skipped ? "✕ Skipped" : "Skip"}
                  </button>
                </div>
                {!skipped && (
                  <textarea
                    className="w-full bg-zinc-950 border border-zinc-800 text-yellow-300 font-mono text-xs p-4 rounded focus:outline-none focus:border-yellow-500"
                    rows={10}
                    value={getContent(pipeline, entry)}
                    onChange={e => updateEntryTmpl(activeRepoTab, pipeline.id, e.target.value)}
                  />
                )}
              </div>
            );
          })()}

          <div className="glass-card p-6 border-l-4 border-l-brand-green">
            <div className="flex items-center justify-between mb-1">
              <h3 className="font-bold text-lg text-brand-green">Project-specific YAMLs</h3>
              <button onClick={addExtraYaml} className="btn-primary text-sm px-3 py-1.5">+ New YAML</button>
            </div>
            <p className="text-zinc-400 text-sm mb-4">Create additional YAML files that will only exist in this repository.</p>

            {extraYamls.length === 0 && (
              <p className="text-zinc-500 text-sm italic">No extra YAMLs added.</p>
            )}

            {extraYamls.map((y, i) => (
              <div key={i} className="mb-4 rounded border border-zinc-700 bg-zinc-950 p-4 space-y-2">
                <div className="flex items-center gap-2">
                  <input
                    className="input-tech flex-1 text-sm font-mono"
                    placeholder="path/to/file.yaml"
                    value={y.path}
                    onChange={e => updateExtraYaml(i, "path", e.target.value)}
                  />
                  <button onClick={() => removeExtraYaml(i)} className="text-red-400 hover:text-red-300 px-2 text-lg">✕</button>
                </div>
                <textarea
                  className="w-full bg-zinc-900 border border-zinc-700 text-brand-green font-mono text-xs p-3 rounded focus:outline-none focus:border-brand-green"
                  rows={10}
                  placeholder="# YAML content..."
                  value={y.content}
                  onChange={e => updateExtraYaml(i, "content", e.target.value)}
                />
              </div>
            ))}
          </div>

          {repoVars.length > 0 && (
            <div className="glass-card p-4 border border-zinc-700">
              <p className="text-sm text-zinc-400">
                🔑 <strong>{repoVars.length}</strong> repo variable(s) applied to all repositories
              </p>
            </div>
          )}

          {preflightResult && (
            <div className={`glass-card p-6 border-l-4 ${preflightResult.critical > 0 ? "border-l-red-500" : preflightResult.high > 0 ? "border-l-orange-500" : preflightResult.scan_error ? "border-l-yellow-500" : "border-l-brand-green"}`}>
              <div className="flex items-center justify-between mb-4">
                <h3 className="font-bold text-lg">Security Check Results</h3>
                <span className="text-xs text-zinc-500">{preflightResult.files_checked} file(s) scanned</span>
              </div>

              {preflightResult.scan_error ? (
                <div className="text-yellow-400 text-sm bg-yellow-500/10 border border-yellow-500/30 rounded p-3 mb-4">
                  ⚠️ {preflightResult.scan_error}
                </div>
              ) : (
                <div className="flex gap-3 mb-4 flex-wrap">
                  {[
                    { label: "Critical", count: preflightResult.critical, color: "text-red-400 bg-red-500/10 border-red-500/30" },
                    { label: "High", count: preflightResult.high, color: "text-orange-400 bg-orange-500/10 border-orange-500/30" },
                    { label: "Medium", count: preflightResult.medium, color: "text-yellow-400 bg-yellow-500/10 border-yellow-500/30" },
                    { label: "Low", count: preflightResult.low, color: "text-green-400 bg-green-500/10 border-green-500/30" },
                  ].map(({ label, count, color }) => (
                    <div key={label} className={`px-4 py-2 rounded border text-sm font-bold ${color}`}>
                      {count} <span className="font-normal text-xs block">{label}</span>
                    </div>
                  ))}
                </div>
              )}

              {preflightResult.findings.length === 0 && !preflightResult.scan_error && (
                <p className="text-brand-green text-sm">No security issues found in your manifests.</p>
              )}

              {preflightResult.findings.length > 0 && (
                <div className="space-y-1 max-h-64 overflow-y-auto">
                  {preflightResult.findings.map((f, i) => (
                    <div key={i} className="flex items-start gap-3 text-xs p-2 rounded bg-zinc-900 border border-zinc-800">
                      <span className={`font-bold shrink-0 ${f.severity === "CRITICAL" ? "text-red-400" : f.severity === "HIGH" ? "text-orange-400" : f.severity === "MEDIUM" ? "text-yellow-400" : "text-green-400"}`}>
                        {f.severity}
                      </span>
                      <span className={`shrink-0 px-1.5 py-0.5 rounded text-xs ${f.type === "secret" ? "bg-red-500/20 text-red-300" : "bg-zinc-700 text-zinc-300"}`}>
                        {f.type}
                      </span>
                      <span className="text-zinc-400 font-mono shrink-0">{f.id}</span>
                      <span className="text-zinc-200 flex-1">{f.title}</span>
                      <span className="text-zinc-600 truncate max-w-32">{f.file.split("/").pop()}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {createResults.length > 0 && (
            <div className="glass-card p-4 space-y-2">
              <p className="text-xs text-zinc-500 mb-2 font-medium">Creation progress</p>
              {createResults.map((r, i) => (
                <div key={i} className="flex items-center gap-3 text-sm">
                  <span className="font-mono text-zinc-300 flex-1">{r.name}</span>
                  {r.status === "pending" && <span className="text-zinc-500">Waiting...</span>}
                  {r.status === "creating" && <span className="text-brand-green animate-pulse">Creating...</span>}
                  {r.status === "done" && <span className="text-brand-green">✓ {r.message}</span>}
                  {r.status === "error" && <span className="text-red-400">✗ {r.message}</span>}
                </div>
              ))}
            </div>
          )}

          <div className="flex items-center justify-between glass-card p-6">
            <button onClick={() => { setStep(1); setPreflightResult(null); setCreateResults([]); }} className="btn-secondary">← Back</button>
            <div className="flex items-center gap-3">
              {repoEntries.length > 1 && (
                <span className="text-xs text-zinc-500">{repoEntries.filter(e => e.name.trim()).length} repositories</span>
              )}
              {!preflightResult ? (
                <button
                  onClick={handlePreflight}
                  disabled={preflightLoading}
                  className="btn-primary px-6 py-3 text-base bg-zinc-700 hover:bg-zinc-600 border-zinc-500 shadow-none"
                >
                  {preflightLoading ? "Scanning..." : "🔍 Run Security Check"}
                </button>
              ) : (
                <button
                  onClick={handlePreflight}
                  disabled={preflightLoading}
                  className="text-sm text-zinc-400 hover:text-zinc-200 underline"
                >
                  {preflightLoading ? "Scanning..." : "Re-run check"}
                </button>
              )}
              <button onClick={handleCreate} disabled={creating} className="btn-primary px-8 py-3 text-lg shadow-[0_0_20px_rgba(16,185,129,0.3)]">
                {creating ? "Creating..." : preflightResult ? "🚀 Confirm & Deploy" : "🚀 Create and Deploy"}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
