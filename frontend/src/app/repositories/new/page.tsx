"use client";

import { useState, useEffect, useCallback, useRef, DragEvent, ClipboardEvent } from "react";
import { apiFetch } from "@/lib/api";

type Template = { id: number; name: string; path: string; content: string; type: string; is_active: boolean };
type RepoVariable = { key: string; value: string; secured: boolean };
type UploadedFile = { path: string; content: string };
type Workspace = { id: number; alias: string; workspace_id: string; project_key: string };
type ArgoCDInst = { id: number; alias: string; server_url: string };
type Project = { id: number; project_key: string; alias: string };
type RegistryCred = { id: number; alias: string; host: string; type: string };

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
  const [name, setName] = useState("");
  const [extraBranch, setExtraBranch] = useState("");
  const [useExtraBranch, setUseExtraBranch] = useState(false);
  const [creating, setCreating] = useState(false);
  const [message, setMessage] = useState("");

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
  const [editedTmpls, setEditedTmpls] = useState<Record<number, string>>({});

  const loadTemplates = async () => {
    const res = await apiFetch(`/templates`);
    const data = await res.json();
    if (Array.isArray(data)) setTemplates(data.filter((t: Template) => t.is_active));
  };

  const [repoVars, setRepoVars] = useState<RepoVariable[]>([]);
  const [newVar, setNewVar] = useState<RepoVariable>({ key: "", value: "", secured: false });

  const [uploadedFiles, setUploadedFiles] = useState<UploadedFile[]>([]);
  const [dragging, setDragging] = useState(false);
  const [pasteText, setPasteText] = useState<string | null>(null);
  const [pasteFileName, setPasteFileName] = useState("");
  const dropZoneRef = useRef<HTMLDivElement>(null);

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

  const getContent = (t: Template) => {
    const base = editedTmpls[t.id] !== undefined ? editedTmpls[t.id] : t.content;
    return base.replace(/\{\{\.ProjectName\}\}/g, name || "project-name");
  };

  const textExt = /\.(ts|tsx|js|jsx|py|go|java|kt|scala|rb|rs|cs|cpp|c|h|sh|bash|yaml|yml|json|json5|md|txt|env|toml|xml|css|scss|html|htm|conf|cfg|ini|sql|graphql|proto|mod|sum|lock|tf|tfvars|hcl|properties|gradle|mvn|pom|Makefile|gitignore|dockerignore|editorconfig)$/i;
  const binaryExt = /\.(png|jpg|jpeg|gif|webp|ico|svg|pdf|zip|tar|gz|tgz|rar|7z|bin|exe|so|dll|class|jar|wasm|mp3|mp4|avi|mov|ttf|woff|woff2|eot)$/i;

  const addFiles = useCallback((incoming: UploadedFile[]) => {
    const filtered = incoming.filter(f => {
      if (binaryExt.test(f.path)) return false;
      return textExt.test(f.path) || !f.path.includes(".");
    });
    setUploadedFiles(prev => {
      const map = new Map(prev.map(f => [f.path, f]));
      filtered.forEach(f => map.set(f.path, f));
      return Array.from(map.values());
    });
  }, []);

  const onDrop = useCallback(async (e: React.DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setDragging(false);
    const items = Array.from(e.dataTransfer.items);
    const allFiles: UploadedFile[] = [];
    for (const item of items) {
      const entry = item.webkitGetAsEntry?.();
      if (entry) {
        const files = await readEntry(entry);
        allFiles.push(...files);
      }
    }
    addFiles(allFiles);
  }, [addFiles]);

  const onPaste = useCallback(async (e: ClipboardEvent<HTMLDivElement>) => {
    const items = Array.from(e.clipboardData.items);
    const fileItems = items.filter(i => i.kind === "file");
    if (fileItems.length > 0) {
      e.preventDefault();
      const allFiles: UploadedFile[] = [];
      for (const item of fileItems) {
        const file = item.getAsFile();
        if (!file) continue;
        const text = await file.text();
        allFiles.push({ path: file.name, content: text });
      }
      addFiles(allFiles);
      return;
    }
    const textItem = items.find(i => i.kind === "string" && i.type === "text/plain");
    if (textItem) {
      textItem.getAsString(text => {
        setPasteText(text);
        setPasteFileName("");
      });
    }
  }, [addFiles]);

  const confirmPasteText = () => {
    if (!pasteFileName || pasteText === null) return;
    addFiles([{ path: pasteFileName, content: pasteText }]);
    setPasteText(null);
    setPasteFileName("");
  };

  const removeUploadedFile = (path: string) =>
    setUploadedFiles(prev => prev.filter(f => f.path !== path));

  const addVar = () => {
    if (!newVar.key) return;
    setRepoVars(prev => [...prev, newVar]);
    setNewVar({ key: "", value: "", secured: false });
  };
  const removeVar = (i: number) => setRepoVars(prev => prev.filter((_, idx) => idx !== i));

  const handleCreate = async () => {
    setCreating(true);
    setMessage("");

    try {
      const res = await apiFetch("/repositories", {
        method: "POST",
        body: JSON.stringify({
          name,
          edited_templates: Object.entries(editedTmpls).map(([id, content]) => ({ id: Number(id), content })),
          repo_variables: repoVars.filter(v => v.key),
          uploaded_files: [
            ...uploadedFiles,
            ...extraYamls.filter(y => y.path && y.content),
          ],
          workspace_id: selectedWorkspaceId > 0 ? selectedWorkspaceId : undefined,
          argocd_instance_id: selectedArgoCDId > 0 ? selectedArgoCDId : undefined,
          project_key: selectedProjectKey || undefined,
          extra_branch: useExtraBranch && extraBranch ? extraBranch : undefined,
          registry_id: selectedRegistryId > 0 ? selectedRegistryId : undefined,
          docker_image_private: dockerImagePrivate,
          provider,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to create repo");
      if (res.status === 202) {
        setMessage("⏳ Repository pending admin approval.");
        setTimeout(() => { window.location.href = "/"; }, 3000);
        return;
      }
      setMessage("✅ Repository created and ArgoCD configured successfully!");
      setTimeout(() => { window.location.href = "/"; }, 2500);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setMessage(`❌ Error: ${msg}`);
      setCreating(false);
    }
  };

  const manifests = templates.filter(t => t.type === "manifest");
  const pipeline  = templates.find(t => t.type === "pipeline");

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <header>
        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold">
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
          <div className="glass-card p-8">
            <h2 className="text-xl font-bold mb-6">1. Repository Name</h2>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
              className="input-tech text-xl py-3"
              placeholder="e.g. my-app"
            />
            <p className="text-zinc-500 text-xs mt-2">Lowercase letters, numbers and hyphens only.</p>
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
                    <div className="mt-2">
                      <label className="block text-xs text-zinc-500 mb-1">Project Key</label>
                      <select
                        className="input-tech text-sm"
                        value={selectedProjectKey}
                        onChange={e => setSelectedProjectKey(e.target.value)}
                      >
                        {wsProjects.map(p => (
                          <option key={p.id || p.project_key} value={p.project_key}>
                            {p.project_key}{p.alias ? ` — ${p.alias}` : ""}
                          </option>
                        ))}
                        {wsProjects.length === 0 && <option value="">— No project keys registered —</option>}
                      </select>
                    </div>
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

          <div className="glass-card p-6 border-l-4 border-l-purple-500">
            <h2 className="text-xl font-bold mb-1">5. Source Code Upload <span className="text-sm font-normal text-zinc-400">(optional)</span></h2>
            <p className="text-zinc-400 text-sm mb-4">Drag a folder with the project code. Files will be committed alongside the manifests.</p>

            <div
              onDragOver={e => { e.preventDefault(); setDragging(true); }}
              onDragLeave={() => setDragging(false)}
              onDrop={onDrop}
              className={`border-2 border-dashed rounded-xl p-10 text-center transition-all duration-200 cursor-pointer ${dragging ? "border-purple-400 bg-purple-500/10" : "border-zinc-700 hover:border-zinc-500"}`}
            >
              <div className="text-4xl mb-3">📁</div>
              <p className="text-zinc-300 font-medium">Drag a folder here</p>
              <p className="text-zinc-500 text-sm mt-1">Only text/code files will be included</p>
            </div>

            {uploadedFiles.length > 0 && (
              <div className="mt-4 space-y-1 max-h-48 overflow-y-auto">
                <p className="text-zinc-400 text-sm font-medium">{uploadedFiles.length} file(s) selected:</p>
                {uploadedFiles.map(f => (
                  <div key={f.path} className="flex items-center gap-2 text-xs font-mono text-zinc-400 hover:text-zinc-200 group">
                    <span className="text-purple-400">📄</span>
                    <span className="flex-1 truncate">{f.path}</span>
                    <button onClick={() => removeUploadedFile(f.path)} className="text-red-400 opacity-0 group-hover:opacity-100 px-1">✕</button>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div className="flex justify-end">
            <button
              onClick={() => name && setStep(2)}
              disabled={!name}
              className="btn-primary"
            >
              Next: Review Manifests →
            </button>
          </div>
        </div>
      )}

      {step === 2 && (
        <div className="space-y-6">
          <p className="text-zinc-400">Review and edit the manifests that will be committed. Base templates come from <strong>Templates</strong>. <span className="text-brand-green text-sm">✏️ All fields are editable.</span></p>

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
          {manifests.map(t => (
            <div key={t.id} className="glass-card p-6" style={{ borderLeft: `4px solid ${t.name.includes("deploy") ? "#a855f7" : t.name.includes("service") ? "#3b82f6" : "#f59e0b"}` }}>
              <h3 className="font-bold text-lg mb-2" style={{ color: t.name.includes("deploy") ? "#c084fc" : t.name.includes("service") ? "#60a5fa" : "#fbbf24" }}>
                {t.name}
              </h3>
              <textarea
                className="w-full bg-zinc-950 border border-zinc-800 text-brand-green font-mono text-xs p-4 rounded focus:outline-none focus:border-brand-green"
                rows={12}
                value={getContent(t)}
                onChange={e => setEditedTmpls(prev => ({ ...prev, [t.id]: e.target.value }))}
              />
            </div>
          ))}

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
          {pipeline && (
            <div className="glass-card p-6 border-l-4 border-l-yellow-500">
              <h3 className="font-bold text-lg mb-2 text-yellow-400">🔧 bitbucket-pipelines.yml</h3>
              <textarea
                className="w-full bg-zinc-950 border border-zinc-800 text-yellow-300 font-mono text-xs p-4 rounded focus:outline-none focus:border-yellow-500"
                rows={10}
                value={getContent(pipeline)}
                onChange={e => setEditedTmpls(prev => ({ ...prev, [pipeline.id]: e.target.value }))}
              />
            </div>
          )}

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

          {(repoVars.length > 0 || uploadedFiles.length > 0) && (
            <div className="glass-card p-4 border border-zinc-700">
              <p className="text-sm text-zinc-400">
                {repoVars.length > 0 && <span>🔑 <strong>{repoVars.length}</strong> repo variable(s) &nbsp;</span>}
                {uploadedFiles.length > 0 && <span>📁 <strong>{uploadedFiles.length}</strong> source file(s) to commit</span>}
              </p>
            </div>
          )}

          <div className="flex items-center justify-between glass-card p-6">
            <button onClick={() => setStep(1)} className="btn-secondary">← Back</button>
            <button onClick={handleCreate} disabled={creating} className="btn-primary px-8 py-3 text-lg shadow-[0_0_20px_rgba(16,185,129,0.3)]">
              {creating ? "Creating and Committing..." : "🚀 Create and Deploy"}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
