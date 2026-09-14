"use client";

import { useState, useEffect } from "react";
import { apiFetch } from "@/lib/api";

type Workspace = { id: number; alias: string; workspace_id: string; project_key: string };
type Project = { id: number; project_key: string; alias: string };
type ImportResult = { imported: string[]; skipped: string[]; total: number };

export default function ImportRepository() {
  const [mode, setMode] = useState<"single" | "project">("single");
  const [name, setName] = useState("");
  const [argoApp, setArgoApp] = useState("");
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedWorkspaceId, setSelectedWorkspaceId] = useState<number>(0);
  const [selectedProjectKey, setSelectedProjectKey] = useState<string>("");
  const [importing, setImporting] = useState(false);
  const [message, setMessage] = useState("");
  const [projectResult, setProjectResult] = useState<ImportResult | null>(null);

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }
    const role = localStorage.getItem("role") || "";
    if (role !== "root" && role !== "admin") { window.location.href = "/"; return; }
    apiFetch("/workspaces").then(r => r.json()).then(data => {
      if (Array.isArray(data)) {
        setWorkspaces(data);
        if (data.length > 0) {
          setSelectedWorkspaceId(data[0].id);
          setSelectedProjectKey(data[0].project_key || "");
          loadProjects(data[0].id, data[0].project_key || "");
        }
      }
    });
  }, []);

  const loadProjects = async (wsId: number, defaultKey: string) => {
    const res = await apiFetch(`/workspaces/${wsId}/projects`);
    const ps: Project[] = await res.json();
    const registered = Array.isArray(ps) ? ps : [];
    const combined: Project[] = [];
    if (defaultKey && !registered.find(p => p.project_key === defaultKey)) {
      combined.push({ id: 0, project_key: defaultKey, alias: "default" });
    }
    combined.push(...registered);
    setProjects(combined);
    setSelectedProjectKey(combined[0]?.project_key || defaultKey || "");
  };

  const handleWorkspaceChange = (wsId: number) => {
    setSelectedWorkspaceId(wsId);
    const ws = workspaces.find(w => w.id === wsId);
    if (ws) {
      setSelectedProjectKey(ws.project_key || "");
      loadProjects(wsId, ws.project_key || "");
    }
  };

  const handleImportSingle = async () => {
    if (!name) return;
    setImporting(true);
    setMessage("");
    try {
      const res = await apiFetch("/repositories/import", {
        method: "POST",
        body: JSON.stringify({
          name,
          workspace_id: selectedWorkspaceId > 0 ? selectedWorkspaceId : undefined,
          argo_app: argoApp || undefined,
          project_key: selectedProjectKey || undefined,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to import");
      setMessage("✅ Repository imported successfully!");
      setTimeout(() => { window.location.href = "/"; }, 2000);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setMessage(`❌ Error: ${msg}`);
      setImporting(false);
    }
  };

  const handleImportProject = async () => {
    if (!selectedWorkspaceId || !selectedProjectKey) return;
    setImporting(true);
    setMessage("");
    setProjectResult(null);
    try {
      const res = await apiFetch("/repositories/import-project", {
        method: "POST",
        body: JSON.stringify({
          workspace_id: selectedWorkspaceId,
          project_key: selectedProjectKey,
        }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to import project");
      setProjectResult(data as ImportResult);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Unknown error";
      setMessage(`❌ Error: ${msg}`);
    } finally {
      setImporting(false);
    }
  };

  return (
    <div className="max-w-2xl mx-auto space-y-8">
      <header>
        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold">
          Import Repository
        </h1>
        <p className="text-zinc-400 mt-2">
          Add existing Bitbucket repositories to CommitKube without creating anything new.
        </p>
      </header>

      <div className="flex gap-2">
        <button
          onClick={() => { setMode("single"); setMessage(""); setProjectResult(null); }}
          className={`px-4 py-2 rounded-lg text-sm font-medium border transition-all ${mode === "single" ? "border-brand-green bg-brand-green/10 text-brand-green" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}
        >
          Single Repository
        </button>
        <button
          onClick={() => { setMode("project"); setMessage(""); setProjectResult(null); }}
          className={`px-4 py-2 rounded-lg text-sm font-medium border transition-all ${mode === "project" ? "border-brand-gold bg-brand-gold/10 text-brand-gold" : "border-zinc-700 text-zinc-400 hover:border-zinc-500"}`}
        >
          Entire Project
        </button>
      </div>

      {message && (
        <div className={`p-4 rounded border ${message.startsWith("✅") ? "bg-brand-green/10 border-brand-green/50 text-brand-green" : "bg-red-500/10 border-red-500/50 text-red-400"}`}>
          {message}
        </div>
      )}

      {mode === "single" && (
        <div className="glass-card p-8 space-y-6">
          <div>
            <label className="block text-sm font-medium text-zinc-400 mb-1">Repository name <span className="text-red-400">*</span></label>
            <input
              type="text"
              value={name}
              onChange={e => setName(e.target.value.toLowerCase().replace(/\s+/g, "-"))}
              className="input-tech text-lg py-3"
              placeholder="my-existing-repo"
            />
            <p className="text-zinc-500 text-xs mt-1">Must match the exact name in Bitbucket.</p>
          </div>

          {workspaces.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-zinc-400 mb-1">Bitbucket Workspace</label>
              <select
                className="input-tech text-sm"
                value={selectedWorkspaceId}
                onChange={e => setSelectedWorkspaceId(Number(e.target.value))}
              >
                {workspaces.map(ws => (
                  <option key={ws.id} value={ws.id}>{ws.alias} ({ws.workspace_id})</option>
                ))}
              </select>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-zinc-400 mb-1">ArgoCD App name <span className="text-zinc-500 font-normal">(optional)</span></label>
            <input
              type="text"
              value={argoApp}
              onChange={e => setArgoApp(e.target.value)}
              className="input-tech text-sm"
              placeholder={name || "my-existing-repo"}
            />
            <p className="text-zinc-500 text-xs mt-1">Leave blank to use the repository name.</p>
          </div>

          <div className="flex items-center justify-between pt-2">
            <a href="/" className="btn-secondary">← Cancel</a>
            <button
              onClick={handleImportSingle}
              disabled={!name || importing}
              className="btn-primary px-8 py-3 text-lg"
            >
              {importing ? "Importing..." : "Import Repository"}
            </button>
          </div>
        </div>
      )}

      {mode === "project" && (
        <div className="glass-card p-8 space-y-6">
          <p className="text-sm text-zinc-400">
            Fetch all repositories from a Bitbucket project and import them into CommitKube at once.
            Repositories already registered will be skipped.
          </p>

          {workspaces.length > 0 && (
            <div>
              <label className="block text-sm font-medium text-zinc-400 mb-1">Bitbucket Workspace</label>
              <select
                className="input-tech text-sm"
                value={selectedWorkspaceId}
                onChange={e => handleWorkspaceChange(Number(e.target.value))}
              >
                {workspaces.map(ws => (
                  <option key={ws.id} value={ws.id}>{ws.alias} ({ws.workspace_id})</option>
                ))}
              </select>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-zinc-400 mb-1">Project Key <span className="text-red-400">*</span></label>
            {projects.length > 1 ? (
              <select
                className="input-tech text-sm"
                value={selectedProjectKey}
                onChange={e => setSelectedProjectKey(e.target.value)}
              >
                {projects.map(p => (
                  <option key={p.project_key} value={p.project_key}>
                    {p.alias ? `${p.alias} (${p.project_key})` : p.project_key}
                  </option>
                ))}
              </select>
            ) : (
              <input
                type="text"
                value={selectedProjectKey}
                onChange={e => setSelectedProjectKey(e.target.value.toUpperCase())}
                className="input-tech text-sm font-mono"
                placeholder="MYPROJECT"
              />
            )}
            <p className="text-zinc-500 text-xs mt-1">The Bitbucket project key (e.g. CORE, MYPROJ).</p>
          </div>

          {projectResult && (
            <div className="space-y-3">
              <div className="grid grid-cols-3 gap-3">
                <div className="text-center p-3 rounded-lg bg-brand-green/10 border border-brand-green/30">
                  <div className="text-2xl font-black text-brand-green">{projectResult.imported.length}</div>
                  <div className="text-xs text-zinc-400 mt-0.5">Imported</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-zinc-800/50 border border-zinc-700">
                  <div className="text-2xl font-black text-zinc-400">{projectResult.skipped.length}</div>
                  <div className="text-xs text-zinc-400 mt-0.5">Skipped</div>
                </div>
                <div className="text-center p-3 rounded-lg bg-zinc-800/50 border border-zinc-700">
                  <div className="text-2xl font-black text-zinc-300">{projectResult.total}</div>
                  <div className="text-xs text-zinc-400 mt-0.5">Total found</div>
                </div>
              </div>
              {projectResult.imported.length > 0 && (
                <div>
                  <p className="text-xs text-zinc-400 mb-1">Imported repositories:</p>
                  <div className="flex flex-wrap gap-1.5">
                    {projectResult.imported.map(r => (
                      <span key={r} className="text-xs font-mono bg-brand-green/10 text-brand-green border border-brand-green/30 px-2 py-0.5 rounded">{r}</span>
                    ))}
                  </div>
                </div>
              )}
              {projectResult.skipped.length > 0 && (
                <div>
                  <p className="text-xs text-zinc-400 mb-1">Already registered (skipped):</p>
                  <div className="flex flex-wrap gap-1.5">
                    {projectResult.skipped.map(r => (
                      <span key={r} className="text-xs font-mono bg-zinc-800 text-zinc-500 border border-zinc-700 px-2 py-0.5 rounded">{r}</span>
                    ))}
                  </div>
                </div>
              )}
              <div className="flex justify-end pt-2">
                <a href="/" className="btn-primary px-6 py-2 text-sm">Go to Dashboard</a>
              </div>
            </div>
          )}

          {!projectResult && (
            <div className="flex items-center justify-between pt-2">
              <a href="/" className="btn-secondary">← Cancel</a>
              <button
                onClick={handleImportProject}
                disabled={!selectedWorkspaceId || !selectedProjectKey || importing}
                className="btn-primary px-8 py-3 text-lg disabled:opacity-50"
              >
                {importing ? "Fetching repositories..." : "Import All Repositories"}
              </button>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
