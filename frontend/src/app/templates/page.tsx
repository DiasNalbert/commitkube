"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

type Template = { id: number; name: string; path: string; content: string; type: string; is_active: boolean };
type GlobalVar = { id: number; key: string; value: string; secured: boolean };
type Workspace = { id: number; alias: string; workspace_id: string; project_key: string };
type Project = { id: number; project_key: string; alias: string };

export default function TemplatesPage() {
  const [message, setMessage] = useState("");

  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [wsOpen, setWsOpen] = useState<Record<number, boolean>>({});

  const [globalVars, setGlobalVars] = useState<GlobalVar[]>([]);
  const [newVar, setNewVar] = useState({ key: "", value: "", secured: false });
  const [projects, setProjects] = useState<Record<number, Project[]>>({});
  const [projOpen, setProjOpen] = useState<Record<string, boolean>>({});
  const [projVars, setProjVars] = useState<Record<string, GlobalVar[]>>({});
  const [newProjVar, setNewProjVar] = useState<Record<string, { key: string; value: string; secured: boolean }>>({});
  const [projTmpls, setProjTmpls] = useState<Record<string, Template[]>>({});
  const [projEditingTmpl, setProjEditingTmpl] = useState<Record<string, Template | null>>({});
  const [showNewProjTmpl, setShowNewProjTmpl] = useState<Record<string, boolean>>({});
  const [newProjTmpl, setNewProjTmpl] = useState<Record<string, { name: string; path: string; content: string; type: string }>>({});

  const [globalTmpls, setGlobalTmpls] = useState<Template[]>([]);
  const [globalTmplExpanded, setGlobalTmplExpanded] = useState<Record<string, boolean>>({});
  const [globalEditingTmpl, setGlobalEditingTmpl] = useState<Template | null>(null);

  const [copyOpen, setCopyOpen] = useState<Record<string, boolean>>({});
  const [copySource, setCopySource] = useState<Record<string, string>>({});
  const [copying, setCopying] = useState<Record<string, boolean>>({});

  const projKey = (wsId: number, pk: string) => `${wsId}/${pk}`;

  const allProjectOptions = (): { label: string; value: string }[] => {
    const opts: { label: string; value: string }[] = [];
    workspaces.forEach(ws => {
      const pks = allProjectKeys(ws);
      pks.forEach(pk => {
        opts.push({ label: `${ws.alias} / ${pk}`, value: projKey(ws.id, pk) });
      });
    });
    return opts;
  };

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }

    Promise.all([
      apiFetch("/workspaces").then(r => r.json()),
      apiFetch("/global-vars").then(r => r.json()),
      apiFetch("/templates").then(r => r.json()),
    ]).then(([wsList, vars, tmpls]) => {
      const ws = Array.isArray(wsList) ? wsList : [];
      setWorkspaces(ws);
      setGlobalVars(Array.isArray(vars) ? vars : []);
      setGlobalTmpls(Array.isArray(tmpls) ? tmpls : []);
      ws.forEach((w: Workspace) => {
        apiFetch(`/workspaces/${w.id}/projects`).then(r => r.json()).then(ps => {
          setProjects(prev => ({ ...prev, [w.id]: Array.isArray(ps) ? ps : [] }));
        });
      });
    });
  }, []);

  const msg = (m: string) => { setMessage(m); setTimeout(() => setMessage(""), 3000); };

  const addGlobalVar = async () => {
    if (!newVar.key) return;
    const res = await apiFetch("/global-vars", { method: "POST", body: JSON.stringify(newVar) });
    const v = await res.json();
    setGlobalVars(prev => [...prev, v]);
    setNewVar({ key: "", value: "", secured: false });
    msg("✅ Variable added!");
  };
  const deleteGlobalVar = async (id: number) => {
    await apiFetch(`/global-vars/${id}`, { method: "DELETE" });
    setGlobalVars(prev => prev.filter(v => v.id !== id));
  };

  const toggleWs = (wsId: number) => {
    setWsOpen(prev => ({ ...prev, [wsId]: !prev[wsId] }));
  };

  const toggleProj = async (wsId: number, pk: string) => {
    const k = projKey(wsId, pk);
    const isOpen = projOpen[k];
    setProjOpen(prev => ({ ...prev, [k]: !isOpen }));
    if (!isOpen) {
      if (!projVars[k]) {
        const r = await apiFetch(`/global-vars?workspace_id=${wsId}&project_key=${encodeURIComponent(pk)}`);
        const data = await r.json();
        setProjVars(prev => ({ ...prev, [k]: Array.isArray(data) ? data : [] }));
      }
      if (!projTmpls[k]) {
        const r = await apiFetch(`/templates?workspace_id=${wsId}&project_key=${encodeURIComponent(pk)}`);
        const data = await r.json();
        setProjTmpls(prev => ({ ...prev, [k]: Array.isArray(data) ? data : [] }));
      }
    }
  };

  const addProjVar = async (wsId: number, pk: string) => {
    const k = projKey(wsId, pk);
    const form = newProjVar[k];
    if (!form?.key) return;
    const res = await apiFetch("/global-vars", { method: "POST", body: JSON.stringify({ ...form, workspace_id: wsId, project_key: pk }) });
    const v = await res.json();
    setProjVars(prev => ({ ...prev, [k]: [...(prev[k] || []), v] }));
    setNewProjVar(prev => ({ ...prev, [k]: { key: "", value: "", secured: false } }));
  };
  const deleteProjVar = async (wsId: number, pk: string, varId: number) => {
    const k = projKey(wsId, pk);
    await apiFetch(`/global-vars/${varId}`, { method: "DELETE" });
    setProjVars(prev => ({ ...prev, [k]: prev[k].filter(v => v.id !== varId) }));
  };

  const createProjTmpl = async (wsId: number, pk: string) => {
    const k = projKey(wsId, pk);
    const form = newProjTmpl[k];
    if (!form?.name || !form?.content) return;
    const res = await apiFetch("/templates", { method: "POST", body: JSON.stringify({ ...form, workspace_id: wsId, project_key: pk }) });
    const t = await res.json();
    setProjTmpls(prev => ({ ...prev, [k]: [...(prev[k] || []), t] }));
    setNewProjTmpl(prev => ({ ...prev, [k]: { name: "", path: "", content: "", type: "manifest" } }));
    setShowNewProjTmpl(prev => ({ ...prev, [k]: false }));
    msg("✅ Template created!");
  };
  const saveProjTmpl = async (wsId: number, pk: string) => {
    const k = projKey(wsId, pk);
    const tmpl = projEditingTmpl[k];
    if (!tmpl) return;
    await apiFetch(`/templates/${tmpl.id}`, { method: "PUT", body: JSON.stringify({ content: tmpl.content, name: tmpl.name, path: tmpl.path }) });
    setProjTmpls(prev => ({ ...prev, [k]: (prev[k] || []).map(t => t.id === tmpl.id ? tmpl : t) }));
    setProjEditingTmpl(prev => ({ ...prev, [k]: null }));
    msg("✅ Template saved!");
  };
  const deleteProjTmpl = async (wsId: number, pk: string, tmplId: number) => {
    const k = projKey(wsId, pk);
    await apiFetch(`/templates/${tmplId}`, { method: "DELETE" });
    setProjTmpls(prev => ({ ...prev, [k]: (prev[k] || []).filter(t => t.id !== tmplId) }));
  };

  const saveGlobalTmpl = async () => {
    if (!globalEditingTmpl) return;
    await apiFetch(`/templates/${globalEditingTmpl.id}`, { method: "PUT", body: JSON.stringify({ content: globalEditingTmpl.content, name: globalEditingTmpl.name, path: globalEditingTmpl.path }) });
    setGlobalTmpls(prev => prev.map(t => t.id === globalEditingTmpl.id ? globalEditingTmpl : t));
    setGlobalEditingTmpl(null);
    msg("✅ Global template saved!");
  };
  const deleteGlobalTmpl = async (id: number) => {
    await apiFetch(`/templates/${id}`, { method: "DELETE" });
    setGlobalTmpls(prev => prev.filter(t => t.id !== id));
    if (globalEditingTmpl?.id === id) setGlobalEditingTmpl(null);
  };

  const copyTemplates = async (targetWsId: number, targetPk: string) => {
    const k = projKey(targetWsId, targetPk);
    const src = copySource[k];
    if (!src) return;
    setCopying(prev => ({ ...prev, [k]: true }));
    try {
      const [srcWsId, srcPk] = src.split("/");
      const r = await apiFetch(`/templates?workspace_id=${srcWsId}&project_key=${encodeURIComponent(srcPk)}`);
      const srcTmpls: Template[] = await r.json();
      if (!Array.isArray(srcTmpls) || srcTmpls.length === 0) {
        msg("⚠️ Source project has no templates.");
        return;
      }
      const created: Template[] = [];
      for (const t of srcTmpls) {
        const res = await apiFetch("/templates", {
          method: "POST",
          body: JSON.stringify({ name: t.name, path: t.path, content: t.content, type: t.type, workspace_id: targetWsId, project_key: targetPk }),
        });
        const nt = await res.json();
        created.push(nt);
      }
      setProjTmpls(prev => ({ ...prev, [k]: [...(prev[k] || []), ...created] }));
      setCopyOpen(prev => ({ ...prev, [k]: false }));
      msg(`✅ ${created.length} template(s) copied!`);
    } finally {
      setCopying(prev => ({ ...prev, [k]: false }));
    }
  };

  const allProjectKeys = (ws: Workspace): string[] => {
    const registered = (projects[ws.id] || []).map(p => p.project_key);
    const keys = new Set<string>(registered);
    if (ws.project_key) keys.add(ws.project_key);
    return Array.from(keys).sort();
  };

  const VarRow = ({ v, onDelete }: { v: GlobalVar; onDelete: () => void }) => (
    <div className="flex items-center gap-2 p-2 rounded text-sm" style={{ background: "var(--color-surface)", border: "1px solid var(--card-border)" }}>
      <span className="font-mono text-brand-green flex-1">{v.key}</span>
      <span className="flex-1" style={{ color: "var(--color-fg)", opacity: 0.6 }}>{v.secured ? "●●●●●●●" : v.value}</span>
      {v.secured && <span className="text-xs text-yellow-500 bg-yellow-500/10 px-1.5 py-0.5 rounded">secured</span>}
      <button onClick={onDelete} className="text-red-400 hover:text-red-300 px-1">✕</button>
    </div>
  );

  const VarForm = ({ form, onChange, onAdd }: { form: { key: string; value: string; secured: boolean }; onChange: (f: typeof form) => void; onAdd: () => void }) => (
    <div className="flex gap-2 flex-wrap pt-1">
      <input className="input-tech flex-1 min-w-28 text-sm" placeholder="KEY" value={form.key} onChange={e => onChange({ ...form, key: e.target.value })} />
      <input className="input-tech flex-1 min-w-36 text-sm" placeholder="value" type={form.secured ? "password" : "text"} value={form.value} onChange={e => onChange({ ...form, value: e.target.value })} />
      <label className="flex items-center gap-1.5 text-sm cursor-pointer" style={{ color: "var(--color-fg)", opacity: 0.7 }}>
        <input type="checkbox" checked={form.secured} onChange={e => onChange({ ...form, secured: e.target.checked })} className="accent-brand-green" /> Secured
      </label>
      <button onClick={onAdd} className="btn-primary px-3 py-1.5 text-sm">+ Add</button>
    </div>
  );

  const TmplRow = ({ t, editing, onToggleEdit, onDelete, onSave, onCancel, onChange }: {
    t: Template; editing: Template | null;
    onToggleEdit: () => void; onDelete: () => void; onSave: () => void; onCancel: () => void;
    onChange: (content: string) => void;
  }) => (
    <div className="rounded mb-1" style={{ border: "1px solid var(--card-border)" }}>
      <div className="flex items-center gap-2 px-3 py-2 text-sm" style={{ background: "var(--color-surface)" }}>
        <span className="font-mono text-brand-green flex-1 text-xs">{t.path ? `${t.path}/` : ""}<strong>{t.name}</strong></span>
        <button onClick={onToggleEdit} className="text-xs px-2 py-0.5 rounded btn-secondary">
          {editing !== null && editing.id === t.id ? "Close" : "✏️ Edit"}
        </button>
        <button onClick={onDelete} className="text-red-400 hover:text-red-300 text-xs px-1">✕</button>
      </div>
      {editing !== null && editing.id === t.id && (
        <div className="p-3 border-t" style={{ borderColor: "var(--card-border)", background: "var(--color-surface)" }}>
          <p className="text-xs text-zinc-500 mb-1.5">
            Use <code className="font-mono text-brand-green">{"<your_application>"}</code> wherever you want the repository name (name, namespace, labels, etc.)
          </p>
          <textarea
            className="w-full font-mono text-xs p-2 rounded mb-2 focus:outline-none focus:border-brand-green"
            style={{ background: "var(--input-bg)", color: "var(--input-fg)", border: "1px solid var(--input-border)" }}
            rows={10}
            value={editing.content}
            onChange={e => onChange(e.target.value)}
          />
          <div className="flex gap-2 justify-end">
            <button onClick={onCancel} className="btn-secondary text-xs px-2 py-1">Cancel</button>
            <button onClick={onSave} className="btn-primary text-xs px-3 py-1">💾 Save</button>
          </div>
        </div>
      )}
    </div>
  );

  return (
    <div className="max-w-5xl mx-auto space-y-8">
      <header>
        <h1 className="text-3xl font-bold bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold">
          Templates & Variables
        </h1>
        <p className="mt-1 text-sm" style={{ color: "var(--color-fg)", opacity: 0.6 }}>Manage YAML templates and variables per project.</p>
      </header>

      {message && (
        <div className={`p-3 rounded border text-sm ${message.startsWith("✅") ? "bg-brand-green/10 border-brand-green/40 text-brand-green" : message.startsWith("⚠️") ? "bg-yellow-500/10 border-yellow-500/40 text-yellow-400" : "bg-red-500/10 border-red-500/40 text-red-400"}`}>
          {message}
        </div>
      )}

      <div className="glass-card p-4 border border-blue-500/30 bg-blue-500/5 rounded-lg">
        <p className="text-sm font-semibold text-blue-300 mb-1">💡 Repository name placeholder</p>
        <p className="text-xs text-zinc-400 leading-relaxed">
          In manifest and pipeline templates, use <code className="font-mono text-brand-green bg-brand-green/10 px-1 rounded">&lt;your_application&gt;</code> as a
          placeholder in fields such as <code className="font-mono text-zinc-300">name</code>, <code className="font-mono text-zinc-300">namespace</code>, labels and <code className="font-mono text-zinc-300">containerName</code>.
          CommitKube will automatically replace it with the repository name when creating.
        </p>
        <p className="text-xs text-zinc-500 mt-1.5">
          Example: <code className="font-mono text-zinc-400">name: &lt;your_application&gt;</code> → <code className="font-mono text-zinc-300">name: my-service</code>
        </p>
      </div>

      <div className="glass-card p-6 border-l-4 border-l-yellow-500">
        <h2 className="text-xl font-bold mb-1 flex items-center gap-2" style={{ color: "var(--color-fg)" }}>🌐 Global Variables</h2>
        <p className="text-sm mb-4" style={{ color: "var(--color-fg)", opacity: 0.6 }}>Added automatically to <strong>all</strong> repositories.</p>
        <div className="space-y-2 mb-4">
          {globalVars.map(v => <VarRow key={v.id} v={v} onDelete={() => deleteGlobalVar(v.id)} />)}
          {globalVars.length === 0 && <p className="text-sm italic" style={{ color: "var(--color-fg)", opacity: 0.4 }}>No global variables.</p>}
        </div>
        <VarForm form={newVar} onChange={setNewVar} onAdd={addGlobalVar} />
      </div>

      {workspaces.length === 0 && (
        <div className="glass-card p-8 text-center" style={{ color: "var(--color-fg)", opacity: 0.5 }}>
          <p>No workspaces registered. Add one in <a href="/settings" className="text-brand-green hover:underline">Settings</a>.</p>
        </div>
      )}

      {workspaces.map(ws => (
        <div key={ws.id} className="glass-card border-l-4 border-l-blue-500 overflow-hidden">
          <button
            onClick={() => toggleWs(ws.id)}
            className="w-full flex items-center justify-between px-6 py-4 transition hover:bg-brand-green/5"
          >
            <div className="flex items-center gap-3">
              <span className="text-lg font-bold text-blue-400">{ws.alias}</span>
              <span className="text-sm" style={{ color: "var(--color-fg)", opacity: 0.5 }}>{ws.workspace_id}</span>
            </div>
            <span className="text-xs" style={{ color: "var(--color-fg)", opacity: 0.5 }}>{wsOpen[ws.id] ? "▲ Close" : "▼ Expand"}</span>
          </button>

          {wsOpen[ws.id] && (
            <div className="border-t px-6 pb-6 space-y-4 pt-4" style={{ borderColor: "var(--card-border)" }}>
              {allProjectKeys(ws).length === 0 && (
                <p className="text-sm italic" style={{ color: "var(--color-fg)", opacity: 0.4 }}>No project keys registered for this workspace.</p>
              )}

              {allProjectKeys(ws).map(pk => {
                const k = projKey(ws.id, pk);
                const srcOpts = allProjectOptions().filter(o => o.value !== k);
                return (
                  <div key={k} className="rounded overflow-hidden" style={{ border: "1px solid var(--card-border)" }}>
                    <button
                      onClick={() => toggleProj(ws.id, pk)}
                      className="w-full flex items-center justify-between px-4 py-3 text-sm transition hover:bg-brand-green/5"
                      style={{ background: "var(--color-surface)" }}
                    >
                      <span className="font-medium">📁 Project: <span className="text-yellow-400 font-mono">{pk}</span></span>
                      <span className="text-xs" style={{ color: "var(--color-fg)", opacity: 0.5 }}>{projOpen[k] ? "▲" : "▼"}</span>
                    </button>

                    {projOpen[k] && (
                      <div className="px-4 pb-4 pt-3 space-y-5" style={{ background: "var(--color-bg)" }}>
                        <div>
                          <p className="text-xs font-semibold uppercase tracking-wider mb-2" style={{ color: "var(--color-fg)", opacity: 0.5 }}>🔑 Project Variables</p>
                          <div className="space-y-1 mb-2">
                            {(projVars[k] || []).map(v => <VarRow key={v.id} v={v} onDelete={() => deleteProjVar(ws.id, pk, v.id)} />)}
                            {(projVars[k] || []).length === 0 && <p className="text-xs italic mb-2" style={{ color: "var(--color-fg)", opacity: 0.35 }}>No variables.</p>}
                          </div>
                          <VarForm
                            form={newProjVar[k] || { key: "", value: "", secured: false }}
                            onChange={f => setNewProjVar(prev => ({ ...prev, [k]: f }))}
                            onAdd={() => addProjVar(ws.id, pk)}
                          />
                        </div>

                        <div className="border-t pt-4" style={{ borderColor: "var(--card-border)" }}>
                          <div className="flex items-center justify-between mb-3">
                            <p className="text-xs font-semibold uppercase tracking-wider" style={{ color: "var(--color-fg)", opacity: 0.5 }}>📄 Project Templates</p>
                            <div className="flex gap-2">
                              <button
                                onClick={() => setCopyOpen(prev => ({ ...prev, [k]: !prev[k] }))}
                                className="btn-secondary text-xs px-2 py-1"
                              >
                                📋 Copy from...
                              </button>
                              <button
                                onClick={() => setShowNewProjTmpl(prev => ({ ...prev, [k]: !prev[k] }))}
                                className="btn-primary text-xs px-2 py-1"
                              >
                                + New
                              </button>
                            </div>
                          </div>

                          {copyOpen[k] && (
                            <div className="mb-3 p-3 rounded flex items-center gap-2 flex-wrap" style={{ background: "var(--color-surface)", border: "1px solid var(--card-border)" }}>
                              <select
                                className="input-tech text-xs flex-1 min-w-48"
                                value={copySource[k] || ""}
                                onChange={e => setCopySource(prev => ({ ...prev, [k]: e.target.value }))}
                              >
                                <option value="">— Select source project —</option>
                                {srcOpts.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
                              </select>
                              <button
                                onClick={() => copyTemplates(ws.id, pk)}
                                disabled={!copySource[k] || copying[k]}
                                className="btn-primary text-xs px-3 py-1.5"
                              >
                                {copying[k] ? "Copying..." : "Copy"}
                              </button>
                              <button
                                onClick={() => setCopyOpen(prev => ({ ...prev, [k]: false }))}
                                className="btn-secondary text-xs px-2 py-1"
                              >
                                Cancel
                              </button>
                            </div>
                          )}

                          {showNewProjTmpl[k] && (
                            <div className="mb-3 p-3 rounded space-y-2" style={{ background: "var(--color-surface)", border: "1px solid var(--card-border)" }}>
                              <select className="input-tech text-xs"
                                value={newProjTmpl[k]?.type || "manifest"}
                                onChange={e => {
                                  const t = e.target.value;
                                  setNewProjTmpl(prev => ({
                                    ...prev,
                                    [k]: {
                                      ...prev[k] || { name: "", path: "", content: "", type: "manifest" },
                                      type: t,
                                      name: t === "pipeline" ? "bitbucket-pipelines.yml" : (prev[k]?.name === "bitbucket-pipelines.yml" ? "" : prev[k]?.name || ""),
                                      path: t === "pipeline" ? "" : (prev[k]?.path || ""),
                                    }
                                  }));
                                }}>
                                <option value="manifest">Manifest (K8s)</option>
                                <option value="pipeline">Pipeline (bitbucket-pipelines.yml)</option>
                              </select>
                              <div className="grid grid-cols-2 gap-2">
                                <div>
                                  <label className="text-xs mb-1 block" style={{ color: "var(--color-fg)", opacity: 0.6 }}>File</label>
                                  <input
                                    className="input-tech text-xs"
                                    placeholder="exemplo.yaml"
                                    disabled={newProjTmpl[k]?.type === "pipeline"}
                                    value={newProjTmpl[k]?.type === "pipeline" ? "bitbucket-pipelines.yml" : (newProjTmpl[k]?.name || "")}
                                    onChange={e => setNewProjTmpl(prev => ({ ...prev, [k]: { ...prev[k] || { name: "", path: "manifests", content: "", type: "manifest" }, name: e.target.value } }))}
                                  />
                                </div>
                                <div>
                                  <label className="text-xs mb-1 block" style={{ color: "var(--color-fg)", opacity: 0.6 }}>Path <span style={{ opacity: 0.5 }}>(blank = repo root)</span></label>
                                  <input
                                    className="input-tech text-xs"
                                    placeholder="Leave blank for repo root"
                                    disabled={newProjTmpl[k]?.type === "pipeline"}
                                    value={newProjTmpl[k]?.type === "pipeline" ? "" : (newProjTmpl[k]?.path || "")}
                                    onChange={e => setNewProjTmpl(prev => ({ ...prev, [k]: { ...prev[k] || { name: "", path: "", content: "", type: "manifest" }, path: e.target.value } }))}
                                  />
                                </div>
                              </div>
                              <p className="text-xs text-zinc-500">
                                Use <code className="font-mono text-brand-green">{"<your_application>"}</code> as a placeholder — it will be replaced by the repository name. Leave Path blank to place the file in the repo root (ArgoCD will sync from root).
                              </p>
                              <textarea
                                className="w-full font-mono text-xs p-2 rounded focus:outline-none focus:border-brand-green"
                                style={{ background: "var(--input-bg)", color: "var(--input-fg)", border: "1px solid var(--input-border)" }}
                                rows={6}
                                placeholder="# YAML content..."
                                value={newProjTmpl[k]?.content || ""}
                                onChange={e => setNewProjTmpl(prev => ({ ...prev, [k]: { ...prev[k] || { name: "", path: "", content: "", type: "manifest" }, content: e.target.value } }))}
                              />
                              <div className="flex gap-2 justify-end">
                                <button onClick={() => setShowNewProjTmpl(prev => ({ ...prev, [k]: false }))} className="btn-secondary text-xs px-2 py-1">Cancel</button>
                                <button onClick={() => createProjTmpl(ws.id, pk)} className="btn-primary text-xs px-3 py-1">Create Template</button>
                              </div>
                            </div>
                          )}

                          {(projTmpls[k] || []).length === 0 && !showNewProjTmpl[k] && !copyOpen[k] && globalTmpls.length === 0 && (
                            <p className="text-xs italic" style={{ color: "var(--color-fg)", opacity: 0.35 }}>No templates. Use the button above to create or copy.</p>
                          )}

                          {(projTmpls[k] || []).map(t => (
                            <TmplRow key={t.id} t={t}
                              editing={projEditingTmpl[k] || null}
                              onToggleEdit={() => setProjEditingTmpl(prev => ({ ...prev, [k]: prev[k]?.id === t.id ? null : t }))}
                              onDelete={() => deleteProjTmpl(ws.id, pk, t.id)}
                              onSave={() => saveProjTmpl(ws.id, pk)}
                              onCancel={() => setProjEditingTmpl(prev => ({ ...prev, [k]: null }))}
                              onChange={content => setProjEditingTmpl(prev => ({ ...prev, [k]: prev[k] ? { ...prev[k]!, content } : null }))}
                            />
                          ))}

                          {globalTmpls.filter(g => !(projTmpls[k] || []).some(p => p.name === g.name && p.path === g.path)).length > 0 && (
                            <div className="mt-2">
                              <button
                                onClick={() => setGlobalTmplExpanded(prev => ({ ...prev, [k]: !prev[k] }))}
                                className="text-xs flex items-center gap-1 mb-2"
                                style={{ color: "var(--color-fg)", opacity: 0.5 }}
                              >
                                {globalTmplExpanded[k] ? "▼" : "▶"} Inherited global templates ({globalTmpls.filter(g => !(projTmpls[k] || []).some(p => p.name === g.name && p.path === g.path)).length})
                              </button>
                              {globalTmplExpanded[k] && globalTmpls
                                .filter(g => !(projTmpls[k] || []).some(p => p.name === g.name && p.path === g.path))
                                .map(g => (
                                  <TmplRow key={g.id} t={g}
                                    editing={globalEditingTmpl}
                                    onToggleEdit={() => setGlobalEditingTmpl(prev => prev?.id === g.id ? null : g)}
                                    onDelete={() => deleteGlobalTmpl(g.id)}
                                    onSave={saveGlobalTmpl}
                                    onCancel={() => setGlobalEditingTmpl(null)}
                                    onChange={content => setGlobalEditingTmpl(prev => prev ? { ...prev, content } : null)}
                                  />
                                ))
                              }
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          )}
        </div>
      ))}
    </div>
  );
}
