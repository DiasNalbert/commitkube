"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface UserProfile {
  id: number;
  email: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
  created_at: string;
}

type Workspace = { id: number; alias: string; username: string; workspace_id: string; project_key: string; ssh_pub_key: string };
type ArgoCDInst = { id: number; alias: string; server_url: string; default_namespace: string; default_project: string; prometheus_url: string };
type Project = { id: number; project_key: string; alias: string };
type RegistryCred = { id: number; alias: string; host: string; type: string; username: string; aws_region: string; has_password: boolean; has_aws_key: boolean; has_gcr_key: boolean };

const emptyWs = () => ({ alias: "", username: "", app_pass: "", workspace_id: "", project_key: "", ssh_priv_key: "", ssh_pub_key: "" });
const emptyArgo = () => ({ alias: "", server_url: "", auth_token: "", default_namespace: "", default_project: "", prometheus_url: "" });
const emptyReg = () => ({ alias: "", host: "", type: "generic", username: "", password: "", aws_access_key: "", aws_secret_key: "", aws_region: "", gcr_key_json: "" });

export default function ProfilePage() {
  const [profile, setProfile] = useState<UserProfile | null>(null);
  const [loading, setLoading] = useState(true);
  const [userRole, setUserRole] = useState("");

  const [newPassword, setNewPassword] = useState("");
  const [confirmPassword, setConfirmPassword] = useState("");
  const [pwError, setPwError] = useState("");
  const [pwSuccess, setPwSuccess] = useState("");
  const [saving, setSaving] = useState(false);

  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [editingWs, setEditingWs] = useState<number | null>(null);
  const [wsForm, setWsForm] = useState(emptyWs());
  const [showNewWs, setShowNewWs] = useState(false);
  const [newWsForm, setNewWsForm] = useState(emptyWs());
  const [projects, setProjects] = useState<Record<number, Project[]>>({});
  const [newProjectKey, setNewProjectKey] = useState<Record<number, { project_key: string; alias: string }>>({});

  const [argoInstances, setArgoInstances] = useState<ArgoCDInst[]>([]);
  const [editingArgo, setEditingArgo] = useState<number | null>(null);
  const [argoForm, setArgoForm] = useState(emptyArgo());
  const [showNewArgo, setShowNewArgo] = useState(false);
  const [newArgoForm, setNewArgoForm] = useState(emptyArgo());

  const [registryCreds, setRegistryCreds] = useState<RegistryCred[]>([]);
  const [editingReg, setEditingReg] = useState<number | null>(null);
  const [regForm, setRegForm] = useState(emptyReg());
  const [showNewReg, setShowNewReg] = useState(false);
  const [newRegForm, setNewRegForm] = useState(emptyReg());

  const [message, setMessage] = useState("");
  const msg = (m: string) => { setMessage(m); setTimeout(() => setMessage(""), 3000); };

  const loadProjects = async (wsId: number) => {
    const res = await apiFetch(`/workspaces/${wsId}/projects`);
    const ps = await res.json();
    setProjects(prev => ({ ...prev, [wsId]: Array.isArray(ps) ? ps : [] }));
  };

  useEffect(() => {
    const token = localStorage.getItem("token");
    if (!token) { window.location.href = "/login"; return; }

    try {
      const tokenData = JSON.parse(atob(token.split(".")[1]));
      setUserRole(tokenData.role || "");
    } catch {}

    apiFetch("/users/me").then(async (res) => {
      if (res.status === 401) { window.location.href = "/login"; return; }
      setProfile(await res.json());
      setLoading(false);
    });

    Promise.all([
      apiFetch("/workspaces").then(r => r.json()),
      apiFetch("/argocd-instances").then(r => r.json()),
      apiFetch("/registry-credentials").then(r => r.json()),
    ]).then(([wsList, argoList, regList]) => {
      const ws = Array.isArray(wsList) ? wsList : [];
      setWorkspaces(ws);
      setArgoInstances(Array.isArray(argoList) ? argoList : []);
      setRegistryCreds(Array.isArray(regList) ? regList : []);
      ws.forEach((w: Workspace) => loadProjects(w.id));
    });
  }, []);

  const handleChangePassword = async (e: React.FormEvent) => {
    e.preventDefault();
    setPwError(""); setPwSuccess("");
    if (newPassword !== confirmPassword) { setPwError("Passwords do not match."); return; }
    if (newPassword.length < 6) { setPwError("Password must be at least 6 characters."); return; }
    setSaving(true);
    try {
      const res = await apiFetch(`/users/${profile!.id}/password`, {
        method: "PUT",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ new_password: newPassword }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to change password");
      setPwSuccess("Password changed successfully.");
      setNewPassword(""); setConfirmPassword("");
    } catch (err: any) { setPwError(err.message); }
    finally { setSaving(false); }
  };

  const isAdmin = userRole === "admin" || userRole === "root";

  const createWorkspace = async () => {
    if (!newWsForm.alias || !newWsForm.workspace_id) return;
    const res = await apiFetch("/workspaces", { method: "POST", body: JSON.stringify(newWsForm) });
    const ws = await res.json();
    setWorkspaces(prev => [...prev, ws]);
    setNewWsForm(emptyWs()); setShowNewWs(false);
    msg("✅ Workspace created!"); loadProjects(ws.id);
  };

  const saveWorkspace = async (id: number) => {
    const res = await apiFetch(`/workspaces/${id}`, { method: "PUT", body: JSON.stringify(wsForm) });
    const updated = await res.json();
    setWorkspaces(prev => prev.map(w => w.id === id ? updated : w));
    setEditingWs(null); msg("✅ Workspace saved!");
  };

  const deleteWorkspace = async (id: number) => {
    await apiFetch(`/workspaces/${id}`, { method: "DELETE" });
    setWorkspaces(prev => prev.filter(w => w.id !== id));
  };

  const addProject = async (wsId: number) => {
    const form = newProjectKey[wsId];
    if (!form?.project_key) return;
    const res = await apiFetch(`/workspaces/${wsId}/projects`, { method: "POST", body: JSON.stringify(form) });
    const proj = await res.json();
    setProjects(prev => ({ ...prev, [wsId]: [...(prev[wsId] || []), proj] }));
    setNewProjectKey(prev => ({ ...prev, [wsId]: { project_key: "", alias: "" } }));
    msg("✅ Project key added!");
  };

  const deleteProject = async (wsId: number, projId: number) => {
    await apiFetch(`/workspaces/${wsId}/projects/${projId}`, { method: "DELETE" });
    setProjects(prev => ({ ...prev, [wsId]: prev[wsId].filter(p => p.id !== projId) }));
  };

  const createArgoCDInstance = async () => {
    if (!newArgoForm.alias || !newArgoForm.server_url) return;
    const res = await apiFetch("/argocd-instances", { method: "POST", body: JSON.stringify(newArgoForm) });
    const inst = await res.json();
    setArgoInstances(prev => [...prev, inst]);
    setNewArgoForm(emptyArgo()); setShowNewArgo(false);
    msg("✅ ArgoCD instance created!");
  };

  const saveArgoCDInstance = async (id: number) => {
    const res = await apiFetch(`/argocd-instances/${id}`, { method: "PUT", body: JSON.stringify(argoForm) });
    const updated = await res.json();
    setArgoInstances(prev => prev.map(a => a.id === id ? updated : a));
    setEditingArgo(null); msg("✅ ArgoCD instance saved!");
  };

  const deleteArgoCDInstance = async (id: number) => {
    await apiFetch(`/argocd-instances/${id}`, { method: "DELETE" });
    setArgoInstances(prev => prev.filter(a => a.id !== id));
  };

  if (loading) return <div className="text-center mt-20 text-brand-green">Loading...</div>;
  if (!profile) return null;

  const roleLabel: Record<string, string> = { root: "Root", admin: "Admin", user: "User", bootstrap: "Bootstrap" };

  return (
    <div className="space-y-8 max-w-5xl">
      <header>
        <h1 className="text-3xl font-bold">My Profile</h1>
        <p className="text-zinc-400 mt-2">Your account information and integration credentials.</p>
      </header>

      {message && (
        <div className={`p-3 rounded border text-sm ${message.startsWith("✅") ? "bg-brand-green/10 border-brand-green/40 text-brand-green" : "bg-red-500/10 border-red-500/40 text-red-400"}`}>
          {message}
        </div>
      )}

      <div className="glass-card p-6 space-y-4">
        <div className="flex items-center gap-4">
          <div className="w-14 h-14 rounded-full bg-brand-green/10 border border-brand-green/30 flex items-center justify-center text-2xl font-bold text-brand-green">
            {profile.email[0].toUpperCase()}
          </div>
          <div>
            <p className="font-semibold text-zinc-100">{profile.email}</p>
            <span className={`text-xs px-2 py-0.5 rounded mt-1 inline-block ${
              profile.role === "root" ? "bg-brand-gold/10 text-brand-gold" :
              profile.role === "admin" ? "bg-blue-500/10 text-blue-400" :
              "bg-zinc-700/50 text-zinc-400"
            }`}>
              {roleLabel[profile.role] || profile.role}
            </span>
          </div>
        </div>
        <div className="grid grid-cols-2 gap-4 pt-2 text-sm">
          <div>
            <p className="text-zinc-500">MFA</p>
            <p className={profile.mfa_enabled ? "text-brand-green" : "text-zinc-400"}>
              {profile.mfa_enabled ? "Active" : "Not configured"}
            </p>
          </div>
          <div>
            <p className="text-zinc-500">Member since</p>
            <p className="text-zinc-300">{new Date(profile.created_at).toLocaleDateString("en-US")}</p>
          </div>
        </div>
      </div>

      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4">Change password</h2>
        {pwError && <div className="mb-4 p-3 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{pwError}</div>}
        {pwSuccess && <div className="mb-4 p-3 rounded bg-brand-green/10 border border-brand-green/30 text-brand-green text-sm">{pwSuccess}</div>}
        <form onSubmit={handleChangePassword} className="space-y-4 max-w-sm">
          <div>
            <label className="block text-sm text-zinc-400 mb-1">New password</label>
            <input type="password" required value={newPassword} onChange={e => setNewPassword(e.target.value)} className="input-tech" placeholder="••••••••" />
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Confirm new password</label>
            <input type="password" required value={confirmPassword} onChange={e => setConfirmPassword(e.target.value)} className="input-tech" placeholder="••••••••" />
          </div>
          <button type="submit" disabled={saving} className="btn-primary py-2 px-6">{saving ? "Saving..." : "Save password"}</button>
        </form>
      </div>

      <div className="glass-card p-6 border-l-4 border-l-[#0052CC]">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-bold">Bitbucket Workspaces</h2>
            <p className="text-zinc-400 text-sm mt-1">Credentials and project keys per workspace.</p>
          </div>
          <button onClick={() => setShowNewWs(!showNewWs)} className="btn-primary text-sm px-3 py-1.5 shrink-0">+ New Workspace</button>
        </div>

        <div className="mb-4 p-3 rounded bg-blue-500/10 border border-blue-500/30 text-sm space-y-2">
          <p className="font-semibold text-blue-200">📋 Required token scopes:</p>
          <ol className="list-decimal list-inside space-y-1 text-zinc-300">
            <li>Go to <a href="https://id.atlassian.com/manage-profile/security/api-tokens" target="_blank" rel="noreferrer" className="text-blue-400 underline">id.atlassian.com → Security → API tokens</a></li>
            <li>Enable the following scopes:
              <div className="flex flex-wrap gap-1.5 mt-2 ml-4">
                <code className="bg-zinc-800 px-1.5 py-0.5 rounded text-xs">Repositories: Admin</code>
                <code className="bg-zinc-800 px-1.5 py-0.5 rounded text-xs">Repositories: Write</code>
                <code className="bg-zinc-800 px-1.5 py-0.5 rounded text-xs">Projects: Write</code>
                <code className="bg-zinc-800 px-1.5 py-0.5 rounded text-xs text-yellow-300">Pipelines: Admin</code>
                <code className="bg-zinc-800 px-1.5 py-0.5 rounded text-xs text-yellow-300">Account: Write</code>
              </div>
            </li>
          </ol>
          <p className="text-zinc-400 text-xs mt-1">⚠️ <span className="text-yellow-300">Pipelines: Admin</span> is required to set pipeline variables. <span className="text-yellow-300">Account: Write</span> is required to add deploy keys (used by ArgoCD).</p>
          <p className="text-zinc-400 text-xs">🔑 <strong className="text-zinc-300">Private SSH Key</strong> is required for ArgoCD to access private repositories.</p>
        </div>

        {showNewWs && (
          <div className="mb-4 p-4 rounded bg-zinc-900 border border-blue-500/40 space-y-3">
            <h3 className="font-semibold text-sm text-blue-300">New Workspace</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <div className="md:col-span-2">
                <label className="text-xs text-zinc-400 mb-1 block">Name / Alias</label>
                <input className="input-tech text-sm" placeholder="My Company" value={newWsForm.alias} onChange={e => setNewWsForm({ ...newWsForm, alias: e.target.value })} />
              </div>
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Atlassian Email</label>
                <input className="input-tech text-sm" placeholder="your@email.com" value={newWsForm.username} onChange={e => setNewWsForm({ ...newWsForm, username: e.target.value })} />
              </div>
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">API Token</label>
                <input type="password" className="input-tech text-sm" placeholder="ATATT..." value={newWsForm.app_pass} onChange={e => setNewWsForm({ ...newWsForm, app_pass: e.target.value })} />
              </div>
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Workspace ID</label>
                <input className="input-tech text-sm" placeholder="my-workspace" value={newWsForm.workspace_id} onChange={e => setNewWsForm({ ...newWsForm, workspace_id: e.target.value })} />
              </div>
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Default Project Key</label>
                <input className="input-tech text-sm" placeholder="PROJ" value={newWsForm.project_key} onChange={e => setNewWsForm({ ...newWsForm, project_key: e.target.value })} />
              </div>
              <div className="md:col-span-2">
                <label className="text-xs text-zinc-400 mb-1 block">Private SSH Key <span className="text-zinc-500">(used by ArgoCD)</span></label>
                <textarea className="input-tech font-mono text-xs" rows={3} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..." value={newWsForm.ssh_priv_key} onChange={e => setNewWsForm({ ...newWsForm, ssh_priv_key: e.target.value })} />
              </div>
              <div className="md:col-span-2">
                <label className="text-xs text-zinc-400 mb-1 block">Public SSH Key</label>
                <textarea className="input-tech font-mono text-xs" rows={2} placeholder="ssh-rsa AAAA..." value={newWsForm.ssh_pub_key} onChange={e => setNewWsForm({ ...newWsForm, ssh_pub_key: e.target.value })} />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowNewWs(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
              <button onClick={createWorkspace} className="btn-primary text-sm px-4 py-1.5">Create Workspace</button>
            </div>
          </div>
        )}

        <div className="space-y-2">
          {workspaces.length === 0 && <p className="text-zinc-500 text-sm italic">No workspaces registered.</p>}
          {workspaces.map(ws => (
            <div key={ws.id} className="rounded border border-zinc-700">
              <div className="flex items-center gap-3 px-4 py-3 bg-zinc-900 rounded-t">
                <div className="flex-1">
                  <span className="font-semibold text-blue-300">{ws.alias}</span>
                  <span className="text-zinc-500 text-xs ml-2">{ws.workspace_id}</span>
                </div>
                <button onClick={() => { setEditingWs(ws.id); setWsForm({ alias: ws.alias, username: ws.username, app_pass: "", workspace_id: ws.workspace_id, project_key: ws.project_key, ssh_priv_key: "", ssh_pub_key: ws.ssh_pub_key }); }} className="text-zinc-400 hover:text-zinc-200 text-sm px-2">✏️</button>
                <button onClick={() => deleteWorkspace(ws.id)} className="text-red-400 hover:text-red-300 text-sm px-1">✕</button>
              </div>
              {editingWs === ws.id && (
                <div className="p-4 border-t border-zinc-700 bg-zinc-950 space-y-3">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                    <div className="md:col-span-2">
                      <label className="text-xs text-zinc-400 mb-1 block">Name / Alias</label>
                      <input className="input-tech text-sm" value={wsForm.alias} onChange={e => setWsForm({ ...wsForm, alias: e.target.value })} />
                    </div>
                    <div>
                      <label className="text-xs text-zinc-400 mb-1 block">Atlassian Email</label>
                      <input className="input-tech text-sm" value={wsForm.username} onChange={e => setWsForm({ ...wsForm, username: e.target.value })} />
                    </div>
                    <div>
                      <label className="text-xs text-zinc-400 mb-1 block">API Token <span className="text-zinc-500">(leave blank to keep)</span></label>
                      <input type="password" className="input-tech text-sm" placeholder="New token..." value={wsForm.app_pass} onChange={e => setWsForm({ ...wsForm, app_pass: e.target.value })} />
                    </div>
                    <div>
                      <label className="text-xs text-zinc-400 mb-1 block">Workspace ID</label>
                      <input className="input-tech text-sm" value={wsForm.workspace_id} onChange={e => setWsForm({ ...wsForm, workspace_id: e.target.value })} />
                    </div>
                    <div>
                      <label className="text-xs text-zinc-400 mb-1 block">Default Project Key</label>
                      <input className="input-tech text-sm" value={wsForm.project_key} onChange={e => setWsForm({ ...wsForm, project_key: e.target.value })} />
                    </div>
                    <div className="md:col-span-2">
                      <label className="text-xs text-zinc-400 mb-1 block">Private SSH Key <span className="text-zinc-500">(leave blank to keep)</span></label>
                      <textarea className="input-tech font-mono text-xs" rows={3} placeholder="-----BEGIN OPENSSH PRIVATE KEY-----..." value={wsForm.ssh_priv_key} onChange={e => setWsForm({ ...wsForm, ssh_priv_key: e.target.value })} />
                    </div>
                    <div className="md:col-span-2">
                      <label className="text-xs text-zinc-400 mb-1 block">Public SSH Key</label>
                      <textarea className="input-tech font-mono text-xs" rows={2} value={wsForm.ssh_pub_key} onChange={e => setWsForm({ ...wsForm, ssh_pub_key: e.target.value })} />
                    </div>
                  </div>
                  <div className="flex gap-2 justify-end">
                    <button onClick={() => setEditingWs(null)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
                    <button onClick={() => saveWorkspace(ws.id)} className="btn-primary text-sm px-4 py-1.5">💾 Save</button>
                  </div>
                </div>
              )}
              <div className="border-t border-zinc-800 px-4 py-3 bg-zinc-900/50">
                <p className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2">🗂️ Project Keys</p>
                <div className="flex flex-wrap gap-2 mb-2">
                  {ws.project_key && (
                    <span className="text-xs px-2 py-1 rounded bg-zinc-800 border border-zinc-700 font-mono text-yellow-300">
                      {ws.project_key} <span className="text-zinc-500">(default)</span>
                    </span>
                  )}
                  {(projects[ws.id] || []).map(p => (
                    <span key={p.id} className="text-xs px-2 py-1 rounded bg-zinc-800 border border-zinc-700 font-mono text-yellow-300 flex items-center gap-1">
                      {p.project_key}{p.alias ? ` — ${p.alias}` : ""}
                      <button onClick={() => deleteProject(ws.id, p.id)} className="text-red-400 hover:text-red-300 ml-1">✕</button>
                    </span>
                  ))}
                  {!ws.project_key && (projects[ws.id] || []).length === 0 && <span className="text-zinc-600 text-xs italic">No project keys registered.</span>}
                </div>
                <div className="flex gap-2 flex-wrap">
                  <input className="input-tech text-sm flex-1 min-w-24" placeholder="KEY"
                    value={newProjectKey[ws.id]?.project_key || ""}
                    onChange={e => setNewProjectKey(prev => ({ ...prev, [ws.id]: { ...prev[ws.id] || { project_key: "", alias: "" }, project_key: e.target.value } }))} />
                  <input className="input-tech text-sm flex-1 min-w-28" placeholder="Alias (optional)"
                    value={newProjectKey[ws.id]?.alias || ""}
                    onChange={e => setNewProjectKey(prev => ({ ...prev, [ws.id]: { ...prev[ws.id] || { project_key: "", alias: "" }, alias: e.target.value } }))} />
                  <button onClick={() => addProject(ws.id)} className="btn-primary px-3 py-1.5 text-sm">+ Add</button>
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>

      <div className="glass-card p-6 border-l-4 border-l-[#EF7B4D]">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-bold">ArgoCD Instances</h2>
            <p className="text-zinc-400 text-sm mt-1">Register multiple ArgoCD servers. {!isAdmin && <span className="text-yellow-500 text-xs">Admin only</span>}</p>
          </div>
          {isAdmin && <button onClick={() => setShowNewArgo(!showNewArgo)} className="btn-primary text-sm px-3 py-1.5 shrink-0">+ New Instance</button>}
        </div>
        {isAdmin && showNewArgo && (
          <div className="mb-4 p-4 rounded bg-zinc-900 border border-orange-500/40 space-y-3">
            <h3 className="font-semibold text-sm text-orange-300">New ArgoCD Instance</h3>
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Name / Alias</label>
              <input className="input-tech text-sm" placeholder="My ArgoCD" value={newArgoForm.alias} onChange={e => setNewArgoForm({ ...newArgoForm, alias: e.target.value })} />
            </div>
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Server URL</label>
              <input className="input-tech text-sm" placeholder="https://argocd.example.com" value={newArgoForm.server_url} onChange={e => setNewArgoForm({ ...newArgoForm, server_url: e.target.value })} />
            </div>
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Auth Token</label>
              <input type="password" className="input-tech text-sm" placeholder="Access token..." value={newArgoForm.auth_token} onChange={e => setNewArgoForm({ ...newArgoForm, auth_token: e.target.value })} />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">Destination Namespace <span className="text-zinc-600">(default: default)</span></label>
                <input className="input-tech text-sm font-mono" placeholder="default" value={newArgoForm.default_namespace} onChange={e => setNewArgoForm({ ...newArgoForm, default_namespace: e.target.value })} />
              </div>
              <div>
                <label className="text-xs text-zinc-400 mb-1 block">ArgoCD Project <span className="text-zinc-600">(default: default)</span></label>
                <input className="input-tech text-sm font-mono" placeholder="default" value={newArgoForm.default_project} onChange={e => setNewArgoForm({ ...newArgoForm, default_project: e.target.value })} />
              </div>
            </div>
            <div>
              <label className="text-xs text-zinc-400 mb-1 block">Prometheus URL <span className="text-zinc-600">(optional — enables CPU/memory/network metrics)</span></label>
              <input className="input-tech text-sm" placeholder="http://prometheus-service.monitoring:9090" value={newArgoForm.prometheus_url} onChange={e => setNewArgoForm({ ...newArgoForm, prometheus_url: e.target.value })} />
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowNewArgo(false)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
              <button onClick={createArgoCDInstance} className="btn-primary text-sm px-4 py-1.5">Create Instance</button>
            </div>
          </div>
        )}
        <div className="space-y-2">
          {argoInstances.length === 0 && <p className="text-zinc-500 text-sm italic">No ArgoCD instances registered.</p>}
          {argoInstances.map(inst => (
            <div key={inst.id} className="rounded border border-zinc-700">
              <div className="flex items-center gap-3 px-4 py-3 bg-zinc-900 rounded-t">
                <div className="flex-1">
                  <span className="font-semibold text-orange-300">{inst.alias}</span>
                  <span className="text-zinc-500 text-xs ml-2">{inst.server_url}</span>
                  <span className="text-zinc-600 text-xs ml-2">ns: {inst.default_namespace || "default"} · project: {inst.default_project || "default"}{inst.prometheus_url ? " · prometheus ✓" : ""}</span>
                </div>
                {isAdmin && <>
                  <button onClick={() => { setEditingArgo(inst.id); setArgoForm({ alias: inst.alias, server_url: inst.server_url, auth_token: "", default_namespace: inst.default_namespace || "", default_project: inst.default_project || "", prometheus_url: inst.prometheus_url || "" }); }} className="text-zinc-400 hover:text-zinc-200 text-sm px-2">✏️</button>
                  <button onClick={() => deleteArgoCDInstance(inst.id)} className="text-red-400 hover:text-red-300 text-sm px-1">✕</button>
                </>}
              </div>
              {editingArgo === inst.id && (
                <div className="p-4 border-t border-zinc-700 bg-zinc-950 space-y-3">
                  <div>
                    <label className="text-xs text-zinc-400 mb-1 block">Name / Alias</label>
                    <input className="input-tech text-sm" value={argoForm.alias} onChange={e => setArgoForm({ ...argoForm, alias: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-xs text-zinc-400 mb-1 block">Server URL</label>
                    <input className="input-tech text-sm" value={argoForm.server_url} onChange={e => setArgoForm({ ...argoForm, server_url: e.target.value })} />
                  </div>
                  <div>
                    <label className="text-xs text-zinc-400 mb-1 block">Auth Token <span className="text-zinc-500">(leave blank to keep)</span></label>
                    <input type="password" className="input-tech text-sm" placeholder="New token..." value={argoForm.auth_token} onChange={e => setArgoForm({ ...argoForm, auth_token: e.target.value })} />
                  </div>
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <label className="text-xs text-zinc-400 mb-1 block">Destination Namespace</label>
                      <input className="input-tech text-sm font-mono" placeholder="default" value={argoForm.default_namespace} onChange={e => setArgoForm({ ...argoForm, default_namespace: e.target.value })} />
                    </div>
                    <div>
                      <label className="text-xs text-zinc-400 mb-1 block">ArgoCD Project</label>
                      <input className="input-tech text-sm font-mono" placeholder="default" value={argoForm.default_project} onChange={e => setArgoForm({ ...argoForm, default_project: e.target.value })} />
                    </div>
                  </div>
                  <div>
                    <label className="text-xs text-zinc-400 mb-1 block">Prometheus URL</label>
                    <input className="input-tech text-sm" placeholder="http://prometheus-service.monitoring:9090" value={argoForm.prometheus_url} onChange={e => setArgoForm({ ...argoForm, prometheus_url: e.target.value })} />
                  </div>
                  <div className="flex gap-2 justify-end">
                    <button onClick={() => setEditingArgo(null)} className="btn-secondary text-sm px-3 py-1.5">Cancel</button>
                    <button onClick={() => saveArgoCDInstance(inst.id)} className="btn-primary text-sm px-4 py-1.5">💾 Save</button>
                  </div>
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      <div className="glass-card p-6 border-l-4 border-l-cyan-500">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h2 className="text-xl font-bold">🐳 Registry Credentials</h2>
            <p className="text-zinc-400 text-sm mt-1">Credentials for container registries used in image security scans.</p>
          </div>
          <button onClick={() => { setShowNewReg(true); setNewRegForm(emptyReg()); }} className="btn-primary text-sm px-3 py-1.5">+ New Registry</button>
        </div>

        {showNewReg && (
          <RegistryForm
            form={newRegForm}
            onChange={setNewRegForm}
            onSave={async () => {
              const res = await apiFetch("/registry-credentials", { method: "POST", body: JSON.stringify(newRegForm) });
              const data = await res.json();
              if (res.ok) {
                const r = await apiFetch("/registry-credentials").then(r => r.json());
                setRegistryCreds(Array.isArray(r) ? r : []);
                setShowNewReg(false);
                msg("✅ Registry saved!");
              } else { msg(`❌ ${data.error}`); }
            }}
            onCancel={() => setShowNewReg(false)}
          />
        )}

        {registryCreds.map(reg => (
          <div key={reg.id} className="border border-zinc-700 rounded-lg p-4 mb-2">
            {editingReg === reg.id ? (
              <RegistryForm
                form={regForm}
                onChange={setRegForm}
                onSave={async () => {
                  const res = await apiFetch(`/registry-credentials/${reg.id}`, { method: "PUT", body: JSON.stringify(regForm) });
                  if (res.ok) {
                    const r = await apiFetch("/registry-credentials").then(r => r.json());
                    setRegistryCreds(Array.isArray(r) ? r : []);
                    setEditingReg(null);
                    msg("✅ Registry updated!");
                  }
                }}
                onCancel={() => setEditingReg(null)}
              />
            ) : (
              <div className="flex items-center justify-between gap-3">
                <div>
                  <span className="font-bold text-brand-gold">{reg.alias}</span>
                  <span className="ml-2 text-xs text-zinc-500">{reg.host}</span>
                  <span className={`ml-2 text-[10px] px-2 py-0.5 rounded font-medium ${reg.type === "ecr" ? "bg-orange-900/40 text-orange-400" : reg.type === "gcr" ? "bg-blue-900/40 text-blue-400" : "bg-zinc-800 text-zinc-400"}`}>{reg.type.toUpperCase()}</span>
                  <div className="text-xs text-zinc-500 mt-1">
                    {reg.type === "ecr" && <span>Region: {reg.aws_region} · Key: {reg.has_aws_key ? "✓" : "—"}</span>}
                    {reg.type === "gcr" && <span>Service Account: {reg.has_gcr_key ? "✓" : "—"}</span>}
                    {reg.type === "generic" && <span>User: {reg.username || "—"} · Password: {reg.has_password ? "✓" : "—"}</span>}
                  </div>
                </div>
                <div className="flex gap-2">
                  <button onClick={() => { setEditingReg(reg.id); setRegForm({ alias: reg.alias, host: reg.host, type: reg.type, username: reg.username || "", password: "", aws_access_key: "", aws_secret_key: "", aws_region: reg.aws_region || "", gcr_key_json: "" }); }} className="text-zinc-400 hover:text-brand-gold transition text-sm">✏️</button>
                  <button onClick={async () => { await apiFetch(`/registry-credentials/${reg.id}`, { method: "DELETE" }); setRegistryCreds(prev => prev.filter(r => r.id !== reg.id)); }} className="text-zinc-400 hover:text-red-400 transition text-sm">✕</button>
                </div>
              </div>
            )}
          </div>
        ))}

        {registryCreds.length === 0 && !showNewReg && (
          <p className="text-zinc-500 text-sm italic">No registry credentials configured. Add one to enable image scanning.</p>
        )}
      </div>
    </div>
  );
}

function RegistryForm({ form, onChange, onSave, onCancel }: {
  form: ReturnType<typeof emptyReg>;
  onChange: (f: ReturnType<typeof emptyReg>) => void;
  onSave: () => void;
  onCancel: () => void;
}) {
  const f = (key: string, val: string) => onChange({ ...form, [key]: val });
  return (
    <div className="border border-zinc-600 rounded-lg p-4 space-y-3 bg-zinc-900/40 mb-2">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
        <div>
          <label className="text-xs text-zinc-400 mb-1 block">Alias</label>
          <input className="input-tech text-sm" placeholder="My Registry" value={form.alias} onChange={e => f("alias", e.target.value)} />
        </div>
        <div>
          <label className="text-xs text-zinc-400 mb-1 block">Registry Host</label>
          <input className="input-tech text-sm" placeholder="docker.io" value={form.host} onChange={e => f("host", e.target.value)} />
        </div>
        <div>
          <label className="text-xs text-zinc-400 mb-1 block">Type</label>
          <select className="input-tech text-sm" value={form.type} onChange={e => f("type", e.target.value)}>
            <option value="generic">Generic (DockerHub, OCI, Harbor...)</option>
            <option value="ecr">AWS ECR</option>
            <option value="gcr">Google GCR</option>
          </select>
        </div>
      </div>
      {form.type === "generic" && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Username</label>
            <input className="input-tech text-sm" placeholder="username or email" value={form.username} onChange={e => f("username", e.target.value)} />
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">Password / Token <span className="text-zinc-600">(leave blank to keep)</span></label>
            <input className="input-tech text-sm" type="password" placeholder="••••••••" value={form.password} onChange={e => f("password", e.target.value)} />
          </div>
        </div>
      )}
      {form.type === "ecr" && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">AWS Access Key ID <span className="text-zinc-600">(leave blank to keep)</span></label>
            <input className="input-tech text-sm" type="password" placeholder="AKIA..." value={form.aws_access_key} onChange={e => f("aws_access_key", e.target.value)} />
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">AWS Secret Access Key <span className="text-zinc-600">(leave blank to keep)</span></label>
            <input className="input-tech text-sm" type="password" placeholder="••••••••" value={form.aws_secret_key} onChange={e => f("aws_secret_key", e.target.value)} />
          </div>
          <div>
            <label className="text-xs text-zinc-400 mb-1 block">AWS Region</label>
            <input className="input-tech text-sm" placeholder="us-east-1" value={form.aws_region} onChange={e => f("aws_region", e.target.value)} />
          </div>
        </div>
      )}
      {form.type === "gcr" && (
        <div>
          <label className="text-xs text-zinc-400 mb-1 block">Service Account JSON <span className="text-zinc-600">(leave blank to keep)</span></label>
          <textarea className="input-tech text-sm font-mono w-full h-28" placeholder='{"type": "service_account", ...}' value={form.gcr_key_json} onChange={e => f("gcr_key_json", e.target.value)} />
        </div>
      )}
      <div className="flex gap-2 justify-end">
        <button onClick={onCancel} className="px-3 py-1.5 text-sm border border-zinc-600 rounded text-zinc-400 hover:bg-zinc-800 transition">Cancel</button>
        <button onClick={onSave} className="btn-primary text-sm px-4 py-1.5">Save</button>
      </div>
    </div>
  );
}
