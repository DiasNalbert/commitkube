"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface User {
  id: number;
  email: string;
  role: string;
}

interface Workspace {
  id: number;
  alias: string;
  workspace_id: string;
}

interface GroupMember {
  user_id: number;
  email: string;
}

interface GroupWorkspace {
  workspace_id: number;
  alias: string;
  workspace_id_slug: string;
}

interface Group {
  id: number;
  name: string;
  description: string;
  members: GroupMember[];
  workspaces: GroupWorkspace[];
}

export default function GroupsPage() {
  const [groups, setGroups] = useState<Group[]>([]);
  const [users, setUsers] = useState<User[]>([]);
  const [workspaces, setWorkspaces] = useState<Workspace[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  // new group form
  const [showNewForm, setShowNewForm] = useState(false);
  const [newName, setNewName] = useState("");
  const [newDesc, setNewDesc] = useState("");
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState("");

  // per-group add-member dropdown state
  const [addMemberGroup, setAddMemberGroup] = useState<number | null>(null);
  const [addMemberUser, setAddMemberUser] = useState<string>("");

  // per-group add-workspace dropdown state
  const [addWsGroup, setAddWsGroup] = useState<number | null>(null);
  const [addWsId, setAddWsId] = useState<string>("");

  const fetchAll = async () => {
    const [rGroups, rUsers, rWs] = await Promise.all([
      apiFetch("/groups"),
      apiFetch("/users"),
      apiFetch("/workspaces"),
    ]);
    if (rGroups.ok) setGroups(await rGroups.json());
    if (rUsers.ok) setUsers(await rUsers.json());
    if (rWs.ok) setWorkspaces(await rWs.json());
    setLoading(false);
  };

  useEffect(() => {
    const role = localStorage.getItem("role") || "";
    if (role !== "root" && role !== "admin") {
      window.location.href = "/";
      return;
    }
    fetchAll();
  }, []);

  const createGroup = async (e: React.FormEvent) => {
    e.preventDefault();
    setCreateError("");
    setCreating(true);
    try {
      const res = await apiFetch("/groups", {
        method: "POST",
        body: JSON.stringify({ name: newName, description: newDesc }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to create group");
      setNewName("");
      setNewDesc("");
      setShowNewForm(false);
      await fetchAll();
    } catch (err: unknown) {
      setCreateError(err instanceof Error ? err.message : "Unknown error");
    } finally {
      setCreating(false);
    }
  };

  const deleteGroup = async (g: Group) => {
    if (!confirm(`Delete group "${g.name}"? This will remove all member and workspace assignments.`)) return;
    const res = await apiFetch(`/groups/${g.id}`, { method: "DELETE" });
    if (res.ok) await fetchAll();
  };

  const addMember = async (groupId: number) => {
    if (!addMemberUser) return;
    const res = await apiFetch(`/groups/${groupId}/members`, {
      method: "POST",
      body: JSON.stringify({ user_id: parseInt(addMemberUser, 10) }),
    });
    if (res.ok) {
      setAddMemberGroup(null);
      setAddMemberUser("");
      await fetchAll();
    }
  };

  const removeMember = async (groupId: number, userId: number) => {
    const res = await apiFetch(`/groups/${groupId}/members/${userId}`, { method: "DELETE" });
    if (res.ok) await fetchAll();
  };

  const addWorkspace = async (groupId: number) => {
    if (!addWsId) return;
    const res = await apiFetch(`/groups/${groupId}/workspaces`, {
      method: "POST",
      body: JSON.stringify({ workspace_id: parseInt(addWsId, 10) }),
    });
    if (res.ok) {
      setAddWsGroup(null);
      setAddWsId("");
      await fetchAll();
    }
  };

  const removeWorkspace = async (groupId: number, wsId: number) => {
    const res = await apiFetch(`/groups/${groupId}/workspaces/${wsId}`, { method: "DELETE" });
    if (res.ok) await fetchAll();
  };

  if (loading) return <div className="text-center mt-20 text-brand-green">Loading...</div>;
  if (error) return <div className="text-center mt-20 text-red-400">{error}</div>;

  return (
    <div className="space-y-8">
      <header className="flex items-start justify-between">
        <div>
          <h1 className="text-3xl font-bold">User Groups</h1>
          <p className="text-zinc-400 mt-2">Assign users to groups and control workspace access.</p>
        </div>
        <button
          onClick={() => { setShowNewForm(true); setCreateError(""); }}
          className="btn-primary py-2 px-4"
        >
          New Group
        </button>
      </header>

      {showNewForm && (
        <div className="glass-card p-6 space-y-4">
          <h2 className="text-lg font-semibold">Create group</h2>
          {createError && (
            <div className="p-3 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{createError}</div>
          )}
          <form onSubmit={createGroup} className="grid grid-cols-1 sm:grid-cols-3 gap-4 items-end">
            <div>
              <label className="block text-sm text-zinc-400 mb-1">Name</label>
              <input
                required
                value={newName}
                onChange={(e) => setNewName(e.target.value)}
                className="input-tech w-full"
                placeholder="e.g. DEV01"
              />
            </div>
            <div>
              <label className="block text-sm text-zinc-400 mb-1">Description</label>
              <input
                value={newDesc}
                onChange={(e) => setNewDesc(e.target.value)}
                className="input-tech w-full"
                placeholder="Optional description"
              />
            </div>
            <div className="flex gap-3">
              <button type="submit" disabled={creating} className="btn-primary py-2 px-4 flex-1">
                {creating ? "Creating..." : "Create"}
              </button>
              <button
                type="button"
                onClick={() => setShowNewForm(false)}
                className="text-zinc-400 hover:text-zinc-200 text-sm px-3"
              >
                Cancel
              </button>
            </div>
          </form>
        </div>
      )}

      {groups.length === 0 && !showNewForm && (
        <div className="glass-card p-10 text-center text-zinc-500">
          No groups yet. Click <span className="text-brand-green">"New Group"</span> to create one.
        </div>
      )}

      <div className="space-y-4">
        {groups.map((g) => {
          const memberUserIds = new Set(g.members.map((m) => m.user_id));
          const assignedWsIds = new Set(g.workspaces.map((w) => w.workspace_id));
          const availableUsers = users.filter((u) => !memberUserIds.has(u.id));
          const availableWs = workspaces.filter((w) => !assignedWsIds.has(w.id));

          return (
            <div key={g.id} className="glass-card p-6 space-y-5">
              {/* Header */}
              <div className="flex items-start justify-between gap-4">
                <div>
                  <h2 className="text-lg font-semibold text-brand-gold">{g.name}</h2>
                  {g.description && (
                    <p className="text-sm text-zinc-400 mt-0.5">{g.description}</p>
                  )}
                </div>
                <button
                  onClick={() => deleteGroup(g)}
                  className="text-zinc-500 hover:text-red-400 transition-colors text-sm shrink-0"
                >
                  Delete group
                </button>
              </div>

              {/* Members section */}
              <div className="space-y-2">
                <p className="text-xs font-semibold uppercase tracking-widest text-zinc-500">Members</p>
                {g.members.length === 0 && (
                  <p className="text-sm text-zinc-600 italic">No members yet.</p>
                )}
                <div className="flex flex-wrap gap-2">
                  {g.members.map((m) => (
                    <span
                      key={m.user_id}
                      className="flex items-center gap-1.5 bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-300 font-mono"
                    >
                      {m.email}
                      <button
                        onClick={() => removeMember(g.id, m.user_id)}
                        className="text-zinc-500 hover:text-red-400 transition-colors ml-1 leading-none"
                        title="Remove member"
                      >
                        &times;
                      </button>
                    </span>
                  ))}
                </div>

                {addMemberGroup === g.id ? (
                  <div className="flex items-center gap-2 mt-2">
                    <select
                      value={addMemberUser}
                      onChange={(e) => setAddMemberUser(e.target.value)}
                      className="input-tech text-sm py-1"
                    >
                      <option value="">Select user...</option>
                      {availableUsers.map((u) => (
                        <option key={u.id} value={u.id}>{u.email}</option>
                      ))}
                    </select>
                    <button
                      onClick={() => addMember(g.id)}
                      disabled={!addMemberUser}
                      className="btn-primary py-1 px-3 text-sm"
                    >
                      Add
                    </button>
                    <button
                      onClick={() => { setAddMemberGroup(null); setAddMemberUser(""); }}
                      className="text-zinc-500 hover:text-zinc-200 text-sm"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => { setAddMemberGroup(g.id); setAddMemberUser(""); }}
                    className="text-xs text-brand-green hover:text-brand-green/80 transition-colors mt-1"
                  >
                    + Add member
                  </button>
                )}
              </div>

              {/* Workspaces section */}
              <div className="space-y-2">
                <p className="text-xs font-semibold uppercase tracking-widest text-zinc-500">Workspaces</p>
                {g.workspaces.length === 0 && (
                  <p className="text-sm text-zinc-600 italic">No workspaces assigned.</p>
                )}
                <div className="flex flex-wrap gap-2">
                  {g.workspaces.map((w) => (
                    <span
                      key={w.workspace_id}
                      className="flex items-center gap-1.5 bg-zinc-800 border border-zinc-700 rounded px-2 py-1 text-xs text-zinc-300"
                    >
                      <span className="text-brand-green font-semibold">{w.alias}</span>
                      <span className="text-zinc-500 font-mono">{w.workspace_id_slug}</span>
                      <button
                        onClick={() => removeWorkspace(g.id, w.workspace_id)}
                        className="text-zinc-500 hover:text-red-400 transition-colors ml-1 leading-none"
                        title="Remove workspace"
                      >
                        &times;
                      </button>
                    </span>
                  ))}
                </div>

                {addWsGroup === g.id ? (
                  <div className="flex items-center gap-2 mt-2">
                    <select
                      value={addWsId}
                      onChange={(e) => setAddWsId(e.target.value)}
                      className="input-tech text-sm py-1"
                    >
                      <option value="">Select workspace...</option>
                      {availableWs.map((w) => (
                        <option key={w.id} value={w.id}>{w.alias} ({w.workspace_id})</option>
                      ))}
                    </select>
                    <button
                      onClick={() => addWorkspace(g.id)}
                      disabled={!addWsId}
                      className="btn-primary py-1 px-3 text-sm"
                    >
                      Add
                    </button>
                    <button
                      onClick={() => { setAddWsGroup(null); setAddWsId(""); }}
                      className="text-zinc-500 hover:text-zinc-200 text-sm"
                    >
                      Cancel
                    </button>
                  </div>
                ) : (
                  <button
                    onClick={() => { setAddWsGroup(g.id); setAddWsId(""); }}
                    className="text-xs text-brand-green hover:text-brand-green/80 transition-colors mt-1"
                  >
                    + Add workspace
                  </button>
                )}
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
