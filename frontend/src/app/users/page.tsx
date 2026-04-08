"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface User {
  id: number;
  email: string;
  role: string;
  is_active: boolean;
  mfa_enabled: boolean;
}

export default function UsersPage() {
  const [users, setUsers] = useState<User[]>([]);
  const [loading, setLoading] = useState(true);
  const [myRole, setMyRole] = useState("");
  const [error, setError] = useState("");

  const [newEmail, setNewEmail] = useState("");
  const [newPassword, setNewPassword] = useState("");
  const [newRole, setNewRole] = useState("user");
  const [creating, setCreating] = useState(false);
  const [formError, setFormError] = useState("");
  const [formSuccess, setFormSuccess] = useState("");

  const fetchUsers = async () => {
    const res = await apiFetch("/users");
    if (res.status === 401) { window.location.href = "/login"; return; }
    if (res.status === 403) { setError("Access denied."); setLoading(false); return; }
    const data = await res.json();
    setUsers(Array.isArray(data) ? data : []);
    setLoading(false);
  };

  useEffect(() => {
    const role = localStorage.getItem("role") || "";
    setMyRole(role);
    if (role !== "root" && role !== "admin") {
      window.location.href = "/";
      return;
    }
    fetchUsers();
  }, []);

  const createUser = async (e: React.FormEvent) => {
    e.preventDefault();
    setFormError("");
    setFormSuccess("");
    setCreating(true);
    try {
      const res = await apiFetch("/users", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ email: newEmail, password: newPassword, role: newRole }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Failed to create user");
      setFormSuccess(`User ${newEmail} created. They must configure the account on first login.`);
      setNewEmail("");
      setNewPassword("");
      setNewRole("user");
      fetchUsers();
    } catch (err: any) {
      setFormError(err.message);
    } finally {
      setCreating(false);
    }
  };

  const deleteUser = async (user: User) => {
    if (!confirm(`Permanently delete user ${user.email}? This action cannot be undone.`)) return;
    const res = await apiFetch(`/users/${user.id}`, { method: "DELETE" });
    if (res.ok) setUsers(prev => prev.filter(u => u.id !== user.id));
  };

  const changeRole = async (user: User, role: string) => {
    await apiFetch(`/users/${user.id}/role`, {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ role }),
    });
    fetchUsers();
  };

  const resetMFA = async (user: User) => {
    if (!confirm(`Reset MFA for ${user.email}? They will need to re-enroll on next login.`)) return;
    const res = await apiFetch(`/users/${user.id}/mfa`, { method: "DELETE" });
    if (res.ok) fetchUsers();
  };

  if (loading) return <div className="text-center mt-20 text-brand-green">Loading...</div>;
  if (error) return <div className="text-center mt-20 text-red-400">{error}</div>;

  return (
    <div className="space-y-8">
      <header>
        <h1 className="text-3xl font-bold">User Management</h1>
        <p className="text-zinc-400 mt-2">Create and manage system users.</p>
      </header>

      <div className="glass-card p-6">
        <h2 className="text-lg font-semibold mb-4">New user</h2>
        {formError && (
          <div className="mb-4 p-3 rounded bg-red-500/10 border border-red-500/30 text-red-400 text-sm">{formError}</div>
        )}
        {formSuccess && (
          <div className="mb-4 p-3 rounded bg-brand-green/10 border border-brand-green/30 text-brand-green text-sm">{formSuccess}</div>
        )}
        <form onSubmit={createUser} className="grid grid-cols-1 sm:grid-cols-4 gap-4 items-end">
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Email</label>
            <input
              type="email"
              required
              value={newEmail}
              onChange={(e) => setNewEmail(e.target.value)}
              className="input-tech"
              placeholder="user@email.com"
            />
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Temporary password</label>
            <input
              type="text"
              required
              value={newPassword}
              onChange={(e) => setNewPassword(e.target.value)}
              className="input-tech"
              placeholder="Initial password"
            />
          </div>
          <div>
            <label className="block text-sm text-zinc-400 mb-1">Role</label>
            <select
              value={newRole}
              onChange={(e) => setNewRole(e.target.value)}
              className="input-tech"
            >
              <option value="user">User</option>
              {myRole === "root" && <option value="admin">Admin</option>}
            </select>
          </div>
          <button type="submit" disabled={creating} className="btn-primary py-2">
            {creating ? "Creating..." : "Create user"}
          </button>
        </form>
      </div>

      <div className="glass-card overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-700 text-zinc-400">
              <th className="text-left px-6 py-3">Email</th>
              <th className="text-left px-6 py-3">Role</th>
              <th className="text-left px-6 py-3">Status</th>
              <th className="text-left px-6 py-3">MFA</th>
              <th className="px-6 py-3" />
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id} className="border-b border-zinc-800 hover:bg-surface-hover">
                <td className="px-6 py-3 font-mono text-zinc-200">{u.email}</td>
                <td className="px-6 py-3">
                  {myRole === "root" && u.role !== "root" ? (
                    <select
                      value={u.role}
                      onChange={(e) => changeRole(u, e.target.value)}
                      className="bg-transparent border border-zinc-700 rounded px-2 py-0.5 text-xs text-zinc-300"
                    >
                      <option value="user">user</option>
                      <option value="admin">admin</option>
                    </select>
                  ) : (
                    <span className={`text-xs px-2 py-1 rounded ${
                      u.role === "root" ? "bg-brand-gold/10 text-brand-gold" :
                      u.role === "admin" ? "bg-blue-500/10 text-blue-400" :
                      "bg-zinc-700/50 text-zinc-400"
                    }`}>
                      {u.role}
                    </span>
                  )}
                </td>
                <td className="px-6 py-3">
                  <span className={`text-xs px-2 py-1 rounded ${u.is_active ? "bg-brand-green/10 text-brand-green" : "bg-red-500/10 text-red-400"}`}>
                    {u.is_active ? "active" : "inactive"}
                  </span>
                </td>
                <td className="px-6 py-3">
                  <span className={`text-xs ${u.mfa_enabled ? "text-brand-green" : "text-zinc-500"}`}>
                    {u.mfa_enabled ? "✓ active" : "pending"}
                  </span>
                </td>
                <td className="px-6 py-3 text-right">
                  <div className="flex items-center justify-end gap-3">
                    {u.mfa_enabled && (
                      <button
                        onClick={() => resetMFA(u)}
                        className="text-zinc-500 hover:text-amber-400 transition-colors text-xs"
                      >
                        Reset MFA
                      </button>
                    )}
                    {u.role !== "root" && (
                      <button
                        onClick={() => deleteUser(u)}
                        className="text-zinc-500 hover:text-red-400 transition-colors text-xs"
                      >
                        Delete
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
