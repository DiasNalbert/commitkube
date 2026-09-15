"use client";

import { useState } from "react";
import { apiFetch } from "@/lib/api";

interface User { id: number; email: string; role: string; is_active: boolean }

/** Creating, removing and recovering an account. These used to live on their
 *  own page; they belong beside the permissions, because "who is this person"
 *  and "what may they do" are one question asked in one place. */
export function UserActions({ user, myRole, rootCount, onChanged, onError }: {
  user: User;
  myRole: string;
  rootCount: number;
  onChanged: () => void;
  onError: (msg: string) => void;
}) {
  const [resetting, setResetting] = useState(false);
  const [newPassword, setNewPassword] = useState("");

  const call = async (path: string, init: RequestInit, ok: string) => {
    const res = await apiFetch(path, init);
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      onError(body.error ?? "action failed");
      return false;
    }
    onError("");
    onChanged();
    return Boolean(ok);
  };

  const changeRole = (role: string) =>
    call(`/users/${user.id}/role`, { method: "PUT", body: JSON.stringify({ role }) }, "role updated");

  const resetMFA = () => {
    if (!confirm(`Reset MFA for ${user.email}? They will set it up again on next sign-in.`)) return;
    call(`/users/${user.id}/mfa`, { method: "DELETE" }, "mfa reset");
  };

  const remove = () => {
    if (!confirm(`Delete ${user.email}? Their grants and namespace scopes go with them.`)) return;
    call(`/users/${user.id}`, { method: "DELETE" }, "deleted");
  };

  const setPassword = async () => {
    if (!newPassword) return;
    const done = await call(`/users/${user.id}/password`,
      { method: "PUT", body: JSON.stringify({ password: newPassword }) }, "password set");
    if (done) { setNewPassword(""); setResetting(false); }
  };

  const isRoot = user.role === "root";

  return (
    <section className="glass-card p-4 space-y-3">
      <h2 className="text-sm font-semibold">Account</h2>

      <div className="flex flex-wrap items-center gap-3">
        <label className="text-sm text-zinc-500 dark:text-zinc-400">Role</label>
        {myRole === "root" ? (
          <select value={user.role} onChange={e => changeRole(e.target.value)}
            className="px-3 py-1.5 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
            <option value="user">user</option>
            <option value="admin">admin</option>
            {/* Root edits the policy and authors cluster RBAC, so it is capped
                at two: the backend refuses a third and refuses removing the
                last one. */}
            <option value="root" disabled={rootCount >= 2 && !isRoot}>
              root{rootCount >= 2 && !isRoot ? " (limit of 2)" : ""}
            </option>
          </select>
        ) : (
          <span className="font-mono text-sm text-brand-green">{user.role}</span>
        )}
        <span className={`text-xs ${user.is_active ? "text-brand-green" : "text-amber-500"}`}>
          {user.is_active ? "active" : "inactive"}
        </span>
      </div>

      <div className="flex flex-wrap gap-2">
        <button onClick={() => setResetting(v => !v)}
          className="px-3 py-1.5 text-sm rounded-lg border border-[var(--card-border)] text-zinc-400 hover:text-brand-green transition">
          Set password
        </button>
        <button onClick={resetMFA}
          className="px-3 py-1.5 text-sm rounded-lg border border-[var(--card-border)] text-zinc-400 hover:text-brand-green transition">
          Reset MFA
        </button>
        <button onClick={remove}
          className="px-3 py-1.5 text-sm rounded-lg border border-red-500/30 text-red-500 hover:bg-red-500/10 transition">
          Delete user
        </button>
      </div>

      {resetting && (
        <div className="flex flex-wrap gap-2">
          <input type="password" value={newPassword} onChange={e => setNewPassword(e.target.value)}
            onKeyDown={e => { if (e.key === "Enter") setPassword(); }}
            placeholder="new password"
            className="flex-1 min-w-[200px] px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
          <button onClick={setPassword} disabled={!newPassword}
            className="px-3 py-2 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-40">
            Save
          </button>
        </div>
      )}
    </section>
  );
}

export function NewUser({ myRole, onCreated, onError }: {
  myRole: string;
  onCreated: () => void;
  onError: (msg: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("user");

  const submit = async () => {
    const res = await apiFetch("/users", {
      method: "POST",
      body: JSON.stringify({ email, password, role }),
    });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      onError(body.error ?? "could not create the user");
      return;
    }
    onError("");
    setEmail(""); setPassword(""); setRole("user"); setOpen(false);
    onCreated();
  };

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="w-full px-3 py-2 mt-1 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition">
        New user
      </button>
    );
  }

  return (
    <div className="p-2 space-y-2">
      <input value={email} onChange={e => setEmail(e.target.value)} placeholder="email"
        className="w-full px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
      <input type="password" value={password} onChange={e => setPassword(e.target.value)} placeholder="password"
        className="w-full px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
      <select value={role} onChange={e => setRole(e.target.value)}
        className="w-full px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50">
        <option value="user">user</option>
        {myRole === "root" && <option value="admin">admin</option>}
      </select>
      <div className="flex gap-2">
        <button onClick={submit} disabled={!email || !password}
          className="flex-1 px-3 py-2 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-40">
          Create
        </button>
        <button onClick={() => setOpen(false)} className="px-3 py-2 text-sm text-zinc-500 hover:text-zinc-300">
          Cancel
        </button>
      </div>
      <p className="text-xs text-zinc-500">
        They will be asked to set a new password and enrol MFA on first sign-in.
      </p>
    </div>
  );
}

export function GroupActions({ groupID, name, onChanged, onError }: {
  groupID: number;
  name: string;
  onChanged: () => void;
  onError: (msg: string) => void;
}) {
  const remove = async () => {
    if (!confirm(`Delete the group ${name}? Its grants and namespace scopes go with it. The cluster RoleBinding stays — removing that is a cluster action.`)) return;
    const res = await apiFetch(`/groups/${groupID}`, { method: "DELETE" });
    if (!res.ok) { onError("could not delete the group"); return; }
    onError("");
    onChanged();
  };

  return (
    <section className="glass-card p-4">
      <h2 className="text-sm font-semibold mb-3">Group</h2>
      <button onClick={remove}
        className="px-3 py-1.5 text-sm rounded-lg border border-red-500/30 text-red-500 hover:bg-red-500/10 transition">
        Delete group
      </button>
    </section>
  );
}

export function NewGroup({ onCreated, onError }: { onCreated: () => void; onError: (msg: string) => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");

  const submit = async () => {
    const res = await apiFetch("/groups", { method: "POST", body: JSON.stringify({ name, description }) });
    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      onError(body.error ?? "could not create the group");
      return;
    }
    onError("");
    setName(""); setDescription(""); setOpen(false);
    onCreated();
  };

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="w-full px-3 py-2 mt-1 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition">
        New group
      </button>
    );
  }

  return (
    <div className="p-2 space-y-2">
      <input value={name} onChange={e => setName(e.target.value)} placeholder="name"
        className="w-full px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
      <input value={description} onChange={e => setDescription(e.target.value)} placeholder="description"
        className="w-full px-3 py-2 text-sm rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
      <div className="flex gap-2">
        <button onClick={submit} disabled={!name}
          className="flex-1 px-3 py-2 text-sm rounded-lg border border-brand-green/30 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-40">
          Create
        </button>
        <button onClick={() => setOpen(false)} className="px-3 py-2 text-sm text-zinc-500 hover:text-zinc-300">
          Cancel
        </button>
      </div>
    </div>
  );
}
