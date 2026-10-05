"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { deliverKeys, shareVault, vaultFetch, type PendingKey, type VaultSummary } from "@/lib/vault-session";
import {
  btnClass, btnPrimary, errorText, IconTrash, IconUser, IconUsers, inputClass, selectClass,
} from "./ui";

export type Role = "writer" | "reader";

export interface PublicKeyEntry {
  user_id: number;
  email: string;
  public_key: string;
  fingerprint: string;
}

export interface GroupEntry {
  id: number;
  name: string;
  description: string;
  members: number;
  enrolled: number;
}

interface Member {
  user_id: number;
  email: string;
  role: "owner" | Role;
  fingerprint: string;
  via_group_id: number | null;
  via_group: string;
}

interface GroupAccess {
  group_id: number;
  name: string;
  role: Role;
  members: number;
  with_key: number;
  awaiting_key: string[];
  unenrolled: string[];
}

/** The people and IAM groups a team vault can be given to. Only people who
 *  have set up their own vault appear: a key cannot be sealed to somebody
 *  who has no key to seal it to. */
export function useDirectory(enabled: boolean) {
  const [people, setPeople] = useState<PublicKeyEntry[]>([]);
  const [groups, setGroups] = useState<GroupEntry[]>([]);
  useEffect(() => {
    if (!enabled) return;
    vaultFetch("/vault/public-keys").then(r => (r.ok ? r.json() : [])).then(setPeople).catch(() => {});
    vaultFetch("/vault/groups").then(r => (r.ok ? r.json() : [])).then(setGroups).catch(() => {});
  }, [enabled]);
  return { people, groups };
}

export const RoleSelect = ({ value, onChange, disabled }: {
  value: Role; onChange: (r: Role) => void; disabled?: boolean;
}) => (
  <select className={selectClass} value={value} disabled={disabled}
    onChange={e => onChange(e.target.value as Role)}>
    <option value="reader">can read</option>
    <option value="writer">can edit</option>
  </select>
);

/** Picks people, by email, from those who can be given a key. */
export function PersonPicker({ people, exclude, onPick }: {
  people: PublicKeyEntry[];
  exclude: Set<number>;
  onPick: (p: PublicKeyEntry) => void;
}) {
  const [q, setQ] = useState("");
  const matches = useMemo(() => {
    const s = q.trim().toLowerCase();
    return people.filter(p => !exclude.has(p.user_id) && (!s || p.email.toLowerCase().includes(s))).slice(0, 8);
  }, [people, exclude, q]);
  return (
    <div className="space-y-1.5">
      <input className={inputClass} placeholder="Search people by email…" value={q}
        onChange={e => setQ(e.target.value)} />
      {matches.length === 0 ? (
        <p className="text-[11px] text-zinc-500">
          {people.length === 0 ? "Nobody else has set up a vault yet." : "No one else matches."}
        </p>
      ) : (
        <div className="max-h-48 overflow-auto space-y-1">
          {matches.map(p => (
            <button key={p.user_id} type="button" onClick={() => { onPick(p); setQ(""); }}
              className="w-full flex items-center gap-2 text-left text-sm px-2 py-1 rounded hover:bg-zinc-100 dark:hover:bg-zinc-800">
              <IconUser />
              <span className="flex-1 truncate">{p.email}</span>
              <code className="text-[10px] text-zinc-400 font-mono">{p.fingerprint.slice(0, 12)}</code>
            </button>
          ))}
        </div>
      )}
    </div>
  );
}

export function GroupPicker({ groups, exclude, onPick }: {
  groups: GroupEntry[];
  exclude: Set<number>;
  onPick: (g: GroupEntry) => void;
}) {
  const left = groups.filter(g => !exclude.has(g.id));
  if (groups.length === 0) {
    return <p className="text-[11px] text-zinc-500">No IAM groups exist yet. Groups are created under IAM.</p>;
  }
  if (left.length === 0) return <p className="text-[11px] text-zinc-500">Every group already has access.</p>;
  return (
    <div className="max-h-48 overflow-auto space-y-1">
      {left.map(g => (
        <button key={g.id} type="button" onClick={() => onPick(g)}
          className="w-full flex items-center gap-2 text-left text-sm px-2 py-1 rounded hover:bg-zinc-100 dark:hover:bg-zinc-800">
          <IconUsers />
          <span className="flex-1 truncate">{g.name}</span>
          <span className="text-[11px] text-zinc-500">
            {g.members} member{g.members === 1 ? "" : "s"}
            {g.enrolled < g.members ? ` · ${g.members - g.enrolled} without a vault yet` : ""}
          </span>
        </button>
      ))}
    </div>
  );
}

/** The people a group says should have a vault, waiting for someone holding
 *  its key to seal them a copy. Nothing goes out until it is ticked here.
 *
 *  Group membership is edited by whoever holds user.manage, not by the vault
 *  owner. Without this step, anyone able to edit a group could add
 *  themselves to it and be handed the key on the owner's next unlock. Each
 *  row shows the fingerprint of the key that would be sealed to, so a key
 *  the server swapped in has a chance of being noticed. */
export function KeyReview({ pending, vaults, onDone }: {
  pending: PendingKey[];
  vaults: VaultSummary[];
  onDone: () => void;
}) {
  const id = (p: PendingKey) => `${p.vault_uuid}:${p.user_id}`;
  const [chosen, setChosen] = useState<Set<string>>(new Set());
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const toggle = (p: PendingKey) => setChosen(prev => {
    const next = new Set(prev);
    if (next.has(id(p))) next.delete(id(p)); else next.add(id(p));
    return next;
  });

  async function seal() {
    setBusy(true);
    setError("");
    try {
      const failed = await deliverKeys(vaults, pending.filter(p => chosen.has(id(p))));
      if (failed.length) setError(`Could not seal a key for ${failed.join(", ")}.`);
      setChosen(new Set());
      onDone();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  if (pending.length === 0) return null;
  return (
    <div className="border border-amber-500/40 bg-amber-500/5 rounded p-3 space-y-2">
      <p className="text-sm font-medium">
        {pending.length === 1 ? "1 person is" : `${pending.length} people are`} waiting for a vault key
      </p>
      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
        They are in a group that was given the vault. Group membership is managed in IAM, not
        here, so check each person should really have it before sealing their key. If one
        should not, leave them unticked and have them taken out of the group.
      </p>
      <div className="space-y-1">
        {pending.map(p => (
          <label key={id(p)} className="flex items-center gap-2 text-sm cursor-pointer">
            <input type="checkbox" checked={chosen.has(id(p))} onChange={() => toggle(p)} />
            <span className="flex-1 min-w-0 truncate">
              <span className="font-medium">{p.email}</span>
              <span className="text-zinc-500"> → {p.vault_name} · via {p.group || "a group"} · {p.role === "writer" ? "can edit" : "can read"}</span>
            </span>
            <code className="text-[10px] text-zinc-400 font-mono" title="Fingerprint of the key that will be sealed to">
              {p.fingerprint.slice(0, 16)}
            </code>
          </label>
        ))}
      </div>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <div className="flex items-center gap-2">
        <button className={btnPrimary} disabled={busy || chosen.size === 0} onClick={seal}>
          {busy ? "Sealing…" : chosen.size ? `Seal ${chosen.size} key${chosen.size === 1 ? "" : "s"}` : "Seal keys"}
        </button>
        <button type="button" className="text-[11px] text-zinc-500 hover:text-brand-green"
          onClick={() => setChosen(new Set(pending.map(id)))}>Select all</button>
      </div>
    </div>
  );
}

/** Who can use a team vault, and how. Anyone in the vault can see this; only
 *  the owner, holding vault.share, can change it. */
export function AccessPanel({ vault, canShare, pending, onClose, onChanged }: {
  vault: VaultSummary;
  canShare: boolean;
  /** Keys waiting for this vault, from the page's queue. */
  pending: PendingKey[];
  onClose: () => void;
  onChanged: () => void;
}) {
  const manage = canShare && vault.role === "owner";
  const { people, groups } = useDirectory(manage);
  const [members, setMembers] = useState<Member[]>([]);
  const [access, setAccess] = useState<GroupAccess[]>([]);
  const [newRole, setNewRole] = useState<Role>("reader");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [note, setNote] = useState("");

  const load = useCallback(async () => {
    const [m, g] = await Promise.all([
      vaultFetch(`/vaults/${vault.uuid}/members`),
      vaultFetch(`/vaults/${vault.uuid}/groups`),
    ]);
    if (m.ok) setMembers(await m.json());
    if (g.ok) setAccess(await g.json());
  }, [vault.uuid]);

  useEffect(() => { load(); }, [load]);

  async function run(fn: () => Promise<void>) {
    setBusy(true);
    setError("");
    setNote("");
    try {
      await fn();
      await load();
      onChanged();
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  const call = async (path: string, init: RequestInit) => {
    const res = await vaultFetch(path, init);
    if (!res.ok) {
      const j = await res.json().catch(() => ({}));
      throw new Error(j.error || "the change was refused");
    }
    return res;
  };

  const addPerson = (p: PublicKeyEntry) => run(() => shareVault(vault, p, newRole));
  const setPersonRole = (m: Member, role: Role) =>
    run(async () => { await call(`/vaults/${vault.uuid}/members/${m.user_id}`, { method: "PUT", body: JSON.stringify({ role }) }); });
  const removePerson = (m: Member) => {
    if (!confirm(`Remove ${m.email}? Their key is deleted, but anything they already opened is not un-read — rotate what they saw.`)) return;
    run(async () => { await call(`/vaults/${vault.uuid}/members/${m.user_id}`, { method: "DELETE" }); });
  };

  // Giving a group access seals nothing by itself: its members appear in
  // the review below, to be approved one by one.
  const addGroup = (g: GroupEntry) => run(async () => {
    await call(`/vaults/${vault.uuid}/groups`, { method: "POST", body: JSON.stringify({ group_id: g.id, role: newRole }) });
    setNote(`${g.name} has access. Approve its members below to seal their keys.`);
  });
  const setGroupRole = (g: GroupAccess, role: Role) =>
    run(async () => { await call(`/vaults/${vault.uuid}/groups`, { method: "POST", body: JSON.stringify({ group_id: g.group_id, role }) }); });
  const removeGroup = (g: GroupAccess) => {
    if (!confirm(`Remove ${g.name}? Everyone who has this vault only through that group loses their key. People added by name keep theirs.`)) return;
    run(async () => { await call(`/vaults/${vault.uuid}/groups/${g.group_id}`, { method: "DELETE" }); });
  };

  const memberIDs = new Set(members.map(m => m.user_id));
  const grantedIDs = new Set(access.map(a => a.group_id));

  return (
    <div className="glass-card p-4 space-y-4">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-sm">Who can use “{vault.name}”</h3>
        <button className={btnClass} onClick={onClose}>Close</button>
      </div>
      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
        The vault key is resealed in a browser to each person&apos;s public key — the server never
        holds it. When a group is given access, its members who have set up a vault are listed
        here for you to approve, and so is anyone who joins the group later; each one gets a key
        only once an owner or editor approves them. Leaving the group removes the key. Removing
        somebody does not un-read what they already opened; rotate anything they saw.
      </p>

      {error && <p className="text-sm text-red-500">{error}</p>}
      {note && <p className="text-sm text-brand-green">{note}</p>}

      <section className="space-y-1.5">
        <p className="text-[11px] uppercase tracking-wide text-zinc-500 flex items-center gap-1.5"><IconUsers /> Groups</p>
        {access.length === 0 && <p className="text-sm text-zinc-500">No groups have access.</p>}
        {access.map(g => (
          <div key={g.group_id} className="border border-zinc-200 dark:border-zinc-800 rounded p-2 space-y-1">
            <div className="flex items-center gap-2 text-sm">
              <span className="flex-1 truncate font-medium">{g.name}</span>
              <span className="text-[11px] text-zinc-500">{g.with_key} of {g.members} have the key</span>
              {manage ? (
                <RoleSelect value={g.role} disabled={busy} onChange={r => setGroupRole(g, r)} />
              ) : (
                <span className="text-[11px] uppercase tracking-wide text-zinc-500">{g.role === "writer" ? "can edit" : "can read"}</span>
              )}
              {manage && <button className={btnClass} disabled={busy} onClick={() => removeGroup(g)} title="Remove group"><IconTrash /></button>}
            </div>
            {g.awaiting_key.length > 0 && (
              <p className="text-[11px] text-amber-600 dark:text-amber-400">
                Waiting for a key: {g.awaiting_key.join(", ")}
              </p>
            )}
            {g.unenrolled.length > 0 && (
              <p className="text-[11px] text-zinc-500">
                Need to set up their vault first: {g.unenrolled.join(", ")}
              </p>
            )}
          </div>
        ))}
        {manage && (
          <KeyReview pending={pending} vaults={[vault]} onDone={() => { load(); onChanged(); }} />
        )}
      </section>

      <section className="space-y-1.5">
        <p className="text-[11px] uppercase tracking-wide text-zinc-500 flex items-center gap-1.5"><IconUser /> People</p>
        {members.map(m => (
          <div key={m.user_id} className="flex items-center gap-2 text-sm">
            <span className="flex-1 truncate">{m.email}</span>
            {m.via_group_id && <span className="text-[11px] text-zinc-500">via {m.via_group || "a group"}</span>}
            <code className="text-[10px] text-zinc-400 font-mono">{m.fingerprint.slice(0, 12)}</code>
            {m.role === "owner" ? (
              <span className="text-[11px] uppercase tracking-wide text-zinc-500">owner</span>
            ) : manage && !m.via_group_id ? (
              <>
                <RoleSelect value={m.role} disabled={busy} onChange={r => setPersonRole(m, r)} />
                <button className={btnClass} disabled={busy} onClick={() => removePerson(m)} title="Remove"><IconTrash /></button>
              </>
            ) : (
              <span className="text-[11px] uppercase tracking-wide text-zinc-500">{m.role === "writer" ? "can edit" : "can read"}</span>
            )}
          </div>
        ))}
      </section>

      {manage && (
        <section className="border-t border-zinc-200 dark:border-zinc-800 pt-3 space-y-3">
          <div className="flex items-center gap-2">
            <p className="text-[11px] uppercase tracking-wide text-zinc-500">Give access</p>
            <span className="text-[11px] text-zinc-500">as</span>
            <RoleSelect value={newRole} onChange={setNewRole} />
          </div>
          <div className="grid md:grid-cols-2 gap-4">
            <div>
              <p className="text-xs font-medium mb-1">A person</p>
              <PersonPicker people={people} exclude={memberIDs} onPick={addPerson} />
            </div>
            <div>
              <p className="text-xs font-medium mb-1">A group from IAM</p>
              <GroupPicker groups={groups} exclude={grantedIDs} onPick={addGroup} />
            </div>
          </div>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            Compare a person&apos;s fingerprint with them directly before sharing something sensitive —
            it is what proves the key you sealed to is really theirs.
          </p>
        </section>
      )}
      {!manage && vault.role === "owner" && (
        <p className="text-[11px] text-zinc-500">Changing who has access needs the vault.share permission.</p>
      )}
      {busy && <p className="text-[11px] text-zinc-500">Working…</p>}
    </div>
  );
}
