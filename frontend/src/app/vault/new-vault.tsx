"use client";

import { useState } from "react";
import {
  createVault, deliverPendingKeys, myFingerprint, shareVault, vaultFetch, type VaultSummary,
} from "@/lib/vault-session";
import { btnClass, btnPrimary, errorText, Field, IconTrash, IconUser, IconUsers, inputClass } from "./ui";
import {
  GroupPicker, PersonPicker, RoleSelect, useDirectory, type GroupEntry, type PublicKeyEntry, type Role,
} from "./access";

/** A personal vault is yours alone and cannot be shared. A team vault is
 *  given to people by name, to IAM groups, or both -- and can be changed
 *  afterwards from its access panel. */
export function NewVault({ myPublicKey, canShare, onCreated, onCancel }: {
  myPublicKey: string;
  canShare: boolean;
  onCreated: (uuid: string) => void;
  onCancel: () => void;
}) {
  const [kind, setKind] = useState<"personal" | "team">("personal");
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [people, setPeople] = useState<{ p: PublicKeyEntry; role: Role }[]>([]);
  const [groups, setGroups] = useState<{ g: GroupEntry; role: Role }[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const dir = useDirectory(canShare && kind === "team");
  // You own it already; the directory lists everyone enrolled, you included.
  const others = dir.people.filter(p => p.fingerprint !== myFingerprint());

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    let uuid = "";
    try {
      uuid = await createVault({ name, description, kind, myPublicKey });
      if (kind === "team" && (people.length || groups.length)) {
        // Sharing needs this vault's wrapped key, which only the list carries.
        const list: VaultSummary[] = await vaultFetch("/vaults").then(r => r.json());
        const v = list.find(x => x.uuid === uuid);
        if (!v) throw new Error("the vault was created but could not be reloaded to share it");
        for (const { p, role } of people) await shareVault(v, p, role);
        for (const { g, role } of groups) {
          const res = await vaultFetch(`/vaults/${uuid}/groups`, {
            method: "POST", body: JSON.stringify({ group_id: g.id, role }),
          });
          if (!res.ok) {
            const j = await res.json().catch(() => ({}));
            throw new Error(j.error || `could not give ${g.name} access`);
          }
        }
        await deliverPendingKeys([v]);
      }
      onCreated(uuid);
    } catch (err) {
      // A vault that exists but is only partly shared is still worth
      // opening: the access panel shows exactly who is missing.
      if (uuid) {
        setError(`The vault was created, but sharing stopped: ${errorText(err)}. Open its access panel to finish.`);
        setTimeout(() => onCreated(uuid), 2500);
      } else {
        setError(errorText(err));
      }
    } finally {
      setBusy(false);
    }
  }

  const kindCard = (k: "personal" | "team", title: string, body: string, disabled = false) => (
    <button type="button" disabled={disabled} onClick={() => setKind(k)}
      className={`text-left rounded border p-3 transition-colors disabled:opacity-50 ${
        kind === k ? "border-brand-green" : "border-zinc-300 dark:border-zinc-700 hover:border-brand-green"
      }`}>
      <p className="text-sm font-medium flex items-center gap-1.5">{k === "personal" ? <IconUser /> : <IconUsers />} {title}</p>
      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 mt-0.5">{body}</p>
    </button>
  );

  return (
    <form onSubmit={submit} className="glass-card p-4 space-y-3">
      <h3 className="font-semibold text-sm">New vault</h3>
      <div className="grid sm:grid-cols-2 gap-2">
        {kindCard("personal", "Personal", "Only you. It can never be shared.")}
        {kindCard("team", "Team",
          canShare ? "Give it to people, IAM groups, or both." : "Needs the vault.share permission.", !canShare)}
      </div>
      <Field label="Name">
        <input className={inputClass} value={name} autoFocus required maxLength={120}
          placeholder={kind === "team" ? "e.g. Platform — production" : "e.g. Side projects"}
          onChange={e => setName(e.target.value)} />
      </Field>
      <Field label="Description (optional)">
        <input className={inputClass} value={description} maxLength={500}
          onChange={e => setDescription(e.target.value)} />
      </Field>
      <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
        The vault&apos;s name and description are visible to the server so the list can be shown
        before anything is unlocked. Everything inside is sealed.
      </p>

      {kind === "team" && canShare && (
        <div className="space-y-3 border-t border-zinc-200 dark:border-zinc-800 pt-3">
          <div className="grid md:grid-cols-2 gap-4">
            <div className="space-y-2">
              <p className="text-xs font-medium flex items-center gap-1.5"><IconUsers /> Groups</p>
              {groups.map(({ g, role }) => (
                <div key={g.id} className="flex items-center gap-2 text-sm">
                  <span className="flex-1 truncate">{g.name}</span>
                  <RoleSelect value={role} onChange={r => setGroups(gs => gs.map(x => x.g.id === g.id ? { ...x, role: r } : x))} />
                  <button type="button" className={btnClass} onClick={() => setGroups(gs => gs.filter(x => x.g.id !== g.id))}><IconTrash /></button>
                </div>
              ))}
              <GroupPicker groups={dir.groups} exclude={new Set(groups.map(x => x.g.id))}
                onPick={g => setGroups(gs => [...gs, { g, role: "reader" }])} />
            </div>
            <div className="space-y-2">
              <p className="text-xs font-medium flex items-center gap-1.5"><IconUser /> People</p>
              {people.map(({ p, role }) => (
                <div key={p.user_id} className="flex items-center gap-2 text-sm">
                  <span className="flex-1 truncate">{p.email}</span>
                  <RoleSelect value={role} onChange={r => setPeople(ps => ps.map(x => x.p.user_id === p.user_id ? { ...x, role: r } : x))} />
                  <button type="button" className={btnClass} onClick={() => setPeople(ps => ps.filter(x => x.p.user_id !== p.user_id))}><IconTrash /></button>
                </div>
              ))}
              <PersonPicker people={others} exclude={new Set(people.map(x => x.p.user_id))}
                onPick={p => setPeople(ps => [...ps, { p, role: "reader" }])} />
            </div>
          </div>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            You are the owner. Everyone else gets the role you pick here; it can be changed later.
          </p>
        </div>
      )}

      {error && <p className="text-sm text-red-500">{error}</p>}
      <div className="flex gap-2">
        <button className={btnPrimary} disabled={busy || !name.trim()}>
          {busy ? "Sealing…" : kind === "team" ? "Create team vault" : "Create personal vault"}
        </button>
        <button type="button" className={btnClass} onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}
