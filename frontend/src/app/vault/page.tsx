"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import { loadPermissions, PERMISSIONS } from "@/lib/permissions";
import { openOverview } from "@/lib/vault-crypto";
import {
  ensurePersonalVault,
  fetchPendingKeys,
  fetchKeyring,
  fetchVaultStatus,
  hasVaultSession,
  isUnlocked,
  lock,
  myFingerprint,
  onLockChange,
  touch,
  vaultFetch,
  vaultKey,
  type Keyring,
  type PendingKey,
  type VaultStatus,
  type VaultSummary,
} from "@/lib/vault-session";
import { btnClass, btnPrimary, errorText, IconPlus, IconShield, IconTrash, IconUser, IconUsers, inputClass } from "./ui";
import { ChangePassphrase, CodePanel, MFASetupPanel, SetupPanel, UnlockPanel } from "./gate";
import { ItemCard, ItemEditor, typeOf, type DecryptedItem, type ItemRow } from "./items";
import { AccessPanel, KeyReview } from "./access";
import { NewVault } from "./new-vault";

const roleLabel = (r: VaultSummary["role"]) => (r === "owner" ? "owner" : r === "writer" ? "can edit" : "can read");

function VaultButton({ v, active, onClick }: { v: VaultSummary; active: boolean; onClick: () => void }) {
  return (
    <button onClick={onClick}
      className={`w-full text-left glass-card px-3 py-2 ${active ? "border-brand-green" : ""} ${v.pending ? "opacity-60" : ""}`}>
      <p className="text-sm font-medium truncate">{v.name}</p>
      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
        {v.pending
          ? "waiting for a key"
          : <>{v.item_count} secret{v.item_count === 1 ? "" : "s"}
              {v.kind === "team" ? ` · ${v.member_count} ${v.member_count === 1 ? "person" : "people"}` : ""}
              {` · ${roleLabel(v.role)}`}</>}
      </p>
    </button>
  );
}

export default function VaultPage() {
  const [status, setStatus] = useState<VaultStatus | undefined>(undefined);
  const [, setSessionTick] = useState(0);
  const [keyring, setKeyring] = useState<Keyring | null>(null);
  const [unlocked, setUnlocked] = useState(false);
  const [vaults, setVaults] = useState<VaultSummary[]>([]);
  const [active, setActive] = useState<string>("");
  const [items, setItems] = useState<DecryptedItem[]>([]);
  const [loadingItems, setLoadingItems] = useState(false);
  const [search, setSearch] = useState("");
  const [typeFilter, setTypeFilter] = useState("");
  const [creating, setCreating] = useState(false);
  const [addingItem, setAddingItem] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [changingPass, setChangingPass] = useState(false);
  const [perms, setPerms] = useState({ create: false, edit: false, share: false });
  const [error, setError] = useState("");
  const [pendingKeys, setPendingKeys] = useState<PendingKey[]>([]);
  const [reviewing, setReviewing] = useState(false);

  const refreshStatus = useCallback(() => {
    fetchVaultStatus().then(setStatus).catch(e => setError(errorText(e)));
  }, []);

  useEffect(() => {
    loadPermissions().then(p => {
      // An empty set means the lookup failed: show everything and let the
      // backend refuse what it will.
      const all = p.size === 0;
      setPerms({
        create: all || p.has(PERMISSIONS.vaultCreate),
        edit: all || p.has(PERMISSIONS.vaultWrite),
        share: all || p.has(PERMISSIONS.vaultShare),
      });
    });
    refreshStatus();
    setUnlocked(isUnlocked());
    return onLockChange(setUnlocked);
  }, [refreshStatus]);

  const loadVaults = useCallback(async () => {
    const res = await vaultFetch("/vaults");
    if (!res.ok) return [];
    const list: VaultSummary[] = await res.json();
    setVaults(list);
    setActive(prev => (list.some(v => v.uuid === prev) ? prev : list.find(v => !v.pending)?.uuid || ""));
    return list;
  }, []);

  // The unlocked identity lives in a module and survives client-side
  // navigation; this page's copy of the public half does not.
  useEffect(() => {
    if (unlocked && !keyring) fetchKeyring().then(setKeyring).catch(e => setError(errorText(e)));
  }, [unlocked, keyring]);

  // Keys a group says somebody is owed. Only listed, never sealed here: the
  // person has to approve each one (see KeyReview).
  const loadPending = useCallback(async () => {
    if (!perms.share) return setPendingKeys([]);
    setPendingKeys(await fetchPendingKeys());
  }, [perms.share]);

  // After every unlock: make sure the personal vault exists, and find out
  // who is waiting for a key. Both need a browser holding keys.
  useEffect(() => {
    if (!unlocked || !keyring) return;
    (async () => {
      try {
        const list = await loadVaults();
        if (await ensurePersonalVault(list, keyring.public_key)) await loadVaults();
        await loadPending();
      } catch (e) {
        setError(errorText(e));
      }
    })();
  }, [unlocked, keyring, loadVaults, loadPending]);

  const activeVault = useMemo(() => vaults.find(v => v.uuid === active), [vaults, active]);

  const loadItems = useCallback(async () => {
    if (!activeVault || activeVault.pending) return setItems([]);
    setLoadingItems(true);
    setError("");
    try {
      const res = await vaultFetch(`/vaults/${activeVault.uuid}/items`);
      if (!res.ok) throw new Error("could not list the secrets");
      const rows: ItemRow[] = await res.json();
      const key = await vaultKey(activeVault);
      const out = await Promise.all(rows.map(async row => {
        try {
          return { ...row, overview: await openOverview(key, activeVault.uuid, row.uuid, row.overview_enc) };
        } catch {
          // One unreadable row must not blank the list: it is far more likely
          // to be an item sealed under a key this person no longer holds than
          // a sign that anything else is wrong.
          return { ...row, overview: null };
        }
      }));
      setItems(out);
    } catch (e) {
      setError(errorText(e));
    } finally {
      setLoadingItems(false);
    }
  }, [activeVault]);

  useEffect(() => { if (unlocked) loadItems(); }, [unlocked, loadItems]);

  async function deleteVault(v: VaultSummary) {
    const what = v.kind === "team"
      ? `Delete the team vault "${v.name}" and every secret in it, for everyone who uses it?`
      : `Delete "${v.name}" and every secret in it?`;
    if (!confirm(`${what} This cannot be undone.`)) return;
    touch();
    const res = await vaultFetch(`/vaults/${v.uuid}`, { method: "DELETE" });
    if (!res.ok) {
      const j = await res.json().catch(() => ({}));
      return setError(j.error || "could not delete the vault");
    }
    setActive("");
    await loadVaults();
  }

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    return items.filter(i =>
      (!typeFilter || typeOf(i.overview).id === typeFilter) &&
      (!q ||
        (i.overview?.name ?? "").toLowerCase().includes(q) ||
        (i.overview?.username ?? "").toLowerCase().includes(q) ||
        (i.overview?.url ?? "").toLowerCase().includes(q)));
  }, [items, search, typeFilter]);

  const presentTypes = useMemo(() => {
    const seen = new Map<string, string>();
    for (const i of items) {
      const t = typeOf(i.overview);
      if (i.overview) seen.set(t.id, t.label);
    }
    return [...seen.entries()];
  }, [items]);

  // WebCrypto exists only in a secure context, so over plain HTTP on anything
  // but localhost every call below throws. Saying so is the difference between
  // an explainable deployment note and a page that fails with "cannot read
  // properties of undefined".
  if (typeof window !== "undefined" && !window.isSecureContext) {
    return (
      <div className="p-4 max-w-[1500px] mx-auto">
        <div className="glass-card p-4 max-w-xl">
          <h1 className="text-xl font-semibold flex items-center gap-2"><IconShield /> Vault</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-2">
            This page needs a secure context. The browser only exposes the cryptography the
            vault is built on over HTTPS (or on localhost), and without it nothing here could
            be sealed properly. Serve CommitKube over HTTPS and reload.
          </p>
        </div>
      </div>
    );
  }

  if (status === undefined) {
    return <div className="p-4 text-sm text-zinc-500">{error || "Loading…"}</div>;
  }

  const personal = vaults.filter(v => v.kind === "personal");
  const team = vaults.filter(v => v.kind === "team");
  const canAddItem = Boolean(activeVault && !activeVault.pending && perms.create && activeVault.role !== "reader");
  const canEditItems = Boolean(activeVault && perms.edit && activeVault.role !== "reader");

  let gate: React.ReactNode = null;
  if (!status.mfa_enabled) {
    gate = <MFASetupPanel onDone={() => { refreshStatus(); setSessionTick(t => t + 1); }} />;
  } else if (!status.enrolled) {
    gate = hasVaultSession()
      ? <SetupPanel onDone={async () => { setKeyring(await fetchKeyring()); refreshStatus(); }} />
      : <CodePanel onDone={() => setSessionTick(t => t + 1)} />;
  } else if (!unlocked) {
    gate = <UnlockPanel onUnlocked={k => { setKeyring(k); setUnlocked(true); }} />;
  } else if (changingPass) {
    gate = <ChangePassphrase onClose={() => setChangingPass(false)} />;
  }

  return (
    <div className="p-4 max-w-[1500px] mx-auto">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2"><IconShield /> Vault</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
            Secrets sealed in your browser. The server stores ciphertext and the keys to open it
            are derived from a passphrase it never receives — nobody here, including an
            administrator, can read what you keep in this page. Opening it takes your vault
            passphrase and a code from its own authenticator entry.
          </p>
        </div>
        {unlocked && (
          <div className="text-right shrink-0">
            <button className={btnClass} onClick={() => setChangingPass(v => !v)}>Passphrase</button>
            <button className={`${btnClass} ml-2`} onClick={lock}>Lock now</button>
            <p className="text-[10px] text-zinc-400 font-mono mt-1" title="Your key fingerprint">
              {myFingerprint().slice(0, 16)}
            </p>
          </div>
        )}
      </div>

      <div className="mt-4">
        {gate ?? (
          <div className="grid grid-cols-1 lg:grid-cols-[280px_1fr] gap-4">
            <aside className="space-y-3">
              <div className="flex items-center justify-between">
                <p className="text-[11px] uppercase tracking-wide text-zinc-500">Vaults</p>
                {perms.create && (
                  <button className={btnClass} onClick={() => setCreating(v => !v)} title="New vault"><IconPlus /></button>
                )}
              </div>

              <div className="space-y-1.5">
                <p className="text-[11px] text-zinc-500 flex items-center gap-1.5"><IconUser /> Personal</p>
                {personal.map(v => (
                  <VaultButton key={v.uuid} v={v} active={v.uuid === active}
                    onClick={() => { setActive(v.uuid); setSharing(false); setAddingItem(false); touch(); }} />
                ))}
                {personal.length === 0 && <p className="text-[11px] text-zinc-500">Creating your personal vault…</p>}
              </div>

              <div className="space-y-1.5">
                <p className="text-[11px] text-zinc-500 flex items-center gap-1.5"><IconUsers /> Team</p>
                {team.map(v => (
                  <VaultButton key={v.uuid} v={v} active={v.uuid === active}
                    onClick={() => { setActive(v.uuid); setSharing(false); setAddingItem(false); touch(); }} />
                ))}
                {team.length === 0 && (
                  <p className="text-[11px] text-zinc-500">
                    {perms.share ? "No team vaults yet. Create one with +." : "No team vaults have been shared with you."}
                  </p>
                )}
              </div>
            </aside>

            <section className="space-y-3 min-w-0">
              {pendingKeys.length > 0 && !reviewing && (
                <div className="flex items-center justify-between gap-2 border border-amber-500/40 bg-amber-500/5 rounded px-3 py-2">
                  <p className="text-sm">
                    {pendingKeys.length === 1 ? "1 person is" : `${pendingKeys.length} people are`} waiting
                    for a key to a team vault you can share.
                  </p>
                  <button className={btnClass} onClick={() => setReviewing(true)}>Review</button>
                </div>
              )}
              {reviewing && (
                <div className="glass-card p-3 space-y-2">
                  <div className="flex justify-end">
                    <button className={btnClass} onClick={() => setReviewing(false)}>Close</button>
                  </div>
                  <KeyReview pending={pendingKeys} vaults={vaults}
                    onDone={async () => {
                      await loadVaults();
                      const left = await fetchPendingKeys();
                      setPendingKeys(left);
                      if (left.length === 0) setReviewing(false);
                    }} />
                </div>
              )}

              {creating && keyring && (
                <NewVault myPublicKey={keyring.public_key} canShare={perms.share}
                  onCreated={async uuid => { setCreating(false); await loadVaults(); setActive(uuid); await loadPending(); }}
                  onCancel={() => setCreating(false)} />
              )}

              {!activeVault ? (
                <p className="text-sm text-zinc-500">Pick a vault on the left.</p>
              ) : activeVault.pending ? (
                <div className="glass-card p-4 space-y-1">
                  <h2 className="font-semibold text-sm">{activeVault.name}</h2>
                  <p className="text-sm text-zinc-500 dark:text-zinc-400">
                    A group you are in was given this vault ({roleLabel(activeVault.role)}), but your key
                    has not been sealed yet. That happens in the browser of an owner or editor — the
                    server cannot do it — the next time one of them unlocks the vault. The owner is{" "}
                    <span className="font-medium">{activeVault.owner}</span>.
                  </p>
                </div>
              ) : (
                <>
                  <div className="flex flex-wrap items-start justify-between gap-2">
                    <div className="min-w-0">
                      <h2 className="font-semibold flex items-center gap-2">
                        {activeVault.kind === "team" ? <IconUsers /> : <IconUser />} {activeVault.name}
                      </h2>
                      <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                        {activeVault.kind === "team"
                          ? `Team vault · owner ${activeVault.owner} · you ${roleLabel(activeVault.role)}`
                          : "Personal vault · only you can open it"}
                        {activeVault.description ? ` · ${activeVault.description}` : ""}
                      </p>
                    </div>
                    <div className="flex gap-1.5">
                      {activeVault.kind === "team" && (
                        <button className={btnClass} onClick={() => setSharing(s => !s)}>
                          <span className="flex items-center gap-1.5"><IconUsers /> Access</span>
                        </button>
                      )}
                      {activeVault.role === "owner" && perms.edit && (
                        <button className={btnClass} onClick={() => deleteVault(activeVault)} title="Delete vault">
                          <IconTrash />
                        </button>
                      )}
                    </div>
                  </div>

                  {sharing && activeVault.kind === "team" && (
                    <AccessPanel vault={activeVault} canShare={perms.share}
                      pending={pendingKeys.filter(p => p.vault_uuid === activeVault.uuid)}
                      onClose={() => setSharing(false)}
                      onChanged={() => { loadVaults(); loadPending(); }} />
                  )}

                  <div className="flex flex-wrap items-center gap-2">
                    <input className={`${inputClass} flex-1 min-w-[12rem]`} placeholder="Search this vault…" value={search}
                      onChange={e => setSearch(e.target.value)} />
                    {presentTypes.length > 1 && (
                      <select className={`${inputClass} w-auto`} value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
                        <option value="">All types</option>
                        {presentTypes.map(([id, label]) => <option key={id} value={id}>{label}</option>)}
                      </select>
                    )}
                    {canAddItem && (
                      <button className={btnPrimary} onClick={() => setAddingItem(true)}>New secret</button>
                    )}
                  </div>
                  {activeVault.role === "reader" && (
                    <p className="text-[11px] text-zinc-500">You can read this vault but not change it.</p>
                  )}

                  {addingItem && (
                    <ItemEditor vault={activeVault} item={null}
                      onSaved={() => { setAddingItem(false); loadItems(); loadVaults(); }}
                      onCancel={() => setAddingItem(false)} />
                  )}

                  {error && <p className="text-sm text-red-500">{error}</p>}
                  {loadingItems ? (
                    <p className="text-sm text-zinc-500">Decrypting…</p>
                  ) : shown.length === 0 ? (
                    <p className="text-sm text-zinc-500">
                      {items.length === 0 ? "This vault is empty." : "Nothing matches that search."}
                    </p>
                  ) : (
                    <div className="space-y-2">
                      {shown.map(i => (
                        <ItemCard key={i.uuid} vault={activeVault} item={i} canEdit={canEditItems}
                          onChanged={() => { loadItems(); loadVaults(); }} />
                      ))}
                    </div>
                  )}
                </>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
