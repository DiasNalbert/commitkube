"use client";

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { apiFetch } from "@/lib/api";
import { loadPermissions, PERMISSIONS } from "@/lib/permissions";
import {
  generatePassword,
  normaliseRecoveryCode,
  openOverview,
  openSecret,
  sealOverview,
  sealSecret,
  type ItemOverview,
  type ItemSecret,
} from "@/lib/vault-crypto";
import {
  changePassphrase,
  createVault,
  fetchKeyring,
  isUnlocked,
  lock,
  myFingerprint,
  onLockChange,
  recoverWithCode,
  setUpVault,
  shareVault,
  touch,
  unlock,
  vaultKey,
  type Keyring,
  type VaultSummary,
} from "@/lib/vault-session";

interface ItemRow {
  uuid: string;
  overview_enc: string;
  version: number;
  updated_at: string;
  updated_by: string;
}

interface DecryptedItem extends ItemRow {
  overview: ItemOverview | null;
}

interface PublicKeyEntry {
  user_id: number;
  email: string;
  public_key: string;
  fingerprint: string;
}

const IconLock = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-4 h-4">
    <rect x="3" y="11" width="18" height="11" rx="2" /><path d="M7 11V7a5 5 0 0110 0v4" />
  </svg>
);
const IconShield = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5">
    <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
  </svg>
);
const IconCopy = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <rect x="9" y="9" width="13" height="13" rx="2" /><path d="M5 15H4a2 2 0 01-2-2V4a2 2 0 012-2h9a2 2 0 012 2v1" />
  </svg>
);
const IconPlus = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" />
  </svg>
);
const IconTrash = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-3.5 h-3.5">
    <polyline points="3 6 5 6 21 6" /><path d="M19 6v14a2 2 0 01-2 2H7a2 2 0 01-2-2V6m3 0V4a2 2 0 012-2h4a2 2 0 012 2v2" />
  </svg>
);

/** A rough bit count, not a verdict. It is here to stop somebody choosing a
 *  passphrase that six weeks later turns out to have been the only thing
 *  between a database copy and every password in it. */
function strengthOf(s: string): { bits: number; label: string; tone: string } {
  let pool = 0;
  if (/[a-z]/.test(s)) pool += 26;
  if (/[A-Z]/.test(s)) pool += 26;
  if (/[0-9]/.test(s)) pool += 10;
  if (/[^a-zA-Z0-9]/.test(s)) pool += 30;
  const bits = s.length ? Math.round(s.length * Math.log2(pool || 1)) : 0;
  if (bits < 60) return { bits, label: "too weak", tone: "text-red-500 dark:text-red-400" };
  if (bits < 80) return { bits, label: "workable", tone: "text-amber-600 dark:text-amber-400" };
  if (bits < 110) return { bits, label: "good", tone: "text-sky-600 dark:text-sky-400" };
  return { bits, label: "strong", tone: "text-emerald-600 dark:text-emerald-400" };
}

/** Copies, then blanks the clipboard half a minute later. It is a courtesy,
 *  not a control -- anything that read the clipboard in those thirty seconds
 *  already has the password -- and it is worth having because the usual way a
 *  password escapes is being pasted into the wrong window an hour later. */
function useClipboard() {
  const [copied, setCopied] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  const copy = useCallback(async (value: string, label: string) => {
    try {
      await navigator.clipboard.writeText(value);
      setCopied(label);
      setTimeout(() => setCopied(""), 1500);
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        navigator.clipboard.writeText("").catch(() => {});
      }, 30000);
    } catch {
      setCopied("");
    }
  }, []);
  return { copied, copy };
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="block">
      <span className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</span>
      <div className="mt-1">{children}</div>
    </label>
  );
}

const inputClass =
  "w-full bg-white/60 dark:bg-zinc-900/60 border border-zinc-300 dark:border-zinc-700 rounded px-2.5 py-1.5 text-sm outline-none focus:border-brand-green";
const btnClass =
  "px-3 py-1.5 text-sm rounded border border-zinc-300 dark:border-zinc-700 hover:border-brand-green transition-colors disabled:opacity-50";
const btnPrimary =
  "px-3 py-1.5 text-sm rounded bg-brand-green text-white hover:brightness-110 transition disabled:opacity-50";

/** Shown once, and only once: the server never holds this in a form it could
 *  give back. Making the person tick a box is the difference between a code
 *  they saved and a code they scrolled past. */
function RecoveryCode({ code, onDone }: { code: string; onDone: () => void }) {
  const [ack, setAck] = useState(false);
  const { copied, copy } = useClipboard();
  return (
    <div className="glass-card p-4 max-w-xl">
      <h2 className="font-semibold flex items-center gap-2"><IconShield /> Save your recovery code</h2>
      <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
        This is the only other way into your vault. It is not stored anywhere we can read,
        so if you lose both this and your passphrase, the contents are gone — there is no
        administrator who can recover them.
      </p>
      <div className="mt-3 font-mono text-sm tracking-wider bg-zinc-100 dark:bg-zinc-900 border border-zinc-300 dark:border-zinc-700 rounded p-3 break-all select-all">
        {code}
      </div>
      <div className="flex items-center gap-2 mt-3">
        <button className={btnClass} onClick={() => copy(code, "code")}>
          <span className="flex items-center gap-1.5"><IconCopy /> {copied ? "Copied" : "Copy"}</span>
        </button>
        <label className="flex items-center gap-2 text-sm ml-auto">
          <input type="checkbox" checked={ack} onChange={e => setAck(e.target.checked)} />
          I have written it down
        </label>
        <button className={btnPrimary} disabled={!ack} onClick={onDone}>Continue</button>
      </div>
    </div>
  );
}

function SetupPanel({ onDone }: { onDone: () => void }) {
  const [pass, setPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [code, setCode] = useState("");
  const strength = strengthOf(pass);

  if (code) return <RecoveryCode code={code} onDone={onDone} />;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (pass !== confirm) return setError("the two passphrases do not match");
    if (strength.bits < 60) return setError("that passphrase is too weak to be the only thing protecting the vault");
    setBusy(true);
    try {
      setCode(await setUpVault(pass));
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="glass-card p-4 max-w-xl space-y-3">
      <div>
        <h2 className="font-semibold flex items-center gap-2"><IconShield /> Set up your vault</h2>
        <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1">
          Choose a passphrase. It is stretched in your browser and used to unlock a key that
          never leaves this tab — the server stores only sealed bytes and cannot read anything
          you put in the vault. Do not reuse your sign-in password.
        </p>
      </div>
      <Field label="Vault passphrase">
        <input type="password" className={inputClass} value={pass} autoFocus
          onChange={e => setPass(e.target.value)} />
      </Field>
      {pass && (
        <p className={`text-[11px] ${strength.tone}`}>
          about {strength.bits} bits — {strength.label}
        </p>
      )}
      <Field label="Confirm passphrase">
        <input type="password" className={inputClass} value={confirm}
          onChange={e => setConfirm(e.target.value)} />
      </Field>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <button className={btnPrimary} disabled={busy || !pass}>
        {busy ? "Deriving key…" : "Create vault"}
      </button>
    </form>
  );
}

function UnlockPanel({ keyring, onUnlocked }: { keyring: Keyring; onUnlocked: () => void }) {
  const [pass, setPass] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [mode, setMode] = useState<"pass" | "recover">("pass");
  const [code, setCode] = useState("");
  const [newPass, setNewPass] = useState("");
  const [fresh, setFresh] = useState("");

  if (fresh) return <RecoveryCode code={fresh} onDone={onUnlocked} />;

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    try {
      if (mode === "pass") {
        await unlock(keyring, pass);
        onUnlocked();
      } else {
        if (strengthOf(newPass).bits < 60) throw new Error("the new passphrase is too weak");
        setFresh(await recoverWithCode(normaliseRecoveryCode(code), newPass));
      }
    } catch {
      setError(mode === "pass"
        ? "that passphrase did not open the vault"
        : "that recovery code did not open the vault");
    } finally {
      setBusy(false);
    }
  }

  return (
    <form onSubmit={submit} className="glass-card p-4 max-w-xl space-y-3">
      <h2 className="font-semibold flex items-center gap-2"><IconLock /> Vault locked</h2>
      {mode === "pass" ? (
        <>
          <Field label="Vault passphrase">
            <input type="password" className={inputClass} value={pass} autoFocus
              onChange={e => setPass(e.target.value)} />
          </Field>
          {error && <p className="text-sm text-red-500">{error}</p>}
          <div className="flex items-center gap-3">
            <button className={btnPrimary} disabled={busy || !pass}>
              {busy ? "Deriving key…" : "Unlock"}
            </button>
            <button type="button" className="text-sm text-zinc-500 hover:text-brand-green"
              onClick={() => { setMode("recover"); setError(""); }}>
              Use a recovery code
            </button>
          </div>
        </>
      ) : (
        <>
          <p className="text-sm text-zinc-500 dark:text-zinc-400">
            The code is used once. Resetting the passphrase issues a new one, which you will
            be shown on the next screen.
          </p>
          <Field label="Recovery code">
            <input className={`${inputClass} font-mono`} value={code} autoFocus
              onChange={e => setCode(e.target.value)} placeholder="XXXXX-XXXXX-…" />
          </Field>
          <Field label="New passphrase">
            <input type="password" className={inputClass} value={newPass}
              onChange={e => setNewPass(e.target.value)} />
          </Field>
          {error && <p className="text-sm text-red-500">{error}</p>}
          <div className="flex items-center gap-3">
            <button className={btnPrimary} disabled={busy || !code || !newPass}>
              {busy ? "Working…" : "Reset passphrase"}
            </button>
            <button type="button" className="text-sm text-zinc-500 hover:text-brand-green"
              onClick={() => { setMode("pass"); setError(""); }}>
              Back
            </button>
          </div>
        </>
      )}
    </form>
  );
}

/** Changing a passphrase reseals the same identity, so nothing has to be
 *  re-shared and no other member notices. The old passphrase is asked for
 *  rather than the unlocked session being taken as proof: the point of the
 *  prompt is that it is still the same person at the keyboard. */
function ChangePassphrase({ keyring, onClose }: { keyring: Keyring; onClose: () => void }) {
  const [oldPass, setOldPass] = useState("");
  const [newPass, setNewPass] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [done, setDone] = useState(false);
  const strength = strengthOf(newPass);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    if (newPass !== confirm) return setError("the two passphrases do not match");
    if (strength.bits < 60) return setError("that passphrase is too weak");
    setBusy(true);
    try {
      await changePassphrase(keyring, oldPass, newPass);
      setDone(true);
    } catch {
      setError("the current passphrase did not open the vault");
    } finally {
      setBusy(false);
    }
  }

  if (done) {
    return (
      <div className="glass-card p-4 max-w-xl space-y-2">
        <p className="text-sm">Passphrase changed. Your recovery code is unchanged and still works.</p>
        <button className={btnPrimary} onClick={onClose}>Done</button>
      </div>
    );
  }

  return (
    <form onSubmit={submit} className="glass-card p-4 max-w-xl space-y-3">
      <h3 className="font-semibold text-sm">Change vault passphrase</h3>
      <Field label="Current passphrase">
        <input type="password" className={inputClass} value={oldPass} autoFocus
          onChange={e => setOldPass(e.target.value)} />
      </Field>
      <Field label="New passphrase">
        <input type="password" className={inputClass} value={newPass}
          onChange={e => setNewPass(e.target.value)} />
      </Field>
      {newPass && <p className={`text-[11px] ${strength.tone}`}>about {strength.bits} bits — {strength.label}</p>}
      <Field label="Confirm new passphrase">
        <input type="password" className={inputClass} value={confirm}
          onChange={e => setConfirm(e.target.value)} />
      </Field>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <div className="flex gap-2">
        <button className={btnPrimary} disabled={busy || !oldPass || !newPass}>
          {busy ? "Deriving key…" : "Change passphrase"}
        </button>
        <button type="button" className={btnClass} onClick={onClose}>Cancel</button>
      </div>
    </form>
  );
}

function ItemEditor({ vault, item, onSaved, onCancel }: {
  vault: VaultSummary;
  item: DecryptedItem | null;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const [name, setName] = useState(item?.overview?.name ?? "");
  const [username, setUsername] = useState(item?.overview?.username ?? "");
  const [url, setUrl] = useState(item?.overview?.url ?? "");
  const [password, setPassword] = useState("");
  const [notes, setNotes] = useState("");
  const [loaded, setLoaded] = useState(item === null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  // Editing needs the secret half, which means an audited fetch. Opening the
  // editor is going looking, so it is recorded like any other reveal.
  useEffect(() => {
    if (!item) return;
    (async () => {
      try {
        const res = await apiFetch(`/vaults/${vault.uuid}/items/${item.uuid}/secret`);
        if (!res.ok) throw new Error("could not load the item");
        const body = await res.json();
        const key = await vaultKey(vault);
        const secret = await openSecret(key, vault.uuid, item.uuid, body.secret_enc);
        setPassword(secret.password ?? "");
        setNotes(secret.notes ?? "");
        setLoaded(true);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [item, vault]);

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    touch();
    try {
      const key = await vaultKey(vault);
      const uuid = item?.uuid ?? crypto.randomUUID();
      const overview: ItemOverview = { name, username: username || undefined, url: url || undefined };
      const secret: ItemSecret = { password: password || undefined, notes: notes || undefined };
      const overview_enc = await sealOverview(key, vault.uuid, uuid, overview);
      const secret_enc = await sealSecret(key, vault.uuid, uuid, secret);

      const res = item
        ? await apiFetch(`/vaults/${vault.uuid}/items/${uuid}`, {
            method: "PUT",
            body: JSON.stringify({ overview_enc, secret_enc, base_version: item.version }),
          })
        : await apiFetch(`/vaults/${vault.uuid}/items`, {
            method: "POST",
            body: JSON.stringify({ uuid, overview_enc, secret_enc }),
          });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || "could not save the item");
      }
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    } finally {
      setBusy(false);
    }
  }

  if (!loaded && !error) {
    return <div className="glass-card p-4 text-sm text-zinc-500">Decrypting…</div>;
  }

  return (
    <form onSubmit={save} className="glass-card p-4 space-y-3">
      <h3 className="font-semibold text-sm">{item ? "Edit item" : "New item"}</h3>
      <Field label="Name"><input className={inputClass} value={name} autoFocus required
        onChange={e => setName(e.target.value)} /></Field>
      <div className="grid grid-cols-2 gap-3">
        <Field label="Username"><input className={inputClass} value={username}
          onChange={e => setUsername(e.target.value)} /></Field>
        <Field label="URL"><input className={inputClass} value={url}
          onChange={e => setUrl(e.target.value)} /></Field>
      </div>
      <Field label="Password">
        <div className="flex gap-2">
          <input className={`${inputClass} font-mono`} value={password}
            onChange={e => setPassword(e.target.value)} />
          <button type="button" className={btnClass}
            onClick={() => setPassword(generatePassword(24))}>Generate</button>
        </div>
      </Field>
      <Field label="Notes"><textarea className={inputClass} rows={3} value={notes}
        onChange={e => setNotes(e.target.value)} /></Field>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <div className="flex gap-2">
        <button className={btnPrimary} disabled={busy}>{busy ? "Sealing…" : "Save"}</button>
        <button type="button" className={btnClass} onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

function ItemCard({ vault, item, canWrite, onChanged }: {
  vault: VaultSummary;
  item: DecryptedItem;
  canWrite: boolean;
  onChanged: () => void;
}) {
  const [secret, setSecret] = useState<ItemSecret | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(false);
  const { copied, copy } = useClipboard();

  async function reveal() {
    setBusy(true);
    setError("");
    touch();
    try {
      const res = await apiFetch(`/vaults/${vault.uuid}/items/${item.uuid}/secret`);
      if (!res.ok) throw new Error("could not load the item");
      const body = await res.json();
      const key = await vaultKey(vault);
      setSecret(await openSecret(key, vault.uuid, item.uuid, body.secret_enc));
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!confirm(`Delete "${item.overview?.name ?? item.uuid}"? This cannot be undone.`)) return;
    touch();
    await apiFetch(`/vaults/${vault.uuid}/items/${item.uuid}`, { method: "DELETE" });
    onChanged();
  }

  if (editing) {
    return <ItemEditor vault={vault} item={item}
      onSaved={() => { setEditing(false); onChanged(); }}
      onCancel={() => setEditing(false)} />;
  }

  return (
    <div className="glass-card p-3">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="font-medium text-sm truncate">{item.overview?.name ?? <span className="text-red-500">could not decrypt</span>}</p>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
            {item.overview?.username || "—"}
            {item.overview?.url ? ` · ${item.overview.url}` : ""}
          </p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button className={btnClass} onClick={reveal} disabled={busy}>
            {busy ? "…" : secret ? "Refresh" : "Reveal"}
          </button>
          {canWrite && <button className={btnClass} onClick={() => setEditing(true)}>Edit</button>}
          {canWrite && <button className={btnClass} onClick={remove}><IconTrash /></button>}
        </div>
      </div>

      {error && <p className="text-sm text-red-500 mt-2">{error}</p>}

      {secret && (
        <div className="mt-3 space-y-2 border-t border-zinc-200 dark:border-zinc-800 pt-3">
          {secret.password && (
            <div className="flex items-center gap-2">
              <code className="flex-1 font-mono text-sm break-all bg-zinc-100 dark:bg-zinc-900 rounded px-2 py-1">
                {secret.password}
              </code>
              <button className={btnClass} onClick={() => copy(secret.password ?? "", item.uuid)}>
                <span className="flex items-center gap-1.5"><IconCopy />{copied === item.uuid ? "Copied" : "Copy"}</span>
              </button>
            </div>
          )}
          {secret.notes && (
            <p className="text-sm whitespace-pre-wrap text-zinc-600 dark:text-zinc-300">{secret.notes}</p>
          )}
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            This read was recorded in the audit log. The clipboard is cleared 30 seconds after a copy.
          </p>
        </div>
      )}
    </div>
  );
}

function ShareDialog({ vault, onClose }: { vault: VaultSummary; onClose: () => void }) {
  const [people, setPeople] = useState<PublicKeyEntry[]>([]);
  const [members, setMembers] = useState<{ user_id: number; email: string; role: string; fingerprint: string }[]>([]);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const load = useCallback(async () => {
    const [p, m] = await Promise.all([
      apiFetch("/vault/public-keys"),
      apiFetch(`/vaults/${vault.uuid}/members`),
    ]);
    if (p.ok) setPeople(await p.json());
    if (m.ok) setMembers(await m.json());
  }, [vault.uuid]);

  useEffect(() => { load(); }, [load]);

  async function add(person: PublicKeyEntry, role: "writer" | "reader") {
    setBusy(true);
    setError("");
    try {
      await shareVault(vault, person, role);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove(userID: number) {
    await apiFetch(`/vaults/${vault.uuid}/members/${userID}`, { method: "DELETE" });
    await load();
  }

  const memberIDs = new Set(members.map(m => m.user_id));
  const candidates = people.filter(p => !memberIDs.has(p.user_id));

  return (
    <div className="glass-card p-4 space-y-3">
      <div className="flex items-center justify-between">
        <h3 className="font-semibold text-sm">Sharing · {vault.name}</h3>
        <button className={btnClass} onClick={onClose}>Close</button>
      </div>
      <p className="text-[11px] text-zinc-500 dark:text-zinc-400 leading-relaxed">
        The vault key is resealed in your browser to each person&apos;s public key. Compare the
        fingerprint with them directly before sharing something sensitive — it is what proves
        the key you sealed to is really theirs. Removing somebody deletes their key, but it
        does not un-read what they already opened; rotate anything they saw.
      </p>

      <div className="space-y-1.5">
        {members.map(m => (
          <div key={m.user_id} className="flex items-center gap-2 text-sm">
            <span className="flex-1 truncate">{m.email}</span>
            <span className="text-[11px] uppercase tracking-wide text-zinc-500">{m.role}</span>
            <code className="text-[10px] text-zinc-400 font-mono">{m.fingerprint.slice(0, 12)}</code>
            {m.role !== "owner" && (
              <button className={btnClass} onClick={() => remove(m.user_id)}><IconTrash /></button>
            )}
          </div>
        ))}
      </div>

      {error && <p className="text-sm text-red-500">{error}</p>}

      {candidates.length > 0 && (
        <div className="border-t border-zinc-200 dark:border-zinc-800 pt-3 space-y-1.5">
          <p className="text-[11px] uppercase tracking-wide text-zinc-500">Add someone</p>
          {candidates.map(p => (
            <div key={p.user_id} className="flex items-center gap-2 text-sm">
              <span className="flex-1 truncate">{p.email}</span>
              <code className="text-[10px] text-zinc-400 font-mono">{p.fingerprint.slice(0, 12)}</code>
              <button className={btnClass} disabled={busy} onClick={() => add(p, "reader")}>Reader</button>
              <button className={btnClass} disabled={busy} onClick={() => add(p, "writer")}>Writer</button>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

export default function VaultPage() {
  const [keyring, setKeyring] = useState<Keyring | null | undefined>(undefined);
  const [unlocked, setUnlocked] = useState(false);
  const [vaults, setVaults] = useState<VaultSummary[]>([]);
  const [active, setActive] = useState<string>("");
  const [items, setItems] = useState<DecryptedItem[]>([]);
  const [loadingItems, setLoadingItems] = useState(false);
  const [search, setSearch] = useState("");
  const [creating, setCreating] = useState(false);
  const [newVaultName, setNewVaultName] = useState("");
  const [addingItem, setAddingItem] = useState(false);
  const [sharing, setSharing] = useState(false);
  const [changingPass, setChangingPass] = useState(false);
  const [canWriteVaults, setCanWriteVaults] = useState(false);
  const [canShare, setCanShare] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    loadPermissions().then(p => {
      setCanWriteVaults(p.size === 0 || p.has(PERMISSIONS.vaultWrite));
      setCanShare(p.size === 0 || p.has(PERMISSIONS.vaultShare));
    });
    fetchKeyring().then(setKeyring).catch(() => setKeyring(null));
    setUnlocked(isUnlocked());
    return onLockChange(setUnlocked);
  }, []);

  const loadVaults = useCallback(async () => {
    const res = await apiFetch("/vaults");
    if (!res.ok) return;
    const list: VaultSummary[] = await res.json();
    setVaults(list);
    setActive(prev => prev || list[0]?.uuid || "");
  }, []);

  useEffect(() => { if (unlocked) loadVaults(); }, [unlocked, loadVaults]);

  const activeVault = useMemo(() => vaults.find(v => v.uuid === active), [vaults, active]);

  const loadItems = useCallback(async () => {
    if (!activeVault) return setItems([]);
    setLoadingItems(true);
    setError("");
    try {
      const res = await apiFetch(`/vaults/${activeVault.uuid}/items`);
      if (!res.ok) throw new Error("could not list the items");
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
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoadingItems(false);
    }
  }, [activeVault]);

  useEffect(() => { if (unlocked) loadItems(); }, [unlocked, loadItems]);

  async function submitVault(e: React.FormEvent) {
    e.preventDefault();
    if (!keyring) return;
    try {
      await createVault({
        name: newVaultName, description: "", kind: "personal",
        myPublicKey: keyring.public_key,
      });
      setNewVaultName("");
      setCreating(false);
      await loadVaults();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  }

  const shown = useMemo(() => {
    const q = search.trim().toLowerCase();
    if (!q) return items;
    return items.filter(i =>
      (i.overview?.name ?? "").toLowerCase().includes(q) ||
      (i.overview?.username ?? "").toLowerCase().includes(q) ||
      (i.overview?.url ?? "").toLowerCase().includes(q)
    );
  }, [items, search]);

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

  if (keyring === undefined) {
    return <div className="p-4 text-sm text-zinc-500">Loading…</div>;
  }

  return (
    <div className="p-4 max-w-[1500px] mx-auto">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold flex items-center gap-2"><IconShield /> Vault</h1>
          <p className="text-sm text-zinc-500 dark:text-zinc-400 mt-1 max-w-3xl">
            Passwords sealed in your browser. The server stores ciphertext and the keys to open it
            are derived from a passphrase it never receives — nobody here, including an
            administrator, can read what you keep in this page.
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
        {keyring === null ? (
          <SetupPanel onDone={() => fetchKeyring().then(setKeyring)} />
        ) : !unlocked ? (
          <UnlockPanel keyring={keyring} onUnlocked={() => setUnlocked(true)} />
        ) : changingPass ? (
          <ChangePassphrase keyring={keyring} onClose={() => setChangingPass(false)} />
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-[260px_1fr] gap-4">
            <aside className="space-y-2">
              <div className="flex items-center justify-between">
                <p className="text-[11px] uppercase tracking-wide text-zinc-500">Vaults</p>
                {canWriteVaults && (
                  <button className={btnClass} onClick={() => setCreating(v => !v)}><IconPlus /></button>
                )}
              </div>
              {creating && (
                <form onSubmit={submitVault} className="glass-card p-2 space-y-2">
                  <input className={inputClass} placeholder="Vault name" value={newVaultName}
                    autoFocus onChange={e => setNewVaultName(e.target.value)} />
                  <button className={btnPrimary} disabled={!newVaultName.trim()}>Create</button>
                </form>
              )}
              {vaults.map(v => (
                <button key={v.uuid} onClick={() => { setActive(v.uuid); setSharing(false); touch(); }}
                  className={`w-full text-left glass-card px-3 py-2 ${v.uuid === active ? "border-brand-green" : ""}`}>
                  <p className="text-sm font-medium truncate">{v.name}</p>
                  <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
                    {v.item_count} item{v.item_count === 1 ? "" : "s"} · {v.kind}
                    {v.kind === "group" ? ` · ${v.member_count} members` : ""} · {v.role}
                  </p>
                </button>
              ))}
              {vaults.length === 0 && (
                <p className="text-sm text-zinc-500">No vaults yet.</p>
              )}
            </aside>

            <section className="space-y-3">
              {activeVault ? (
                <>
                  <div className="flex items-center gap-2">
                    <input className={inputClass} placeholder="Search this vault…" value={search}
                      onChange={e => setSearch(e.target.value)} />
                    {canWriteVaults && activeVault.role !== "reader" && (
                      <button className={btnPrimary} onClick={() => setAddingItem(true)}>New item</button>
                    )}
                    {canShare && activeVault.kind === "group" && activeVault.role === "owner" && (
                      <button className={btnClass} onClick={() => setSharing(s => !s)}>Share</button>
                    )}
                  </div>

                  {sharing && <ShareDialog vault={activeVault} onClose={() => setSharing(false)} />}

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
                        <ItemCard key={i.uuid} vault={activeVault} item={i}
                          canWrite={activeVault.role !== "reader"}
                          onChanged={() => { loadItems(); loadVaults(); }} />
                      ))}
                    </div>
                  )}
                </>
              ) : (
                <p className="text-sm text-zinc-500">Create a vault to get started.</p>
              )}
            </section>
          </div>
        )}
      </div>
    </div>
  );
}
