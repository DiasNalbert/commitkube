"use client";

import { useEffect, useState } from "react";
import {
  generatePassword,
  openSecret,
  sealOverview,
  sealSecret,
  type ItemField,
  type ItemOverview,
  type ItemSecret,
} from "@/lib/vault-crypto";
import { touch, vaultFetch, vaultKey, type VaultSummary } from "@/lib/vault-session";
import {
  btnClass, btnPrimary, errorText, Field, IconCopy, IconEye, IconPlus, IconTrash, inputClass, useClipboard,
} from "./ui";

export interface ItemRow {
  uuid: string;
  overview_enc: string;
  version: number;
  updated_at: string;
  updated_by: string;
}

export interface DecryptedItem extends ItemRow {
  overview: ItemOverview | null;
}

/** The kinds of secret people actually keep here, each with the fields it
 *  usually has. A template only fills in labels -- every field can be renamed,
 *  removed or added to -- so nothing a person needs to store is ever "not a
 *  supported type". */
export const ITEM_TYPES: {
  id: string;
  label: string;
  username: boolean;
  url: boolean;
  password: boolean;
  fields: ItemField[];
}[] = [
  { id: "login", label: "Login", username: true, url: true, password: true, fields: [] },
  {
    id: "api_key", label: "API key", username: false, url: true, password: false,
    fields: [{ label: "Key", value: "", secret: true }],
  },
  {
    id: "database", label: "Database", username: true, url: false, password: true,
    fields: [
      { label: "Host", value: "" },
      { label: "Port", value: "" },
      { label: "Database", value: "" },
    ],
  },
  {
    id: "ssh_key", label: "SSH key", username: true, url: false, password: false,
    fields: [
      { label: "Host", value: "" },
      { label: "Private key", value: "", secret: true, multiline: true },
      { label: "Public key", value: "", multiline: true },
      { label: "Key passphrase", value: "", secret: true },
    ],
  },
  { id: "note", label: "Secure note", username: false, url: false, password: false, fields: [] },
  { id: "custom", label: "Custom", username: true, url: true, password: true, fields: [] },
];

export const typeOf = (o: ItemOverview | null | undefined) =>
  ITEM_TYPES.find(t => t.id === (o?.type ?? "login")) ?? ITEM_TYPES[0];

/** Fetches and opens the secret half. It goes through the audited endpoint,
 *  so every caller of this is, as far as the log is concerned, going looking. */
async function revealSecret(vault: VaultSummary, itemUUID: string): Promise<ItemSecret> {
  const res = await vaultFetch(`/vaults/${vault.uuid}/items/${itemUUID}/secret`);
  if (!res.ok) throw new Error("could not load the item");
  const body = await res.json();
  const key = await vaultKey(vault);
  return openSecret(key, vault.uuid, itemUUID, body.secret_enc);
}

function FieldsEditor({ fields, onChange }: { fields: ItemField[]; onChange: (f: ItemField[]) => void }) {
  const set = (i: number, patch: Partial<ItemField>) =>
    onChange(fields.map((f, j) => (j === i ? { ...f, ...patch } : f)));
  return (
    <div className="space-y-3">
      {fields.map((f, i) => (
        <div key={i}>
          {/* The label reads as a caption, not as a second value box: a
              row of two identical inputs is read as two values. */}
          <input className="w-full bg-transparent text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400 outline-none border-b border-transparent hover:border-zinc-300 focus:border-brand-green dark:hover:border-zinc-700 mb-1"
            placeholder="Field name" value={f.label} aria-label="Field name"
            onChange={e => set(i, { label: e.target.value })} />
          <div className="flex gap-2 items-start">
            {f.multiline ? (
              <textarea className={`${inputClass} font-mono text-xs`} rows={4} value={f.value}
                aria-label={f.label || "Field value"} spellCheck={false}
                onChange={e => set(i, { value: e.target.value })} />
            ) : (
              <input className={`${inputClass} ${f.secret ? "font-mono" : ""}`} value={f.value}
                aria-label={f.label || "Field value"}
                type={f.secret ? "password" : "text"} autoComplete="off"
                onChange={e => set(i, { value: e.target.value })} />
            )}
            <button type="button" className={btnClass} title={f.secret ? "Hidden when revealed — click to show plainly" : "Shown plainly — click to hide it"}
              onClick={() => set(i, { secret: !f.secret })}>
              <IconEye off={!f.secret} />
            </button>
            <button type="button" className={btnClass} title={f.multiline ? "Single line" : "Multi-line (keys, certificates)"}
              onClick={() => set(i, { multiline: !f.multiline })}>
              <span className="text-[11px] font-mono">¶</span>
            </button>
            <button type="button" className={btnClass} title="Remove field"
              onClick={() => onChange(fields.filter((_, j) => j !== i))}>
              <IconTrash />
            </button>
          </div>
        </div>
      ))}
      <button type="button" className={btnClass}
        onClick={() => onChange([...fields, { label: "", value: "", secret: true }])}>
        <span className="flex items-center gap-1.5"><IconPlus /> Add field</span>
      </button>
    </div>
  );
}

export function ItemEditor({ vault, item, onSaved, onCancel }: {
  vault: VaultSummary;
  item: DecryptedItem | null;
  onSaved: () => void;
  onCancel: () => void;
}) {
  const [type, setType] = useState(item?.overview?.type ?? "login");
  const [name, setName] = useState(item?.overview?.name ?? "");
  const [username, setUsername] = useState(item?.overview?.username ?? "");
  const [url, setUrl] = useState(item?.overview?.url ?? "");
  const [password, setPassword] = useState("");
  const [showPassword, setShowPassword] = useState(false);
  const [notes, setNotes] = useState("");
  const [fields, setFields] = useState<ItemField[]>(item ? [] : ITEM_TYPES[0].fields);
  const [loaded, setLoaded] = useState(item === null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const t = ITEM_TYPES.find(x => x.id === type) ?? ITEM_TYPES[0];

  // Editing needs the secret half, which means an audited fetch. Opening the
  // editor is going looking, so it is recorded like any other reveal.
  useEffect(() => {
    if (!item) return;
    (async () => {
      try {
        const secret = await revealSecret(vault, item.uuid);
        setPassword(secret.password ?? "");
        setNotes(secret.notes ?? "");
        setFields(secret.fields ?? []);
        setLoaded(true);
      } catch (e) {
        setError(errorText(e));
      }
    })();
  }, [item, vault]);

  /** Switching type on a new item swaps the template, keeping anything
   *  already typed into a field the new type also has. */
  function chooseType(id: string) {
    const next = ITEM_TYPES.find(x => x.id === id) ?? ITEM_TYPES[0];
    setType(id);
    if (item) return;
    const typed = new Map(fields.filter(f => f.value).map(f => [f.label, f]));
    const kept = next.fields.map(f => typed.get(f.label) ?? f);
    const extra = fields.filter(f => f.value && !next.fields.some(n => n.label === f.label));
    setFields([...kept, ...extra]);
  }

  async function save(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setBusy(true);
    touch();
    try {
      const key = await vaultKey(vault);
      const uuid = item?.uuid ?? crypto.randomUUID();
      const overview: ItemOverview = {
        name,
        type,
        username: t.username && username ? username : undefined,
        url: t.url && url ? url : undefined,
      };
      const kept = fields.filter(f => f.label.trim() || f.value);
      const secret: ItemSecret = {
        password: t.password && password ? password : undefined,
        notes: notes || undefined,
        fields: kept.length ? kept.map(f => ({ ...f, label: f.label.trim() || "Field" })) : undefined,
      };
      const overview_enc = await sealOverview(key, vault.uuid, uuid, overview);
      const secret_enc = await sealSecret(key, vault.uuid, uuid, secret);

      const res = item
        ? await vaultFetch(`/vaults/${vault.uuid}/items/${uuid}`, {
            method: "PUT",
            body: JSON.stringify({ overview_enc, secret_enc, base_version: item.version }),
          })
        : await vaultFetch(`/vaults/${vault.uuid}/items`, {
            method: "POST",
            body: JSON.stringify({ uuid, overview_enc, secret_enc }),
          });
      if (!res.ok) {
        const j = await res.json().catch(() => ({}));
        throw new Error(j.error || "could not save the item");
      }
      onSaved();
    } catch (err) {
      setError(errorText(err));
    } finally {
      setBusy(false);
    }
  }

  if (!loaded && !error) {
    return <div className="glass-card p-4 text-sm text-zinc-500">Decrypting…</div>;
  }

  return (
    <form onSubmit={save} className="glass-card p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h3 className="font-semibold text-sm">{item ? "Edit secret" : "New secret"}</h3>
        <div className="flex flex-wrap gap-1">
          {ITEM_TYPES.map(x => (
            <button key={x.id} type="button" onClick={() => chooseType(x.id)}
              className={`px-2 py-1 text-xs rounded border transition-colors ${
                x.id === type
                  ? "border-brand-green text-brand-green"
                  : "border-zinc-300 dark:border-zinc-700 text-zinc-500 hover:border-brand-green"
              }`}>
              {x.label}
            </button>
          ))}
        </div>
      </div>

      <Field label="Name"><input className={inputClass} value={name} autoFocus required
        placeholder={t.id === "database" ? "e.g. orders-db production" : t.id === "api_key" ? "e.g. Stripe live key" : ""}
        onChange={e => setName(e.target.value)} /></Field>

      {(t.username || t.url) && (
        <div className={`grid gap-3 ${t.username && t.url ? "sm:grid-cols-2" : ""}`}>
          {t.username && <Field label="Username"><input className={inputClass} value={username}
            autoComplete="off" onChange={e => setUsername(e.target.value)} /></Field>}
          {t.url && <Field label="URL"><input className={inputClass} value={url}
            onChange={e => setUrl(e.target.value)} /></Field>}
        </div>
      )}

      {t.password && (
        <Field label="Password">
          <div className="flex gap-2">
            <input className={`${inputClass} font-mono`} value={password} autoComplete="new-password"
              type={showPassword ? "text" : "password"}
              onChange={e => setPassword(e.target.value)} />
            <button type="button" className={btnClass} onClick={() => setShowPassword(v => !v)}
              title={showPassword ? "Hide" : "Show"}>
              <IconEye off={showPassword} />
            </button>
            <button type="button" className={btnClass}
              onClick={() => { setPassword(generatePassword(24)); setShowPassword(true); }}>Generate</button>
          </div>
        </Field>
      )}

      <div>
        <span className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">
          {t.id === "custom" || t.fields.length === 0 ? "Fields" : `${t.label} details`}
        </span>
        <div className="mt-1"><FieldsEditor fields={fields} onChange={setFields} /></div>
      </div>

      <Field label="Notes"><textarea className={inputClass} rows={t.id === "note" ? 8 : 3} value={notes}
        onChange={e => setNotes(e.target.value)} /></Field>

      <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
        Everything here, the name included, is sealed in your browser before it is sent.
      </p>
      {error && <p className="text-sm text-red-500">{error}</p>}
      <div className="flex gap-2">
        <button className={btnPrimary} disabled={busy}>{busy ? "Sealing…" : "Save"}</button>
        <button type="button" className={btnClass} onClick={onCancel}>Cancel</button>
      </div>
    </form>
  );
}

function RevealedValue({ id, label, value, secret, multiline }: {
  id: string; label: string; value: string; secret?: boolean; multiline?: boolean;
}) {
  const [shown, setShown] = useState(!secret);
  const { copied, copy } = useClipboard();
  return (
    <div>
      <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">{label}</p>
      <div className="flex items-start gap-2 mt-0.5">
        {multiline ? (
          <pre className="flex-1 font-mono text-xs whitespace-pre-wrap break-all bg-zinc-100 dark:bg-zinc-900 rounded px-2 py-1 max-h-48 overflow-auto">
            {shown ? value : "•".repeat(24)}
          </pre>
        ) : (
          <code className="flex-1 font-mono text-sm break-all bg-zinc-100 dark:bg-zinc-900 rounded px-2 py-1">
            {shown ? value : "•".repeat(Math.min(value.length, 24) || 8)}
          </code>
        )}
        {secret && (
          <button className={btnClass} onClick={() => setShown(s => !s)} title={shown ? "Hide" : "Show"}>
            <IconEye off={shown} />
          </button>
        )}
        <button className={btnClass} onClick={() => copy(value, id)}>
          <span className="flex items-center gap-1.5"><IconCopy />{copied === id ? "Copied" : "Copy"}</span>
        </button>
      </div>
    </div>
  );
}

export function ItemCard({ vault, item, canEdit, onChanged }: {
  vault: VaultSummary;
  item: DecryptedItem;
  canEdit: boolean;
  onChanged: () => void;
}) {
  const [secret, setSecret] = useState<ItemSecret | null>(null);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [editing, setEditing] = useState(false);
  const t = typeOf(item.overview);

  async function reveal() {
    if (secret) return setSecret(null);
    setBusy(true);
    setError("");
    touch();
    try {
      setSecret(await revealSecret(vault, item.uuid));
    } catch (e) {
      setError(errorText(e));
    } finally {
      setBusy(false);
    }
  }

  async function remove() {
    if (!confirm(`Delete "${item.overview?.name ?? item.uuid}"? This cannot be undone.`)) return;
    touch();
    const res = await vaultFetch(`/vaults/${vault.uuid}/items/${item.uuid}`, { method: "DELETE" });
    if (!res.ok) {
      const j = await res.json().catch(() => ({}));
      return setError(j.error || "could not delete the item");
    }
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
          <p className="font-medium text-sm truncate flex items-center gap-2">
            {item.overview?.name ?? <span className="text-red-500">could not decrypt</span>}
            {item.overview && (
              <span className="text-[10px] uppercase tracking-wide text-zinc-500 border border-zinc-300 dark:border-zinc-700 rounded px-1">
                {t.label}
              </span>
            )}
          </p>
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400 truncate">
            {item.overview?.username || "—"}
            {item.overview?.url ? ` · ${item.overview.url}` : ""}
            {` · updated by ${item.updated_by || "unknown"}`}
          </p>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          <button className={btnClass} onClick={reveal} disabled={busy || !item.overview}>
            {busy ? "…" : secret ? "Hide" : "Reveal"}
          </button>
          {canEdit && <button className={btnClass} onClick={() => setEditing(true)}>Edit</button>}
          {canEdit && <button className={btnClass} onClick={remove} title="Delete"><IconTrash /></button>}
        </div>
      </div>

      {error && <p className="text-sm text-red-500 mt-2">{error}</p>}

      {secret && (
        <div className="mt-3 space-y-2.5 border-t border-zinc-200 dark:border-zinc-800 pt-3">
          {item.overview?.username && (
            <RevealedValue id={`${item.uuid}:user`} label="Username" value={item.overview.username} />
          )}
          {secret.password && (
            <RevealedValue id={`${item.uuid}:pw`} label="Password" value={secret.password} secret />
          )}
          {(secret.fields ?? []).filter(f => f.value).map((f, i) => (
            <RevealedValue key={i} id={`${item.uuid}:f${i}`} label={f.label} value={f.value}
              secret={f.secret} multiline={f.multiline} />
          ))}
          {secret.notes && (
            <div>
              <p className="text-[11px] uppercase tracking-wide text-zinc-500 dark:text-zinc-400">Notes</p>
              <p className="text-sm whitespace-pre-wrap text-zinc-600 dark:text-zinc-300 mt-0.5">{secret.notes}</p>
            </div>
          )}
          {!secret.password && !secret.notes && !(secret.fields ?? []).some(f => f.value) && (
            <p className="text-sm text-zinc-500">This secret has nothing in it yet.</p>
          )}
          <p className="text-[11px] text-zinc-500 dark:text-zinc-400">
            This read was recorded in the audit log. The clipboard is cleared 30 seconds after a copy.
          </p>
        </div>
      )}
    </div>
  );
}
