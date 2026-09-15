"use client";

import { useState, useEffect, useMemo } from "react";
import { apiFetch } from "@/lib/api";
import { loadPermissions, PERMISSIONS } from "@/lib/permissions";
import { useSidebarWidth } from "@/app/components/Sidebar";

interface ExternalSecretItem {
  name: string;
  namespace: string;
  store: string;
  keys: string[];
}

interface K8sSecretItem {
  name: string;
  namespace: string;
  type: string;
  keys: string[];
  values: Record<string, string>;
}

interface SecretsListResponse {
  external_secrets: ExternalSecretItem[];
  kubernetes_secrets: K8sSecretItem[];
  external_secrets_error?: string;
}

const IconLock = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5">
    <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
    <path d="M7 11V7a5 5 0 0110 0v4" />
  </svg>
);
const IconEye = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-4 h-4">
    <path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z" />
    <circle cx="12" cy="12" r="3" />
  </svg>
);
const IconEyeOff = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-4 h-4">
    <path d="M17.94 17.94A10.07 10.07 0 0112 20c-7 0-11-8-11-8a18.45 18.45 0 015.06-5.94M9.9 4.24A9.12 9.12 0 0112 4c7 0 11 8 11 8a18.5 18.5 0 01-2.16 3.19m-6.72-1.07a3 3 0 11-4.24-4.24" />
    <line x1="1" y1="1" x2="23" y2="23" />
  </svg>
);
const IconKey = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
  </svg>
);
const IconExternalLink = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-4 h-4">
    <path d="M18 13v6a2 2 0 01-2 2H5a2 2 0 01-2-2V8a2 2 0 012-2h6" />
    <polyline points="15 3 21 3 21 9" /><line x1="10" y1="14" x2="21" y2="3" />
  </svg>
);
const IconSearch = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-4 h-4">
    <circle cx="11" cy="11" r="8" /><line x1="21" y1="21" x2="16.65" y2="16.65" />
  </svg>
);

export default function SecretsPage() {
  const ml = useSidebarWidth();
  const [unlocked, setUnlocked] = useState(false);
  const [password, setPassword] = useState("");
  const [passwordInput, setPasswordInput] = useState("");
  const [unlockError, setUnlockError] = useState("");
  const [unlockLoading, setUnlockLoading] = useState(false);

  const [nsFilter, setNsFilter] = useState("");
  const [search, setSearch] = useState("");
  const [data, setData] = useState<SecretsListResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [tab, setTab] = useState<"external" | "k8s">("external");

  const [revealedKeys, setRevealedKeys] = useState<Record<string, string>>({});
  const [revealLoading, setRevealLoading] = useState<Record<string, boolean>>({});
  const [editing, setEditing] = useState<Record<string, boolean>>({});
  const [draft, setDraft] = useState<Record<string, string>>({});
  const [saving, setSaving] = useState<Record<string, boolean>>({});
  const [saveError, setSaveError] = useState<Record<string, string>>({});
  const [note, setNote] = useState("");
  const [canWrite, setCanWrite] = useState(false);
  const [addingTo, setAddingTo] = useState("");
  const [newKey, setNewKey] = useState("");

  useEffect(() => {
    loadPermissions().then(p => setCanWrite(p.size === 0 || p.has(PERMISSIONS.secretsWrite)));
  }, []);

  const [role, setRole] = useState("");
  useEffect(() => { setRole(localStorage.getItem("role") || ""); }, []);

  const isAdmin = role === "root" || role === "admin";

  async function handleUnlock(e: React.FormEvent) {
    e.preventDefault();
    setUnlockLoading(true);
    setUnlockError("");
    const res = await apiFetch("/secrets/list", {
      method: "POST",
      body: JSON.stringify({ password: passwordInput, namespace: nsFilter }),
    });
    setUnlockLoading(false);
    if (!res.ok) {
      const j = await res.json().catch(() => ({}));
      setUnlockError(j.error || "invalid password");
      return;
    }
    const json: SecretsListResponse = await res.json();
    setPassword(passwordInput);
    setData(json);
    setUnlocked(true);
  }

  async function fetchSecrets() {
    if (!unlocked) return;
    setLoading(true);
    setError("");
    const res = await apiFetch("/secrets/list", {
      method: "POST",
      body: JSON.stringify({ password, namespace: nsFilter }),
    });
    setLoading(false);
    if (!res.ok) {
      setError("Failed to reload secrets");
      return;
    }
    setData(await res.json());
    setRevealedKeys({});
  }

  async function revealKey(secretName: string, secretNamespace: string, key: string) {
    const mapKey = `${secretNamespace}/${secretName}/${key}`;
    setRevealLoading(prev => ({ ...prev, [mapKey]: true }));
    const res = await apiFetch("/secrets/reveal", {
      method: "POST",
      body: JSON.stringify({ password, namespace: secretNamespace, name: secretName, key }),
    });
    setRevealLoading(prev => ({ ...prev, [mapKey]: false }));
    if (!res.ok) return;
    const j = await res.json();
    setRevealedKeys(prev => ({ ...prev, [mapKey]: j.value }));
  }

  async function saveKey(secretName: string, secretNamespace: string, key: string, acknowledge = false, allowNew = false) {
    const mapKey = `${secretNamespace}/${secretName}/${key}`;
    setSaveError(prev => ({ ...prev, [mapKey]: "" }));
    setSaving(prev => ({ ...prev, [mapKey]: true }));

    const res = await apiFetch("/secrets/value", {
      method: "PUT",
      body: JSON.stringify({
        password, namespace: secretNamespace, name: secretName, key,
        value: draft[mapKey] ?? "", acknowledge_managed: acknowledge, allow_new_key: allowNew,
      }),
    });
    setSaving(prev => ({ ...prev, [mapKey]: false }));
    const body = await res.json().catch(() => ({}));

    if (!res.ok) {
      // An operator owns this Secret: the edit would be reverted on its next
      // refresh, so it asks rather than letting the change quietly undo itself.
      if (body.needs_consent) {
        if (confirm(`${body.error}\n\nApply anyway?`)) return saveKey(secretName, secretNamespace, key, true, allowNew);
        return;
      }
      setSaveError(prev => ({ ...prev, [mapKey]: body.error ?? "could not save" }));
      return;
    }

    setRevealedKeys(prev => ({ ...prev, [mapKey]: draft[mapKey] ?? "" }));
    setEditing(prev => { const n = { ...prev }; delete n[mapKey]; return n; });
    if (allowNew) { setAddingTo(""); setNewKey(""); fetchSecrets(); }
    setNote(body.note ?? "");
    setTimeout(() => setNote(""), 6000);
  }

  function hideKey(secretName: string, secretNamespace: string, key: string) {
    const mapKey = `${secretNamespace}/${secretName}/${key}`;
    setRevealedKeys(prev => { const n = { ...prev }; delete n[mapKey]; return n; });
  }

  const q = search.toLowerCase();

  const filteredExternal = useMemo(() => {
    if (!data) return [];
    if (!q) return data.external_secrets;
    return data.external_secrets.filter(es =>
      es.name.toLowerCase().includes(q) ||
      es.namespace.toLowerCase().includes(q) ||
      es.store.toLowerCase().includes(q) ||
      es.keys.some(k => k.toLowerCase().includes(q))
    );
  }, [data, q]);

  const filteredK8s = useMemo(() => {
    if (!data) return [];
    if (!q) return data.kubernetes_secrets;
    return data.kubernetes_secrets.filter(s =>
      s.name.toLowerCase().includes(q) ||
      s.namespace.toLowerCase().includes(q) ||
      s.keys.some(k => k.toLowerCase().includes(q))
    );
  }, [data, q]);

  const badgeColor = (type: string) => {
    if (type.includes("service-account")) return "bg-blue-500/15 text-blue-400 border-blue-500/30";
    if (type.includes("tls")) return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    if (type === "Opaque") return "bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-300 border-zinc-300 dark:border-zinc-600";
    return "bg-zinc-200 dark:bg-zinc-700 text-zinc-700 dark:text-zinc-300 border-zinc-300 dark:border-zinc-600";
  };

  if (!unlocked) {
    return (
      <div className="flex items-center justify-center min-h-[70vh]">
        <div className="glass-panel rounded-2xl border border-brand-green/20 p-8 w-full max-w-sm">
          <div className="flex flex-col items-center gap-3 mb-6">
            <div className="w-12 h-12 rounded-xl bg-brand-green/10 border border-brand-green/30 flex items-center justify-center text-brand-green">
              <IconLock />
            </div>
            <h1 className="text-lg font-semibold text-zinc-900 dark:text-zinc-100">Secrets</h1>
            <p className="text-sm text-zinc-600 dark:text-zinc-400 text-center">Enter your KubeCommit password to view cluster secrets</p>
          </div>
          <form onSubmit={handleUnlock} className="flex flex-col gap-4">
            <div>
              <label className="block text-xs font-medium text-zinc-600 dark:text-zinc-400 mb-1.5">Namespace (optional)</label>
              <input
                type="text"
                value={nsFilter}
                onChange={e => setNsFilter(e.target.value)}
                placeholder="all namespaces"
                className="w-full bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:border-brand-green/50"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-zinc-600 dark:text-zinc-400 mb-1.5">Password</label>
              <input
                type="password"
                value={passwordInput}
                onChange={e => setPasswordInput(e.target.value)}
                placeholder="your KubeCommit password"
                autoFocus
                className="w-full bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg px-3 py-2 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:border-brand-green/50"
              />
            </div>
            {unlockError && <p className="text-xs text-red-400">{unlockError}</p>}
            <button
              type="submit"
              disabled={unlockLoading || !passwordInput}
              className="w-full py-2.5 rounded-lg bg-brand-green text-black font-semibold text-sm hover:bg-brand-green/90 transition disabled:opacity-40 disabled:cursor-not-allowed"
            >
              {unlockLoading ? "Verifying..." : "Unlock"}
            </button>
          </form>
        </div>
      </div>
    );
  }

  return (
    <main className={`${ml} min-h-screen p-6`}>
      <div className="max-w-6xl mx-auto space-y-6">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-brand-green/10 border border-brand-green/30 flex items-center justify-center text-brand-green">
              <IconKey />
            </div>
            <div>
              <h1 className="text-xl font-semibold text-zinc-900 dark:text-zinc-100">Secrets</h1>
              <p className="text-xs text-zinc-500 dark:text-zinc-400">Cluster secrets and ExternalSecrets</p>
            </div>
          </div>
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative">
              <span className="absolute left-3 top-1/2 -translate-y-1/2 text-zinc-500 dark:text-zinc-400"><IconSearch /></span>
              <input
                type="text"
                value={search}
                onChange={e => setSearch(e.target.value)}
                placeholder="search by name, namespace or key..."
                className="bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg pl-9 pr-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:border-brand-green/50 w-64"
              />
            </div>
            <input
              type="text"
              value={nsFilter}
              onChange={e => setNsFilter(e.target.value)}
              onKeyDown={e => e.key === "Enter" && fetchSecrets()}
              placeholder="namespace"
              className="bg-[var(--input-bg)] border border-[var(--input-border)] rounded-lg px-3 py-1.5 text-sm text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:border-brand-green/50 w-36"
            />
            <button
              onClick={fetchSecrets}
              disabled={loading}
              className="px-4 py-1.5 rounded-lg bg-brand-green/10 border border-brand-green/30 text-brand-green text-sm font-medium hover:bg-brand-green/20 transition disabled:opacity-40"
            >
              {loading ? "Loading..." : "Refresh"}
            </button>
            <button
              onClick={() => { setUnlocked(false); setPassword(""); setPasswordInput(""); setData(null); setRevealedKeys({}); setSearch(""); }}
              className="px-4 py-1.5 rounded-lg bg-zinc-100 dark:bg-zinc-800 border border-[var(--input-border)] text-zinc-600 dark:text-zinc-400 text-sm font-medium hover:text-zinc-800 dark:hover:text-zinc-200 transition"
            >
              Lock
            </button>
          </div>
        </div>

        {error && <div className="text-sm text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-4 py-3">{error}</div>}

        {/* Tabs */}
        <div className="flex gap-1 border-b border-[var(--card-border)]">
          {([
            { key: "external", label: "External Secrets", count: filteredExternal.length },
            { key: "k8s", label: "Kubernetes Secrets", count: filteredK8s.length },
          ] as const).map(t => (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`px-4 py-2 text-sm font-medium border-b-2 transition ${
                tab === t.key
                  ? "border-brand-green text-brand-green"
                  : "border-transparent text-zinc-600 dark:text-zinc-400 hover:text-zinc-800 dark:hover:text-zinc-200"
              }`}
            >
              {t.label}
              <span className="ml-2 text-xs bg-zinc-100 dark:bg-zinc-800 text-zinc-600 dark:text-zinc-400 px-1.5 py-0.5 rounded-full">{t.count}</span>
            </button>
          ))}
        </div>

        {/* External Secrets Tab */}
        {tab === "external" && (
          <div className="space-y-3">
            {data?.external_secrets_error && (
              <div className="text-sm text-amber-400 bg-amber-500/10 border border-amber-500/20 rounded-lg px-4 py-3">
                ExternalSecrets: {data.external_secrets_error}
              </div>
            )}
            {filteredExternal.length === 0 && !data?.external_secrets_error && (
              <div className="text-sm text-zinc-500 dark:text-zinc-400 py-8 text-center">
                {search ? `No ExternalSecrets matching "${search}"` : "No ExternalSecrets found"}
              </div>
            )}
            {filteredExternal.map(es => (
              <div key={`${es.namespace}/${es.name}`} className="glass-panel rounded-xl border border-brand-green/15 p-4">
                <div className="flex items-start justify-between gap-4">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-8 h-8 rounded-lg bg-brand-green/10 border border-brand-green/20 flex items-center justify-center text-brand-green shrink-0">
                      <IconExternalLink />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 font-mono truncate">{es.name}</p>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400 font-mono">{es.namespace}</p>
                    </div>
                  </div>
                  {es.store && (
                    <span className="text-xs bg-zinc-100 dark:bg-zinc-800 border border-[var(--input-border)] text-zinc-600 dark:text-zinc-400 px-2 py-0.5 rounded font-mono shrink-0">
                      store: {es.store}
                    </span>
                  )}
                </div>
                {es.keys.length > 0 && (
                  <div className="mt-3 flex flex-wrap gap-1.5">
                    {es.keys.map(k => (
                      <span key={k} className="text-xs bg-zinc-100 dark:bg-zinc-800 border border-[var(--input-border)] text-zinc-700 dark:text-zinc-300 px-2 py-0.5 rounded font-mono">
                        {k}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        )}

        {/* Kubernetes Secrets Tab */}
        {tab === "k8s" && (
          <div className="space-y-3">
            {filteredK8s.length === 0 && (
              <div className="text-sm text-zinc-500 dark:text-zinc-400 py-8 text-center">
                {search ? `No Secrets matching "${search}"` : "No Secrets found"}
              </div>
            )}
            {filteredK8s.map(s => (
              <div key={`${s.namespace}/${s.name}`} className="glass-panel rounded-xl border border-[var(--card-border)] p-4">
                <div className="flex items-start justify-between gap-4 mb-3">
                  <div className="flex items-center gap-3 min-w-0">
                    <div className="w-8 h-8 rounded-lg bg-zinc-100 dark:bg-zinc-800 border border-[var(--input-border)] flex items-center justify-center text-zinc-600 dark:text-zinc-400 shrink-0">
                      <IconLock />
                    </div>
                    <div className="min-w-0">
                      <p className="text-sm font-semibold text-zinc-900 dark:text-zinc-100 font-mono truncate">{s.name}</p>
                      <p className="text-xs text-zinc-500 dark:text-zinc-400 font-mono">{s.namespace}</p>
                    </div>
                  </div>
                  <span className={`text-xs border px-2 py-0.5 rounded font-mono shrink-0 ${badgeColor(s.type)}`}>
                    {s.type}
                  </span>
                </div>
                <div className="space-y-1.5">
                  {s.keys.map(key => {
                    const mapKey = `${s.namespace}/${s.name}/${key}`;
                    const revealed = revealedKeys[mapKey];
                    const rLoading = revealLoading[mapKey];
                    return (
                      <div key={key} className="flex items-center gap-2 bg-zinc-100 dark:bg-zinc-900/60 rounded-lg px-3 py-2">
                        <span className="text-xs font-mono text-zinc-600 dark:text-zinc-400 w-40 shrink-0 truncate">{key}</span>
                        {editing[mapKey] ? (
                          <input
                            value={draft[mapKey] ?? ""}
                            onChange={e => setDraft(prev => ({ ...prev, [mapKey]: e.target.value }))}
                            onKeyDown={e => { if (e.key === "Enter") saveKey(s.name, s.namespace, key); }}
                            autoFocus
                            className="flex-1 text-xs font-mono px-2 py-1 rounded bg-[var(--input-bg)] border border-brand-green/40 text-[var(--input-fg)] focus:outline-none"
                          />
                        ) : (
                          <span className="flex-1 text-xs font-mono text-zinc-700 dark:text-zinc-300 truncate">
                            {revealed ?? "••••••••"}
                          </span>
                        )}

                        {isAdmin && !editing[mapKey] && (
                          <button
                            onClick={() => revealed ? hideKey(s.name, s.namespace, key) : revealKey(s.name, s.namespace, key)}
                            disabled={rLoading}
                            title={revealed ? "Hide value" : "Reveal value"}
                            className="text-zinc-500 dark:text-zinc-400 hover:text-brand-green transition shrink-0 disabled:opacity-40"
                          >
                            {rLoading ? <span className="text-xs">...</span> : revealed ? <IconEyeOff /> : <IconEye />}
                          </button>
                        )}

                        {/* Editing starts from the current value, so a change
                            is a change rather than a blind overwrite. */}
                        {canWrite && !editing[mapKey] && (
                          <button
                            onClick={async () => {
                              if (revealed === undefined) await revealKey(s.name, s.namespace, key);
                              setDraft(prev => ({ ...prev, [mapKey]: revealedKeys[mapKey] ?? "" }));
                              setEditing(prev => ({ ...prev, [mapKey]: true }));
                            }}
                            title="Edit value"
                            className="text-xs text-zinc-500 hover:text-brand-green transition shrink-0"
                          >
                            Edit
                          </button>
                        )}
                        {editing[mapKey] && (
                          <>
                            <button onClick={() => saveKey(s.name, s.namespace, key)} disabled={saving[mapKey]}
                              className="text-xs text-brand-green hover:opacity-80 shrink-0 disabled:opacity-40">
                              {saving[mapKey] ? "…" : "Save"}
                            </button>
                            <button onClick={() => setEditing(prev => { const n = { ...prev }; delete n[mapKey]; return n; })}
                              className="text-xs text-zinc-500 hover:text-zinc-300 shrink-0">
                              Cancel
                            </button>
                          </>
                        )}
                      </div>
                    );
                  })}
                </div>

                {canWrite && (
                  addingTo === `${s.namespace}/${s.name}` ? (
                    <div className="flex flex-wrap items-center gap-2 mt-2">
                      <input value={newKey} onChange={e => setNewKey(e.target.value)} placeholder="new key"
                        className="text-xs font-mono px-2 py-1.5 rounded bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50 w-40" />
                      <input value={draft[`${s.namespace}/${s.name}/${newKey}`] ?? ""}
                        onChange={e => setDraft(prev => ({ ...prev, [`${s.namespace}/${s.name}/${newKey}`]: e.target.value }))}
                        placeholder="value"
                        className="flex-1 min-w-[160px] text-xs font-mono px-2 py-1.5 rounded bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50" />
                      <button onClick={() => saveKey(s.name, s.namespace, newKey, false, true)}
                        disabled={!newKey || s.keys.includes(newKey)}
                        className="text-xs text-brand-green hover:opacity-80 disabled:opacity-40">
                        {s.keys.includes(newKey) ? "key exists" : "Add"}
                      </button>
                      <button onClick={() => { setAddingTo(""); setNewKey(""); }}
                        className="text-xs text-zinc-500 hover:text-zinc-300">Cancel</button>
                      {saveError[`${s.namespace}/${s.name}/${newKey}`] && (
                        <span className="text-xs text-red-500 w-full">{saveError[`${s.namespace}/${s.name}/${newKey}`]}</span>
                      )}
                    </div>
                  ) : (
                    <button onClick={() => setAddingTo(`${s.namespace}/${s.name}`)}
                      className="mt-2 text-xs text-zinc-500 hover:text-brand-green transition">
                      + Add key
                    </button>
                  )
                )}
              </div>
            ))}
          </div>
        )}
      </div>

      {note && (
        <p className="fixed bottom-4 right-4 max-w-sm text-xs px-3 py-2 rounded-lg glass-card border-amber-500/30 text-amber-600 dark:text-amber-400">
          {note}
        </p>
      )}
    </main>
  );
}
