"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PERMISSIONS } from "@/lib/permissions";
import { usePermissions } from "@/app/components/usePermissions";
import { useShellRefresh } from "@/app/components/shell/refresh";
import { GitopsTabs, Status, ago, type GitopsRepo } from "../shared";

/** Connecting a repository: a name, its SSH URL, and either a key pair
 *  CommitKube generates or a private key that already has access. */
function ConnectForm({ onCreated, onCancel }: { onCreated: (id: number) => void; onCancel: () => void }) {
  const [name, setName] = useState("");
  const [url, setUrl] = useState("");
  const [mode, setMode] = useState<"generate" | "paste">("generate");
  const [key, setKey] = useState("");
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  // The URL usually says what the repository is called.
  const suggestName = (u: string) => {
    const m = u.match(/[/:]([^/:]+?)(\.git)?$/);
    return m ? m[1].toLowerCase().replace(/[^a-z0-9-]/g, "-").replace(/^-+|-+$/g, "").slice(0, 63) : "";
  };

  const submit = async () => {
    setBusy(true); setError("");
    const res = await apiFetch("/gitops/repos", {
      method: "POST",
      body: JSON.stringify({ name, url, private_key: mode === "paste" ? key : "" }),
    });
    const d = await res.json().catch(() => ({}));
    setBusy(false);
    if (!res.ok) { setError(d.error ?? `Request failed (${res.status})`); return; }
    onCreated(d.id);
  };

  const label = "flex flex-col gap-1 text-xs";
  return (
    <div className="flex flex-col gap-4 p-5" style={{ background: "var(--card)", border: "1px solid var(--rule)" }}>
      <h2 className="m-0 text-base font-semibold">Connect a repository</h2>
      <div className="grid gap-3" style={{ gridTemplateColumns: "minmax(0,2fr) minmax(0,1fr)" }}>
        <label className={label} style={{ color: "var(--t3)" }}>SSH URL
          <input className="input-tech font-mono" placeholder="git@github.com:acme/platform-manifests.git" value={url}
            onChange={e => { const u = e.target.value.trim(); if (!name || name === suggestName(url)) setName(suggestName(u)); setUrl(u); }} />
        </label>
        <label className={label} style={{ color: "var(--t3)" }}>Name
          <input className="input-tech font-mono" placeholder="platform-manifests" value={name} onChange={e => setName(e.target.value.toLowerCase())} />
        </label>
      </div>
      <div className="flex flex-col gap-2 text-[13px]">
        <label className="flex items-start gap-2">
          <input type="radio" className="mt-1" checked={mode === "generate"} onChange={() => setMode("generate")} />
          <span>Generate a key pair <span style={{ color: "var(--m2)" }}>— recommended. CommitKube keeps the private key; you add the public key to the repository as a read-only deploy key.</span></span>
        </label>
        <label className="flex items-start gap-2">
          <input type="radio" className="mt-1" checked={mode === "paste"} onChange={() => setMode("paste")} />
          <span>Use a private key I already have <span style={{ color: "var(--m2)" }}>— one with read access to the repository and no passphrase. It is stored encrypted and never shown again.</span></span>
        </label>
      </div>
      {mode === "paste" && (
        <textarea className="input-tech font-mono text-[11.5px]" rows={7} spellCheck={false} autoComplete="off"
          placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n…\n-----END OPENSSH PRIVATE KEY-----"} value={key} onChange={e => setKey(e.target.value)} />
      )}
      {error && <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{error}</p>}
      <div className="flex gap-2">
        <button type="button" onClick={submit} disabled={busy || !url || !name || (mode === "paste" && !key.trim())} className="btn-primary disabled:opacity-50">
          {busy ? (mode === "paste" ? "Connecting…" : "Creating…") : mode === "paste" ? "Connect" : "Generate key"}
        </button>
        <button type="button" onClick={onCancel} className="btn-secondary">Cancel</button>
      </div>
    </div>
  );
}

export default function GitopsReposPage() {
  const [repos, setRepos] = useState<GitopsRepo[] | null>(null);
  const [connecting, setConnecting] = useState(false);
  const { can } = usePermissions();

  const { markSynced } = useShellRefresh(() => load());
  const load = useCallback(async () => {
    const res = await apiFetch("/gitops/repos");
    const data = await res.json().catch(() => []);
    setRepos(Array.isArray(data) ? data : []);
    markSynced();
  }, [markSynced]);

  useEffect(() => { load(); }, [load]);

  if (repos === null) return <p className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>Reading repositories…</p>;
  const failing = repos.filter(r => r.status !== "connected").length;

  return (
    <div className="max-w-[1280px] flex flex-col gap-8">
      <GitopsTabs active="repos" />
      <section className="flex flex-col gap-4 max-w-[980px]">
        <h1 className="m-0 text-[26px] md:text-[30px] leading-[1.25] font-medium tracking-[-0.02em]">
          {repos.length === 0 ? "No repository is connected for GitOps yet." : (
            <>
              {repos.length} {repos.length === 1 ? "repository" : "repositories"} connected over SSH.{" "}
              {failing === 0 ? "All reachable." : <span style={{ color: "var(--gold)" }}>{failing} not connected.</span>}
            </>
          )}
        </h1>
        <p className="m-0 text-[13px] max-w-[760px]" style={{ color: "var(--t3)" }}>
          Any Git host reachable over SSH — GitHub, GitLab, Bitbucket, Gitea or your own. Each repository gets a key of its own, and
          the server&apos;s host key is pinned on the first connection: if it ever changes, CommitKube stops and says so instead of
          trusting the new one.
        </p>
        {can(PERMISSIONS.gitopsManage) && !connecting && (
          <button type="button" onClick={() => setConnecting(true)} className="btn-primary self-start">Connect repository</button>
        )}
      </section>

      {connecting && <ConnectForm onCancel={() => setConnecting(false)} onCreated={id => { window.location.href = `/gitops/repos/${id}`; }} />}

      {repos.length > 0 && (
        <section className="flex flex-col">
          <div className="grid gap-4 py-2 text-[11.5px]" style={{ gridTemplateColumns: "minmax(0,1fr) minmax(0,1.6fr) 110px 90px 130px", color: "var(--m2)" }}>
            <span>Repository</span><span>URL</span><span>Status</span><span>Apps</span><span>Last push</span>
          </div>
          {repos.map(r => (
            <a key={r.id} href={`/gitops/repos/${r.id}`} className="grid gap-4 items-center py-3 no-underline hover:bg-[var(--hover)]"
              style={{ gridTemplateColumns: "minmax(0,1fr) minmax(0,1.6fr) 110px 90px 130px", borderTop: "1px solid var(--rule2)", color: "var(--text)" }}>
              <span className="flex flex-col min-w-0">
                <span className="font-mono text-[13px] truncate">{r.name}</span>
                <span className="text-[11.5px] truncate" style={{ color: "var(--m2)" }}>{r.key_source === "generated" ? "generated key" : "imported key"}{r.default_branch ? ` · ${r.default_branch}` : ""}</span>
              </span>
              <span className="font-mono text-[12px] truncate" style={{ color: "var(--t2)" }}>{r.url}</span>
              <Status value={r.status} kind="repo" />
              <span className="font-mono text-[13px]">{r.apps}</span>
              <span className="text-[12px]" style={{ color: "var(--m2)" }}>{r.last_push_at ? ago(r.last_push_at) : "no webhook yet"}</span>
            </a>
          ))}
        </section>
      )}
    </div>
  );
}
