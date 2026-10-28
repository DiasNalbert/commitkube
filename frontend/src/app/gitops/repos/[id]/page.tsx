"use client";

import { useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { PERMISSIONS } from "@/lib/permissions";
import { usePermissions } from "@/app/components/usePermissions";
import { CopyButton, GitopsTabs, Status, ago, type GitopsApp, type GitopsRepo } from "../../shared";

type Provider = "github" | "gitlab" | "bitbucket" | "other";

function providerOf(url: string): Provider {
  const host = (url.match(/@([^:/]+)/)?.[1] ?? url.match(/^ssh:\/\/([^/:@]+)/)?.[1] ?? "").toLowerCase();
  if (host.includes("github")) return "github";
  if (host.includes("gitlab")) return "gitlab";
  if (host.includes("bitbucket")) return "bitbucket";
  return "other";
}

const DEPLOY_KEY_HELP: Record<Provider, string> = {
  github: "On GitHub: the repository's Settings → Deploy keys → Add deploy key. Leave “Allow write access” off.",
  gitlab: "On GitLab: the project's Settings → Repository → Deploy keys → Add new key. Leave “Grant write permissions” off.",
  bitbucket: "On Bitbucket: Repository settings → Access keys → Add key (Bitbucket Data Center: Repository settings → Access keys, permission Read).",
  other: "Add it to the repository as a read-only deploy key (or to an account that can read it).",
};

const WEBHOOK_HELP: Record<Provider, string> = {
  github: "GitHub: Settings → Webhooks → Add webhook. Payload URL below, content type application/json, the secret below, “Just the push event”.",
  gitlab: "GitLab: Settings → Webhooks → Add new webhook. URL below, the secret below as Secret token, trigger Push events.",
  bitbucket: "Bitbucket: Repository settings → Webhooks → Add webhook. URL below, the secret below, trigger Repository push.",
  other: "In the host's webhook settings: the URL below, the secret below, push events. Signed with X-Hub-Signature-256 (HMAC-SHA256) or sent as X-Gitlab-Token.",
};

function Step({ n, title, done, children }: { n: number; title: string; done?: boolean; children: React.ReactNode }) {
  return (
    <section className="grid gap-4" style={{ gridTemplateColumns: "28px minmax(0,1fr)" }}>
      <span className="w-7 h-7 flex items-center justify-center font-mono text-[12px] rounded-full"
        style={{ border: `1px solid ${done ? "var(--green)" : "var(--line2)"}`, color: done ? "var(--green)" : "var(--t3)" }}>{done ? "✓" : n}</span>
      <div className="flex flex-col gap-3 min-w-0">
        <h2 className="m-0 text-[15px] font-semibold leading-7">{title}</h2>
        {children}
      </div>
    </section>
  );
}

export default function GitopsRepoPage() {
  const { id } = useParams<{ id: string }>();
  const { can } = usePermissions();
  const manage = can(PERMISSIONS.gitopsManage);
  const [repo, setRepo] = useState<GitopsRepo | null>(null);
  const [apps, setApps] = useState<GitopsApp[]>([]);
  const [webhook, setWebhook] = useState<{ path: string; secret: string } | null>(null);
  const [showSecret, setShowSecret] = useState(false);
  const [busy, setBusy] = useState("");
  const [error, setError] = useState("");
  const [testError, setTestError] = useState("");
  const [editing, setEditing] = useState<"" | "url" | "key">("");
  const [draft, setDraft] = useState("");

  const load = useCallback(async () => {
    const res = await apiFetch(`/gitops/repos/${id}`);
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { setError(d.error ?? `Request failed (${res.status})`); return; }
    setRepo(d);
    apiFetch("/gitops/apps").then(r => r.json()).then((list: GitopsApp[]) => setApps((Array.isArray(list) ? list : []).filter(a => a.gitops_repo_id === Number(id)))).catch(() => {});
  }, [id]);

  useEffect(() => { load(); }, [load]);
  useEffect(() => {
    if (!manage) return;
    apiFetch(`/gitops/repos/${id}/webhook`).then(r => r.ok ? r.json() : null).then(setWebhook).catch(() => {});
  }, [id, manage]);

  const test = async () => {
    setBusy("test"); setTestError("");
    const res = await apiFetch(`/gitops/repos/${id}/test`, { method: "POST" });
    const d = await res.json().catch(() => ({}));
    setBusy("");
    if (d.repo) setRepo(d.repo);
    if (!res.ok) setTestError(d.error ?? `Request failed (${res.status})`);
  };

  const update = async (body: Record<string, unknown>, what: string) => {
    setBusy(what); setError("");
    const res = await apiFetch(`/gitops/repos/${id}`, { method: "PUT", body: JSON.stringify(body) });
    const d = await res.json().catch(() => ({}));
    setBusy("");
    if (!res.ok) { setError(d.error ?? `Request failed (${res.status})`); return false; }
    setRepo(d); setEditing(""); setDraft(""); setTestError("");
    if (body.rotate_webhook_secret) apiFetch(`/gitops/repos/${id}/webhook`).then(r => r.json()).then(setWebhook).catch(() => {});
    return true;
  };

  const remove = async () => {
    if (!confirm(`Disconnect ${repo?.name}? Its key is deleted with it.`)) return;
    const res = await apiFetch(`/gitops/repos/${id}`, { method: "DELETE" });
    const d = await res.json().catch(() => ({}));
    if (!res.ok) { setError(d.error ?? `Request failed (${res.status})`); return; }
    window.location.href = "/gitops/repos";
  };

  if (!repo) return <p className="font-mono text-[11px]" style={{ color: error ? "var(--red)" : "var(--m2)" }}>{error || "Reading the repository…"}</p>;

  const provider = providerOf(repo.url);
  const connected = repo.status === "connected";
  const webhookURL = webhook ? `${window.location.origin}${webhook.path}` : "";
  const box = { background: "var(--side)", border: "1px solid var(--rule)" };

  return (
    <div className="max-w-[1100px] flex flex-col gap-8 pb-10">
      <GitopsTabs active="repos" />
      <a href="/gitops/repos" className="text-[12.5px] no-underline self-start" style={{ color: "var(--t3)" }}>← Repositories</a>

      <section className="flex flex-col gap-3">
        <h1 className="m-0 text-[26px] md:text-[30px] leading-[1.25] font-medium tracking-[-0.02em]">
          {connected ? <>{repo.name} is connected</> : repo.status === "failed" ? <><span style={{ color: "var(--red)" }}>{repo.name} cannot be reached</span></> : <>{repo.name} is waiting for its deploy key</>}
        </h1>
        <p className="m-0 font-mono text-[13px] break-all" style={{ color: "var(--t3)" }}>{repo.url}</p>
        <div className="flex gap-4 flex-wrap items-center text-xs" style={{ color: "var(--m2)" }}>
          <Status value={repo.status} kind="repo" />
          <span>tested {ago(repo.checked_at)}</span>
          {repo.default_branch && <span>default branch <span className="font-mono">{repo.default_branch}</span></span>}
          {repo.host_key && <span title="Pinned at the first connection">host key <span className="font-mono">{repo.host_key}</span></span>}
        </div>
        {repo.message && repo.status !== "connected" && <p className="m-0 text-[13px]" style={{ color: repo.status === "failed" ? "var(--red)" : "var(--gold)" }}>{repo.message}</p>}
        {error && <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{error}</p>}
      </section>

      <Step n={1} title={repo.key_source === "generated" ? "Add this public key to the repository" : "Key"} done={connected}>
        {repo.key_source === "generated" ? (
          <>
            <p className="m-0 text-[13px]" style={{ color: "var(--t3)" }}>{DEPLOY_KEY_HELP[provider]}</p>
            <div className="flex gap-2 items-start">
              <pre className="m-0 p-3 flex-1 font-mono text-[11.5px] whitespace-pre-wrap break-all" style={box}>{repo.ssh_pub_key}</pre>
              <CopyButton text={repo.ssh_pub_key} />
            </div>
          </>
        ) : (
          <p className="m-0 text-[13px]" style={{ color: "var(--t3)" }}>An imported private key. Its public half:</p>
        )}
        {repo.key_source !== "generated" && <pre className="m-0 p-3 font-mono text-[11.5px] whitespace-pre-wrap break-all" style={box}>{repo.ssh_pub_key}</pre>}
        <p className="m-0 text-xs font-mono" style={{ color: "var(--m2)" }}>{repo.key_fingerprint}</p>
      </Step>

      <Step n={2} title="Test the connection" done={connected}>
        <p className="m-0 text-[13px]" style={{ color: "var(--t3)" }}>
          CommitKube lists the repository&apos;s branches with the key. The first success pins the server&apos;s host key.
        </p>
        {manage && (
          <div className="flex gap-2 items-center flex-wrap">
            <button type="button" onClick={test} disabled={!!busy} className="btn-primary disabled:opacity-50">{busy === "test" ? "Testing…" : connected ? "Test again" : "Test connection"}</button>
            {connected && <span className="text-[13px]" style={{ color: "var(--green)" }}>✓ {repo.message}</span>}
          </div>
        )}
        {testError && <p className="m-0 text-[13px]" style={{ color: "var(--red)" }}>{testError}</p>}
      </Step>

      <Step n={3} title="Send pushes to CommitKube (optional)" done={!!repo.last_push_at}>
        <p className="m-0 text-[13px]" style={{ color: "var(--t3)" }}>
          Without a webhook, applications notice a new commit on the next poll, every few minutes. With it, they refresh — and
          auto-sync — as soon as the push lands. {WEBHOOK_HELP[provider]}
        </p>
        {webhook ? (
          <div className="flex flex-col gap-2">
            <div className="flex gap-2 items-center">
              <span className="w-16 text-xs shrink-0" style={{ color: "var(--m2)" }}>URL</span>
              <code className="flex-1 p-2 font-mono text-[11.5px] break-all" style={box}>{webhookURL}</code>
              <CopyButton text={webhookURL} />
            </div>
            <div className="flex gap-2 items-center">
              <span className="w-16 text-xs shrink-0" style={{ color: "var(--m2)" }}>Secret</span>
              <code className="flex-1 p-2 font-mono text-[11.5px] break-all" style={box}>{showSecret ? webhook.secret : "•".repeat(32)}</code>
              <button type="button" className="text-[11px] px-2 py-0.5 rounded" style={{ border: "1px solid var(--line2)", color: "var(--t3)" }} onClick={() => setShowSecret(v => !v)}>{showSecret ? "Hide" : "Show"}</button>
              <CopyButton text={webhook.secret} />
            </div>
            <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>
              {repo.last_push_at ? `Last push received ${ago(repo.last_push_at)}.` : "No push received yet."} The URL must be reachable from the Git host; behind a private network, the poll still works.
            </p>
          </div>
        ) : <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>Only people who manage GitOps see the webhook secret.</p>}
      </Step>

      <Step n={4} title="Deploy something from it" done={apps.length > 0}>
        {apps.length > 0 && (
          <div className="flex flex-col">
            {apps.map(a => (
              <a key={a.id} href={`/gitops/${a.id}`} className="grid gap-4 items-center py-2 no-underline hover:bg-[var(--hover)]"
                style={{ gridTemplateColumns: "minmax(0,1fr) minmax(0,1fr) 110px 110px", borderTop: "1px solid var(--rule2)", color: "var(--text)" }}>
                <span className="font-mono text-[13px] truncate">{a.name}</span>
                <span className="font-mono text-[12px] truncate" style={{ color: "var(--t3)" }}>{a.branch}:{a.path || "/"} → {a.namespace}</span>
                <Status value={a.sync_status} kind="sync" />
                <Status value={a.health} kind="health" />
              </a>
            ))}
          </div>
        )}
        {manage && (
          <a href={connected ? `/gitops?new=${repo.id}` : undefined} aria-disabled={!connected}
            className="btn-primary self-start no-underline" style={connected ? undefined : { opacity: 0.5, pointerEvents: "none" }}>
            Create application
          </a>
        )}
        {!connected && <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>Available once the connection test passes.</p>}
      </Step>

      {manage && (
        <section className="flex flex-col gap-3 pt-4" style={{ borderTop: "1px solid var(--rule2)" }}>
          <h2 className="m-0 text-[15px] font-semibold">Manage</h2>
          <div className="flex gap-2 flex-wrap">
            <button type="button" className="btn-secondary" onClick={() => { setEditing(editing === "url" ? "" : "url"); setDraft(repo.url); }}>Change URL</button>
            <button type="button" className="btn-secondary" onClick={() => { setEditing(editing === "key" ? "" : "key"); setDraft(""); }}>Replace key</button>
            {repo.host_key && <button type="button" className="btn-secondary" disabled={!!busy}
              onClick={() => confirm("Forget the pinned host key? The next test accepts whatever key the server presents. Do this only if you know the server's key changed.") && update({ forget_host_key: true }, "host")}>Forget host key</button>}
            {webhook && <button type="button" className="btn-secondary" disabled={!!busy}
              onClick={() => confirm("Rotate the webhook secret? Pushes are refused until the new secret is set on the Git host.") && update({ rotate_webhook_secret: true }, "secret")}>Rotate webhook secret</button>}
            <button type="button" onClick={remove} className="ml-auto text-[12.5px] p-0" style={{ color: "var(--red)" }}>Disconnect</button>
          </div>
          {editing === "url" && (
            <div className="flex gap-2">
              <input className="input-tech font-mono flex-1" value={draft} onChange={e => setDraft(e.target.value.trim())} />
              <button type="button" className="btn-primary" disabled={!!busy} onClick={() => update({ url: draft }, "url")}>Save</button>
            </div>
          )}
          {editing === "key" && (
            <div className="flex flex-col gap-2">
              <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>Generate a new pair (then add its public key on the host), or paste a private key. The old key stops being used at once.</p>
              <textarea className="input-tech font-mono text-[11.5px]" rows={5} spellCheck={false} placeholder="Paste a private key, or leave empty to generate a new pair" value={draft} onChange={e => setDraft(e.target.value)} />
              <div className="flex gap-2">
                <button type="button" className="btn-primary" disabled={!!busy}
                  onClick={() => update(draft.trim() ? { private_key: draft } : { regenerate_key: true }, "key")}>{draft.trim() ? "Use this key" : "Generate new pair"}</button>
              </div>
            </div>
          )}
        </section>
      )}
    </div>
  );
}
