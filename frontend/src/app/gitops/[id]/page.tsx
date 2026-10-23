"use client";

import { Fragment, useCallback, useEffect, useState } from "react";
import { useParams } from "next/navigation";
import { apiFetch } from "@/lib/api";
import { PERMISSIONS } from "@/lib/permissions";
import { usePermissions } from "@/app/components/usePermissions";
import { useShellRefresh } from "@/app/components/shell/refresh";
import { Status, ago, shortSha, type GitopsApp, type GitopsResource, type GitopsSync } from "../shared";

type Detail = { app: GitopsApp; cluster: string; resources: GitopsResource[]; syncs: GitopsSync[] };
type Access = { identity: string; namespace: string; missing: string[]; grant: string; error?: string };

function DiffBlock({ diff }: { diff: string }) {
  return (
    <pre className="m-0 p-3 font-mono text-[11px] leading-[1.6] overflow-x-auto" style={{ background: "var(--side)", border: "1px solid var(--rule)" }}>
      {diff.split("\n").map((l, i) => (
        <div key={i} style={{ color: l.startsWith("+ ") ? "var(--green)" : l.startsWith("- ") ? "var(--red)" : "var(--t3)" }}>{l || " "}</div>
      ))}
    </pre>
  );
}

/** What CommitKube may write in the app's namespace, and the RBAC that
 *  grants what is missing -- there and nowhere else. */
function AccessPanel({ appId }: { appId: number }) {
  const [a, setA] = useState<Access | null>(null);
  useEffect(() => {
    apiFetch(`/gitops/apps/${appId}/access`).then(async r => setA(await r.json().catch(() => ({ error: `${r.status}` }))))
      .catch(() => setA({ identity: "", namespace: "", missing: [], grant: "", error: "could not reach the API" }));
  }, [appId]);
  if (!a) return <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>Asking the cluster what CommitKube may do…</p>;
  if (a.error) return <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{a.error}</p>;
  if (a.missing.length === 0) {
    return <p className="m-0 text-[13px]" style={{ color: "var(--green)" }}>✓ {a.identity || "CommitKube"} can write everything an application needs in {a.namespace}.</p>;
  }
  return (
    <div className="flex flex-col gap-2">
      <p className="m-0 text-[13px]" style={{ color: "var(--gold)" }}>
        {a.identity || "CommitKube"} cannot yet write in {a.namespace}: {a.missing.length} permission{a.missing.length === 1 ? "" : "s"} missing
        ({a.missing.slice(0, 4).join(", ")}{a.missing.length > 4 ? ", …" : ""}). Apply this once, as a cluster admin:
      </p>
      <div className="flex justify-end">
        <button type="button" className="text-[11px] px-2 py-0.5 rounded" style={{ border: "1px solid var(--line2)", color: "var(--t3)" }}
          onClick={() => navigator.clipboard.writeText(`kubectl apply -f - <<'EOF'\n${a.grant}EOF`).catch(() => {})}>Copy command</button>
      </div>
      <pre className="m-0 p-3 font-mono text-[11px] leading-[1.6] overflow-x-auto" style={{ background: "var(--side)", border: "1px solid var(--rule)", color: "var(--t2)" }}>{a.grant}</pre>
      <p className="m-0 text-xs" style={{ color: "var(--m2)" }}>
        The ClusterRole holds no RBAC objects on purpose: a deployer that can write RoleBindings can grant itself anything.
      </p>
    </div>
  );
}

export default function GitopsAppPage() {
  const { id } = useParams<{ id: string }>();
  const { can } = usePermissions();
  const [d, setD] = useState<Detail | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState<"" | "sync" | "refresh" | "save">("");
  const [openDiff, setOpenDiff] = useState<number | null>(null);
  const [openRun, setOpenRun] = useState<number | null>(null);
  const [showAccess, setShowAccess] = useState(false);

  const { markSynced } = useShellRefresh(() => load());
  const load = useCallback(async () => {
    const res = await apiFetch(`/gitops/apps/${id}`);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) { setError(body.error ?? `Request failed (${res.status})`); return; }
    setError("");
    setD(body);
    markSynced();
  }, [id, markSynced]);

  useEffect(() => {
    load();
    const t = setInterval(() => { if (!document.hidden) load(); }, 10_000);
    return () => clearInterval(t);
  }, [load]);

  const act = async (what: "sync" | "refresh") => {
    setBusy(what);
    const res = await apiFetch(`/gitops/apps/${id}/${what}`, { method: "POST" });
    const body = await res.json().catch(() => ({}));
    setBusy("");
    if (!res.ok) setError(body.error ?? `Request failed (${res.status})`);
    load();
  };

  const save = async (patch: Partial<GitopsApp>) => {
    setBusy("save");
    const res = await apiFetch(`/gitops/apps/${id}`, { method: "PUT", body: JSON.stringify(patch) });
    const body = await res.json().catch(() => ({}));
    setBusy("");
    if (!res.ok) setError(body.error ?? `Request failed (${res.status})`);
    load();
  };

  const remove = async () => {
    const cascade = confirm("Also delete the objects this application created in the cluster?\n\nOK deletes them; Cancel keeps them running and only stops managing them.");
    if (!confirm(`Stop managing ${d?.app.name}${cascade ? " and delete its objects" : ""}?`)) return;
    await apiFetch(`/gitops/apps/${id}${cascade ? "?cascade=true" : ""}`, { method: "DELETE" });
    window.location.href = "/gitops";
  };

  if (!d) return <p className="font-mono text-[11px]" style={{ color: error ? "var(--red)" : "var(--m2)" }}>{error || "Reading the application…"}</p>;

  const { app, resources, syncs } = d;
  const counts = (s: string) => resources.filter(r => r.status === s).length;
  const forbidden = resources.some(r => /forbidden/i.test(r.message)) || syncs.slice(0, 1).some(s => /forbidden/i.test(s.results + s.message));
  const canSync = can(PERMISSIONS.gitopsSync);
  const canManage = can(PERMISSIONS.gitopsManage);

  const headline = (() => {
    if (app.sync_status === "Unknown") return <><span style={{ color: "var(--red)" }}>{app.name} cannot be compared</span>: {app.message || "not refreshed yet"}.</>;
    const sync = app.sync_status === "Synced"
      ? <>{app.name} matches <span className="font-mono text-[22px] md:text-[24px]">{shortSha(app.revision)}</span></>
      : <><span style={{ color: "var(--gold)" }}>{app.name} is out of sync</span> with <span className="font-mono text-[22px] md:text-[24px]">{shortSha(app.revision)}</span></>;
    const health = app.health === "Healthy" ? " and is healthy." : <>, and is <span style={{ color: app.health === "Progressing" ? "var(--gold)" : "var(--red)" }}>{app.health.toLowerCase()}</span>.</>;
    return <>{sync}{health}</>;
  })();

  return (
    <div className="max-w-[1280px] flex flex-col gap-8 pb-10">
      <a href="/gitops" className="text-[12.5px] no-underline self-start" style={{ color: "var(--t3)" }}>← Applications</a>
      <section className="flex flex-col gap-4 max-w-[1000px]">
        <h1 className="m-0 text-[26px] md:text-[30px] leading-[1.25] font-medium tracking-[-0.02em]">{headline}</h1>
        <p className="m-0 text-[13px] font-mono" style={{ color: "var(--t3)" }}>
          {app.repo_name}{app.path ? `/${app.path}` : ""} @ {app.branch} → {d.cluster} / {app.namespace}
        </p>
        <div className="flex gap-2.5 flex-wrap items-center">
          {canSync && <button type="button" disabled={!!busy} onClick={() => act("sync")} className="btn-primary disabled:opacity-50">{busy === "sync" ? "Syncing…" : `Sync ${shortSha(app.revision)}`}</button>}
          {canSync && <button type="button" disabled={!!busy} onClick={() => act("refresh")} className="btn-secondary disabled:opacity-50">{busy === "refresh" ? "Comparing…" : "Refresh"}</button>}
          <button type="button" onClick={() => setShowAccess(v => !v)} className="btn-secondary">{showAccess ? "Hide access" : "Access"}</button>
          <span className="text-xs" style={{ color: "var(--m2)" }}>compared {ago(app.refreshed_at)} · last sync {ago(app.synced_at)}{app.synced_revision ? ` (${shortSha(app.synced_revision)})` : ""}</span>
        </div>
        {error && <p className="m-0 text-xs" style={{ color: "var(--red)" }}>{error}</p>}
        {(showAccess || forbidden) && <AccessPanel appId={app.id} />}
      </section>

      <section className="flex gap-7 flex-wrap">
        {[["Objects", resources.length, "var(--text)"], ["Synced", counts("Synced"), "var(--green)"], ["Out of sync", counts("OutOfSync") + counts("Missing"), "var(--gold)"],
          ["To prune", counts("Extraneous"), "var(--orange)"], ["Invalid", counts("Invalid"), "var(--red)"]].map(([l, n, c]) => (
          <div key={l as string} className="flex flex-col gap-1">
            <span className="text-[12.5px]" style={{ color: "var(--t3)" }}>{l}</span>
            <span className="font-mono text-[22px] font-light" style={{ color: (n as number) > 0 ? (c as string) : "var(--text)" }}>{n}</span>
          </div>
        ))}
      </section>

      {canManage && (
        <section className="flex gap-5 flex-wrap items-center text-[13px]">
          <label className="flex items-center gap-2"><input type="checkbox" disabled={!!busy} checked={app.auto_sync} onChange={e => save({ auto_sync: e.target.checked, self_heal: e.target.checked && app.self_heal })} /> Auto-sync new commits</label>
          <label className="flex items-center gap-2" style={{ opacity: app.auto_sync ? 1 : 0.5 }}><input type="checkbox" disabled={!!busy || !app.auto_sync} checked={app.self_heal} onChange={e => save({ self_heal: e.target.checked })} /> Self-heal hand edits</label>
          <label className="flex items-center gap-2"><input type="checkbox" disabled={!!busy} checked={app.prune} onChange={e => save({ prune: e.target.checked })} /> Prune what leaves Git</label>
          <button type="button" onClick={remove} className="ml-auto text-[12.5px] p-0" style={{ color: "var(--red)" }}>Remove application</button>
        </section>
      )}

      <section className="flex flex-col">
        <h2 className="m-0 mb-2 text-lg font-semibold">Objects</h2>
        {resources.length === 0 && <p className="m-0 text-[13px] py-3" style={{ color: "var(--t3)", borderTop: "1px solid var(--rule2)" }}>Nothing compared yet.</p>}
        {resources.map(r => (
          <Fragment key={r.id}>
            <div className="grid gap-4 items-center py-2.5" style={{ gridTemplateColumns: "140px minmax(0,1fr) 120px 120px 90px", borderTop: "1px solid var(--rule2)" }}>
              <span className="text-[12.5px]" style={{ color: "var(--t3)" }}>{r.kind}</span>
              <span className="flex flex-col min-w-0">
                <span className="font-mono text-[12.5px] truncate">{r.name}</span>
                {r.message && <span className="text-[11.5px] break-words" style={{ color: r.status === "Invalid" ? "var(--red)" : "var(--m2)" }}>{r.message}</span>}
              </span>
              <Status value={r.status} kind="sync" />
              <Status value={r.health} kind="health" />
              <span className="text-right">
                {r.diff && <button type="button" onClick={() => setOpenDiff(openDiff === r.id ? null : r.id)} className="text-[12px] p-0" style={{ color: "var(--green)" }}>{openDiff === r.id ? "Hide" : "Diff"}</button>}
              </span>
            </div>
            {openDiff === r.id && r.diff && (
              <div className="pb-3">
                <p className="m-0 mb-1 text-[11.5px]" style={{ color: "var(--m2)" }}>Live in red, what a sync would make it in green.</p>
                <DiffBlock diff={r.diff} />
              </div>
            )}
          </Fragment>
        ))}
      </section>

      <section className="flex flex-col">
        <h2 className="m-0 mb-2 text-lg font-semibold">Syncs</h2>
        {syncs.length === 0 && <p className="m-0 text-[13px] py-3" style={{ color: "var(--t3)", borderTop: "1px solid var(--rule2)" }}>Never synced.</p>}
        {syncs.map(s => (
          <Fragment key={s.id}>
            <button type="button" onClick={() => setOpenRun(openRun === s.id ? null : s.id)}
              className="grid gap-4 items-center py-2.5 text-left hover:bg-[var(--hover)]" style={{ gridTemplateColumns: "150px 110px minmax(0,1fr) 90px", borderTop: "1px solid var(--rule2)" }}>
              <span className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>{new Date(s.started_at).toLocaleString("en-US")}</span>
              <Status value={s.phase} kind="phase" />
              <span className="text-[12.5px] truncate">{s.message} <span style={{ color: "var(--m2)" }}>· {s.trigger}{s.user_email ? ` by ${s.user_email}` : ""}</span></span>
              <span className="font-mono text-[11px] text-right" style={{ color: "var(--m2)" }}>{shortSha(s.revision)}</span>
            </button>
            {openRun === s.id && s.results && (
              <pre className="m-0 mb-2 p-3 font-mono text-[11px] leading-[1.6] whitespace-pre-wrap" style={{ background: "var(--side)", border: "1px solid var(--rule)", color: "var(--t2)" }}>{s.results}</pre>
            )}
          </Fragment>
        ))}
      </section>
    </div>
  );
}
