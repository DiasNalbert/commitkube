"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { PERMISSIONS } from "@/lib/permissions";
import { usePermissions } from "@/app/components/usePermissions";
import { useShellRefresh } from "@/app/components/shell/refresh";
import AppForm from "./AppForm";
import { GitopsTabs, SOURCE_LABEL, Status, ago, shortSha, type GitopsApp } from "./shared";

export default function GitopsPage() {
  const [apps, setApps] = useState<GitopsApp[] | null>(null);
  // ?new=<repository id> arrives from a repository's page: open the form
  // with that repository chosen. Read from location, not useSearchParams,
  // which would need a Suspense boundary on a client-only page.
  const [creating, setCreating] = useState(false);
  const [initialRepo, setInitialRepo] = useState<number | undefined>();
  useEffect(() => {
    const repo = new URLSearchParams(window.location.search).get("new");
    if (repo !== null) { setCreating(true); setInitialRepo(Number(repo) || undefined); }
  }, []);
  const { can } = usePermissions();

  const { markSynced } = useShellRefresh(() => load());
  const load = useCallback(async () => {
    const res = await apiFetch("/gitops/apps");
    const data = await res.json().catch(() => []);
    setApps(Array.isArray(data) ? data : []);
    markSynced();
  }, [markSynced]);

  useEffect(() => {
    load();
    const t = setInterval(() => { if (!document.hidden) load(); }, 20_000);
    return () => clearInterval(t);
  }, [load]);

  if (apps === null) return <p className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>Reading applications…</p>;

  const outOfSync = apps.filter(a => a.sync_status === "OutOfSync").length;
  const degraded = apps.filter(a => a.health === "Degraded" || a.health === "Missing").length;

  return (
    <div className="max-w-[1280px] flex flex-col gap-8">
      <GitopsTabs active="apps" />
      <section className="flex flex-col gap-4 max-w-[980px]">
        <h1 className="m-0 text-[26px] md:text-[30px] leading-[1.25] font-medium tracking-[-0.02em]">
          {apps.length === 0 ? "No application is deployed by CommitKube yet." : (
            <>
              {apps.length} {apps.length === 1 ? "application" : "applications"} kept in sync with Git.{" "}
              {outOfSync + degraded === 0 ? "All match their repositories and are healthy." : (
                <>
                  {outOfSync > 0 && <span style={{ color: "var(--gold)" }}>{outOfSync} out of sync</span>}
                  {outOfSync > 0 && degraded > 0 && ", "}
                  {degraded > 0 && <span style={{ color: "var(--red)" }}>{degraded} unhealthy</span>}.
                </>
              )}
            </>
          )}
        </h1>
        <p className="m-0 text-[13px] max-w-[760px]" style={{ color: "var(--t3)" }}>
          A path in a repository — plain manifests, a Kustomize overlay or a Helm chart — kept applied to a cluster. CommitKube
          compares the branch with the cluster using the API server&apos;s own dry run, applies new commits when auto-sync is on
          (at once when the repository&apos;s push webhook is set up, otherwise within minutes), and puts back hand edits when
          self-heal is.
        </p>
        {can(PERMISSIONS.gitopsManage) && !creating && (
          <button type="button" onClick={() => setCreating(true)} className="btn-primary self-start">New application</button>
        )}
      </section>

      {creating && <AppForm initialRepo={initialRepo} onCancel={() => setCreating(false)} onDone={id => { window.location.href = `/gitops/${id}`; }} />}

      {apps.length > 0 && (
        <section className="flex flex-col">
          <div className="grid gap-4 py-2 text-[11.5px]" style={{ gridTemplateColumns: "minmax(0,1.3fr) minmax(0,1.4fr) 110px 120px 130px", color: "var(--m2)" }}>
            <span>Application</span><span>Source</span><span>Sync</span><span>Health</span><span>Last sync</span>
          </div>
          {apps.map(a => (
            <a key={a.id} href={`/gitops/${a.id}`} className="grid gap-4 items-center py-3 no-underline hover:bg-[var(--hover)]"
              style={{ gridTemplateColumns: "minmax(0,1.3fr) minmax(0,1.4fr) 110px 120px 130px", borderTop: "1px solid var(--rule2)", color: "var(--text)" }}>
              <span className="flex flex-col min-w-0">
                <span className="font-mono text-[13px] truncate">{a.name}</span>
                <span className="text-[11.5px] truncate" style={{ color: "var(--m2)" }}>{a.cluster} / {a.namespace}{a.cluster_scope ? " · cluster scope" : ""}{a.auto_sync ? " · auto" : ""}{a.self_heal ? " · self-heal" : ""}{a.prune ? " · prune" : ""}</span>
              </span>
              <span className="flex flex-col min-w-0">
                <span className="font-mono text-[12px] truncate">{a.source || a.repo_name}{a.path ? `/${a.path}` : ""}</span>
                <span className="font-mono text-[11px]" style={{ color: "var(--m2)" }}>
                  {a.branch} @ {shortSha(a.revision)}{a.rendered_as && a.rendered_as !== "directory" ? ` · ${SOURCE_LABEL[a.rendered_as] ?? a.rendered_as}` : ""}
                </span>
              </span>
              <Status value={a.sync_status} kind="sync" />
              <Status value={a.health} kind="health" />
              <span className="text-[12px]" style={{ color: "var(--m2)" }}>{ago(a.synced_at)}</span>
            </a>
          ))}
        </section>
      )}
    </div>
  );
}
