"use client";

import { useState } from "react";

export type SourceType = "auto" | "directory" | "kustomize" | "helm";

export type GitopsApp = {
  id: number; name: string; cluster_id: number; gitops_repo_id: number | null; repo_name: string;
  branch: string; path: string; namespace: string;
  source_type: SourceType; include: string; exclude: string;
  helm_release_name: string; helm_value_files: string; helm_values: string;
  cluster_scope: boolean; auto_sync: boolean; self_heal: boolean; prune: boolean;
  revision: string; rendered_as: string; sync_status: string; health: string; message: string; refreshed_at: string | null;
  synced_revision: string; synced_at: string | null; cluster?: string; source?: string;
};

export type GitopsRepo = {
  id: number; name: string; url: string; key_source: "generated" | "imported"; ssh_pub_key: string; key_fingerprint: string;
  host_key: string; status: "pending" | "connected" | "failed"; message: string; checked_at: string | null;
  default_branch: string; webhook_id: string; last_push_at: string | null; apps: number;
};

export const SOURCE_LABEL: Record<string, string> = {
  auto: "Auto-detect", directory: "Plain manifests", kustomize: "Kustomize", helm: "Helm chart",
};

export type GitopsResource = {
  id: number; group: string; version: string; kind: string; namespace: string; name: string;
  status: string; health: string; message: string; diff?: string; applied: boolean;
};

export type GitopsSync = {
  id: number; started_at: string; finished_at: string | null; revision: string; trigger: string;
  user_email?: string; phase: string; message: string; results: string;
};

const SYNC_COLOR: Record<string, string> = {
  Synced: "var(--green)", OutOfSync: "var(--gold)", Missing: "var(--gold)", Extraneous: "var(--orange)",
  Invalid: "var(--red)", Unknown: "var(--m2)",
};
const HEALTH_COLOR: Record<string, string> = {
  Healthy: "var(--green)", Progressing: "var(--gold)", Degraded: "var(--red)", Missing: "var(--orange)",
  Suspended: "var(--m2)", Unknown: "var(--m2)",
};
const PHASE_COLOR: Record<string, string> = { Succeeded: "var(--green)", Failed: "var(--red)", Running: "var(--gold)" };
const REPO_COLOR: Record<string, string> = { connected: "var(--green)", pending: "var(--gold)", failed: "var(--red)" };

export function Status({ value, kind }: { value: string; kind: "sync" | "health" | "phase" | "repo" }) {
  const map = kind === "sync" ? SYNC_COLOR : kind === "health" ? HEALTH_COLOR : kind === "repo" ? REPO_COLOR : PHASE_COLOR;
  const c = map[value] ?? "var(--m2)";
  return (
    <span className="inline-flex items-center gap-1.5 text-[12.5px] whitespace-nowrap" style={{ color: c }}>
      <span className="w-2 h-2 shrink-0" style={{ background: c }} />{value || "Unknown"}
    </span>
  );
}

export const shortSha = (s: string) => (s ? s.slice(0, 7) : "—");

export function ago(iso: string | null): string {
  if (!iso) return "never";
  const s = Math.max(0, Math.round((Date.now() - new Date(iso).getTime()) / 1000));
  if (s < 60) return "just now";
  if (s < 3600) return `${Math.round(s / 60)} min ago`;
  if (s < 86400) return `${Math.round(s / 3600)} h ago`;
  return `${Math.round(s / 86400)} d ago`;
}

/** Applications and the repositories they read from are two pages of one
 *  module; this is how one reaches the other. */
export function GitopsTabs({ active }: { active: "apps" | "repos" }) {
  const tab = (href: string, label: string, on: boolean) => (
    <a href={href} className="pb-2 text-[13.5px] no-underline"
      style={{ color: on ? "var(--text)" : "var(--t3)", borderBottom: on ? "2px solid var(--green)" : "2px solid transparent" }}>{label}</a>
  );
  return (
    <nav className="flex gap-6" style={{ borderBottom: "1px solid var(--rule2)" }}>
      {tab("/gitops", "Applications", active === "apps")}
      {tab("/gitops/repos", "Repositories", active === "repos")}
    </nav>
  );
}

export function CopyButton({ text, label = "Copy" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button type="button" className="text-[11px] px-2 py-0.5 rounded shrink-0" style={{ border: "1px solid var(--line2)", color: done ? "var(--green)" : "var(--t3)" }}
      onClick={() => navigator.clipboard.writeText(text).then(() => { setDone(true); setTimeout(() => setDone(false), 1500); }).catch(() => {})}>
      {done ? "Copied" : label}
    </button>
  );
}
