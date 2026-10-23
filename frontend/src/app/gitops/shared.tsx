"use client";

export type GitopsApp = {
  id: number; name: string; cluster_id: number; repo_name: string; branch: string; path: string; namespace: string;
  auto_sync: boolean; self_heal: boolean; prune: boolean;
  revision: string; sync_status: string; health: string; message: string; refreshed_at: string | null;
  synced_revision: string; synced_at: string | null; cluster?: string;
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

export function Status({ value, kind }: { value: string; kind: "sync" | "health" | "phase" }) {
  const map = kind === "sync" ? SYNC_COLOR : kind === "health" ? HEALTH_COLOR : PHASE_COLOR;
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
