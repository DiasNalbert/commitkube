"use client";

import { useState } from "react";
import { apiFetch } from "@/lib/api";

/** A triage decision as the API stores it. */
export interface Suppression {
  id: number;
  repo_name: string;
  vuln_id: string;
  pkg: string;
  reason: string;
  note: string;
  created_by_email: string;
  created_at: string;
  expires_at?: string;
}

export const REASON_LABEL: Record<string, string> = {
  false_positive: "False positive",
  not_affected: "Not affected",
  accepted_risk: "Accepted risk",
  fix_planned: "Fix planned",
};

export function describeSuppression(s: Suppression) {
  const scope = s.repo_name ? "this repository" : "all repositories";
  // CommitKube's own static-analysis rules are named ck-*, and for them the
  // package is a fingerprint of the matched code rather than a package.
  const pkg = s.vuln_id.startsWith("ck-")
    ? (s.pkg ? "this occurrence" : "every occurrence")
    : (s.pkg ? `package ${s.pkg}` : "any package");
  const by = s.created_by_email ? ` by ${s.created_by_email}` : "";
  const until = s.expires_at ? ` · until ${new Date(s.expires_at).toLocaleDateString("en-US")}` : "";
  return `${REASON_LABEL[s.reason] ?? s.reason} · ${scope}, ${pkg}${by}${until}${s.note ? ` — ${s.note}` : ""}`;
}

/** The form that turns a finding into a decision. It asks for the four
 *  things an auditor will ask later: why, how wide, for how long, and who.
 *  Who comes from the session. */
export default function SuppressForm({
  repo, vulnId, pkg, weakness = false, onDone, onCancel,
}: {
  repo: string;
  vulnId: string;
  pkg: string;
  /** A code weakness: pkg is a fingerprint of the matched code, so the
   *  narrow decision is "this occurrence" and the wide one "this rule". */
  weakness?: boolean;
  onDone: () => void;
  onCancel: () => void;
}) {
  const [reason, setReason] = useState("false_positive");
  const [note, setNote] = useState("");
  const [allRepos, setAllRepos] = useState(false);
  const [anyPkg, setAnyPkg] = useState(false);
  const [expires, setExpires] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");

  const needsNote = reason !== "false_positive";

  const submit = async () => {
    setBusy(true);
    setError("");
    try {
      const res = await apiFetch("/scan-suppressions", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          repo_name: allRepos ? "" : repo,
          vuln_id: vulnId,
          pkg: anyPkg ? "" : pkg,
          reason, note,
          expires_at: expires || undefined,
        }),
      });
      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        setError(body.error || `Request failed (${res.status})`);
        return;
      }
      onDone();
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="rounded border border-zinc-700 bg-zinc-900/60 p-3 space-y-2 text-xs">
      <div className="flex flex-wrap items-center gap-3">
        <span className="font-mono text-zinc-300">{vulnId}</span>
        {pkg && !weakness && <span className="font-mono text-zinc-500">{pkg}</span>}
      </div>
      <div className="flex flex-wrap gap-3 items-end">
        <label className="flex flex-col gap-1">
          <span className="text-zinc-500">Reason</span>
          <select value={reason} onChange={e => setReason(e.target.value)} className="input-tech py-1 text-xs">
            {Object.entries(REASON_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
        </label>
        <label className="flex flex-col gap-1">
          <span className="text-zinc-500">Expires (optional)</span>
          <input type="date" value={expires} onChange={e => setExpires(e.target.value)} className="input-tech py-1 text-xs" />
        </label>
        <label className="flex items-center gap-1.5 text-zinc-400 pb-1.5">
          <input type="checkbox" checked={allRepos} onChange={e => setAllRepos(e.target.checked)} />
          all repositories
        </label>
        {pkg && (
          <label className="flex items-center gap-1.5 text-zinc-400 pb-1.5">
            <input type="checkbox" checked={anyPkg} onChange={e => setAnyPkg(e.target.checked)} />
            {weakness ? "every place this rule matches" : "any package"}
          </label>
        )}
      </div>
      <label className="flex flex-col gap-1">
        <span className="text-zinc-500">Note{needsNote ? " (required)" : ""}</span>
        <textarea
          value={note}
          onChange={e => setNote(e.target.value)}
          rows={2}
          placeholder={needsNote ? "Why this does not count, so the next person does not have to re-derive it" : "Optional"}
          className="input-tech py-1 text-xs w-full"
        />
      </label>
      {error && <p className="text-red-400">{error}</p>}
      <div className="flex gap-2">
        <button
          type="button"
          disabled={busy || (needsNote && !note.trim())}
          onClick={submit}
          className="px-3 py-1 rounded border border-brand-green text-brand-green hover:bg-brand-green/10 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {busy ? "Saving…" : "Suppress"}
        </button>
        <button type="button" onClick={onCancel} className="px-3 py-1 rounded border border-zinc-700 text-zinc-400 hover:bg-zinc-800">
          Cancel
        </button>
      </div>
    </div>
  );
}
