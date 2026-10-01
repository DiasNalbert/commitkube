"use client";

import { useState } from "react";

export type DeployKey = { public_key: string; private_key: string; fingerprint: string };

/** The key pair generated for one repository. The private half is shown here
 *  once and never again: CommitKube keeps it encrypted to clone and scan, but
 *  there is no endpoint that hands it back out. */
export default function DeployKeyPanel({ repo, deployKey }: { repo: string; deployKey: DeployKey }) {
  const [showPrivate, setShowPrivate] = useState(false);
  const [copied, setCopied] = useState<"" | "public" | "private">("");

  const copy = async (which: "public" | "private") => {
    try {
      await navigator.clipboard.writeText(which === "public" ? deployKey.public_key : deployKey.private_key);
      setCopied(which);
      setTimeout(() => setCopied(""), 1500);
    } catch { /* clipboard blocked; the text is still selectable */ }
  };

  const download = (which: "public" | "private") => {
    const name = `${repo}_ed25519${which === "public" ? ".pub" : ""}`;
    const body = which === "public" ? deployKey.public_key + "\n" : deployKey.private_key;
    const url = URL.createObjectURL(new Blob([body], { type: "text/plain" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = name;
    a.click();
    URL.revokeObjectURL(url);
  };

  const btn = "text-xs px-2 py-1 rounded border border-zinc-300 dark:border-zinc-700 text-zinc-600 dark:text-zinc-300 hover:bg-zinc-100 dark:hover:bg-zinc-800";

  return (
    <div className="rounded-md border border-amber-500/30 bg-amber-500/5 p-3 space-y-3 min-w-0">
      <div className="flex flex-wrap items-baseline justify-between gap-2">
        <p className="text-sm font-medium text-zinc-800 dark:text-zinc-200">
          Deploy key for <span className="font-mono">{repo}</span>
        </p>
        <span className="font-mono text-[11px] text-zinc-500 break-all">{deployKey.fingerprint}</span>
      </div>
      <p className="text-xs text-amber-700 dark:text-amber-400">
        Save the private key now — it is not shown again. It was added to the repository as a deploy key and registered in ArgoCD.
      </p>

      <div className="space-y-1">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-zinc-500">Public key</span>
          <div className="flex gap-1">
            <button type="button" className={btn} onClick={() => copy("public")}>{copied === "public" ? "Copied" : "Copy"}</button>
            <button type="button" className={btn} onClick={() => download("public")}>Download</button>
          </div>
        </div>
        <pre className="text-[11px] font-mono whitespace-pre-wrap break-all rounded bg-zinc-100 dark:bg-zinc-900 p-2 text-zinc-700 dark:text-zinc-300">{deployKey.public_key}</pre>
      </div>

      <div className="space-y-1">
        <div className="flex items-center justify-between gap-2">
          <span className="text-xs text-zinc-500">Private key</span>
          <div className="flex gap-1">
            <button type="button" className={btn} onClick={() => setShowPrivate(v => !v)}>{showPrivate ? "Hide" : "Show"}</button>
            <button type="button" className={btn} onClick={() => copy("private")}>{copied === "private" ? "Copied" : "Copy"}</button>
            <button type="button" className={btn} onClick={() => download("private")}>Download</button>
          </div>
        </div>
        {showPrivate ? (
          <pre className="text-[11px] font-mono whitespace-pre-wrap break-all rounded bg-zinc-100 dark:bg-zinc-900 p-2 text-zinc-700 dark:text-zinc-300">{deployKey.private_key}</pre>
        ) : (
          <div className="text-[11px] font-mono rounded bg-zinc-100 dark:bg-zinc-900 p-2 text-zinc-500">-----BEGIN OPENSSH PRIVATE KEY----- ••••••••</div>
        )}
      </div>
    </div>
  );
}
