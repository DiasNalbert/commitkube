"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";

interface ScaleTarget {
  scalable: boolean;
  reason?: string;
  kind?: string;
  name?: string;
  replicas?: number;
}

type Pending = "restart" | "delete" | null;

/**
 * Restart, delete and scale controls for one pod.
 *
 * Note the Kubernetes semantics these map onto, which the labels reflect:
 * there is no restart verb for a pod (a managed pod is restarted by deleting
 * it), and a pod is never scaled — its owning workload is.
 */
export default function PodActions({
  namespace,
  pod,
  onChanged,
}: {
  namespace: string;
  pod: string;
  onChanged: () => void;
}) {
  const [target, setTarget] = useState<ScaleTarget | null>(null);
  const [replicas, setReplicas] = useState(1);
  const [busy, setBusy] = useState(false);
  const [pending, setPending] = useState<Pending>(null);
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    let cancelled = false;
    const qs = `?namespace=${encodeURIComponent(namespace)}&pod=${encodeURIComponent(pod)}`;
    apiFetch(`/kubernetes/pods/scale-target${qs}`)
      .then(r => r.json())
      .then((body: ScaleTarget) => {
        if (cancelled) return;
        setTarget(body);
        if (body.scalable && typeof body.replicas === "number") setReplicas(body.replicas);
      })
      .catch(() => { if (!cancelled) setTarget({ scalable: false, reason: "could not resolve workload" }); });
    return () => { cancelled = true; };
  }, [namespace, pod]);

  const act = async (path: string, init: RequestInit) => {
    setBusy(true);
    setResult(null);
    try {
      const res = await apiFetch(path, init);
      const body = await res.json().catch(() => ({}));
      setResult({ ok: res.ok, text: body.message ?? body.error ?? `Request failed (${res.status})` });
      if (res.ok) onChanged();
    } catch (e) {
      setResult({ ok: false, text: e instanceof Error ? e.message : "Request failed" });
    } finally {
      setBusy(false);
      setPending(null);
    }
  };

  const qs = `?namespace=${encodeURIComponent(namespace)}&pod=${encodeURIComponent(pod)}`;

  const restart = () => act(`/kubernetes/pods/restart${qs}`, { method: "POST" });
  const remove = () => act(`/kubernetes/pods${qs}`, { method: "DELETE" });
  const scale = () =>
    act("/kubernetes/pods/scale", {
      method: "POST",
      body: JSON.stringify({ namespace, pod, replicas }),
    });

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-2">
        <button
          onClick={() => setPending("restart")}
          disabled={busy}
          className="px-3 py-1.5 text-xs rounded-lg border border-amber-500/40 text-amber-600 dark:text-amber-400 hover:bg-amber-500/10 transition disabled:opacity-40"
        >
          Restart pod
        </button>
        <button
          onClick={() => setPending("delete")}
          disabled={busy}
          className="px-3 py-1.5 text-xs rounded-lg border border-red-500/40 text-red-600 dark:text-red-400 hover:bg-red-500/10 transition disabled:opacity-40"
        >
          Delete pod
        </button>

        {target?.scalable ? (
          <div className="flex items-center gap-2 ml-auto">
            <span className="text-xs text-zinc-500 dark:text-zinc-400">
              Scale {target.kind} <span className="font-mono">{target.name}</span>
            </span>
            <input
              type="number"
              min={0}
              max={100}
              value={replicas}
              onChange={e => setReplicas(Math.max(0, Math.min(100, Number(e.target.value))))}
              className="w-16 px-2 py-1.5 text-xs rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] tabular-nums"
            />
            <button
              onClick={scale}
              disabled={busy || replicas === target.replicas}
              className="px-3 py-1.5 text-xs rounded-lg border border-brand-green/40 text-brand-green hover:bg-brand-green/10 transition disabled:opacity-40"
            >
              Apply
            </button>
            <span className="text-xs text-zinc-500 dark:text-zinc-400">
              now {target.replicas}
            </span>
          </div>
        ) : target ? (
          <span className="text-xs text-zinc-500 dark:text-zinc-400 ml-auto">
            Not scalable: {target.reason}
          </span>
        ) : null}
      </div>

      {pending && (
        <div className={`p-3 rounded-lg border text-xs ${
          pending === "delete" ? "border-red-500/30 bg-red-500/10" : "border-amber-500/30 bg-amber-500/10"
        }`}>
          <p className="font-medium mb-2">
            {pending === "delete" ? (
              <>Delete pod <span className="font-mono">{pod}</span>?</>
            ) : (
              <>Restart pod <span className="font-mono">{pod}</span>?</>
            )}
          </p>
          <p className="text-zinc-600 dark:text-zinc-400 mb-3">
            {pending === "delete"
              ? "Kubernetes deletes the pod. If a controller owns it, a replacement starts immediately; if not, the pod is gone permanently."
              : "Kubernetes has no restart verb for a pod. The pod is deleted and its controller starts a replacement, which means a brief drop in capacity for this replica."}
          </p>
          <div className="flex items-center gap-2">
            <button
              onClick={pending === "delete" ? remove : restart}
              disabled={busy}
              className={`px-3 py-1.5 rounded-lg text-white transition disabled:opacity-40 ${
                pending === "delete" ? "bg-red-600 hover:bg-red-500" : "bg-amber-600 hover:bg-amber-500"
              }`}
            >
              {busy ? "Working…" : pending === "delete" ? "Delete" : "Restart"}
            </button>
            <button
              onClick={() => setPending(null)}
              className="px-3 py-1.5 rounded-lg border border-[var(--card-border)] hover:bg-[var(--color-surface-hover)] transition"
            >
              Cancel
            </button>
          </div>
        </div>
      )}

      {result && (
        <p className={`text-xs ${result.ok ? "text-brand-green" : "text-red-500 dark:text-red-400"}`}>
          {result.text}
        </p>
      )}
    </div>
  );
}
