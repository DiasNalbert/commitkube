"use client";

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import { selectedCluster, setSelectedCluster, type ClusterInfo } from "@/lib/cluster";

/** Which cluster the Kubernetes pages are reading. It sits inside that group
 *  because that is exactly what it scopes -- SCM and the platform settings are
 *  cluster-independent and must not appear to change when this does.
 *
 *  Reachability is shown per cluster: an unreachable cluster otherwise looks
 *  identical to an empty one, and the difference is the whole diagnosis. */
export default function ClusterSelector() {
  const [clusters, setClusters] = useState<ClusterInfo[]>([]);
  const [current, setCurrent] = useState("");
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    try {
      const res = await apiFetch("/clusters");
      const body = await res.json().catch(() => ({}));
      const list: ClusterInfo[] = body.clusters ?? [];
      setClusters(list);

      // A stored id that no longer exists would send every request to an
      // unknown cluster, so fall back to the default.
      const stored = selectedCluster();
      const known = list.some(c => String(c.id) === stored);
      if (!known) {
        const fallback = list.find(c => c.is_default) ?? list[0];
        if (fallback) {
          setSelectedCluster(fallback.id);
          setCurrent(String(fallback.id));
        }
      } else {
        setCurrent(stored);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // One cluster is the normal case and a picker with a single option is noise.
  if (loading || clusters.length === 0) return null;

  const active = clusters.find(c => String(c.id) === current);

  if (clusters.length === 1) {
    const only = clusters[0];
    return (
      <div className="px-3 py-1.5 flex items-center gap-2 text-xs text-zinc-500">
        <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${only.reachable ? "bg-brand-green" : "bg-red-500"}`} />
        <span className="truncate font-mono" title={only.error || only.version || only.name}>{only.name}</span>
      </div>
    );
  }

  return (
    <div className="px-2 pb-1">
      <label className="sr-only" htmlFor="cluster-select">Cluster</label>
      <div className="relative">
        <span
          className={`absolute left-2.5 top-1/2 -translate-y-1/2 w-1.5 h-1.5 rounded-full pointer-events-none ${
            active?.reachable ? "bg-brand-green" : "bg-red-500"
          }`}
        />
        <select
          id="cluster-select"
          value={current}
          onChange={e => { setCurrent(e.target.value); setSelectedCluster(e.target.value); window.location.reload(); }}
          title={active?.error || active?.version || ""}
          className="w-full pl-6 pr-2 py-1.5 text-xs font-mono rounded-lg bg-[var(--input-bg)] border border-[var(--input-border)] text-[var(--input-fg)] focus:outline-none focus:border-brand-green/50"
        >
          {clusters.map(c => (
            <option key={c.id} value={c.id}>
              {c.name}{c.reachable ? "" : " (inacessível)"}
            </option>
          ))}
        </select>
      </div>
    </div>
  );
}
