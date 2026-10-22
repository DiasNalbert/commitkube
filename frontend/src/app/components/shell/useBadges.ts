"use client";

import { useEffect, useState } from "react";
import { apiFetch } from "@/lib/api";
import type { BadgeKey } from "./nav";

export type Badges = Partial<Record<BadgeKey, number>>;

/** The three numbers the rail shows next to a module: pods failing now,
 *  critical security findings, open edge alerts. Each comes from a table the
 *  pollers already keep, never from a live cluster call, so the rail costs
 *  three index lookups a minute -- and none while the tab is hidden. */
export function useBadges(can: (perm?: string) => boolean, perms: { k8s: string; security: string }): Badges {
  const [badges, setBadges] = useState<Badges>({});
  const canK8s = can(perms.k8s);
  const canSec = can(perms.security);

  useEffect(() => {
    let stopped = false;
    const load = async () => {
      if (document.hidden) return;
      const next: Badges = {};
      const jobs: Promise<void>[] = [];
      if (canK8s) {
        jobs.push(apiFetch("/monitoring/pods/problems?severity=critical").then(r => r.ok ? r.json() : null).then(d => {
          if (!d?.problems) return;
          const pods = new Set<string>();
          for (const p of d.problems as { namespace: string; pod_name: string }[]) pods.add(`${p.namespace}/${p.pod_name}`);
          next.failing = pods.size;
        }).catch(() => {}));
      }
      if (canSec) {
        jobs.push(apiFetch("/scan-dashboard?limit=1").then(r => r.ok ? r.json() : null).then(d => {
          if (!d) return;
          next.security = (d.code_totals?.critical ?? 0) + (d.image_totals?.critical ?? 0);
        }).catch(() => {}));
        jobs.push(apiFetch("/cloudflare/alerts?limit=1").then(r => r.ok ? r.json() : null).then(d => {
          if (d && typeof d.open === "number") next.edge = d.open;
        }).catch(() => {}));
      }
      await Promise.all(jobs);
      if (!stopped) setBadges(next);
    };
    load();
    const id = setInterval(load, 60_000);
    const onVisible = () => { if (!document.hidden) load(); };
    document.addEventListener("visibilitychange", onVisible);
    return () => { stopped = true; clearInterval(id); document.removeEventListener("visibilitychange", onVisible); };
  }, [canK8s, canSec]);

  return badges;
}
