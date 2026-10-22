import { PERMISSIONS as P } from "@/lib/permissions";

/** The product, as the rail lays it out: six modules, each a short list of
 *  places. A module is a question someone comes with -- what is running, what
 *  shipped, what is exposed -- not a technology. The command bar searches the
 *  same list, so a page added here is findable both ways. */

export type ModuleKey = "cluster" | "delivery" | "security" | "edge" | "vault" | "admin";
export type BadgeKey = "failing" | "security" | "edge";

export interface NavItem {
  href: string;
  label: string;
  perm?: string;
  /** Only for root and admin, on top of the permission. */
  adminOnly?: boolean;
  badge?: BadgeKey;
  /** Other paths that count as being on this item. */
  match?: string[];
}

export interface NavModule {
  key: ModuleKey;
  label: string;
  badge?: BadgeKey;
  items: NavItem[];
}

export const MODULES: NavModule[] = [
  {
    key: "cluster", label: "Cluster", badge: "failing",
    items: [
      { href: "/kubernetes/overview", label: "Overview", perm: P.k8sRead },
      { href: "/kubernetes/triage", label: "Triage", perm: P.k8sRead, badge: "failing" },
      { href: "/kubernetes/pods", label: "Pods", perm: P.k8sRead, match: ["/pods"] },
      { href: "/kubernetes/workloads", label: "Workloads", perm: P.k8sRead, match: ["/monitoring"] },
      { href: "/kubernetes/deployments", label: "Deployments", perm: P.k8sRead },
      { href: "/kubernetes/statefulsets", label: "StatefulSets", perm: P.k8sRead },
      { href: "/kubernetes/daemonsets", label: "DaemonSets", perm: P.k8sRead },
      { href: "/kubernetes/replicasets", label: "ReplicaSets", perm: P.k8sRead },
      { href: "/kubernetes/services", label: "Services", perm: P.k8sRead },
      { href: "/kubernetes/ingresses", label: "Ingresses", perm: P.k8sRead },
      { href: "/kubernetes/topology", label: "Service map", perm: P.k8sRead },
      { href: "/kubernetes/nodes", label: "Nodes", perm: P.k8sRead },
      { href: "/kubernetes/namespaces", label: "Namespaces", perm: P.k8sRead },
      { href: "/kubernetes/secrets", label: "Secrets", perm: P.secretsRead, match: ["/secrets"] },
      { href: "/kubernetes/pvcs", label: "Volume claims", perm: P.k8sRead },
    ],
  },
  {
    key: "delivery", label: "Delivery",
    items: [
      { href: "/", label: "Repositories", perm: P.scmRead, match: ["/repositories/"] },
      // Read from the cluster, so gated on cluster read like its API.
      { href: "/delivery", label: "Releases", perm: P.k8sRead },
      { href: "/templates", label: "Templates", perm: P.templateRead },
      { href: "/golden-paths", label: "Golden paths", perm: P.templateRead },
      { href: "/repositories/new", label: "New repository", perm: P.scmWrite },
      { href: "/repositories/import", label: "Import repository", perm: P.scmWrite, adminOnly: true },
    ],
  },
  {
    key: "security", label: "Security", badge: "security",
    items: [
      { href: "/security/code", label: "Code", perm: P.securityRead, match: ["/security"] },
      { href: "/security/containers", label: "Containers", perm: P.securityRead },
      { href: "/security/workloads", label: "Workloads", perm: P.securityRead },
      { href: "/security/posture", label: "Posture", perm: P.securityRead },
    ],
  },
  {
    // Not under Cluster: a zone is not bound to the cluster selected above.
    key: "edge", label: "Cloudflare", badge: "edge",
    items: [
      { href: "/cloudflare", label: "Zones & exposure", perm: P.securityRead, badge: "edge", match: ["/cloudflare/"] },
    ],
  },
  {
    // Apart from Kubernetes secrets on purpose: that page reads what a
    // cluster holds, this one holds what only its owner can read.
    key: "vault", label: "Vault",
    items: [
      { href: "/vault", label: "Vaults", perm: P.vaultRead },
    ],
  },
  {
    key: "admin", label: "Admin",
    items: [
      { href: "/iam", label: "IAM", perm: P.userManage, adminOnly: true, match: ["/users", "/groups", "/access"] },
      { href: "/notifications", label: "Notifications", perm: P.settingsRead },
      { href: "/audit-logs", label: "Audit log", perm: P.auditRead, adminOnly: true },
      { href: "/settings", label: "Settings", perm: P.settingsRead },
      { href: "/profile", label: "Profile" },
      { href: "/tools/base64", label: "Base64 tool" },
    ],
  },
];

export function itemActive(item: NavItem, pathname: string): boolean {
  if (pathname === item.href) return true;
  return (item.match ?? []).some(m => (m.endsWith("/") ? pathname.startsWith(m) : pathname === m || pathname.startsWith(m + "/")));
}

export function activeModule(pathname: string): ModuleKey | null {
  for (const m of MODULES) if (m.items.some(i => itemActive(i, pathname))) return m.key;
  return null;
}

export function activeItem(pathname: string): { module: NavModule; item: NavItem } | null {
  for (const m of MODULES) for (const i of m.items) if (itemActive(i, pathname)) return { module: m, item: i };
  return null;
}
