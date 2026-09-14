"use client";

import { useState, useEffect, useLayoutEffect } from "react";
import { usePathname } from "next/navigation";
import KubeLogo from "./KubeLogo";
import ThemeToggle from "./ThemeToggle";
import LogoutButton from "./LogoutButton";

const HIDDEN_ROUTES = ["/login", "/register", "/setup"];

const IconDashboard = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="14" y="14" width="7" height="7" rx="1" /><rect x="3" y="14" width="7" height="7" rx="1" />
  </svg>
);
const IconGauge = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M3 17a9 9 0 0 1 18 0" /><path d="M12 17l4.5-4.5" /><circle cx="12" cy="17" r="1.4" />
  </svg>
);
const IconContainer = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M21 8 12 3 3 8v8l9 5 9-5V8z" /><path d="M3 8l9 5 9-5" /><path d="M12 13v8" />
  </svg>
);
const IconBranch = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <circle cx="6" cy="5" r="2.2" /><circle cx="6" cy="19" r="2.2" /><circle cx="18" cy="9" r="2.2" />
    <path d="M6 7.2v9.6" /><path d="M18 11.2c0 4-4 3.8-6 5.4" />
  </svg>
);
const IconShield = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M12 2L3 6v6c0 5.25 3.75 10.15 9 11.25C17.25 22.15 21 17.25 21 12V6L12 2z" />
    <path d="M9 12l2 2 4-4" />
  </svg>
);
const IconKey = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 11-7.778 7.778 5.5 5.5 0 017.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4" />
  </svg>
);
const IconActivity = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <polyline points="22 12 18 12 15 21 9 3 6 12 2 12" />
  </svg>
);
const IconPlus = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <rect x="3" y="3" width="18" height="18" rx="2" />
    <line x1="12" y1="8" x2="12" y2="16" /><line x1="8" y1="12" x2="16" y2="12" />
  </svg>
);
const IconDownload = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M21 15v4a2 2 0 01-2 2H5a2 2 0 01-2-2v-4" />
    <polyline points="7 10 12 15 17 10" /><line x1="12" y1="15" x2="12" y2="3" />
  </svg>
);
const IconFile = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z" />
    <polyline points="14 2 14 8 20 8" />
    <line x1="8" y1="13" x2="16" y2="13" /><line x1="8" y1="17" x2="12" y2="17" />
  </svg>
);
const IconGear = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <circle cx="12" cy="12" r="3" />
    <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-4 0v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 010-4h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 012.83-2.83l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 014 0v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 010 4h-.09a1.65 1.65 0 00-1.51 1z" />
  </svg>
);
const IconUsers = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2" /><circle cx="9" cy="7" r="4" />
    <path d="M23 21v-2a4 4 0 00-3-3.87" /><path d="M16 3.13a4 4 0 010 7.75" />
  </svg>
);
const IconGroups = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <circle cx="9" cy="8" r="3" /><circle cx="17" cy="8" r="3" />
    <path d="M1 20v-1a7 7 0 0114 0v1" /><path d="M17 11a5 5 0 015 5v1h-3" />
  </svg>
);
const IconUser = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2" /><circle cx="12" cy="7" r="4" />
  </svg>
);
const IconHash = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <line x1="4" y1="9" x2="20" y2="9" /><line x1="4" y1="15" x2="20" y2="15" />
    <line x1="10" y1="3" x2="8" y2="21" /><line x1="16" y1="3" x2="14" y2="21" />
  </svg>
);
const IconAudit = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M9 12h6M9 16h6M9 8h6M5 20h14a2 2 0 002-2V6a2 2 0 00-2-2H5a2 2 0 00-2 2v12a2 2 0 002 2z" />
  </svg>
);
const IconBell = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={1.7} className="w-5 h-5 shrink-0">
    <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9M13.73 21a2 2 0 01-3.46 0"/>
  </svg>
);
const IconChevronLeft = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <polyline points="15 18 9 12 15 6" />
  </svg>
);
const IconChevronRight = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <polyline points="9 18 15 12 9 6" />
  </svg>
);

const IconPods = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <path d="M21 16V8a2 2 0 0 0-1-1.73l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.73l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" />
    <polyline points="3.27 6.96 12 12.01 20.73 6.96" />
    <line x1="12" y1="22.08" x2="12" y2="12" />
  </svg>
);

const IconNamespace = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <rect x="3" y="3" width="7" height="7" rx="1" /><rect x="14" y="3" width="7" height="7" rx="1" />
    <rect x="3" y="14" width="7" height="7" rx="1" /><rect x="14" y="14" width="7" height="7" rx="1" />
  </svg>
);
const IconDeployment = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <rect x="2" y="7" width="20" height="10" rx="2" />
    <line x1="7" y1="11" x2="7" y2="13" /><line x1="12" y1="11" x2="12" y2="13" /><line x1="17" y1="11" x2="17" y2="13" />
  </svg>
);
const IconReplicaSet = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <rect x="8" y="8" width="12" height="12" rx="2" /><path d="M16 8V6a2 2 0 00-2-2H6a2 2 0 00-2 2v8a2 2 0 002 2h2" />
  </svg>
);
const IconDaemonSet = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <rect x="3" y="3" width="18" height="6" rx="1" /><rect x="3" y="15" width="18" height="6" rx="1" />
    <line x1="7" y1="9" x2="7" y2="15" /><line x1="17" y1="9" x2="17" y2="15" />
  </svg>
);
const IconStatefulSet = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <ellipse cx="12" cy="5" rx="9" ry="3" /><path d="M3 5v14c0 1.66 4.03 3 9 3s9-1.34 9-3V5" />
    <path d="M3 12c0 1.66 4.03 3 9 3s9-1.34 9-3" />
  </svg>
);
const IconVolume = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <circle cx="12" cy="12" r="9" /><circle cx="12" cy="12" r="3" />
  </svg>
);
const IconIngress = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <path d="M3 12h4l3-7 4 14 3-7h4" />
  </svg>
);
const IconService = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <circle cx="12" cy="5" r="2.5" /><circle cx="5" cy="19" r="2.5" /><circle cx="19" cy="19" r="2.5" />
    <path d="M12 7.5v4m0 0l-5.5 5m5.5-5l5.5 5" />
  </svg>
);
const IconTriage = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <path d="M12 3v6" />
    <path d="M12 9l-6 5" /><path d="M12 9l6 5" />
    <circle cx="6" cy="16" r="2.3" /><circle cx="18" cy="16" r="2.3" />
    <path d="M12 20v1" />
  </svg>
);

const IconTopology = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <rect x="2" y="9" width="6" height="6" rx="1.5" />
    <rect x="16" y="3" width="6" height="6" rx="1.5" />
    <rect x="16" y="15" width="6" height="6" rx="1.5" />
    <path d="M8 12h4m0 0V6h4m-4 6v6h4" />
  </svg>
);
const IconServer = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <rect x="2" y="2" width="20" height="8" rx="2" /><rect x="2" y="14" width="20" height="8" rx="2" />
    <line x1="6" y1="6" x2="6.01" y2="6" /><line x1="6" y1="18" x2="6.01" y2="18" />
  </svg>
);
const IconKubernetes = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-4 h-4">
    <path d="M12 2l8.66 5v10L12 22 3.34 17V7L12 2z" /><circle cx="12" cy="12" r="3" />
  </svg>
);
const IconChevronDown = () => (
  <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth={2} className="w-3.5 h-3.5">
    <polyline points="6 9 12 15 18 9" />
  </svg>
);

// Live cluster resources. The overview leads, as the group's own landing
// page; everything after it is alphabetical, because a list this long is
// scanned by name and any other order is a rule the reader has to learn.
const kubernetesItems = [
  { href: "/kubernetes/overview", label: "Cluster Overview", icon: <IconGauge /> },
  { href: "/kubernetes/daemonsets", label: "DaemonSets", icon: <IconDaemonSet /> },
  { href: "/kubernetes/deployments", label: "Deployments", icon: <IconDeployment /> },
  { href: "/kubernetes/ingresses", label: "Ingresses", icon: <IconIngress /> },
  { href: "/kubernetes/namespaces", label: "Namespaces", icon: <IconNamespace /> },
  { href: "/kubernetes/nodes", label: "Nodes", icon: <IconServer /> },
  { href: "/kubernetes/pods", label: "Pods", icon: <IconPods /> },
  { href: "/kubernetes/replicasets", label: "ReplicaSets", icon: <IconReplicaSet /> },
  { href: "/kubernetes/secrets", label: "Secrets", icon: <IconKey /> },
  { href: "/kubernetes/topology", label: "Service Map", icon: <IconTopology /> },
  { href: "/kubernetes/services", label: "Services", icon: <IconService /> },
  { href: "/kubernetes/statefulsets", label: "StatefulSets", icon: <IconStatefulSet /> },
  { href: "/kubernetes/triage", label: "Triage", icon: <IconTriage /> },
  { href: "/kubernetes/pvcs", label: "Volume Claims", icon: <IconVolume /> },
  { href: "/kubernetes/workloads", label: "Workloads", icon: <IconActivity /> },
];

// Source control: everything that acts on a repository, whichever provider it
// lives in -- Bitbucket, GitHub or GitLab. The repository dashboard leads and
// the rest is alphabetical, matching the Kubernetes group.
const scmItems = [
  { href: "/", label: "Repositories", icon: <IconDashboard />, admin: false },
  { href: "/audit-logs", label: "Audit Log", icon: <IconAudit />, admin: true },
  { href: "/repositories/import", label: "Import Repository", icon: <IconDownload />, admin: true },
  { href: "/repositories/new", label: "New Repository", icon: <IconPlus />, admin: false },
  { href: "/templates", label: "Templates", icon: <IconFile />, admin: false },
];

const mainItems = [
  { href: "/tools/base64", label: "Base64", icon: <IconHash /> },
  { href: "/notifications", label: "Notifications", icon: <IconBell /> },
  { href: "/security/code", label: "Security: Code", icon: <IconShield /> },
  { href: "/security/containers", label: "Security: Containers", icon: <IconContainer /> },
  { href: "/settings", label: "Settings", icon: <IconGear /> },
];

const adminItems = [
  { href: "/groups", label: "Groups", icon: <IconGroups /> },
  { href: "/users", label: "Users", icon: <IconUsers /> },
];

// Routes that belong to SCM, for highlighting the group header. "/" is matched
// exactly: every other path would start with it.
const SCM_PREFIXES = ["/", "/audit-logs", "/repositories", "/templates"];

const bottomItems = [
  { href: "/profile", label: "Profile", icon: <IconUser /> },
];

export default function Sidebar() {
  const pathname = usePathname();
  const [collapsed, setCollapsed] = useState(false);
  const [role, setRole] = useState("");
  // One open flag per group, each remembered on its own, so opening SCM does
  // not close the cluster resources someone was working through.
  const [open, setOpen] = useState<Record<string, boolean>>({ k8s: false, scm: false });

  useLayoutEffect(() => {
    setRole(localStorage.getItem("role") || "");
    const saved = localStorage.getItem("sidebar_collapsed");
    if (saved === "1") setCollapsed(true);
    setOpen({
      k8s: localStorage.getItem("sidebar_k8s_open") !== "0",
      scm: localStorage.getItem("sidebar_scm_open") !== "0",
    });
  }, []);

  const toggle = () => {
    setCollapsed(prev => {
      const next = !prev;
      localStorage.setItem("sidebar_collapsed", next ? "1" : "0");
      window.dispatchEvent(new CustomEvent("sidebar-toggle", { detail: { collapsed: next } }));
      return next;
    });
  };

  const toggleGroup = (key: string) => {
    setOpen(prev => {
      const next = !prev[key];
      localStorage.setItem(`sidebar_${key}_open`, next ? "1" : "0");
      return { ...prev, [key]: next };
    });
  };

  if (HIDDEN_ROUTES.includes(pathname)) return null;

  const isAdminOrRoot = role === "root" || role === "admin";
  const allItems = [
    ...mainItems,
    ...(isAdminOrRoot ? adminItems : []),
  ];
  const visibleScmItems = scmItems.filter(item => !item.admin || isAdminOrRoot);

  const w = collapsed ? "w-16" : "w-60";

  const NavItem = ({ href, label, icon }: { href: string; label: string; icon: React.ReactNode }) => {
    const active = pathname === href;
    return (
      <a
        href={href}
        title={collapsed ? label : undefined}
        className={`flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group relative
          ${active
            ? "bg-brand-green/15 text-brand-green"
            : "text-zinc-400 hover:text-brand-green hover:bg-brand-green/8"
          }`}
      >
        <span className={active ? "text-brand-green" : "text-zinc-500 group-hover:text-brand-green transition-colors"}>
          {icon}
        </span>
        {!collapsed && <span className="truncate">{label}</span>}
        {active && (
          <span className="absolute left-0 top-1/2 -translate-y-1/2 w-0.5 h-5 bg-brand-green rounded-full" />
        )}
      </a>
    );
  };

  /** A collapsible section of the nav. Bitbucket, GitHub and GitLab all land
   *  in the same group: the provider is a detail of the repository, not a
   *  separate place in the product. */
  const NavGroup = ({ groupKey, label, icon, items, active }: {
    groupKey: string;
    label: string;
    icon: React.ReactNode;
    items: { href: string; label: string; icon: React.ReactNode }[];
    active: boolean;
  }) => (
    <>
      <button
        onClick={() => toggleGroup(groupKey)}
        className={`w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150 group
          ${active ? "text-brand-green" : "text-zinc-400 hover:text-brand-green hover:bg-brand-green/8"}`}
      >
        <span className={active ? "text-brand-green" : "text-zinc-500 group-hover:text-brand-green transition-colors"}>
          {icon}
        </span>
        <span className="truncate flex-1 text-left">{label}</span>
        <span className={`transition-transform duration-150 ${open[groupKey] ? "" : "-rotate-90"}`}>
          <IconChevronDown />
        </span>
      </button>
      {open[groupKey] && (
        <div className="ml-3 pl-2 border-l border-brand-green/20 space-y-0.5">
          {items.map(item => (
            <NavItem key={item.href} href={item.href} label={item.label} icon={item.icon} />
          ))}
        </div>
      )}
    </>
  );

  return (
    <aside
      className={`fixed left-0 top-0 bottom-0 z-50 flex flex-col border-r border-brand-green/20 glass-panel transition-all duration-200 ${w}`}
    >
      <div className={`flex items-center h-16 px-3 border-b border-brand-green/20 shrink-0 ${collapsed ? "justify-center" : "gap-3"}`}>
        <a href="/" className="flex items-center gap-2.5 group">
          <div className="w-8 h-8 rounded-lg bg-brand-green/10 border border-brand-green/50 flex items-center justify-center tech-glow group-hover:bg-brand-green/20 transition-all duration-200 p-1.5 shrink-0">
            <KubeLogo className="w-full h-full" />
          </div>
          {!collapsed && (
            <span className="text-xl font-black tracking-tight bg-clip-text text-transparent bg-gradient-to-r from-brand-green to-brand-gold whitespace-nowrap">
              CommitKube
            </span>
          )}
        </a>
      </div>

      <button
        onClick={toggle}
        className={`absolute -right-3 top-[72px] w-6 h-6 rounded-full bg-zinc-800 border border-zinc-600 flex items-center justify-center text-zinc-400 hover:text-white hover:bg-zinc-700 transition-colors z-10`}
        title={collapsed ? "Expand sidebar" : "Collapse sidebar"}
      >
        {collapsed ? <IconChevronRight /> : <IconChevronLeft />}
      </button>

      <nav className="flex-1 overflow-y-auto py-4 px-2 space-y-0.5">
        {/* Collapsed rail has no room for a group header, so every group's
            items render as one flat icon list instead. */}
        {collapsed ? (
          [...kubernetesItems, ...visibleScmItems].map(item => (
            <NavItem key={item.href} href={item.href} label={item.label} icon={item.icon} />
          ))
        ) : (
          <>
            <NavGroup
              groupKey="k8s"
              label="Kubernetes"
              icon={<IconKubernetes />}
              items={kubernetesItems}
              active={pathname.startsWith("/kubernetes")}
            />
            <NavGroup
              groupKey="scm"
              label="SCM"
              icon={<IconBranch />}
              items={visibleScmItems}
              active={SCM_PREFIXES.some(p => (p === "/" ? pathname === "/" : pathname.startsWith(p)))}
            />
          </>
        )}

        <div className="h-2" />

        {allItems.map(item => (
          <NavItem key={item.href} {...item} />
        ))}
      </nav>

      <div className="border-t border-brand-green/20 py-3 px-2 space-y-0.5 shrink-0">
        {bottomItems.map(item => (
          <NavItem key={item.href} {...item} />
        ))}
        <div className={`flex items-center px-3 py-2 gap-3 ${collapsed ? "justify-center flex-col" : ""}`}>
          <ThemeToggle />
          <LogoutButton />
        </div>
      </div>
    </aside>
  );
}

export function useSidebarWidth() {
  const [collapsed, setCollapsed] = useState(false);
  useLayoutEffect(() => {
    setCollapsed(localStorage.getItem("sidebar_collapsed") === "1");
  }, []);
  return collapsed ? "ml-16" : "ml-60";
}
