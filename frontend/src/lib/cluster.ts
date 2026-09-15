/** The cluster the user is currently looking at.
 *
 *  Kept in localStorage rather than in the URL: it is a property of the
 *  session, not of the page, and putting it in every link would mean editing
 *  every link in the product. apiFetch appends it to cluster-bound requests,
 *  so a page never has to remember to pass it.
 */

const KEY = "selected_cluster";

export interface ClusterInfo {
  id: number;
  name: string;
  local: boolean;
  api_server: string;
  is_default: boolean;
  reachable: boolean;
  version?: string;
  error?: string;
}

export function selectedCluster(): string {
  try {
    return localStorage.getItem(KEY) ?? "";
  } catch {
    return "";
  }
}

export function setSelectedCluster(id: number | string) {
  try {
    localStorage.setItem(KEY, String(id));
  } catch {
    // A browser with storage blocked simply falls back to the default cluster.
  }
  window.dispatchEvent(new CustomEvent("cluster-change", { detail: { id } }));
}

/** Requests that resolve against a cluster. Everything else -- repositories,
 *  users, settings -- is cluster-independent and must not carry the parameter,
 *  or an unknown cluster id would start failing unrelated pages. */
export function isClusterScoped(path: string): boolean {
  return path.startsWith("/kubernetes/") || path.startsWith("/monitoring/");
}
