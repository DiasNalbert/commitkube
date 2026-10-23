import { isClusterScoped, selectedCluster } from "./cluster";
import { ensureSession, goToLogin, refreshSession } from "./auth";

const API = process.env.NEXT_PUBLIC_API_URL ?? "/api";

/** Cluster-bound requests carry the selected cluster. Doing it here rather
 *  than at each call site means a page added later cannot forget it. */
function withCluster(path: string): string {
  const cluster = selectedCluster();
  if (!cluster || !isClusterScoped(path)) return path;
  return path + (path.includes("?") ? "&" : "?") + "cluster=" + encodeURIComponent(cluster);
}

const unavailable = () =>
  new Response(JSON.stringify({ error: "the server is not answering; try again in a moment" }), {
    status: 503,
    headers: { "Content-Type": "application/json" },
  });

const unauthorized = () =>
  new Response(JSON.stringify({ error: "not signed in" }), {
    status: 401,
    headers: { "Content-Type": "application/json" },
  });

/** Every call to the API goes through here, with the session's access token.
 *  No session means no request: the page is sent to sign in instead. */
export async function apiFetch(
  path: string,
  options: RequestInit = {}
): Promise<Response> {
  const makeHeaders = (t: string) => ({
    "Content-Type": "application/json",
    ...((options.headers as Record<string, string>) || {}),
    Authorization: `Bearer ${t}`,
  });

  const url = `${API}${withCluster(path)}`;

  let token: string | null;
  try {
    token = await ensureSession();
  } catch {
    // The server could not confirm the session right now. The call fails
    // like any other unavailable request; the session is left alone.
    return unavailable();
  }
  if (!token) {
    goToLogin();
    return unauthorized();
  }

  let res = await fetch(url, { ...options, headers: makeHeaders(token) });

  if (res.status === 401) {
    // The access token may have been signed before a change on the server
    // (a revoked session, a new role). One refresh decides: a new token
    // retries the call, none ends the visit.
    let fresh: string | null;
    try {
      fresh = await refreshSession();
    } catch {
      return res;
    }
    if (!fresh) {
      goToLogin();
      return res;
    }
    res = await fetch(url, { ...options, headers: makeHeaders(fresh) });
  }

  return res;
}

export { API };
