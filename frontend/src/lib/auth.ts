/** The sign-in session, as the page sees it.
 *
 *  The access token lives in this module's memory and nowhere else. The
 *  refresh token is an httpOnly cookie the page cannot read: the browser
 *  drops it when it closes, and the server ends it after a period of
 *  inactivity, a maximum age, a logout, or a change to the account. A page
 *  load therefore starts with no token at all and asks the server for one --
 *  which is the check that the session is still valid, made before anything
 *  is rendered.
 */

export interface SessionUser {
  id: number;
  email: string;
  role: string;
}

const API = process.env.NEXT_PUBLIC_API_URL ?? "/api";

/** Routes that render without a session. */
export const PUBLIC_ROUTES = ["/login", "/setup"];
export const isPublicRoute = (path: string) =>
  PUBLIC_ROUTES.some(p => path === p || path.startsWith(p + "/"));

let accessToken: string | null = null;
let expiresAt = 0;
let user: SessionUser | null = null;
let inflight: Promise<string | null> | null = null;
let leaving = false;

const listeners = new Set<(u: SessionUser | null) => void>();

/** Older builds kept a thirty-day refresh token and the role in
 *  localStorage. They are not used any more; leaving them would leave a
 *  credential on disk. */
function dropLegacyStorage() {
  try {
    for (const k of ["token", "refresh_token", "role"]) localStorage.removeItem(k);
  } catch { /* storage blocked: nothing stored either */ }
}
if (typeof window !== "undefined") dropLegacyStorage();

function apply(token: string, expiresIn: number, u: SessionUser | null) {
  accessToken = token;
  // A little early, so a request is never sent with a token that expires in
  // flight.
  expiresAt = Date.now() + Math.max(0, expiresIn - 30) * 1000;
  if (u) user = u;
  listeners.forEach(l => l(user));
}

function clear() {
  accessToken = null;
  expiresAt = 0;
  user = null;
  listeners.forEach(l => l(null));
}

async function doRefresh(): Promise<string | null> {
  try {
    const res = await fetch(`${API}/auth/refresh`, { method: "POST", credentials: "include" });
    if (!res.ok) { clear(); return null; }
    const data = await res.json();
    if (typeof data.token !== "string") { clear(); return null; }
    apply(data.token, data.expires_in ?? 600, data.user ?? null);
    return data.token;
  } catch {
    // The network, not the session: keep what we have and let the caller
    // decide. A dropped Wi-Fi should not sign anyone out.
    return accessToken;
  }
}

/** Ask the server for a fresh access token. One request at a time, across
 *  every tab: the refresh token rotates on each use, and two tabs spending
 *  the same one at once would look like a stolen token. */
export function refreshSession(): Promise<string | null> {
  if (inflight) return inflight;
  const run = () => doRefresh();
  const locks = typeof navigator !== "undefined" ? (navigator as Navigator & { locks?: LockManager }).locks : undefined;
  const p: Promise<string | null> = locks
    ? (locks.request("commitkube-session", run) as unknown as Promise<string | null>)
    : run();
  inflight = p.finally(() => { inflight = null; });
  return inflight;
}

/** A valid access token, refreshing first when there is none or it is about
 *  to expire. Null means there is no session. */
export async function ensureSession(): Promise<string | null> {
  if (accessToken && Date.now() < expiresAt) return accessToken;
  return refreshSession();
}

export function getSessionUser(): SessionUser | null {
  return user;
}

export function onSessionChange(fn: (u: SessionUser | null) => void): () => void {
  listeners.add(fn);
  return () => { listeners.delete(fn); };
}

/** Called by the sign-in page with what the server answered. */
export function startSession(token: string, expiresIn: number, u: SessionUser) {
  apply(token, expiresIn, u);
}

/** Leave for the sign-in page, remembering where we were. Once: a page that
 *  fires ten requests at a dead session should redirect once, not ten times. */
export function goToLogin() {
  if (typeof window === "undefined" || leaving) return;
  if (isPublicRoute(window.location.pathname)) return;
  leaving = true;
  const next = window.location.pathname + window.location.search;
  window.location.href = `/login?next=${encodeURIComponent(next)}`;
}

/** The path to return to after sign-in, if it is one of ours. */
export function safeNext(raw: string | null): string {
  if (!raw || !raw.startsWith("/") || raw.startsWith("//") || isPublicRoute(raw)) return "/";
  return raw;
}

const SIGNOUT_KEY = "commitkube_signout";

/** End the session on the server, then in every open tab. */
export async function logout() {
  try {
    await fetch(`${API}/auth/logout`, { method: "POST", credentials: "include" });
  } catch { /* the cookie is cleared below by the redirect's next refresh */ }
  clear();
  try { localStorage.setItem(SIGNOUT_KEY, String(Date.now())); } catch { /* single tab then */ }
  window.location.href = "/login";
}

/** Another tab signed out: so does this one. */
export function watchSignOut(onSignOut: () => void): () => void {
  const handler = (e: StorageEvent) => { if (e.key === SIGNOUT_KEY) onSignOut(); };
  window.addEventListener("storage", handler);
  return () => window.removeEventListener("storage", handler);
}
