/** What the signed-in user is allowed to do.
 *
 *  Fetched once and cached for the session: the nav is rendered on every page,
 *  and asking the API each time would be a request per navigation for an
 *  answer that does not change.
 *
 *  This hides what someone cannot do. It does not enforce anything -- the
 *  backend rejects the call regardless, and a hidden button is a courtesy, not
 *  a control.
 */

export const PERMISSIONS = {
  k8sRead: "k8s.read",
  k8sLogs: "k8s.logs.read",
  secretsRead: "k8s.secrets.read",
  secretsShow: "k8s.secrets.show",
  podDelete: "k8s.pod.delete",
  scale: "k8s.scale",
  clusterManage: "cluster.manage",
  scmRead: "scm.read",
  scmWrite: "scm.write",
  scmApprove: "scm.approve",
  templateRead: "template.read",
  templateWrite: "template.write",
  securityRead: "security.read",
  securityScan: "security.scan",
  settingsRead: "settings.read",
  settingsWrite: "settings.write",
  notifyWrite: "notify.write",
  userManage: "user.manage",
  auditRead: "audit.read",
  /** Editing the policy itself. Root only, and deliberately not grantable --
   *  it will never appear in the catalog the Access page offers. */
  iamManage: "iam.manage",
} as const;

let cache: Set<string> | null = null;
let inFlight: Promise<Set<string>> | null = null;

export async function loadPermissions(): Promise<Set<string>> {
  if (cache) return cache;
  if (inFlight) return inFlight;

  const { apiFetch } = await import("./api");
  inFlight = apiFetch("/me/permissions")
    .then(async res => {
      const body = await res.json().catch(() => ({}));
      cache = new Set<string>(body.permissions ?? []);
      return cache;
    })
    .catch(() => {
      // A failed lookup must not blank the whole product: show everything and
      // let the backend refuse what it will. The alternative is a user locked
      // out of a working app by one flaky request.
      cache = null;
      return new Set<string>();
    })
    .finally(() => { inFlight = null; });

  return inFlight;
}

/** Call after a sign-in or sign-out, so the next page does not reuse the
 *  previous person's answer. */
export function clearPermissions() {
  cache = null;
  inFlight = null;
}
