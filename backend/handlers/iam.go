package handlers

import (
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// Authorization used to be four role checks spread across a hundred and twelve
// routes, which meant every route added since was open to anyone with an
// account. The fix is not more checks in more handlers -- that drifts the same
// way -- but one place where every route states what it needs, and a boot-time
// audit that refuses to start if a route forgot to.

// Permissions are coarse enough to explain to a person and fine enough to
// answer the questions actually asked of them: can this person see pods, touch
// secrets, restart something, or only work in the SCM.
const (
	// Kubernetes, read
	PermK8sRead         = "k8s.read"          // pods, workloads, namespaces, nodes, manifests
	PermK8sLogsRead     = "k8s.logs.read"     // pod logs, separate: logs leak credentials
	PermK8sSecretsRead  = "k8s.secrets.read"  // secret names and keys
	PermK8sSecretsShow  = "k8s.secrets.show"  // the values themselves
	PermK8sSecretsWrite = "k8s.secrets.write" // changing them
	// Kubernetes, write
	PermK8sPodDelete = "k8s.pod.delete" // delete and restart
	PermK8sScale     = "k8s.scale"
	PermClusterWrite = "cluster.manage" // import and remove clusters

	// Source control
	PermSCMRead       = "scm.read"
	PermSCMWrite      = "scm.write" // create, import, delete repositories
	PermSCMApprove    = "scm.approve"
	PermTemplateRead  = "template.read"
	PermTemplateWrite = "template.write"

	// Security findings
	PermSecurityRead = "security.read"
	PermSecurityScan = "security.scan" // trigger a scan by hand

	// Platform administration
	PermSettingsRead  = "settings.read"
	PermSettingsWrite = "settings.write"
	PermNotifyWrite   = "notify.write"
	PermUserManage    = "user.manage"
	PermAuditRead     = "audit.read"

	// Anything any signed-in user may do: their own profile, their own keys.
	PermSelf = "self"

	// Editing the policy itself. Deliberately absent from AllPermissions:
	// a permission that can be granted is not root-only, it is root-only
	// until the first admin is handed it. Keeping it ungrantable is what
	// makes "only root decides who may do what" a rule instead of a default.
	PermIAMManage = "iam.manage"
)

// MaxRootUsers caps how many accounts hold the role that edits the policy and
// authors cluster RBAC. Two, so the person holding it can go on holiday
// without the platform becoming unadministrable, and no more, because every
// additional holder is another account whose compromise is total.
const MaxRootUsers = 2

// AllPermissions is the vocabulary, in the order the UI should list it.
var AllPermissions = []string{
	PermK8sRead, PermK8sLogsRead, PermK8sSecretsRead, PermK8sSecretsShow, PermK8sSecretsWrite,
	PermK8sPodDelete, PermK8sScale, PermClusterWrite,
	PermSCMRead, PermSCMWrite, PermSCMApprove, PermTemplateRead, PermTemplateWrite,
	PermSecurityRead, PermSecurityScan,
	PermSettingsRead, PermSettingsWrite, PermNotifyWrite, PermUserManage, PermAuditRead,
}

// rolePermissions keeps the existing roles working while the grants below take
// over. A role is now just a bundle: root holds everything, so an upgrade
// changes nobody's access on the day it lands.
var rolePermissions = map[string][]string{
	"root": append(append([]string{}, AllPermissions...), PermIAMManage),
	"admin": {
		PermK8sRead, PermK8sLogsRead, PermK8sSecretsRead, PermK8sSecretsShow, PermK8sSecretsWrite,
		PermK8sPodDelete, PermK8sScale, PermClusterWrite,
		PermSCMRead, PermSCMWrite, PermSCMApprove, PermTemplateRead, PermTemplateWrite,
		PermSecurityRead, PermSecurityScan,
		PermSettingsRead, PermSettingsWrite, PermNotifyWrite, PermUserManage, PermAuditRead,
	},
	// What a plain account could reach before this existed, minus the things
	// it could reach only because nothing was checking: secret values, pod
	// deletion and scaling were already gated, logs and secret listing were
	// not, and they are the two worth taking back.
	"user": {
		PermK8sRead,
		PermSCMRead, PermTemplateRead,
		PermSecurityRead,
		PermSettingsRead,
	},
}

// permissionsFor resolves everything a user holds: the bundle their role
// carries, plus the grants attached to them directly or through a group.
func permissionsFor(userID uint, role string) map[string]bool {
	held := map[string]bool{PermSelf: true}
	for _, p := range rolePermissions[role] {
		held[p] = true
	}

	// Groups first, then the user's own rows, so a decision made about one
	// person wins over one made about a team they happen to be in.
	var groupIDs []uint
	db.DB.Model(&models.UserGroupMember{}).Where("user_id = ?", userID).Pluck("group_id", &groupIDs)
	if len(groupIDs) > 0 {
		var groupGrants []models.PermissionGrant
		db.DB.Where("subject_type = ? AND subject_id IN ?", "group", groupIDs).Find(&groupGrants)
		for _, g := range groupGrants {
			held[g.Permission] = !g.Denied
		}
	}

	var grants []models.PermissionGrant
	db.DB.Where("subject_type = ? AND subject_id = ?", "user", userID).Find(&grants)
	for _, g := range grants {
		held[g.Permission] = !g.Denied
	}

	// Editing the policy is the one thing a grant cannot confer, whatever the
	// rows say: root-only stops being a rule the moment it is grantable.
	held[PermIAMManage] = role == "root"
	return held
}

// ---- the route registry ---------------------------------------------------

type routeKey struct{ method, path string }

var (
	routePermsMu sync.Mutex
	routePerms   = map[routeKey]string{}
)

// Requires records what a route needs and returns the middleware that enforces
// it. Declaring it at the route is what makes the whole policy readable in one
// screen of main.go instead of scattered through the handlers.
func Requires(permission string) fiber.Handler {
	return func(c *fiber.Ctx) error {
		routePermsMu.Lock()
		routePerms[routeKey{c.Method(), c.Route().Path}] = permission
		routePermsMu.Unlock()

		if permission == PermSelf {
			return c.Next()
		}
		userID := currentUserID(c)
		role, _ := c.Locals("role").(string)
		if !permissionsFor(userID, role)[permission] {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
				"error":               "you do not have permission to do this",
				"required_permission": permission,
			})
		}
		return c.Next()
	}
}

// declaredPermissions is filled as routes are registered, so the audit below
// can tell a route that declared nothing from one that declared something.
var declared = map[routeKey]string{}

// Declare is called at route registration time by the helpers in main, which
// is what lets AuditRoutePermissions run before the first request arrives.
func Declare(method, path, permission string) {
	declared[routeKey{method, path}] = permission
}

// AuditRoutePermissions refuses to start a server with an unguarded API route.
// A route added without a permission is the exact failure this whole change
// exists to prevent, and catching it at boot is the only moment it is cheap.
func AuditRoutePermissions(routes []fiber.Route, skip map[string]bool) error {
	missing := []string{}
	for _, r := range routes {
		if !strings.HasPrefix(r.Path, "/api/") || r.Method == "HEAD" {
			continue
		}
		if skip[r.Path] {
			continue
		}
		if _, ok := declared[routeKey{r.Method, strings.TrimPrefix(r.Path, "/api")}]; !ok {
			missing = append(missing, r.Method+" "+r.Path)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return fmt.Errorf("these API routes declare no permission, so they would be open to any account:\n  %s",
			strings.Join(missing, "\n  "))
	}
	return nil
}

// ---- HTTP -----------------------------------------------------------------

// GetMyPermissions lets the frontend hide what the person cannot do, instead
// of showing a button that answers 403.
func GetMyPermissions(c *fiber.Ctx) error {
	userID := currentUserID(c)
	role, _ := c.Locals("role").(string)
	held := permissionsFor(userID, role)

	list := make([]string, 0, len(held))
	for p := range held {
		list = append(list, p)
	}
	sort.Strings(list)
	return c.JSON(fiber.Map{"role": role, "permissions": list})
}

// ListPermissionCatalog powers the grant editor.
func ListPermissionCatalog(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"permissions": AllPermissions, "roles": rolePermissions})
}

// GrantPermission and RevokePermission attach a permission to a user or a
// group. Roles stay as the coarse default; grants are how a person gets one
// more thing without being promoted to admin for it.
func GrantPermission(c *fiber.Ctx) error {
	var req struct {
		SubjectType string `json:"subject_type"` // user | group
		SubjectID   uint   `json:"subject_id"`
		Permission  string `json:"permission"`
		// Denied writes a subtraction instead of an addition, which is how a
		// permission that arrives with the role is taken away from one person
		// without demoting them.
		Denied bool `json:"denied"`
	}
	if err := c.BodyParser(&req); err != nil || req.SubjectID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "subject_type, subject_id and permission are required"})
	}
	if req.SubjectType != "user" && req.SubjectType != "group" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "subject_type must be user or group"})
	}
	if !validPermission(req.Permission) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unknown permission " + req.Permission})
	}

	grant := models.PermissionGrant{
		SubjectType: req.SubjectType, SubjectID: req.SubjectID,
		Permission: req.Permission, Denied: req.Denied, GrantedBy: currentUserID(c),
	}
	if err := db.DB.Where("subject_type = ? AND subject_id = ? AND permission = ?",
		req.SubjectType, req.SubjectID, req.Permission).
		Assign(map[string]interface{}{"denied": req.Denied, "granted_by": currentUserID(c)}).
		FirstOrCreate(&grant).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	action := "grant_permission"
	if req.Denied {
		action = "deny_permission"
	}
	db.LogAudit(currentUserID(c), action, req.SubjectType,
		fmt.Sprintf("%d", req.SubjectID), `{"permission":"`+req.Permission+`"}`, c.IP())
	return c.Status(fiber.StatusCreated).JSON(grant)
}

func RevokePermission(c *fiber.Ctx) error {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   uint   `json:"subject_id"`
		Permission  string `json:"permission"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	db.DB.Where("subject_type = ? AND subject_id = ? AND permission = ?",
		req.SubjectType, req.SubjectID, req.Permission).Delete(&models.PermissionGrant{})
	db.LogAudit(currentUserID(c), "revoke_permission", req.SubjectType,
		fmt.Sprintf("%d", req.SubjectID), `{"permission":"`+req.Permission+`"}`, c.IP())
	return c.JSON(fiber.Map{"message": "permission revoked"})
}

// ListGrants shows what one subject holds beyond its role.
func ListGrants(c *fiber.Ctx) error {
	var grants []models.PermissionGrant
	q := db.DB.Model(&models.PermissionGrant{})
	if t := c.Query("subject_type"); t != "" {
		q = q.Where("subject_type = ?", t)
	}
	if id := c.QueryInt("subject_id", 0); id > 0 {
		q = q.Where("subject_id = ?", id)
	}
	q.Find(&grants)
	if grants == nil {
		grants = []models.PermissionGrant{}
	}
	return c.JSON(fiber.Map{"grants": grants})
}

func validPermission(p string) bool {
	for _, known := range AllPermissions {
		if known == p {
			return true
		}
	}
	return false
}

// ---- namespace scope ------------------------------------------------------

// allowedNamespaces returns the namespaces a user may see in one cluster, or
// nil meaning "all of them". nil is the answer for an unscoped subject and for
// anyone holding cluster.manage, who is administering the cluster and cannot
// do that through a keyhole.
//
// Reads go through the collector's credential, not the user's, so this is the
// only thing standing between one team's page and another team's namespaces.
// Every handler that returns namespace-bearing data must consult it.
func allowedNamespaces(userID uint, role string, clusterID uint) []string {
	if permissionsFor(userID, role)[PermClusterWrite] {
		return nil
	}

	var groupIDs []uint
	db.DB.Model(&models.UserGroupMember{}).Where("user_id = ?", userID).Pluck("group_id", &groupIDs)

	q := db.DB.Model(&models.NamespaceScope{}).Where("cluster_id = ?", clusterID)
	if len(groupIDs) > 0 {
		q = q.Where("(subject_type = 'user' AND subject_id = ?) OR (subject_type = 'group' AND subject_id IN ?)",
			userID, groupIDs)
	} else {
		q = q.Where("subject_type = 'user' AND subject_id = ?", userID)
	}

	var namespaces []string
	q.Distinct().Pluck("namespace", &namespaces)
	if len(namespaces) == 0 {
		return nil // unscoped: see everything the permission already allows
	}
	sort.Strings(namespaces)
	return namespaces
}

// requestNamespaces is the handler-facing form: the namespaces this request
// may see, and whether it is restricted at all.
func requestNamespaces(c *fiber.Ctx) (allowed []string, restricted bool, err error) {
	clusterID, err := requestClusterID(c)
	if err != nil {
		return nil, false, err
	}
	role, _ := c.Locals("role").(string)
	ns := allowedNamespaces(currentUserID(c), role, clusterID)
	return ns, ns != nil, nil
}

// namespaceAllowed answers for one namespace, for the handlers that address a
// single object rather than listing many.
func namespaceAllowed(c *fiber.Ctx, namespace string) bool {
	allowed, restricted, err := requestNamespaces(c)
	if err != nil || !restricted {
		return err == nil
	}
	for _, ns := range allowed {
		if ns == namespace {
			return true
		}
	}
	return false
}

// forbidNamespace is the single refusal, so the message never varies by
// handler and never reveals whether the namespace exists.
func forbidNamespace(c *fiber.Ctx) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error": "your account is not scoped to that namespace",
	})
}

// ---- namespace scope, HTTP ------------------------------------------------

func ListNamespaceScopes(c *fiber.Ctx) error {
	var scopes []models.NamespaceScope
	q := db.DB.Model(&models.NamespaceScope{})
	if t := c.Query("subject_type"); t != "" {
		q = q.Where("subject_type = ?", t)
	}
	if id := c.QueryInt("subject_id", 0); id > 0 {
		q = q.Where("subject_id = ?", id)
	}
	q.Order("cluster_id, namespace").Find(&scopes)
	if scopes == nil {
		scopes = []models.NamespaceScope{}
	}
	return c.JSON(fiber.Map{"scopes": scopes})
}

func AddNamespaceScope(c *fiber.Ctx) error {
	var req struct {
		SubjectType string `json:"subject_type"`
		SubjectID   uint   `json:"subject_id"`
		ClusterID   uint   `json:"cluster_id"`
		Namespace   string `json:"namespace"`
	}
	if err := c.BodyParser(&req); err != nil || req.SubjectID == 0 || req.Namespace == "" || req.ClusterID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "subject_type, subject_id, cluster_id and namespace are required",
		})
	}
	if req.SubjectType != "user" && req.SubjectType != "group" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "subject_type must be user or group"})
	}

	scope := models.NamespaceScope{
		SubjectType: req.SubjectType, SubjectID: req.SubjectID,
		ClusterID: req.ClusterID, Namespace: req.Namespace, GrantedBy: currentUserID(c),
	}
	if err := db.DB.Where("subject_type = ? AND subject_id = ? AND cluster_id = ? AND namespace = ?",
		req.SubjectType, req.SubjectID, req.ClusterID, req.Namespace).
		FirstOrCreate(&scope).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	db.LogAudit(currentUserID(c), "add_namespace_scope", req.SubjectType,
		fmt.Sprintf("%d", req.SubjectID), `{"namespace":"`+req.Namespace+`"}`, c.IP())
	return c.Status(fiber.StatusCreated).JSON(scope)
}

func RemoveNamespaceScope(c *fiber.Ctx) error {
	var scope models.NamespaceScope
	if err := db.DB.First(&scope, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "scope not found"})
	}
	db.DB.Delete(&scope)
	db.LogAudit(currentUserID(c), "remove_namespace_scope", scope.SubjectType,
		fmt.Sprintf("%d", scope.SubjectID), `{"namespace":"`+scope.Namespace+`"}`, c.IP())
	return c.JSON(fiber.Map{"message": "scope removed"})
}
