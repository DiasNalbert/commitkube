package handlers

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// Impersonation only decides anything if the cluster holds RBAC naming the
// identities being impersonated. Writing that by hand, per group per
// namespace, is where a policy stops being maintained -- so CommitKube
// authors it.
//
// Two ways out on purpose. The preview returns the YAML and needs no
// privilege at all, which is enough for a team that would rather apply it
// themselves. Applying needs the cluster flag, because a product that can
// write a RoleBinding can write itself one.

// rbacTemplate is a named set of rules, phrased as the question someone asks
// when granting it rather than as a list of verbs.
type rbacTemplate struct {
	Name        string
	Description string
	Rules       []rbacv1.PolicyRule
}

// The rules are derived from the permissions the subject already holds, not
// chosen a second time. Asking twice is how the two halves drift: someone
// grants k8s.scale here and forgets the binding there, and the product says
// yes while the cluster says no.
//
// Only the k8s.* permissions have a cluster meaning. scm.read and settings.write
// describe this product and translate to nothing.
func rulesForPermissions(held map[string]bool) []rbacv1.PolicyRule {
	rules := []rbacv1.PolicyRule{}

	if held[PermK8sRead] {
		rules = append(rules,
			rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods", "services", "configmaps", "persistentvolumeclaims", "events"}, Verbs: []string{"get", "list", "watch"}},
			rbacv1.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets"}, Verbs: []string{"get", "list", "watch"}},
			rbacv1.PolicyRule{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"get", "list", "watch"}},
			rbacv1.PolicyRule{APIGroups: []string{"batch"}, Resources: []string{"jobs", "cronjobs"}, Verbs: []string{"get", "list", "watch"}},
		)
	}
	if held[PermK8sLogsRead] {
		rules = append(rules, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}})
	}
	if held[PermK8sPodDelete] {
		rules = append(rules, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}})
	}
	if held[PermK8sScale] {
		rules = append(rules, rbacv1.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments/scale", "statefulsets/scale"}, Verbs: []string{"get", "update"}})
	}
	// Kubernetes has no "names without values" on Secrets: list returns the
	// objects. So both secret permissions map to the same cluster rule, and
	// the difference between seeing a key and seeing a value is enforced by
	// CommitKube masking, not by the cluster. Said out loud in the UI, because
	// assuming otherwise is the kind of mistake that matters.
	if held[PermK8sSecretsRead] || held[PermK8sSecretsShow] {
		rules = append(rules, rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}})
	}
	return rules
}

// permissionsForSubject resolves what a group or user holds, so the rules can
// be derived from the same answer the product itself enforces.
func permissionsForSubject(subjectType string, subjectID uint) map[string]bool {
	if subjectType == "user" {
		var u models.User
		if err := db.DB.First(&u, subjectID).Error; err != nil {
			return map[string]bool{}
		}
		return permissionsFor(u.ID, u.Role)
	}
	held := map[string]bool{}
	var grants []models.PermissionGrant
	db.DB.Where("subject_type = ? AND subject_id = ?", "group", subjectID).Find(&grants)
	for _, g := range grants {
		held[g.Permission] = true
	}
	return held
}

func roleName(groupName string) string    { return "commitkube-" + sanitize(groupName) }
func bindingName(groupName string) string { return "commitkube-" + sanitize(groupName) }

// sanitize turns a CommitKube group name into something Kubernetes accepts as
// an object name.
func sanitize(s string) string {
	out := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
			return r
		case r >= 'A' && r <= 'Z':
			return r + 32
		case r == ' ' || r == '_' || r == '.':
			return '-'
		}
		return -1
	}, s)
	return strings.Trim(out, "-")
}

// AllNamespaces is the namespace value that means cluster-wide. A Role cannot
// span namespaces, so this produces a ClusterRole and a ClusterRoleBinding
// instead -- the same rules, unbounded.
const AllNamespaces = "*"

// buildRBAC returns the objects for one group, derived from what that group
// already holds. Returns interface{} because the cluster-wide case is a
// different pair of kinds, and pretending otherwise would mean two functions
// that drift.
func buildRBAC(groupName, namespace string, rules []rbacv1.PolicyRule) (role, binding interface{}, err error) {
	if len(rules) == 0 {
		return nil, nil, fmt.Errorf("this group holds no Kubernetes permission, so there is nothing to bind; grant k8s.read first")
	}

	subject := rbacv1.Subject{
		Kind: "Group", Name: ImpersonationGroup(groupName), APIGroup: "rbac.authorization.k8s.io",
	}

	if namespace == AllNamespaces {
		cr := &rbacv1.ClusterRole{
			TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
			ObjectMeta: metav1.ObjectMeta{Name: roleName(groupName)},
			Rules:      rules,
		}
		crb := &rbacv1.ClusterRoleBinding{
			TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"},
			ObjectMeta: metav1.ObjectMeta{Name: bindingName(groupName)},
			Subjects:   []rbacv1.Subject{subject},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: roleName(groupName), APIGroup: "rbac.authorization.k8s.io"},
		}
		return cr, crb, nil
	}

	r := &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Name: roleName(groupName), Namespace: namespace},
		Rules:      rules,
	}
	rb := &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: bindingName(groupName), Namespace: namespace},
		Subjects:   []rbacv1.Subject{subject},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: roleName(groupName), APIGroup: "rbac.authorization.k8s.io"},
	}
	return r, rb, nil
}

// impersonationClusterRole is the rule CommitKube's own credential needs, and
// the one place this design can be quietly ruined: impersonate without
// resourceNames lets the holder become any user in the cluster, including a
// cluster-admin, which is strictly worse than the single shared identity it
// was meant to replace.
func impersonationClusterRole(groupNames []string) *rbacv1.ClusterRole {
	names := make([]string, 0, len(groupNames))
	for _, g := range groupNames {
		names = append(names, ImpersonationGroup(g))
	}
	sort.Strings(names)

	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
		ObjectMeta: metav1.ObjectMeta{Name: "commitkube-impersonator"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"groups"},
				Verbs:         []string{"impersonate"},
				ResourceNames: names,
			},
			{
				APIGroups: []string{""},
				Resources: []string{"users"},
				Verbs:     []string{"impersonate"},
				// Users are named per person and the list would change with
				// every hire, so the bindings carry the groups and the user
				// name exists only to land in the audit log.
				ResourceNames: nil,
			},
		},
	}
}

// clusterReaderRole is the companion nobody thinks to ask for and everything
// breaks without. A RoleBinding in a namespace permits Pods("ns").List(); it
// does not permit Pods("").List(), and it does not permit reading nodes or
// listing namespaces at all -- both are cluster-scoped. Without this, turning
// impersonation on leaves the namespace filter, the Nodes page and the Cluster
// Overview empty, which reads as a broken product rather than as a policy.
//
// It grants no workload or secret access: those stay per namespace, which is
// where the actual decision lives.
func clusterReaderRole() *rbacv1.ClusterRole {
	return &rbacv1.ClusterRole{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"},
		ObjectMeta: metav1.ObjectMeta{Name: "commitkube-cluster-reader"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"namespaces", "nodes"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"metrics.k8s.io"}, Resources: []string{"nodes", "pods"}, Verbs: []string{"get", "list"}},
		},
	}
}

func clusterReaderBinding(groupName string) *rbacv1.ClusterRoleBinding {
	return &rbacv1.ClusterRoleBinding{
		TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRoleBinding"},
		ObjectMeta: metav1.ObjectMeta{
			Name: "commitkube-cluster-reader-" + sanitize(groupName),
		},
		Subjects: []rbacv1.Subject{{
			Kind: "Group", Name: ImpersonationGroup(groupName), APIGroup: "rbac.authorization.k8s.io",
		}},
		RoleRef: rbacv1.RoleRef{Kind: "ClusterRole", Name: "commitkube-cluster-reader", APIGroup: "rbac.authorization.k8s.io"},
	}
}

func toYAML(objs ...interface{}) (string, error) {
	var b strings.Builder
	for i, o := range objs {
		out, err := yaml.Marshal(o)
		if err != nil {
			return "", err
		}
		if i > 0 {
			b.WriteString("---\n")
		}
		b.Write(out)
	}
	return b.String(), nil
}

// ---- HTTP -----------------------------------------------------------------

// PreviewClusterRBAC returns the manifest without touching the cluster, and
// needs no cluster privilege at all -- enough for a team that would rather
// apply it themselves.
func PreviewClusterRBAC(c *fiber.Ctx) error {
	group := c.Query("group")
	namespace := c.Query("namespace")
	if group == "" || namespace == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "group and namespace are required"})
	}

	var g models.UserGroup
	if err := db.DB.Where("name = ?", group).First(&g).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "group not found"})
	}

	held := permissionsForSubject("group", g.ID)
	rules := rulesForPermissions(held)
	role, binding, err := buildRBAC(group, namespace, rules)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var groupNames []string
	db.DB.Model(&models.UserGroup{}).Pluck("name", &groupNames)

	objs := []interface{}{role, binding}
	// The cluster-scoped reader is only needed alongside a namespaced binding:
	// a cluster-wide grant already covers listing namespaces and nodes.
	if namespace != AllNamespaces {
		objs = append(objs, clusterReaderRole(), clusterReaderBinding(group))
	}
	manifest, err := toYAML(objs...)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	impersonator, err := toYAML(impersonationClusterRole(groupNames))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	// What the rules came from, so the reader can see the derivation rather
	// than take the YAML on faith.
	from := []string{}
	for _, p := range []string{PermK8sRead, PermK8sLogsRead, PermK8sPodDelete, PermK8sScale, PermK8sSecretsRead, PermK8sSecretsShow} {
		if held[p] {
			from = append(from, p)
		}
	}

	return c.JSON(fiber.Map{
		"manifest":            manifest,
		"impersonator":        impersonator,
		"impersonation_group": ImpersonationGroup(group),
		"derived_from":        from,
		"cluster_wide":        namespace == AllNamespaces,
	})
}

// ApplyClusterRBAC writes it. Two gates: iam.manage on the route, which only
// root holds, and the cluster's own opt-in flag.
func ApplyClusterRBAC(c *fiber.Ctx) error {
	var req struct {
		ClusterID uint   `json:"cluster_id"`
		Group     string `json:"group"`
		Namespace string `json:"namespace"`
	}
	if err := c.BodyParser(&req); err != nil || req.Group == "" || req.Namespace == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "cluster_id, group and namespace are required"})
	}

	var cl models.Cluster
	if err := db.DB.First(&cl, req.ClusterID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "cluster not found"})
	}
	if !cl.CanManageRBAC {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "este cluster não permite que o CommitKube escreva RBAC; use o manifesto e aplique você mesmo, ou libere na caixa abaixo",
		})
	}

	var g models.UserGroup
	if err := db.DB.Where("name = ?", req.Group).First(&g).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "group not found"})
	}
	rules := rulesForPermissions(permissionsForSubject("group", g.ID))
	role, binding, err := buildRBAC(req.Group, req.Namespace, rules)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	typed, _, err := clientsFor(&cl)
	if err != nil {
		return clusterUnreachable(c, err)
	}
	ctx := context.Background()

	if err := applyRBACObjects(ctx, typed, req.Namespace, role, binding); err != nil {
		return k8sError(c, err)
	}
	if req.Namespace != AllNamespaces {
		if err := applyRBACObjects(ctx, typed, AllNamespaces, clusterReaderRole(), clusterReaderBinding(req.Group)); err != nil {
			return k8sError(c, err)
		}
	}

	db.LogAudit(currentUserID(c), "apply_cluster_rbac", "cluster", cl.Name,
		fmt.Sprintf(`{"group":"%s","namespace":"%s"}`, req.Group, req.Namespace), c.IP())

	return c.JSON(fiber.Map{
		"message":             fmt.Sprintf("RBAC aplicado para %s em %s", req.Group, req.Namespace),
		"impersonation_group": ImpersonationGroup(req.Group),
	})
}

// applyRBACObjects creates or replaces one role/binding pair. A RoleBinding's
// roleRef is immutable, so an existing binding is replaced rather than
// updated: otherwise a permission change fails here with an error that reads
// like a bug.
func applyRBACObjects(ctx context.Context, typed *kubernetes.Clientset, namespace string, role, binding interface{}) error {
	exists := func(err error) bool { return err != nil && strings.Contains(err.Error(), "already exists") }

	switch r := role.(type) {
	case *rbacv1.Role:
		if _, err := typed.RbacV1().Roles(namespace).Create(ctx, r, metav1.CreateOptions{}); err != nil {
			if !exists(err) {
				return err
			}
			if _, err := typed.RbacV1().Roles(namespace).Update(ctx, r, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	case *rbacv1.ClusterRole:
		if _, err := typed.RbacV1().ClusterRoles().Create(ctx, r, metav1.CreateOptions{}); err != nil {
			if !exists(err) {
				return err
			}
			if _, err := typed.RbacV1().ClusterRoles().Update(ctx, r, metav1.UpdateOptions{}); err != nil {
				return err
			}
		}
	}

	switch b := binding.(type) {
	case *rbacv1.RoleBinding:
		if _, err := typed.RbacV1().RoleBindings(namespace).Create(ctx, b, metav1.CreateOptions{}); err != nil {
			if !exists(err) {
				return err
			}
			if err := typed.RbacV1().RoleBindings(namespace).Delete(ctx, b.Name, metav1.DeleteOptions{}); err != nil {
				return err
			}
			if _, err := typed.RbacV1().RoleBindings(namespace).Create(ctx, b, metav1.CreateOptions{}); err != nil {
				return err
			}
		}
	case *rbacv1.ClusterRoleBinding:
		if _, err := typed.RbacV1().ClusterRoleBindings().Create(ctx, b, metav1.CreateOptions{}); err != nil {
			if !exists(err) {
				return err
			}
			if err := typed.RbacV1().ClusterRoleBindings().Delete(ctx, b.Name, metav1.DeleteOptions{}); err != nil {
				return err
			}
			if _, err := typed.RbacV1().ClusterRoleBindings().Create(ctx, b, metav1.CreateOptions{}); err != nil {
				return err
			}
		}
	}
	return nil
}
