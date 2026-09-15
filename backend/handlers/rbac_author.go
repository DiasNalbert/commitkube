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

var rbacTemplates = map[string]rbacTemplate{
	"viewer": {
		Name:        "viewer",
		Description: "Ver workloads, pods e serviços do namespace. Não lê log nem Secret.",
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods", "services", "configmaps", "persistentvolumeclaims", "events"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"apps"}, Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"get", "list", "watch"}},
		},
	},
	"operator": {
		Name:        "operator",
		Description: "Tudo do viewer, mais ler log, reiniciar pod e escalar workload.",
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods", "services", "configmaps", "persistentvolumeclaims", "events"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{""}, Resources: []string{"pods/log"}, Verbs: []string{"get"}},
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"delete"}},
			{APIGroups: []string{"apps"}, Resources: []string{"deployments", "replicasets", "statefulsets", "daemonsets"}, Verbs: []string{"get", "list", "watch"}},
			{APIGroups: []string{"apps"}, Resources: []string{"deployments/scale", "statefulsets/scale"}, Verbs: []string{"get", "update"}},
			{APIGroups: []string{"networking.k8s.io"}, Resources: []string{"ingresses"}, Verbs: []string{"get", "list", "watch"}},
		},
	},
	"secret-reader": {
		Name:        "secret-reader",
		Description: "Ler o valor de Secrets do namespace. Conceda isoladamente.",
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}},
		},
	},
}

func roleName(template string) string { return "commitkube-" + template }
func bindingName(group, template string) string {
	return "commitkube-" + sanitize(group) + "-" + template
}

// sanitize turns a CommitKube group name into something Kubernetes accepts as
// an object name, without pretending the result is unique on its own -- the
// binding name carries the template too.
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

func buildRBAC(groupName, namespace, template string) (*rbacv1.Role, *rbacv1.RoleBinding, error) {
	tpl, ok := rbacTemplates[template]
	if !ok {
		names := make([]string, 0, len(rbacTemplates))
		for k := range rbacTemplates {
			names = append(names, k)
		}
		sort.Strings(names)
		return nil, nil, fmt.Errorf("unknown template %q; known: %s", template, strings.Join(names, ", "))
	}

	role := &rbacv1.Role{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"},
		ObjectMeta: metav1.ObjectMeta{Name: roleName(template), Namespace: namespace},
		Rules:      tpl.Rules,
	}
	binding := &rbacv1.RoleBinding{
		TypeMeta:   metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "RoleBinding"},
		ObjectMeta: metav1.ObjectMeta{Name: bindingName(groupName, template), Namespace: namespace},
		Subjects: []rbacv1.Subject{{
			Kind:     "Group",
			Name:     ImpersonationGroup(groupName),
			APIGroup: "rbac.authorization.k8s.io",
		}},
		RoleRef: rbacv1.RoleRef{Kind: "Role", Name: roleName(template), APIGroup: "rbac.authorization.k8s.io"},
	}
	return role, binding, nil
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
				// name exists only to land in the audit log. Narrow this to
				// explicit names if you would rather not allow the shape.
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

func ListRBACTemplates(c *fiber.Ctx) error {
	out := make([]fiber.Map, 0, len(rbacTemplates))
	names := make([]string, 0, len(rbacTemplates))
	for k := range rbacTemplates {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, n := range names {
		out = append(out, fiber.Map{"name": n, "description": rbacTemplates[n].Description})
	}
	return c.JSON(fiber.Map{"templates": out})
}

// PreviewClusterRBAC returns the manifest without touching the cluster. It
// needs no cluster privilege at all, which is the point: a team that does not
// want CommitKube writing RBAC can still get the exact YAML to apply.
func PreviewClusterRBAC(c *fiber.Ctx) error {
	group, namespace, template := c.Query("group"), c.Query("namespace"), c.Query("template", "viewer")
	if group == "" || namespace == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "group and namespace are required"})
	}
	role, binding, err := buildRBAC(group, namespace, template)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var groupNames []string
	db.DB.Model(&models.UserGroup{}).Pluck("name", &groupNames)

	manifest, err := toYAML(role, binding, clusterReaderRole(), clusterReaderBinding(group))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	impersonator, err := toYAML(impersonationClusterRole(groupNames))
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"manifest":            manifest,
		"impersonator":        impersonator,
		"impersonation_group": ImpersonationGroup(group),
	})
}

// ApplyClusterRBAC writes it. Two gates, both deliberate: iam.manage on the
// route, which only root holds, and the cluster's own opt-in flag.
func ApplyClusterRBAC(c *fiber.Ctx) error {
	var req struct {
		ClusterID uint   `json:"cluster_id"`
		Group     string `json:"group"`
		Namespace string `json:"namespace"`
		Template  string `json:"template"`
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
			"error": "this cluster does not allow CommitKube to write RBAC; use the preview and apply it yourself, or enable it on the cluster",
		})
	}

	role, binding, err := buildRBAC(req.Group, req.Namespace, req.Template)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	typed, _, err := clientsFor(&cl)
	if err != nil {
		return clusterUnreachable(c, err)
	}
	ctx := context.Background()

	if _, err := typed.RbacV1().Roles(req.Namespace).Create(ctx, role, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return k8sError(c, err)
		}
		if _, err := typed.RbacV1().Roles(req.Namespace).Update(ctx, role, metav1.UpdateOptions{}); err != nil {
			return k8sError(c, err)
		}
	}
	if _, err := typed.RbacV1().RoleBindings(req.Namespace).Create(ctx, binding, metav1.CreateOptions{}); err != nil {
		if !strings.Contains(err.Error(), "already exists") {
			return k8sError(c, err)
		}
		// A RoleBinding's roleRef is immutable, so an existing one is replaced
		// rather than updated -- otherwise a template change would fail here
		// with an error that reads like a bug.
		if err := typed.RbacV1().RoleBindings(req.Namespace).
			Delete(ctx, binding.Name, metav1.DeleteOptions{}); err != nil {
			return k8sError(c, err)
		}
		if _, err := typed.RbacV1().RoleBindings(req.Namespace).
			Create(ctx, binding, metav1.CreateOptions{}); err != nil {
			return k8sError(c, err)
		}
	}

	// Without the cluster-scoped reader, the namespace filter, the Nodes page
	// and the Cluster Overview come back empty and it looks like a bug.
	crole := clusterReaderRole()
	if _, err := typed.RbacV1().ClusterRoles().Create(ctx, crole, metav1.CreateOptions{}); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return k8sError(c, err)
	}
	cbinding := clusterReaderBinding(req.Group)
	if _, err := typed.RbacV1().ClusterRoleBindings().Create(ctx, cbinding, metav1.CreateOptions{}); err != nil &&
		!strings.Contains(err.Error(), "already exists") {
		return k8sError(c, err)
	}

	db.LogAudit(currentUserID(c), "apply_cluster_rbac", "cluster", cl.Name,
		fmt.Sprintf(`{"group":"%s","namespace":"%s","template":"%s"}`, req.Group, req.Namespace, req.Template), c.IP())

	return c.JSON(fiber.Map{
		"message":             fmt.Sprintf("%s applied for %s in %s", req.Template, req.Group, req.Namespace),
		"impersonation_group": ImpersonationGroup(req.Group),
	})
}
