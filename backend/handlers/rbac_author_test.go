package handlers

import (
	"strings"
	"testing"

	rbacv1 "k8s.io/api/rbac/v1"
)

// Without resourceNames, a credential that may impersonate can become any user
// in the cluster -- including a cluster-admin -- which is strictly worse than
// the single shared identity impersonation was introduced to replace. This is
// the one rule in the design that cannot be got wrong quietly.
func TestImpersonatorIsNarrowedToKnownGroups(t *testing.T) {
	cr := impersonationClusterRole([]string{"platform", "apis-team"})

	var groupRule *struct {
		names []string
		verbs []string
	}
	for _, r := range cr.Rules {
		for _, res := range r.Resources {
			if res == "groups" {
				groupRule = &struct {
					names []string
					verbs []string
				}{r.ResourceNames, r.Verbs}
			}
		}
	}
	if groupRule == nil {
		t.Fatal("no rule covers group impersonation")
	}
	if len(groupRule.names) == 0 {
		t.Fatal("group impersonation carries no resourceNames, so it grants every group in the cluster")
	}
	for _, n := range groupRule.names {
		if !strings.HasPrefix(n, "ck:group:") {
			t.Errorf("%q is impersonable but is not a CommitKube identity", n)
		}
	}
}

func TestRBACBindsTheGroupNotThePerson(t *testing.T) {
	rules := rulesForPermissions(map[string]bool{PermK8sRead: true, PermK8sPodDelete: true})
	role, binding, err := buildRBAC("apis-team", "apis", rules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	r, ok := role.(*rbacv1.Role)
	if !ok {
		t.Fatalf("a namespaced request produced %T, not a Role", role)
	}
	b, ok := binding.(*rbacv1.RoleBinding)
	if !ok {
		t.Fatalf("a namespaced request produced %T, not a RoleBinding", binding)
	}
	if r.Namespace != "apis" || b.Namespace != "apis" {
		t.Error("the objects are not scoped to the namespace they were asked for")
	}
	if len(b.Subjects) != 1 || b.Subjects[0].Kind != "Group" {
		t.Fatal("the binding does not name a group, so it would need rewriting per person")
	}
	if b.Subjects[0].Name != "ck:group:apis-team" {
		t.Errorf("binding names %q, which is not what impersonation sends", b.Subjects[0].Name)
	}
	if b.RoleRef.Name != r.Name {
		t.Error("the binding points at a role that is not the one being created")
	}
}

// A Role cannot span namespaces, so "all namespaces" has to become a different
// pair of kinds -- getting this wrong would produce a Role that silently
// covers one namespace while the UI says it covers every one.
func TestAllNamespacesProducesClusterScopedObjects(t *testing.T) {
	rules := rulesForPermissions(map[string]bool{PermK8sRead: true})
	role, binding, err := buildRBAC("platform", AllNamespaces, rules)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := role.(*rbacv1.ClusterRole); !ok {
		t.Fatalf("got %T, want a ClusterRole", role)
	}
	crb, ok := binding.(*rbacv1.ClusterRoleBinding)
	if !ok {
		t.Fatalf("got %T, want a ClusterRoleBinding", binding)
	}
	if crb.RoleRef.Kind != "ClusterRole" {
		t.Errorf("the binding refers to a %s, which cannot span namespaces", crb.RoleRef.Kind)
	}
}

// The rules come from the permissions already granted, so the two halves
// cannot disagree. A group with no Kubernetes permission has nothing to bind,
// and saying so beats writing an empty Role.
func TestRulesFollowThePermissionsGranted(t *testing.T) {
	if rules := rulesForPermissions(map[string]bool{PermSCMRead: true}); len(rules) != 0 {
		t.Errorf("an SCM-only group produced %d cluster rules", len(rules))
	}
	if _, _, err := buildRBAC("team", "ns", nil); err == nil {
		t.Error("a group with no Kubernetes permission produced a binding anyway")
	}

	readOnly := rulesForPermissions(map[string]bool{PermK8sRead: true})
	for _, r := range readOnly {
		for _, v := range r.Verbs {
			if v == "delete" || v == "update" {
				t.Errorf("k8s.read alone granted %q", v)
			}
		}
		for _, res := range r.Resources {
			if res == "pods/log" || res == "secrets" {
				t.Errorf("k8s.read alone granted %q", res)
			}
		}
	}

	withLogs := rulesForPermissions(map[string]bool{PermK8sRead: true, PermK8sLogsRead: true})
	found := false
	for _, r := range withLogs {
		for _, res := range r.Resources {
			if res == "pods/log" {
				found = true
			}
		}
	}
	if !found {
		t.Error("k8s.logs.read did not produce a pods/log rule")
	}
}

func TestSanitizeProducesAUsableObjectName(t *testing.T) {
	for in, want := range map[string]string{
		"APIs Team":   "apis-team",
		"plataforma":  "plataforma",
		"time_de_rpa": "time-de-rpa",
		"--weird--":   "weird",
	} {
		if got := sanitize(in); got != want {
			t.Errorf("sanitize(%q) = %q, want %q", in, got, want)
		}
	}
}
