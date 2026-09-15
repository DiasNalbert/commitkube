package handlers

import (
	"strings"
	"testing"
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
	role, binding, err := buildRBAC("apis-team", "apis", "operator")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if role.Namespace != "apis" || binding.Namespace != "apis" {
		t.Error("the objects are not scoped to the namespace they were asked for")
	}
	if len(binding.Subjects) != 1 || binding.Subjects[0].Kind != "Group" {
		t.Fatal("the binding does not name a group, so it would need rewriting per person")
	}
	if binding.Subjects[0].Name != "ck:group:apis-team" {
		t.Errorf("binding names %q, which is not what impersonation sends", binding.Subjects[0].Name)
	}
	if binding.RoleRef.Name != role.Name {
		t.Error("the binding points at a role that is not the one being created")
	}
}

func TestViewerCannotReadLogsOrSecrets(t *testing.T) {
	role, _, err := buildRBAC("team", "ns", "viewer")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, rule := range role.Rules {
		for _, res := range rule.Resources {
			if res == "pods/log" || res == "secrets" {
				t.Errorf("the viewer template grants %q, which is what the separate templates are for", res)
			}
			if res == "pods" {
				for _, v := range rule.Verbs {
					if v == "delete" {
						t.Error("the viewer template can delete pods")
					}
				}
			}
		}
	}
}

func TestUnknownTemplateIsRefusedWithTheKnownOnes(t *testing.T) {
	_, _, err := buildRBAC("team", "ns", "superuser")
	if err == nil {
		t.Fatal("an unknown template was accepted")
	}
	if !strings.Contains(err.Error(), "viewer") {
		t.Errorf("the refusal does not say what is available: %v", err)
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
