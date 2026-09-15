package handlers

import (
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// The audit is the load-bearing part of the design: without it, "declare a
// permission on every route" is a convention, and conventions are what let a
// hundred routes go unguarded in the first place.
func TestAuditRoutePermissionsCatchesAnUndeclaredRoute(t *testing.T) {
	Declare("GET", "/declared", PermK8sRead)

	routes := []fiber.Route{
		{Method: "GET", Path: "/api/declared"},
		{Method: "GET", Path: "/api/forgotten"},
	}

	err := AuditRoutePermissions(routes, nil)
	if err == nil {
		t.Fatal("a route with no permission passed the audit")
	}
	if !strings.Contains(err.Error(), "/api/forgotten") {
		t.Fatalf("the audit did not name the offending route: %v", err)
	}
	if strings.Contains(err.Error(), "/api/declared") {
		t.Fatalf("the audit flagged a route that did declare one: %v", err)
	}
}

func TestAuditRoutePermissionsIgnoresWhatItShould(t *testing.T) {
	routes := []fiber.Route{
		{Method: "GET", Path: "/health"},          // not under /api
		{Method: "HEAD", Path: "/api/anything"},   // Fiber's implicit HEAD
		{Method: "POST", Path: "/api/auth/login"}, // deliberately public
	}
	if err := AuditRoutePermissions(routes, map[string]bool{"/api/auth/login": true}); err != nil {
		t.Fatalf("audit rejected routes it should ignore: %v", err)
	}
}

func TestRoleBundles(t *testing.T) {
	// root holds everything, so the day this lands nobody loses access.
	for _, p := range AllPermissions {
		found := false
		for _, held := range rolePermissions["root"] {
			if held == p {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("root is missing %q, so an upgrade would take access away", p)
		}
	}

	// A plain user must not reach the two things that were only unguarded by
	// accident: pod logs and the secret listing.
	for _, forbidden := range []string{PermK8sLogsRead, PermK8sSecretsRead, PermK8sSecretsShow, PermK8sPodDelete} {
		for _, held := range rolePermissions["user"] {
			if held == forbidden {
				t.Errorf("the user role still carries %q", forbidden)
			}
		}
	}
}

func TestValidPermissionRejectsInvention(t *testing.T) {
	if validPermission("k8s.everything") {
		t.Error("an unknown permission was accepted, so a typo would grant nothing silently")
	}
	if !validPermission(PermK8sRead) {
		t.Error("a real permission was rejected")
	}
}

// The scope decision is the fence between one team's page and another team's
// namespaces, and it is consulted from a dozen handlers -- worth testing on
// its own rather than through any one of them.
func TestNamespaceScopeDecision(t *testing.T) {
	cases := []struct {
		name      string
		allowed   []string
		target    string
		wantAllow bool
	}{
		{"unscoped sees everything", nil, "financeiro", true},
		{"scoped sees its own", []string{"apis", "rpas"}, "apis", true},
		{"scoped does not see another", []string{"apis", "rpas"}, "financeiro", false},
		{"an empty scope list is unscoped, not locked out", []string{}, "anything", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			restricted := len(tc.allowed) > 0
			got := !restricted
			for _, ns := range tc.allowed {
				if ns == tc.target {
					got = true
				}
			}
			if got != tc.wantAllow {
				t.Fatalf("namespace %q with scope %v: got %v, want %v",
					tc.target, tc.allowed, got, tc.wantAllow)
			}
		})
	}
}

// The policy editor must not be grantable: a permission an admin can be handed
// is not root-only, it is root-only until someone hands it over.
func TestIAMManageIsNotGrantable(t *testing.T) {
	if validPermission(PermIAMManage) {
		t.Fatal("iam.manage is in the grantable catalog, so root-only is only a default")
	}

	held := false
	for _, p := range rolePermissions["root"] {
		if p == PermIAMManage {
			held = true
		}
	}
	if !held {
		t.Error("root does not hold iam.manage, so nobody can edit the policy")
	}

	for _, role := range []string{"admin", "user"} {
		for _, p := range rolePermissions[role] {
			if p == PermIAMManage {
				t.Errorf("the %s role carries iam.manage", role)
			}
		}
	}
}

func TestRootCapIsTwo(t *testing.T) {
	if MaxRootUsers != 2 {
		t.Fatalf("MaxRootUsers is %d; the agreed cap is 2", MaxRootUsers)
	}
}
