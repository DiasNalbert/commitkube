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
