package handlers

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// useDeliveryDB gives the delivery tests their own database carrying the
// tables the outcome evaluation reads.
func useDeliveryDB(t *testing.T) {
	t.Helper()
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })

	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "delivery.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := gdb.AutoMigrate(
		&models.Deployment{}, &models.ServiceProblem{},
		&models.PodProblem{}, &models.WorkloadEvent{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.DB = gdb
}

func TestCommitSHAFromImage(t *testing.T) {
	cases := []struct {
		image string
		want  string
		why   string
	}{
		{"registry.io/org/api:abc1234", "abc1234", "a bare short hash"},
		{"registry.io/org/api:main-abc1234", "abc1234", "branch prefix"},
		{"registry.io/org/api:1.4.2-deadbeef", "deadbeef", "version prefix"},
		{"api:abc1234-20260101", "abc1234", "date suffix is not the hash"},
		{"api:sha-9f8e7d6", "9f8e7d6", "an explicit sha marker"},
		{"registry:5000/api:cafe1234567", "cafe1234567", "a registry port is not a tag"},
		{"api:0123456789abcdef0123456789abcdef01234567", "0123456789abcdef0123456789abcdef01234567", "a full hash"},

		// The ones that must NOT produce a hash. A wrong answer here attaches
		// a deployment to a commit that did not produce it, and the lead time
		// that follows is a number someone will act on.
		{"api:latest", "", "a mutable tag carries nothing"},
		{"api:build-1234567", "", "a seven digit build number is valid hex and is not a commit"},
		{"api:v1.4.2", "", "a semantic version is not a hash"},
		{"api", "", "no tag at all"},
		{"api@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "", "a digest pins the image, it does not name the commit"},
	}
	for _, tc := range cases {
		if got := commitSHAFromImage(tc.image); got != tc.want {
			t.Errorf("commitSHAFromImage(%q) = %q, want %q -- %s", tc.image, got, tc.want, tc.why)
		}
	}
}

func TestRepoNameFromImage(t *testing.T) {
	cases := map[string]string{
		"registry.io/org/api:abc1234": "api",
		"registry:5000/api:abc1234":   "api",
		"api:abc1234":                 "api",
		"org/api@sha256:00ff":         "api",
	}
	for image, want := range cases {
		if got := repoNameFromImage(image); got != want {
			t.Errorf("repoNameFromImage(%q) = %q, want %q", image, got, want)
		}
	}
}

// A deployment followed by a problem the error layer blamed on a third party
// is not a change failure. Counting it as one reports a team as unreliable for
// an outage it did not cause, which is the most common way this metric lies.
func TestDependencyCausedProblemIsNotAChangeFailure(t *testing.T) {
	useDeliveryDB(t)
	deployedAt := time.Now().Add(-2 * time.Hour)

	dep := models.Deployment{
		ClusterID: 1, Namespace: "shop", WorkloadKind: "Deployment", Workload: "checkout",
		DeployedAt: deployedAt, Image: "api:abc1234", PrevImage: "api:0ldc0de",
		LinkStatus: "pending", Outcome: "pending",
	}
	db.DB.Create(&dep)
	db.DB.Create(&models.ServiceProblem{
		ClusterID: 1, Namespace: "shop", Workload: "checkout", Kind: "http_5xx",
		OpenedAt: deployedAt.Add(10 * time.Minute), CauseKind: "dependency",
		CauseHost: "payments.vendor.com",
	})

	settleDeploymentOutcomes()

	var got models.Deployment
	db.DB.First(&got, dep.ID)
	if got.Outcome != "ok" {
		t.Fatalf("outcome = %q, want ok: a dependency's outage is not this deployment's failure", got.Outcome)
	}
	// Excluded, but not hidden.
	if !got.DependencyIncident {
		t.Error("the exclusion was silent; DependencyIncident must record that a problem did open")
	}
}

// The same problem with no dependency to blame does count.
func TestSelfCausedProblemIsAChangeFailure(t *testing.T) {
	useDeliveryDB(t)
	deployedAt := time.Now().Add(-2 * time.Hour)
	closedAt := deployedAt.Add(25 * time.Minute)

	dep := models.Deployment{
		ClusterID: 1, Namespace: "shop", WorkloadKind: "Deployment", Workload: "checkout",
		DeployedAt: deployedAt, Image: "api:abc1234", LinkStatus: "pending", Outcome: "pending",
	}
	db.DB.Create(&dep)
	db.DB.Create(&models.ServiceProblem{
		ClusterID: 1, Namespace: "shop", Workload: "checkout", Kind: "http_5xx",
		OpenedAt: deployedAt.Add(5 * time.Minute), ClosedAt: &closedAt, CauseKind: "self",
	})

	settleDeploymentOutcomes()

	var got models.Deployment
	db.DB.First(&got, dep.ID)
	if got.Outcome != "failed" {
		t.Fatalf("outcome = %q, want failed", got.Outcome)
	}
	if got.RecoverySec == nil {
		t.Fatal("a problem that closed must produce a recovery time")
	}
	// From the problem opening to it closing: 20 minutes, not the 25 since the
	// deployment. Recovery is measured from when it broke.
	if *got.RecoverySec != 1200 {
		t.Errorf("recovery = %ds, want 1200", *got.RecoverySec)
	}
}

// An unknown cause still counts. "Nobody measured it" is not evidence of
// innocence -- the same rule the error layer applies when it refuses to report
// "self" for traffic it never saw, read from the other side.
func TestUnknownCauseIsAChangeFailure(t *testing.T) {
	useDeliveryDB(t)
	deployedAt := time.Now().Add(-2 * time.Hour)

	dep := models.Deployment{
		ClusterID: 1, Namespace: "shop", WorkloadKind: "Deployment", Workload: "checkout",
		DeployedAt: deployedAt, Image: "api:abc1234", LinkStatus: "pending", Outcome: "pending",
	}
	db.DB.Create(&dep)
	db.DB.Create(&models.ServiceProblem{
		ClusterID: 1, Namespace: "shop", Workload: "checkout", Kind: "error_logs",
		OpenedAt: deployedAt.Add(time.Minute), CauseKind: "unknown",
	})

	settleDeploymentOutcomes()

	var got models.Deployment
	db.DB.First(&got, dep.ID)
	if got.Outcome != "failed" {
		t.Fatalf("outcome = %q, want failed", got.Outcome)
	}
}

// Putting the previous image back is the clearest statement there is that the
// deployment before it was bad, and it is readable from the deployment history
// alone.
func TestRollbackFailsTheDeploymentItReplaced(t *testing.T) {
	useDeliveryDB(t)
	deployedAt := time.Now().Add(-3 * time.Hour)

	bad := models.Deployment{
		ClusterID: 1, Namespace: "shop", WorkloadKind: "Deployment", Workload: "checkout",
		DeployedAt: deployedAt, Image: "api:newc0de", PrevImage: "api:0ldc0de",
		LinkStatus: "pending", Outcome: "pending",
	}
	db.DB.Create(&bad)
	back := models.Deployment{
		ClusterID: 1, Namespace: "shop", WorkloadKind: "Deployment", Workload: "checkout",
		DeployedAt: deployedAt.Add(15 * time.Minute), Image: "api:0ldc0de", PrevImage: "api:newc0de",
		LinkStatus: "pending", Outcome: "pending",
	}
	db.DB.Create(&back)

	settleDeploymentOutcomes()

	var gotBad, gotBack models.Deployment
	db.DB.First(&gotBad, bad.ID)
	db.DB.First(&gotBack, back.ID)

	if gotBad.Outcome != "failed" {
		t.Fatalf("the rolled back deployment is %q, want failed", gotBad.Outcome)
	}
	if !gotBack.Rollback {
		t.Error("the deployment that put the old image back is not marked as a rollback")
	}
	// The rollback itself is a deployment and is not a failure on its own.
	if gotBack.Outcome == "failed" {
		t.Error("the rollback was counted as a failure too, which double counts one incident")
	}
	if gotBad.RecoverySec == nil {
		t.Fatal("a rolled back deployment has a recovery time: the image went back")
	}
	if *gotBad.RecoverySec != 900 {
		t.Errorf("recovery = %ds, want 900 -- the length of the bad release", *gotBad.RecoverySec)
	}
}

// A deployment younger than the failure window has not succeeded yet. Settling
// it early makes every recent deployment count as a success and drags the rate
// down for no reason.
func TestDeploymentInsideTheWindowStaysPending(t *testing.T) {
	useDeliveryDB(t)
	dep := models.Deployment{
		ClusterID: 1, Namespace: "shop", WorkloadKind: "Deployment", Workload: "checkout",
		DeployedAt: time.Now().Add(-5 * time.Minute), Image: "api:abc1234",
		LinkStatus: "pending", Outcome: "pending",
	}
	db.DB.Create(&dep)

	settleDeploymentOutcomes()

	var got models.Deployment
	db.DB.First(&got, dep.ID)
	if got.Outcome != "pending" {
		t.Fatalf("outcome = %q, want pending", got.Outcome)
	}
}

// A problem on a different workload in the same namespace says nothing about
// this deployment.
func TestProblemOnAnotherWorkloadDoesNotFailThisDeployment(t *testing.T) {
	useDeliveryDB(t)
	deployedAt := time.Now().Add(-2 * time.Hour)
	dep := models.Deployment{
		ClusterID: 1, Namespace: "shop", WorkloadKind: "Deployment", Workload: "checkout",
		DeployedAt: deployedAt, Image: "api:abc1234", LinkStatus: "pending", Outcome: "pending",
	}
	db.DB.Create(&dep)
	db.DB.Create(&models.PodProblem{
		ClusterID: 1, Namespace: "shop", Workload: "search", Kind: "OOMKilled",
		OpenedAt: deployedAt.Add(2 * time.Minute),
	})

	settleDeploymentOutcomes()

	var got models.Deployment
	db.DB.First(&got, dep.ID)
	if got.Outcome != "ok" {
		t.Fatalf("outcome = %q, want ok", got.Outcome)
	}
}

func TestDORABands(t *testing.T) {
	const day = 24 * 3600.0
	cases := []struct {
		metric string
		value  float64
		want   string
	}{
		{"deploy_frequency", 3, "elite"},
		{"deploy_frequency", 0.5, "high"},
		{"deploy_frequency", 0.05, "medium"},
		{"deploy_frequency", 0.01, "low"},
		{"lead_time", 3600, "elite"},
		{"lead_time", 3 * day, "high"},
		{"lead_time", 10 * day, "medium"},
		{"lead_time", 60 * day, "low"},
		{"change_failure", 10, "elite"},
		{"change_failure", 25, "high"},
		{"change_failure", 40, "medium"},
		{"change_failure", 70, "low"},
		{"recovery_time", 600, "elite"},
		{"recovery_time", 5 * 3600, "high"},
		{"recovery_time", 3 * day, "medium"},
		{"recovery_time", 30 * day, "low"},
	}
	for _, tc := range cases {
		if got := doraBand(tc.metric, tc.value); got != tc.want {
			t.Errorf("doraBand(%s, %v) = %q, want %q", tc.metric, tc.value, got, tc.want)
		}
	}
}

func TestMedianSec(t *testing.T) {
	if medianSec(nil) != nil {
		t.Error("an empty sample has no median; it must not report zero")
	}
	if got := medianSec([]int64{30, 10, 20}); got == nil || *got != 20 {
		t.Errorf("median = %v, want 20", got)
	}
	if got := medianSec([]int64{10, 20, 30, 40}); got == nil || *got != 25 {
		t.Errorf("median = %v, want 25", got)
	}
}
