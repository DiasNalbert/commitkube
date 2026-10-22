package handlers

import (
	"strings"
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// The point of the list is order: a rollout, then the pods it broke, on
// adjacent lines. Forty pods failing the same way in the same half hour are
// one line, with the namespaces that hold them.
func TestClusterChangesGroupsAndOrders(t *testing.T) {
	useScanDB(t)
	if err := db.DB.AutoMigrate(&models.Deployment{}, &models.PodProblem{}, &models.WorkloadEvent{}); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Hour).Add(-2 * time.Hour)
	rollout := now.Add(31 * time.Minute)
	db.DB.Create(&models.Deployment{ClusterID: 1, Namespace: "payments", WorkloadKind: "Deployment", Workload: "payments-api",
		DeployedAt: rollout, Image: "ghcr.io/acme/payments-api:1.18.2", PrevImage: "ghcr.io/acme/payments-api:1.18.1", CommitSHA: "a41c9e2ffff"})
	for i := 0; i < 3; i++ {
		db.DB.Create(&models.PodProblem{ClusterID: 1, OpenedAt: rollout.Add(2 * time.Minute), Namespace: "payments",
			PodName: "payments-api-" + string(rune('a'+i)), Kind: "crashloop", Severity: "critical", Title: "CrashLoopBackOff"})
	}
	db.DB.Create(&models.PodProblem{ClusterID: 1, OpenedAt: rollout.Add(3 * time.Minute), Namespace: "checkout",
		PodName: "checkout-web-a", Kind: "crashloop", Severity: "critical", Title: "CrashLoopBackOff"})
	// Same pod reported twice: still one pod.
	db.DB.Create(&models.PodProblem{ClusterID: 1, OpenedAt: rollout.Add(4 * time.Minute), Namespace: "checkout",
		PodName: "checkout-web-a", Kind: "crashloop", Severity: "critical", Title: "CrashLoopBackOff"})
	// Informational problems are not changes worth a line.
	db.DB.Create(&models.PodProblem{ClusterID: 1, OpenedAt: rollout, Namespace: "payments", PodName: "x", Kind: "no_limits", Severity: "info"})
	// Another cluster's rows stay out.
	db.DB.Create(&models.PodProblem{ClusterID: 2, OpenedAt: rollout, Namespace: "payments", PodName: "y", Kind: "crashloop", Severity: "critical"})
	db.DB.Create(&models.WorkloadEvent{ClusterID: 1, RecordedAt: rollout.Add(5 * time.Minute), Namespace: "payments", Kind: "Deployment",
		Name: "payments-api", EventType: "status_change", OldValue: "progressing", NewValue: "degraded"})

	ev := buildClusterChanges(1, now.Add(-time.Hour), nil, false)
	if len(ev) != 3 {
		t.Fatalf("events = %d, want 3: %+v", len(ev), ev)
	}
	if ev[0].Kind != "workload" || ev[1].Kind != "problem" || ev[2].Kind != "rollout" {
		t.Fatalf("not newest first: %s, %s, %s", ev[0].Kind, ev[1].Kind, ev[2].Kind)
	}
	p := ev[1]
	if p.Text != "4 pods entered CrashLoopBackOff" || !strings.HasPrefix(p.Sub, "payments 3 · checkout 1") || !p.Failing || p.Tone != "red" {
		t.Fatalf("problem line = %+v", p)
	}
	r := ev[2]
	if r.Text != "payments-api 1.18.2 rolled out" || !strings.Contains(r.Sub, "commit a41c9e2") || !strings.Contains(r.Sub, "was 1.18.1") {
		t.Fatalf("rollout line = %+v", r)
	}

	// A person scoped to checkout sees only checkout.
	scoped := buildClusterChanges(1, now.Add(-time.Hour), []string{"checkout"}, true)
	if len(scoped) != 1 || scoped[0].Text != "1 pod entered CrashLoopBackOff" || scoped[0].Namespace != "checkout" {
		t.Fatalf("scoped = %+v", scoped)
	}
}
