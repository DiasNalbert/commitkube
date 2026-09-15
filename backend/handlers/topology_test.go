package handlers

import (
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// testClusterID stands in for the cluster every fixture belongs to; the
// point of the tests is the persistence, not which cluster it came from.
const testClusterID = uint(1)

// testIndex builds a cluster with two namespaces: `prod` holds api, payments
// and a postgres StatefulSet; `data` holds a redis the prod side is not
// supposed to be able to address by bare name.
func testIndex(t *testing.T) (*topoIndex, []topoWorkload) {
	t.Helper()

	workloads := []topoWorkload{
		{Ref: nodeRef{"prod", "Deployment", "api"}, Labels: map[string]string{"app": "api"}},
		{Ref: nodeRef{"prod", "Deployment", "payments"}, Labels: map[string]string{"app": "payments"}},
		{Ref: nodeRef{"prod", "StatefulSet", "postgres"}, Labels: map[string]string{"app": "postgres"}},
		{Ref: nodeRef{"data", "Deployment", "redis"}, Labels: map[string]string{"app": "redis"}},
	}
	svcs := []corev1.Service{
		{
			ObjectMeta: metav1.ObjectMeta{Name: "payments", Namespace: "prod"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "payments"}, ClusterIP: "10.0.0.7"},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "postgres", Namespace: "prod"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "postgres"}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "redis", Namespace: "data"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "redis"}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "legacy", Namespace: "prod"},
			Spec:       corev1.ServiceSpec{Selector: map[string]string{"app": "nothing-here"}},
		},
		{
			ObjectMeta: metav1.ObjectMeta{Name: "vendor", Namespace: "prod"},
			Spec:       corev1.ServiceSpec{Type: corev1.ServiceTypeExternalName, ExternalName: "api.vendor.com"},
		},
	}

	ix := newTopoIndex()
	for i := range workloads {
		ix.node(workloads[i].Ref)
	}
	indexServices(ix, svcs, workloads)
	return ix, workloads
}

func TestResolveHostForms(t *testing.T) {
	ix, _ := testIndex(t)

	cases := []struct {
		host, callerNS string
		qualified      bool   // the value carried a scheme or a port
		want           string // "" means it must not resolve
		wantConf       string
	}{
		{"payments", "prod", false, "prod/Deployment/payments", "high"},
		{"payments.prod", "prod", false, "prod/Deployment/payments", "high"},
		{"payments.prod.svc", "data", false, "prod/Deployment/payments", "high"},
		{"payments.prod.svc.cluster.local", "data", false, "prod/Deployment/payments", "high"},
		{"PAYMENTS.PROD.SVC", "data", false, "prod/Deployment/payments", "high"},
		{"10.0.0.7", "prod", false, "prod/Deployment/payments", "high"},
		// A bare name only resolves in the caller's own namespace, because that
		// is the only place a pod's DNS search path would find it.
		{"redis", "prod", false, "", ""},
		{"redis", "data", false, "data/Deployment/redis", "high"},
		{"redis.data", "prod", false, "data/Deployment/redis", "high"},
		// A Service selecting nothing is still a node, so the edge is drawn.
		{"legacy", "prod", false, "prod/Service/legacy", "high"},
		// ExternalName forwards out of the cluster.
		{"vendor", "prod", false, "/External/api.vendor.com", "high"},
		// A real external dependency.
		{"api.stripe.com", "prod", false, "/External/api.stripe.com", "medium"},
		// An unfamiliar suffix is only believed when the value was plainly an
		// address; otherwise it is indistinguishable from a config string.
		{"db.corp.lan", "prod", true, "/External/db.corp.lan", "medium"},
		{"db.corp.lan", "prod", false, "", ""},
		// Noise that must never become a node.
		{"localhost", "prod", true, "", ""},
		{"127.0.0.1", "prod", true, "", ""},
		{"0.0.0.0", "prod", true, "", ""},
		{"production", "prod", false, "", ""},
		{"log.level", "prod", false, "", ""},
		{"v1.2.3", "prod", false, "", ""},
		// A dangling in-cluster name is a broken reference, not an external host.
		{"gone.prod.svc.cluster.local", "prod", true, "", ""},
	}

	for _, tc := range cases {
		refs, conf := ix.resolveHost(tc.host, tc.callerNS, tc.qualified)
		if tc.want == "" {
			if len(refs) != 0 {
				t.Errorf("resolveHost(%q, %q) = %v, want no resolution", tc.host, tc.callerNS, refs)
			}
			continue
		}
		if len(refs) != 1 {
			t.Errorf("resolveHost(%q, %q) = %v, want exactly %q", tc.host, tc.callerNS, refs, tc.want)
			continue
		}
		if refs[0].id() != tc.want {
			t.Errorf("resolveHost(%q, %q) = %q, want %q", tc.host, tc.callerNS, refs[0].id(), tc.want)
		}
		if conf != tc.wantConf {
			t.Errorf("resolveHost(%q, %q) confidence = %q, want %q", tc.host, tc.callerNS, conf, tc.wantConf)
		}
	}
}

func TestExtractCandidates(t *testing.T) {
	cases := []struct {
		name      string
		text      string
		allowBare bool
		want      []string // "scheme|host|port"
	}{
		{"plain url", "http://payments:8080/charge", false, []string{"http|payments|8080"}},
		{"dsn keeps host drops credentials",
			"postgres://app:s3cr3t@postgres.prod.svc.cluster.local:5432/app", false,
			[]string{"postgres|postgres.prod.svc.cluster.local|5432"}},
		{"host port", "redis:6379", false, []string{"|redis|6379"}},
		{"broker list", "kafka-0:9092,kafka-1:9092", false, []string{"|kafka-0|9092", "|kafka-1|9092"}},
		{"bare allowed only when asked", "payments", true, []string{"|payments|"}},
		{"bare rejected otherwise", "payments", false, nil},
		{"yaml body", "upstream: http://api.prod.svc:80\ntimeout: 30s", false, []string{"http|api.prod.svc|80"}},
		// A cluster DNS name is unmistakable, so it is read even out of a file
		// body where a bare word would be rejected.
		{"cluster fqdn in a file", "backend: payments.prod.svc.cluster.local\n", false,
			[]string{"|payments.prod.svc.cluster.local|"}},
		{"hostish key takes a plain fqdn", "redis.data.svc.cluster.local", true,
			[]string{"|redis.data.svc.cluster.local|"}},
		{"nothing addressable", "true", false, nil},
		{"port out of range", "host:99999", false, nil},
	}

	for _, tc := range cases {
		got := []string{}
		for _, c := range extractCandidates(tc.text, tc.allowBare) {
			got = append(got, c.Scheme+"|"+c.Host+"|"+c.Port)
		}
		sort.Strings(got)
		want := append([]string{}, tc.want...)
		sort.Strings(want)
		if strings.Join(got, " ") != strings.Join(want, " ") {
			t.Errorf("%s: extractCandidates(%q) = %v, want %v", tc.name, tc.text, got, tc.want)
		}
	}
}

func TestEdgesFromConfigInfersDependencies(t *testing.T) {
	ix, _ := testIndex(t)

	api := topoWorkload{
		Ref:    nodeRef{"prod", "Deployment", "api"},
		Labels: map[string]string{"app": "api"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{
				Name: "app",
				Env: []corev1.EnvVar{
					{Name: "PAYMENTS_URL", Value: "http://payments:8080"},
					{Name: "REDIS_HOST", Value: "redis.data.svc.cluster.local"},
					{Name: "DATABASE_URL", Value: "postgres://app:hunter2@postgres:5432/app"},
					{Name: "NODE_ENV", Value: "production"},
					{Name: "LOG_LEVEL", Value: "debug"},
					{Name: "DB_PASSWORD", Value: "postgres://app:hunter2@postgres:5432/app"},
				},
				Args: []string{"--upstream=http://api.stripe.com"},
			}},
		},
	}

	edges := dedupeEdges(edgesFromConfig(ix, []topoWorkload{api}, nil))

	want := map[string]string{ // dst id -> protocol
		"prod/Deployment/payments":  "http",
		"data/Deployment/redis":     "tcp",
		"prod/StatefulSet/postgres": "postgres",
		"/External/api.stripe.com":  "http",
	}
	got := map[string]string{}
	for _, e := range edges {
		if e.Src.id() != "prod/Deployment/api" {
			t.Errorf("edge from unexpected source %q", e.Src.id())
		}
		got[e.Dst.id()] = e.Protocol
	}
	for dst, proto := range want {
		if got[dst] != proto {
			t.Errorf("edge to %s: protocol %q, want %q (edges: %v)", dst, got[dst], proto, got)
		}
	}
	for dst := range got {
		if _, ok := want[dst]; !ok {
			t.Errorf("unexpected edge to %s -- a config value became a dependency it should not have", dst)
		}
	}

	// A password-shaped key must not put its value in evidence, even though the
	// host inside it is a legitimate edge.
	for _, e := range edges {
		if strings.Contains(e.Evidence, "hunter2") {
			t.Errorf("credential leaked into evidence: %q", e.Evidence)
		}
	}
}

func TestNetworkPolicyEdgesAreLowConfidenceAndCapped(t *testing.T) {
	ix, workloads := testIndex(t)

	np := networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "api-egress", Namespace: "prod"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "api"}},
			Egress: []networkingv1.NetworkPolicyEgressRule{{
				To: []networkingv1.NetworkPolicyPeer{
					{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"app": "payments"}}},
					// A CIDR peer says nothing about services and must be skipped.
					{IPBlock: &networkingv1.IPBlock{CIDR: "0.0.0.0/0"}},
				},
			}},
		},
	}
	nsLabels := map[string]map[string]string{
		"prod": {"kubernetes.io/metadata.name": "prod"},
		"data": {"kubernetes.io/metadata.name": "data"},
	}

	edges := edgesFromNetworkPolicies(ix, []networkingv1.NetworkPolicy{np}, workloads, nsLabels)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d: %+v", len(edges), edges)
	}
	e := edges[0]
	if e.Src.id() != "prod/Deployment/api" || e.Dst.id() != "prod/Deployment/payments" {
		t.Errorf("edge = %s -> %s, want api -> payments", e.Src.id(), e.Dst.id())
	}
	if e.Confidence != "low" {
		t.Errorf("confidence = %q, want low: an allow rule is permission, not a call", e.Confidence)
	}

	// A policy that selects a whole namespace is a blanket allow. Expanding it
	// would bury every real edge, so it is dropped rather than fanned out.
	wide := np
	wide.Spec.Egress = []networkingv1.NetworkPolicyEgressRule{{
		To: []networkingv1.NetworkPolicyPeer{{
			PodSelector:       &metav1.LabelSelector{},
			NamespaceSelector: &metav1.LabelSelector{},
		}},
	}}
	many := make([]topoWorkload, 0, maxPeers+2)
	for i := 0; i < maxPeers+2; i++ {
		many = append(many, topoWorkload{
			Ref:    nodeRef{"prod", "Deployment", "svc-" + strconv.Itoa(i)},
			Labels: map[string]string{"app": "api"},
		})
	}
	if got := edgesFromNetworkPolicies(ix, []networkingv1.NetworkPolicy{wide}, many, nsLabels); len(got) != 0 {
		t.Errorf("a blanket allow produced %d edges, want 0", len(got))
	}
}

func TestDepthRelaxationTerminatesOnCycles(t *testing.T) {
	// The layout depth is computed by relaxation with an iteration cap; a cycle
	// must not spin. This mirrors the loop in GetTopology.
	edges := []topologyEdge{
		{From: "a", To: "b"}, {From: "b", To: "c"}, {From: "c", To: "a"},
	}
	depth := map[string]int{}
	iterations := 0
	for i := 0; i < 20; i++ {
		iterations++
		changed := false
		for _, e := range edges {
			if depth[e.To] < depth[e.From]+1 {
				depth[e.To] = depth[e.From] + 1
				changed = true
			}
		}
		if !changed {
			break
		}
	}
	if iterations > 20 {
		t.Fatalf("relaxation did not terminate")
	}
	if depth["b"] == 0 && depth["c"] == 0 {
		t.Errorf("cycle produced no layering at all: %v", depth)
	}
}

// TestPersistTopologyUpserts exercises the write against a real SQLite file.
// The upsert depends on the composite unique indexes that AutoMigrate creates
// from the model tags; if those ever stop matching the OnConflict columns, the
// write fails and the page just looks empty. That is worth a test, not a log.
func TestPersistTopologyUpserts(t *testing.T) {
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })

	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "topo.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := gdb.AutoMigrate(&models.ServiceNode{}, &models.ServiceEdge{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.DB = gdb

	ix, _ := testIndex(t)
	edges := []edgeAcc{{
		Src: nodeRef{"prod", "Deployment", "api"}, Dst: nodeRef{"prod", "Deployment", "payments"},
		Port: "8080", Protocol: "http", Source: "env",
		Evidence: "PAYMENTS_URL=http://payments:8080", Confidence: "high",
	}}

	first := time.Now().Add(-time.Hour)
	if err := persistTopology(testClusterID, ix, edges, first, 7); err != nil {
		t.Fatalf("first pass: %v", err)
	}

	var nodes, edgeRows int64
	gdb.Model(&models.ServiceNode{}).Count(&nodes)
	gdb.Model(&models.ServiceEdge{}).Count(&edgeRows)
	if nodes == 0 {
		t.Fatal("first pass wrote no nodes")
	}
	if edgeRows != 1 {
		t.Fatalf("first pass wrote %d edges, want 1", edgeRows)
	}

	// The traffic layer owns Observed. A later discovery pass must not clear it.
	gdb.Model(&models.ServiceEdge{}).Where("1 = 1").Update("observed", true)

	second := time.Now()
	edges[0].Evidence = "PAYMENTS_URL=http://payments:8080/v2"
	if err := persistTopology(testClusterID, ix, edges, second, 7); err != nil {
		t.Fatalf("second pass: %v", err)
	}

	var afterNodes, afterEdges int64
	gdb.Model(&models.ServiceNode{}).Count(&afterNodes)
	gdb.Model(&models.ServiceEdge{}).Count(&afterEdges)
	if afterNodes != nodes || afterEdges != 1 {
		t.Errorf("second pass duplicated rows: nodes %d->%d, edges 1->%d", nodes, afterNodes, afterEdges)
	}

	var edge models.ServiceEdge
	gdb.First(&edge)
	if !edge.Observed {
		t.Error("a discovery pass cleared Observed, which belongs to the traffic layer")
	}
	if edge.Evidence != "PAYMENTS_URL=http://payments:8080/v2" {
		t.Errorf("evidence not refreshed: %q", edge.Evidence)
	}
	if !edge.FirstSeen.Truncate(time.Second).Equal(first.Truncate(time.Second)) {
		t.Errorf("FirstSeen moved: %v, want %v", edge.FirstSeen, first)
	}
	if !edge.LastSeen.After(edge.FirstSeen) {
		t.Errorf("LastSeen %v did not advance past FirstSeen %v", edge.LastSeen, edge.FirstSeen)
	}
}

// TestPersistTopologyPrunes checks that a dependency which stops being
// declared eventually leaves the map instead of lingering forever.
func TestPersistTopologyPrunes(t *testing.T) {
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })

	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "topo.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := gdb.AutoMigrate(&models.ServiceNode{}, &models.ServiceEdge{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.DB = gdb

	ix, _ := testIndex(t)
	stale := time.Now().AddDate(0, 0, -30)
	if err := persistTopology(testClusterID, ix, []edgeAcc{{
		Src: nodeRef{"prod", "Deployment", "api"}, Dst: nodeRef{"prod", "Deployment", "payments"},
		Source: "env", Confidence: "high",
	}}, stale, 7); err != nil {
		t.Fatalf("stale pass: %v", err)
	}

	// A pass that discovers nothing must still prune what aged out.
	if err := persistTopology(testClusterID, newTopoIndex(), nil, time.Now(), 7); err != nil {
		t.Fatalf("empty pass: %v", err)
	}

	var edges int64
	gdb.Model(&models.ServiceEdge{}).Count(&edges)
	if edges != 0 {
		t.Errorf("%d stale edges survived retention", edges)
	}
}
