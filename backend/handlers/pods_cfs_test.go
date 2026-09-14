package handlers

import "testing"

func TestParseCFSMetrics(t *testing.T) {
	body := `# HELP container_cpu_cfs_periods_total Number of elapsed enforcement period intervals.
# TYPE container_cpu_cfs_periods_total counter
container_cpu_cfs_periods_total{container="app",id="/kubepods/pod123",image="nginx",name="k8s_app",namespace="prod",pod="api-7d9f-xyz"} 1000 1699999999999
container_cpu_cfs_throttled_periods_total{container="app",id="/kubepods/pod123",image="nginx",name="k8s_app",namespace="prod",pod="api-7d9f-xyz"} 300
container_cpu_cfs_periods_total{container="",id="/kubepods/pod123",namespace="prod",pod="api-7d9f-xyz"} 9999
container_cpu_cfs_periods_total{container="sidecar",namespace="prod",pod="api-7d9f-xyz"} 500
container_cpu_cfs_throttled_periods_total{container="sidecar",namespace="prod",pod="api-7d9f-xyz"} 0
container_cpu_usage_seconds_total{container="app",namespace="prod",pod="api-7d9f-xyz"} 42
`
	got := map[string]cfsSample{}
	parseCFSMetrics(body, got)

	if len(got) != 2 {
		t.Fatalf("expected 2 containers (pod-level cgroup must be skipped), got %d: %v", len(got), got)
	}
	app := got["prod/api-7d9f-xyz/app"]
	if app.Periods != 1000 || app.Throttled != 300 {
		t.Errorf("app: got periods=%v throttled=%v, want 1000/300", app.Periods, app.Throttled)
	}
	if side := got["prod/api-7d9f-xyz/sidecar"]; side.Periods != 500 || side.Throttled != 0 {
		t.Errorf("sidecar: got periods=%v throttled=%v, want 500/0", side.Periods, side.Throttled)
	}
}

func TestCFSLabelDoesNotMatchLabelSuffix(t *testing.T) {
	// "container" must not be satisfied by "container_label_foo".
	labels := `container_label_foo="bar",namespace="prod",pod="api-1"`
	if v := cfsLabel(labels, "container"); v != "" {
		t.Errorf("expected no match for container, got %q", v)
	}
	if v := cfsLabel(labels, "namespace"); v != "prod" {
		t.Errorf("namespace: got %q want prod", v)
	}
	if v := cfsLabel(labels, "pod"); v != "api-1" {
		t.Errorf("pod: got %q want api-1", v)
	}
}

func TestPodWorkloadStripsReplicaSetHash(t *testing.T) {
	ctrl := true
	cases := []struct{ kind, name, wantName, wantKind string }{
		{"ReplicaSet", "checkout-7d9f8b6c4d", "checkout", "Deployment"},
		{"StatefulSet", "postgres", "postgres", "StatefulSet"},
		{"DaemonSet", "fluentd", "fluentd", "DaemonSet"},
	}
	for _, tc := range cases {
		pod := newTestPod(tc.kind, tc.name, ctrl)
		gotName, gotKind := podWorkload(pod)
		if gotName != tc.wantName || gotKind != tc.wantKind {
			t.Errorf("%s/%s: got %s/%s want %s/%s", tc.kind, tc.name, gotName, gotKind, tc.wantName, tc.wantKind)
		}
	}
}
