package handlers

import (
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func ptrBool(b bool) *bool    { return &b }
func ptrInt64(i int64) *int64 { return &i }

func kinds(findings []PodSecurityFinding) map[string]string {
	out := map[string]string{}
	for _, f := range findings {
		out[f.Kind] = f.Severity
	}
	return out
}

// A pod that follows the guidance should produce nothing. A checker that fires
// on a correct pod is a checker people turn off.
func TestAHardenedPodIsQuiet(t *testing.T) {
	pod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "apis"},
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: ptrBool(false),
			Containers: []corev1.Container{{
				Name:  "api",
				Image: "registry.example/api:1.4.2",
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:                ptrInt64(1000),
					RunAsNonRoot:             ptrBool(true),
					AllowPrivilegeEscalation: ptrBool(false),
					ReadOnlyRootFilesystem:   ptrBool(true),
				},
			}},
		},
	}
	if f := inspectPodSecurity(pod); len(f) != 0 {
		t.Fatalf("a hardened pod produced %d findings: %+v", len(f), f)
	}
}

func TestTheOnesThatHandOverTheNodeAreCritical(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			HostNetwork: true,
			HostPID:     true,
			Volumes: []corev1.Volume{{
				Name:         "docker",
				VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"}},
			}},
			Containers: []corev1.Container{{
				Name:  "agent",
				Image: "agent:1.0",
				SecurityContext: &corev1.SecurityContext{
					Privileged:   ptrBool(true),
					Capabilities: &corev1.Capabilities{Add: []corev1.Capability{"SYS_ADMIN"}},
				},
			}},
		},
	}

	got := kinds(inspectPodSecurity(pod))
	for _, kind := range []string{"host_network", "host_pid", "host_path", "privileged", "capability"} {
		if got[kind] != "critical" {
			t.Errorf("%s reported as %q, want critical", kind, got[kind])
		}
	}
}

// Running as root is common and contained on its own. Reporting it as critical
// would drown the findings that actually hand over the node.
func TestRunningAsRootIsAWarningNotACritical(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "app", Image: "app:1.0"}},
		},
	}
	got := kinds(inspectPodSecurity(pod))
	if got["run_as_root"] != "warning" {
		t.Errorf("run_as_root reported as %q, want warning", got["run_as_root"])
	}
}

// A non-root user set on the pod covers its containers, and reporting root
// anyway would be wrong in the direction that costs trust.
func TestPodLevelSecurityContextCounts(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			SecurityContext: &corev1.PodSecurityContext{RunAsUser: ptrInt64(1000)},
			Containers:      []corev1.Container{{Name: "app", Image: "app:1.0"}},
		},
	}
	if _, found := kinds(inspectPodSecurity(pod))["run_as_root"]; found {
		t.Error("a pod-level runAsUser was ignored")
	}
}

func TestMutableTagAndStartupFetchAreCaught(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			InitContainers: []corev1.Container{{
				Name:    "fetch-config",
				Image:   "busybox:latest",
				Command: []string{"sh", "-c", "wget -O /cfg https://example.internal/cfg.json"},
			}},
			Containers: []corev1.Container{{Name: "app", Image: "app"}},
		},
	}
	got := kinds(inspectPodSecurity(pod))
	if got["fetches_at_start"] != "warning" {
		t.Error("a container that downloads at start-up was not reported")
	}
	if got["mutable_tag"] != "warning" {
		t.Error("an image with no fixed tag was not reported")
	}
}

// NET_RAW is on by default nearly everywhere; firing on it would train people
// to ignore the page.
func TestCommonCapabilitiesDoNotFire(t *testing.T) {
	pod := &corev1.Pod{
		Spec: corev1.PodSpec{
			AutomountServiceAccountToken: ptrBool(false),
			Containers: []corev1.Container{{
				Name:  "app",
				Image: "app:1.0",
				SecurityContext: &corev1.SecurityContext{
					RunAsUser:                ptrInt64(1000),
					AllowPrivilegeEscalation: ptrBool(false),
					ReadOnlyRootFilesystem:   ptrBool(true),
					Capabilities:             &corev1.Capabilities{Add: []corev1.Capability{"NET_RAW", "CHOWN"}},
				},
			}},
		},
	}
	if f := inspectPodSecurity(pod); len(f) != 0 {
		t.Errorf("everyday capabilities produced findings: %+v", f)
	}
}

func TestWorstOfRanksCorrectly(t *testing.T) {
	if worstOf(nil) != "healthy" {
		t.Error("no findings should be healthy")
	}
	mixed := []PodSecurityFinding{{Severity: "info"}, {Severity: "critical"}, {Severity: "warning"}}
	if worstOf(mixed) != "critical" {
		t.Error("critical did not win")
	}
	if worstOf([]PodSecurityFinding{{Severity: "info"}, {Severity: "warning"}}) != "warning" {
		t.Error("warning did not win over info")
	}
}
