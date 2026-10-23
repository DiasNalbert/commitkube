package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/strategicpatch"
)

// A deployment that fails every workload rule there is a patch for.
func badDeployment() *appsv1.Deployment {
	priv, esc := true, true
	root := int64(0)
	unconfined := corev1.ProcMountType("Unmasked")
	return &appsv1.Deployment{
		TypeMeta:   metav1.TypeMeta{APIVersion: "apps/v1", Kind: "Deployment"},
		ObjectMeta: metav1.ObjectMeta{Name: "api", Namespace: "shop", Labels: map[string]string{"app.kubernetes.io/managed-by": "Helm", "app.kubernetes.io/instance": "shop"}},
		Spec: appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{
			ObjectMeta: metav1.ObjectMeta{Annotations: map[string]string{"container.apparmor.security.beta.kubernetes.io/app": "unconfined"}},
			Spec: corev1.PodSpec{
				HostNetwork: true, HostPID: true, HostIPC: true,
				SecurityContext: &corev1.PodSecurityContext{SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeUnconfined}},
				InitContainers:  []corev1.Container{{Name: "init", Image: "busybox"}},
				Containers: []corev1.Container{{
					Name: "app", Image: "shop/api:1",
					Ports: []corev1.ContainerPort{{ContainerPort: 8080, HostPort: 8080}},
					SecurityContext: &corev1.SecurityContext{
						Privileged: &priv, AllowPrivilegeEscalation: &esc, RunAsUser: &root, ProcMount: &unconfined,
						Capabilities:   &corev1.Capabilities{Add: []corev1.Capability{"NET_RAW", "SYS_ADMIN", "NET_BIND_SERVICE"}},
						SELinuxOptions: &corev1.SELinuxOptions{Type: "spc_t"},
					},
				}},
			},
		}},
	}
}

func patchFrom(t *testing.T, r postureRemediation) []byte {
	t.Helper()
	for _, s := range r.Steps {
		if strings.Contains(s.Command, " patch ") {
			i := strings.Index(s.Command, "-p '")
			return []byte(strings.TrimSuffix(s.Command[i+4:], "'"))
		}
	}
	t.Fatalf("%s: no patch step in %+v", r.Rule, r.Steps)
	return nil
}

// The command is what gets run, so the command is what is tested: each
// patch is applied the way kubectl applies it, and the rule's own check
// must pass on the result.
func TestWorkloadPatchesFixWhatTheyClaim(t *testing.T) {
	rules := []string{"KSE-WL-001", "KSE-WL-002", "KSE-WL-003", "KSE-WL-004", "KSE-WL-005", "KSE-WL-009", "KSE-WL-010",
		"KSE-WL-011", "KSE-WL-013", "KSE-WL-015", "KSE-WL-016", "KSE-WL-018", "KSE-WL-022", "KSE-WL-024", "KSE-WL-025",
		"KSE-WL-026", "KSE-WL-027"}
	for _, id := range rules {
		t.Run(id, func(t *testing.T) {
			rule := postureRuleByID[id]
			d := badDeployment()
			w := postureWorkload{Kind: "Deployment", Namespace: "shop", Name: "api", Spec: d.Spec.Template.Spec, Annotations: d.Spec.Template.Annotations, LongRunning: true}
			if ruleCheckPasses(rule, &postureInventory{Workloads: []postureWorkload{w}, ServiceAccounts: map[string]*corev1.ServiceAccount{}}) {
				t.Fatal("fixture should fail this rule")
			}

			r := remediateWorkload(rule, "Deployment", "shop", "api", &d.Spec.Template.Spec, d.Spec.Template.Annotations, &d.ObjectMeta)
			if !r.Verified {
				t.Fatalf("not verified: %+v", r)
			}
			if r.ManagedBy != "Helm release shop" || !strings.Contains(r.Warnings[0], "put it back") {
				t.Fatalf("the Helm owner must be named first: %q %v", r.ManagedBy, r.Warnings)
			}

			orig, _ := json.Marshal(d)
			patched, err := strategicpatch.StrategicMergePatch(orig, patchFrom(t, r), appsv1.Deployment{})
			if err != nil {
				t.Fatalf("kubectl would reject the patch: %v", err)
			}
			var after appsv1.Deployment
			if err := json.Unmarshal(patched, &after); err != nil {
				t.Fatal(err)
			}
			w2 := postureWorkload{Kind: "Deployment", Namespace: "shop", Name: "api", Spec: after.Spec.Template.Spec, Annotations: after.Spec.Template.Annotations, LongRunning: true}
			if !ruleCheckPasses(rule, &postureInventory{Workloads: []postureWorkload{w2}, ServiceAccounts: map[string]*corev1.ServiceAccount{}}) {
				out := rule.Check(&postureInventory{Workloads: []postureWorkload{w2}})
				t.Fatalf("still failing after the patch: %v", out)
			}
			// The patch touches only what the rule is about: the image and the
			// other container stay as they were.
			if after.Spec.Template.Spec.Containers[0].Image != "shop/api:1" || len(after.Spec.Template.Spec.InitContainers) != 1 {
				t.Fatal("the patch changed more than it should")
			}
		})
	}
}

func TestWorkloadRulesWithoutACommandGiveGuidance(t *testing.T) {
	d := badDeployment()
	d.Spec.Template.Spec.Containers[0].Env = []corev1.EnvVar{{Name: "DB_PASS", ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{LocalObjectReference: corev1.LocalObjectReference{Name: "db"}, Key: "pass"}}}}
	r := remediateWorkload(postureRuleByID["KSE-SEC-001"], "Deployment", "shop", "api", &d.Spec.Template.Spec, nil, &d.ObjectMeta)
	if len(r.Steps) != 0 || !strings.Contains(r.Guidance, "secretName: db") {
		t.Fatalf("secrets-as-files: %+v", r)
	}
	// A Job's template is immutable: say so instead of handing out a patch
	// the API server refuses.
	j := remediateWorkload(postureRuleByID["KSE-WL-003"], "Job", "shop", "migrate", &d.Spec.Template.Spec, nil, &d.ObjectMeta)
	if len(j.Steps) != 0 || !strings.Contains(j.Guidance, "cannot be changed") {
		t.Fatalf("job: %+v", j)
	}
}

// The role keeps everything the rule does not object to.
func TestNarrowRoleRemovesExactlyTheFinding(t *testing.T) {
	rules := []rbacv1.PolicyRule{
		{APIGroups: []string{""}, Resources: []string{"secrets", "configmaps"}, Verbs: []string{"*"}},
		{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"get", "list"}},
		{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"app-token"}, Verbs: []string{"get"}},
	}
	meta := metav1.ObjectMeta{Name: "app-reader", Namespace: "shop"}
	r := remediateRole(postureRuleByID["KSE-RBAC-001"], "Role", meta, rules, false)
	if !r.Verified {
		t.Fatalf("not verified: %+v", r)
	}
	cmd := r.Steps[1].Command
	for _, want := range []string{"kind: Role", "name: app-reader", "configmaps", "deployments", "app-token"} {
		if !strings.Contains(cmd, want) {
			t.Errorf("the narrowed role lost %q:\n%s", want, cmd)
		}
	}
	if strings.Count(cmd, "- secrets") != 2 {
		// secrets survive twice: write verbs on the unnamed rule, and the
		// named one. get/list/watch on all secrets is what goes.
		t.Errorf("secrets rules:\n%s", cmd)
	}
	joined := strings.Join(r.Warnings, " ")
	if !strings.Contains(joined, "get, list, watch on secrets") {
		t.Errorf("the removal is not spelled out: %v", r.Warnings)
	}

	// Wildcards cannot be narrowed without knowing what the role needs.
	wild := remediateRole(postureRuleByID["KSE-RBAC-007"], "ClusterRole", metav1.ObjectMeta{Name: "x"},
		[]rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"get"}}}, false)
	if wild.Verified || !strings.Contains(strings.Join(wild.Warnings, " "), "instead of *") {
		t.Fatalf("wildcard: %+v", wild)
	}

	// A role shipped by a chart is flagged as the chart's.
	helm := remediateRole(postureRuleByID["KSE-RBAC-001"], "ClusterRole",
		metav1.ObjectMeta{Name: "argocd-server", Annotations: map[string]string{"meta.helm.sh/release-name": "argocd"}}, rules, false)
	if helm.ManagedBy != "Helm release argocd" || !strings.Contains(helm.Warnings[0], "accept the finding") {
		t.Fatalf("helm role: %+v", helm)
	}
}
