package handlers

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func postureRuleNamed(t *testing.T, id string) *postureRule {
	t.Helper()
	r := postureRuleByID[id]
	if r == nil {
		t.Fatalf("rule %s is not in the catalog", id)
	}
	return r
}

// failingNames runs one rule and returns the names of the resources it failed.
func failingNames(t *testing.T, id string, inv *postureInventory) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, o := range postureRuleNamed(t, id).Check(inv) {
		if o.Detail != "" {
			out[o.Ref.Name] = o.Detail
		}
	}
	return out
}

func clusterRole(name string, rules ...rbacv1.PolicyRule) rbacv1.ClusterRole {
	return rbacv1.ClusterRole{ObjectMeta: metav1.ObjectMeta{Name: name}, Rules: rules}
}

func rolesInventory(roles ...rbacv1.ClusterRole) *postureInventory {
	return buildPostureInventory(&postureSources{ClusterRoles: roles})
}

func TestPostureCatalogIsWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for _, r := range postureCatalog {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true
		if _, ok := postureSeverityRank[r.Severity]; !ok {
			t.Errorf("%s: unknown severity %q", r.ID, r.Severity)
		}
		if r.Title == "" || r.Description == "" || r.Remediation == "" || r.Category == "" || r.Check == nil {
			t.Errorf("%s: incomplete rule", r.ID)
		}
	}
	if len(postureCatalog) < 25 {
		t.Errorf("catalog has %d rules, expected at least 25", len(postureCatalog))
	}
}

// Security Essentials mirrors the published Dynatrace standard one for one:
// 33 rules, each mapped to a distinct DTSE id, with its severity.
func TestPostureSecurityEssentialsMatchesTheStandard(t *testing.T) {
	want := map[string]string{
		"DTSE-83180": "critical", "DTSE-83182": "critical", "DTSE-83188": "critical",
		"DTSE-83185": "critical", "DTSE-83187": "critical", "DTSE-83189": "critical",
		"DTSE-83183": "high", "DTSE-83204": "high", "DTSE-83192": "high", "DTSE-83176": "high",
		"DTSE-83172": "high", "DTSE-83174": "high", "DTSE-83173": "high", "DTSE-83200": "high",
		"DTSE-83175": "high",
		"DTSE-83171": "medium", "DTSE-83639": "medium", "DTSE-83186": "medium", "DTSE-83190": "medium",
		"DTSE-83181": "medium", "DTSE-83184": "medium", "DTSE-83191": "medium", "DTSE-83202": "medium",
		"DTSE-83195": "medium", "DTSE-83177": "medium", "DTSE-83201": "medium", "DTSE-83203": "medium",
		"DTSE-83207": "medium", "DTSE-83209": "medium", "DTSE-83208": "medium", "DTSE-83205": "medium",
		"DTSE-83206": "medium",
		"DTSE-83178": "low",
	}
	got := map[string]string{}
	for _, r := range postureCatalog {
		switch r.Standard {
		case postureStandard:
			if r.Ref == "" {
				t.Errorf("%s is in %s without a DTSE ref", r.ID, postureStandard)
			}
			if _, dup := got[r.Ref]; dup {
				t.Errorf("%s maps to %s twice", r.ID, r.Ref)
			}
			got[r.Ref] = r.Severity
		case postureBestPractices:
		default:
			t.Errorf("%s has no standard", r.ID)
		}
	}
	for ref, sev := range want {
		if got[ref] != sev {
			t.Errorf("%s: severity %q, want %q", ref, got[ref], sev)
		}
	}
	if len(got) != len(want) {
		t.Errorf("Security Essentials has %d rules, want %d", len(got), len(want))
	}
}

// Best-practice rules are assessed but never move the headline score.
func TestPostureBestPracticesDoNotMoveTheScore(t *testing.T) {
	spec := hardenedPodSpec()
	spec.Containers[0].LivenessProbe = nil // a best-practice rule only
	results, nsRes := evaluatePosture(buildPostureInventory(&postureSources{
		Deployments: []appsv1.Deployment{deployment("apps", "api", spec)},
	}), postureCatalog)
	var a, bp models.PostureAssessment
	summarizePosture(&a, results, nsRes)
	summarizeStandard(&bp, results, postureBestPractices)
	if a.RulesFailed != 0 || a.Score != 100 {
		t.Errorf("Security Essentials moved: %+v", a)
	}
	if bp.RulesFailed != 1 {
		t.Errorf("best practices should fail the liveness rule: %+v", bp)
	}
}

func TestPostureAddedRules(t *testing.T) {
	unmasked := corev1.UnmaskedProcMount
	caps := hardenedPodSpec()
	caps.Containers[0].SecurityContext.Capabilities = &corev1.Capabilities{
		Drop: []corev1.Capability{"ALL"},
		Add:  []corev1.Capability{"NET_BIND_SERVICE", "SYS_ADMIN"}, // first allowed, second not
	}
	netraw := hardenedPodSpec()
	netraw.Containers[0].SecurityContext.Capabilities = nil // NET_RAW kept by default
	selinux := hardenedPodSpec()
	selinux.SecurityContext.SELinuxOptions = &corev1.SELinuxOptions{Type: "spc_t"}
	proc := hardenedPodSpec()
	proc.Containers[0].SecurityContext.ProcMount = &unmasked
	apparmor := deployment("apps", "apparmor", hardenedPodSpec())
	apparmor.Spec.Template.Annotations = map[string]string{"container.apparmor.security.beta.kubernetes.io/api": "unconfined"}
	dash := hardenedPodSpec()
	dash.Containers[0].Image = "kubernetesui/dashboard:v2.7.0"

	inv := buildPostureInventory(&postureSources{
		Deployments: []appsv1.Deployment{
			deployment("apps", "caps", caps), deployment("apps", "netraw", netraw),
			deployment("apps", "selinux", selinux), deployment("apps", "proc", proc), apparmor,
			deployment("kubernetes-dashboard", "kubernetes-dashboard", dash),
			// kube-system: a labelled add-on passes, something dropped there fails.
			func() appsv1.Deployment {
				d := deployment("kube-system", "coredns", hardenedPodSpec())
				d.Labels = map[string]string{"k8s-app": "kube-dns"}
				return d
			}(),
			deployment("kube-system", "my-app", hardenedPodSpec()),
		},
		ClusterRoles: []rbacv1.ClusterRole{
			clusterRole("pv-maker", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"persistentvolumes"}, Verbs: []string{"create"}}),
			clusterRole("token-minter", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"serviceaccounts/token"}, Verbs: []string{"create"}}),
			clusterRole("debugger", rbacv1.PolicyRule{NonResourceURLs: []string{"/debug/*"}, Verbs: []string{"get"}}),
			clusterRole("discovery", rbacv1.PolicyRule{NonResourceURLs: []string{"/api", "/version", "/healthz"}, Verbs: []string{"get"}}),
		},
	})
	cases := map[string][]string{
		"KSE-WL-022":   {"caps"},
		"KSE-WL-024":   {"netraw"},
		"KSE-WL-025":   {"selinux"},
		"KSE-WL-026":   {"apparmor"},
		"KSE-WL-027":   {"proc"},
		"KSE-WL-023":   {"my-app"},
		"KSE-RBAC-010": {"debugger"},
		"KSE-RBAC-011": {"pv-maker"},
		"KSE-RBAC-012": {"token-minter"},
		"KSE-CL-001":   {"cluster"},
	}
	for id, names := range cases {
		failing := failingNames(t, id, inv)
		if len(failing) != len(names) {
			t.Errorf("%s fails %v, want exactly %v", id, failing, names)
			continue
		}
		for _, n := range names {
			if _, ok := failing[n]; !ok {
				t.Errorf("%s does not fail %s (fails %v)", id, n, failing)
			}
		}
	}
}

func TestPostureRBACSecrets(t *testing.T) {
	inv := rolesInventory(
		clusterRole("reads-secrets", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get", "list"}}),
		clusterRole("wildcard", rbacv1.PolicyRule{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}),
		clusterRole("named-secret", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, ResourceNames: []string{"my-tls"}, Verbs: []string{"get"}}),
		clusterRole("configmaps", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}}),
		clusterRole("secrets-other-group", rbacv1.PolicyRule{APIGroups: []string{"example.io"}, Resources: []string{"secrets"}, Verbs: []string{"get"}}),
		clusterRole("system:controller:foo", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}),
	)
	got := failingNames(t, "KSE-RBAC-001", inv)
	if len(got) != 2 || got["reads-secrets"] == "" || got["wildcard"] == "" {
		t.Fatalf("expected reads-secrets and wildcard to fail, got %v", got)
	}
	// The system: role is excluded from the inventory entirely.
	for _, r := range inv.Roles {
		if r.Name == "system:controller:foo" {
			t.Fatal("system: ClusterRole should be excluded")
		}
	}
}

func TestPostureRBACImpersonateBindEscalate(t *testing.T) {
	inv := rolesInventory(
		clusterRole("impersonator", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"users", "groups"}, Verbs: []string{"impersonate"}}),
		clusterRole("binder", rbacv1.PolicyRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"clusterroles"}, Verbs: []string{"bind"}}),
		clusterRole("escalator", rbacv1.PolicyRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles"}, Verbs: []string{"escalate"}}),
		clusterRole("role-reader", rbacv1.PolicyRule{APIGroups: []string{"rbac.authorization.k8s.io"}, Resources: []string{"roles", "clusterroles"}, Verbs: []string{"get", "list"}}),
	)
	got := failingNames(t, "KSE-RBAC-002", inv)
	for _, want := range []string{"impersonator", "binder", "escalator"} {
		if got[want] == "" {
			t.Errorf("%s should fail, got %v", want, got)
		}
	}
	if got["role-reader"] != "" {
		t.Errorf("reading roles is not bind/escalate: %v", got)
	}
}

func TestPostureRBACNodeProxyAndWebhooks(t *testing.T) {
	inv := rolesInventory(
		clusterRole("kubelet-proxy", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"nodes/proxy"}, Verbs: []string{"get"}}),
		clusterRole("node-metrics", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"nodes/metrics", "nodes"}, Verbs: []string{"get"}}),
		clusterRole("webhook-editor", rbacv1.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"mutatingwebhookconfigurations"}, Verbs: []string{"patch"}}),
		clusterRole("webhook-reader", rbacv1.PolicyRule{APIGroups: []string{"admissionregistration.k8s.io"}, Resources: []string{"validatingwebhookconfigurations"}, Verbs: []string{"get", "list", "watch"}}),
	)
	if got := failingNames(t, "KSE-RBAC-003", inv); len(got) != 1 || got["kubelet-proxy"] == "" {
		t.Errorf("node proxy: %v", got)
	}
	if got := failingNames(t, "KSE-RBAC-005", inv); len(got) != 1 || got["webhook-editor"] == "" {
		t.Errorf("webhooks: %v", got)
	}
}

// Approving a CSR takes both halves; either alone cannot issue a certificate.
func TestPostureRBACCertificateApprovalNeedsBothHalves(t *testing.T) {
	approval := rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"certificatesigningrequests/approval"}, Verbs: []string{"update"}}
	signers := rbacv1.PolicyRule{APIGroups: []string{"certificates.k8s.io"}, Resources: []string{"signers"}, Verbs: []string{"approve"}}
	inv := rolesInventory(
		clusterRole("approver", approval, signers),
		clusterRole("half", approval),
	)
	if got := failingNames(t, "KSE-RBAC-004", inv); len(got) != 1 || got["approver"] == "" {
		t.Errorf("certificate approval: %v", got)
	}
}

func TestPostureRBACPodCreation(t *testing.T) {
	inv := rolesInventory(
		clusterRole("pod-maker", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"create"}}),
		clusterRole("deployer", rbacv1.PolicyRule{APIGroups: []string{"apps"}, Resources: []string{"deployments"}, Verbs: []string{"create", "update"}}),
		clusterRole("job-runner", rbacv1.PolicyRule{APIGroups: []string{"batch"}, Resources: []string{"cronjobs"}, Verbs: []string{"*"}}),
		clusterRole("pod-viewer", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get", "list", "delete"}}),
	)
	got := failingNames(t, "KSE-RBAC-006", inv)
	if len(got) != 3 || got["pod-viewer"] != "" {
		t.Errorf("pod creation: %v", got)
	}
}

func TestPostureRBACExclusions(t *testing.T) {
	inv := buildPostureInventory(&postureSources{
		ClusterRoles: []rbacv1.ClusterRole{{
			ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin", Labels: map[string]string{"kubernetes.io/bootstrapping": "rbac-defaults"}},
			Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
		}},
		Roles: []rbacv1.Role{
			{ObjectMeta: metav1.ObjectMeta{Name: "x", Namespace: "kube-system"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "y", Namespace: "apps"}},
		},
		ClusterRoleBindings: []rbacv1.ClusterRoleBinding{
			{
				// kubeadm's own binding: only system:masters, so it passes.
				ObjectMeta: metav1.ObjectMeta{Name: "admins"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:masters"}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "ci-admin"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
				Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "ci", Namespace: "ci"}},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "everyone-views"},
				RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
				Subjects:   []rbacv1.Subject{{Kind: "Group", Name: "system:authenticated"}},
			},
		},
	})
	if len(inv.Roles) != 1 || inv.Roles[0].Name != "y" {
		t.Fatalf("expected only Role apps/y to be assessed, got %+v", inv.Roles)
	}
	if got := failingNames(t, "KSE-RBAC-008", inv); len(got) != 1 || got["ci-admin"] == "" {
		t.Errorf("cluster-admin bindings: %v", got)
	}
	if got := failingNames(t, "KSE-RBAC-009", inv); len(got) != 1 || got["everyone-views"] == "" {
		t.Errorf("broad group bindings: %v", got)
	}
}

func hardenedPodSpec() corev1.PodSpec {
	return corev1.PodSpec{
		ServiceAccountName:           "api",
		AutomountServiceAccountToken: ptrBool(false),
		SecurityContext: &corev1.PodSecurityContext{
			RunAsNonRoot:   ptrBool(true),
			SeccompProfile: &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault},
		},
		Containers: []corev1.Container{{
			Name:  "api",
			Image: "registry.example:5000/api:1.4.2",
			SecurityContext: &corev1.SecurityContext{
				AllowPrivilegeEscalation: ptrBool(false),
				ReadOnlyRootFilesystem:   ptrBool(true),
				Capabilities:             &corev1.Capabilities{Drop: []corev1.Capability{"ALL"}},
			},
			Resources: corev1.ResourceRequirements{
				Limits:   corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("500m"), corev1.ResourceMemory: resource.MustParse("256Mi")},
				Requests: corev1.ResourceList{corev1.ResourceCPU: resource.MustParse("100m"), corev1.ResourceMemory: resource.MustParse("128Mi")},
			},
			LivenessProbe:  &corev1.Probe{},
			ReadinessProbe: &corev1.Probe{},
		}},
	}
}

func deployment(ns, name string, spec corev1.PodSpec) appsv1.Deployment {
	return appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
		Spec:       appsv1.DeploymentSpec{Template: corev1.PodTemplateSpec{Spec: spec}},
	}
}

// A workload that follows the guidance fails no workload rule.
func TestPostureHardenedWorkloadPassesEveryWorkloadRule(t *testing.T) {
	inv := buildPostureInventory(&postureSources{
		Deployments: []appsv1.Deployment{deployment("apps", "api", hardenedPodSpec())},
	})
	results, _ := evaluatePosture(inv, postureCatalog)
	for _, r := range results {
		if r.Result == "failed" {
			t.Errorf("%s failed on a hardened workload: %+v", r.RuleID, r.Failures)
		}
	}
}

func TestPostureWorkloadRules(t *testing.T) {
	bad := hardenedPodSpec()
	bad.HostNetwork = true
	bad.Containers[0].SecurityContext.Privileged = ptrBool(true)
	bad.Containers[0].SecurityContext.AllowPrivilegeEscalation = nil
	bad.Containers[0].Image = "nginx"
	bad.Containers[0].Env = []corev1.EnvVar{{
		Name: "DB_PASSWORD",
		ValueFrom: &corev1.EnvVarSource{SecretKeyRef: &corev1.SecretKeySelector{
			LocalObjectReference: corev1.LocalObjectReference{Name: "db"}, Key: "password",
		}},
	}}
	bad.Volumes = []corev1.Volume{{
		Name:         "runtime",
		VolumeSource: corev1.VolumeSource{HostPath: &corev1.HostPathVolumeSource{Path: "/var/run"}},
	}}

	inv := buildPostureInventory(&postureSources{
		Deployments: []appsv1.Deployment{deployment("apps", "bad", bad), deployment("apps", "good", hardenedPodSpec())},
	})
	for _, id := range []string{"KSE-WL-001", "KSE-WL-002", "KSE-WL-003", "KSE-SEC-001", "KSE-WL-006", "KSE-WL-008", "KSE-WL-014"} {
		got := failingNames(t, id, inv)
		if len(got) != 1 || got["bad"] == "" {
			t.Errorf("%s: expected only bad to fail, got %v", id, got)
		}
	}
}

func TestPostureControllerLevelAssessment(t *testing.T) {
	spec := hardenedPodSpec()
	inv := buildPostureInventory(&postureSources{
		CronJobs: []batchv1.CronJob{{
			ObjectMeta: metav1.ObjectMeta{Name: "nightly", Namespace: "apps"},
			Spec:       batchv1.CronJobSpec{JobTemplate: batchv1.JobTemplateSpec{Spec: batchv1.JobSpec{Template: corev1.PodTemplateSpec{Spec: spec}}}},
		}},
		Jobs: []batchv1.Job{{
			ObjectMeta: metav1.ObjectMeta{Name: "nightly-123", Namespace: "apps", OwnerReferences: []metav1.OwnerReference{{Kind: "CronJob", Name: "nightly"}}},
		}},
		Pods: []corev1.Pod{
			{ObjectMeta: metav1.ObjectMeta{Name: "api-abc", Namespace: "apps", OwnerReferences: []metav1.OwnerReference{{Kind: "ReplicaSet", Name: "api"}}}},
			{ObjectMeta: metav1.ObjectMeta{Name: "debug", Namespace: "apps"}, Spec: spec},
		},
		Deployments: []appsv1.Deployment{deployment("kube-system", "coredns", corev1.PodSpec{})},
	})
	names := map[string]string{}
	for _, w := range inv.Workloads {
		names[w.Name] = w.Kind
	}
	if len(names) != 2 || names["nightly"] != "CronJob" || names["debug"] != "Pod" {
		t.Fatalf("expected CronJob nightly and bare Pod debug only, got %v", names)
	}
	// Probes do not apply to the CronJob.
	for _, o := range postureRuleNamed(t, "KSE-WL-020").Check(inv) {
		if o.Ref.Name == "nightly" {
			t.Error("liveness probes should not be assessed on a CronJob")
		}
	}
}

func TestPostureImageTags(t *testing.T) {
	cases := map[string]bool{
		"nginx":                           true,
		"nginx:latest":                    true,
		"registry:5000/team/api":          true,
		"registry:5000/team/api:1.2":      false,
		"nginx@sha256:abcdef":             false,
		"ghcr.io/org/app:latest@sha256:0": false,
	}
	for img, want := range cases {
		if got := imageUnpinned(img); got != want {
			t.Errorf("imageUnpinned(%q) = %v, want %v", img, got, want)
		}
	}
}

func TestPostureNamespacesAndNotRelevant(t *testing.T) {
	inv := buildPostureInventory(&postureSources{
		Namespaces: []corev1.Namespace{
			{ObjectMeta: metav1.ObjectMeta{Name: "open"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "locked"}},
			{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		},
		NetworkPolicies: []networkingv1.NetworkPolicy{{
			ObjectMeta: metav1.ObjectMeta{Name: "deny", Namespace: "locked"},
			Spec:       networkingv1.NetworkPolicySpec{PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress}},
		}},
	})
	if got := failingNames(t, "KSE-NET-001", inv); len(got) != 1 || got["open"] == "" {
		t.Errorf("network policy: %v", got)
	}
	if got := failingNames(t, "KSE-NET-002", inv); len(got) != 1 || got["open"] == "" {
		t.Errorf("default deny: %v", got)
	}

	results, _ := evaluatePosture(inv, postureCatalog)
	for _, r := range results {
		if r.RuleID == "KSE-WL-001" && r.Result != "not_relevant" {
			t.Errorf("no workloads: KSE-WL-001 should be not_relevant, got %s", r.Result)
		}
	}
}

// A scoped user sees exactly what an assessment of their namespaces alone
// would give, and nothing cluster-scoped.
func TestPostureScopeMatchesAnAssessmentOfThoseNamespaces(t *testing.T) {
	bad := hardenedPodSpec()
	bad.HostNetwork = true
	src := &postureSources{
		Deployments: []appsv1.Deployment{deployment("team-a", "ok", hardenedPodSpec()), deployment("team-b", "net", bad)},
		ClusterRoles: []rbacv1.ClusterRole{
			clusterRole("reads-secrets", rbacv1.PolicyRule{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}}),
		},
	}
	all, allRes := evaluatePosture(buildPostureInventory(src), postureCatalog)

	scoped, scopedRes := scopePosture(all, allRes, map[string]bool{"team-a": true})
	onlyA, onlyARes := evaluatePosture(buildPostureInventory(&postureSources{
		Deployments: []appsv1.Deployment{deployment("team-a", "ok", hardenedPodSpec())},
	}), postureCatalog)

	// Both sides under the same scope: cluster-scoped resources (the
	// ClusterRole, the cluster-wide Dashboard check) are hidden from a scoped
	// user by design, so what has to match is everything namespaced.
	wantRes, wantResNs := scopePosture(onlyA, onlyARes, map[string]bool{"team-a": true})
	var got, want models.PostureAssessment
	summarizePosture(&got, scoped, scopedRes)
	summarizePosture(&want, wantRes, wantResNs)
	if got != want {
		t.Fatalf("scoped summary differs:\n got  %+v\n want %+v", got, want)
	}
	for _, r := range scoped {
		for _, f := range r.Failures {
			if f.Namespace != "team-a" {
				t.Errorf("%s leaks %s/%s/%s", r.RuleID, f.Kind, f.Namespace, f.Name)
			}
		}
	}
}

func usePostureDB(t *testing.T) {
	t.Helper()
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "posture.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := gdb.AutoMigrate(&models.PostureAssessment{}, &models.PostureRuleResult{}); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.DB = gdb
}

func TestPosturePersistRoundTrip(t *testing.T) {
	usePostureDB(t)
	bad := hardenedPodSpec()
	bad.HostPID = true
	inv := buildPostureInventory(&postureSources{
		Deployments: []appsv1.Deployment{deployment("apps", "pid", bad)},
	})
	results, nsRes := evaluatePosture(inv, postureCatalog)
	a, err := persistPosture(7, "manual", time.Now(), results, nsRes)
	if err != nil {
		t.Fatalf("persist: %v", err)
	}
	// One workload and the cluster itself (the Dashboard rule).
	if a.FailedHigh != 1 || a.ResourcesFailed != 1 || a.ResourcesAssessed != 2 || a.CatalogVersion != postureCatalogVersion {
		t.Errorf("unexpected summary %+v", a)
	}

	latest, ok := latestPosture(7)
	if !ok || latest.ID != a.ID {
		t.Fatal("latest assessment not found")
	}
	var rows []models.PostureRuleResult
	db.DB.Where("assessment_id = ?", a.ID).Find(&rows)
	if len(rows) != len(postureCatalog) {
		t.Fatalf("expected %d rule rows, got %d", len(postureCatalog), len(rows))
	}
	for i := range rows {
		r := fromPostureRow(&rows[i])
		if r.RuleID == "KSE-WL-004" {
			if r.Result != "failed" || len(r.Failures) != 1 || r.Failures[0].Name != "pid" || r.NamespaceCounts["apps"][0] != 1 {
				t.Errorf("host PID result did not round-trip: %+v", r)
			}
		}
	}
}
