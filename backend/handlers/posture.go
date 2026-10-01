package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/gorm"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Security Posture is a catalog of rules, each assessed against every cluster
// resource it applies to, in the shape of a KSPM "Security Essentials"
// standard: a rule passes when none of its resources fail, fails when any do,
// and is not relevant when the cluster has nothing it applies to.
//
// Where the pod security page answers "what can this pod do", this answers
// "how is the cluster doing against a fixed bar, and is it getting better".
// That second half is why every assessment is stored: the trend is the
// product, and a live scan cannot have one.
//
// Like the pod security scan, everything is read from declared state -- specs
// and RBAC objects -- with the checks written as pure functions over typed
// objects so they are tested against fixtures, not against a cluster.
//
// Workloads are assessed at the controller (Deployment, StatefulSet,
// DaemonSet, Job, CronJob, and bare Pods with no owner), not per replica: a
// Deployment with forty replicas is one thing to fix, and counting it forty
// times would make the resource numbers track scale instead of posture.

const (
	postureStandard = "Security Essentials"
	// postureFailedResourceCap bounds how many failing resources one rule
	// stores per assessment. The Failed count is always exact.
	postureFailedResourceCap = 200
	postureSystemPrefix      = "system:"
)

// postureExcludedNamespaces are not assessed. A KSPM product evaluates them
// too, but what runs there is installed and reconciled by the distribution:
// the user cannot change it, and a page that is permanently red over
// kube-proxy trains people to ignore it. Edit this set to include them.
//
// The same reasoning excludes, on the RBAC side (see postureRBACExcluded):
//   - Roles, ClusterRoles and bindings whose name starts with "system:";
//   - objects labelled kubernetes.io/bootstrapping=rbac-defaults, which the
//     API server recreates on every restart (cluster-admin, admin, edit,
//     view). Who is BOUND to cluster-admin is still assessed, by
//     KSE-RBAC-008, because that part the user does control;
//   - binding subjects whose name starts with "system:" (system:masters and
//     friends), and service accounts living in an excluded namespace.
var postureExcludedNamespaces = map[string]bool{
	"kube-system":     true,
	"kube-public":     true,
	"kube-node-lease": true,
}

func postureNamespaceExcluded(ns string) bool { return postureExcludedNamespaces[ns] }

func postureRBACExcluded(meta *metav1.ObjectMeta) bool {
	if strings.HasPrefix(meta.Name, postureSystemPrefix) {
		return true
	}
	if meta.Labels["kubernetes.io/bootstrapping"] == "rbac-defaults" {
		return true
	}
	return meta.Namespace != "" && postureNamespaceExcluded(meta.Namespace)
}

// ---- inventory ---------------------------------------------------------------

type postureRef struct {
	Kind      string
	Namespace string // "" for cluster-scoped resources
	Name      string
}

// PostureFailure is one failing resource as stored and returned.
type PostureFailure struct {
	Kind      string `json:"kind"`
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Detail    string `json:"detail"`
}

// postureOutcome is one resource assessed by one rule; an empty Detail means
// it passed.
type postureOutcome struct {
	Ref    postureRef
	Detail string
}

type postureWorkload struct {
	Kind      string
	Namespace string
	Name      string
	Spec      corev1.PodSpec
	// LongRunning is false for Jobs, CronJobs and run-to-completion Pods,
	// for which liveness and readiness probes mean nothing.
	LongRunning bool
}

type postureRole struct {
	Kind      string // Role | ClusterRole
	Namespace string
	Name      string
	Rules     []rbacv1.PolicyRule
}

type postureBinding struct {
	Kind      string // RoleBinding | ClusterRoleBinding
	Namespace string
	Name      string
	RoleRef   rbacv1.RoleRef
	Subjects  []rbacv1.Subject
}

type postureInventory struct {
	Workloads       []postureWorkload
	Roles           []postureRole
	Bindings        []postureBinding
	Namespaces      []string
	NetworkPolicies []networkingv1.NetworkPolicy
	ServiceAccounts map[string]*corev1.ServiceAccount // "ns/name"
}

// postureSources is everything one assessment lists from the cluster.
type postureSources struct {
	Deployments         []appsv1.Deployment
	StatefulSets        []appsv1.StatefulSet
	DaemonSets          []appsv1.DaemonSet
	Jobs                []batchv1.Job
	CronJobs            []batchv1.CronJob
	Pods                []corev1.Pod
	Roles               []rbacv1.Role
	ClusterRoles        []rbacv1.ClusterRole
	RoleBindings        []rbacv1.RoleBinding
	ClusterRoleBindings []rbacv1.ClusterRoleBinding
	Namespaces          []corev1.Namespace
	NetworkPolicies     []networkingv1.NetworkPolicy
	ServiceAccounts     []corev1.ServiceAccount
}

// buildPostureInventory reduces the raw listings to what the rules assess,
// applying the exclusions above. Pure.
func buildPostureInventory(src *postureSources) *postureInventory {
	inv := &postureInventory{ServiceAccounts: map[string]*corev1.ServiceAccount{}}
	addWorkload := func(kind string, meta *metav1.ObjectMeta, spec corev1.PodSpec, longRunning bool) {
		if postureNamespaceExcluded(meta.Namespace) {
			return
		}
		inv.Workloads = append(inv.Workloads, postureWorkload{
			Kind: kind, Namespace: meta.Namespace, Name: meta.Name, Spec: spec, LongRunning: longRunning,
		})
	}
	for i := range src.Deployments {
		d := &src.Deployments[i]
		addWorkload("Deployment", &d.ObjectMeta, d.Spec.Template.Spec, true)
	}
	for i := range src.StatefulSets {
		s := &src.StatefulSets[i]
		addWorkload("StatefulSet", &s.ObjectMeta, s.Spec.Template.Spec, true)
	}
	for i := range src.DaemonSets {
		d := &src.DaemonSets[i]
		addWorkload("DaemonSet", &d.ObjectMeta, d.Spec.Template.Spec, true)
	}
	for i := range src.CronJobs {
		cj := &src.CronJobs[i]
		addWorkload("CronJob", &cj.ObjectMeta, cj.Spec.JobTemplate.Spec.Template.Spec, false)
	}
	for i := range src.Jobs {
		j := &src.Jobs[i]
		ownedByCronJob := false
		for _, o := range j.OwnerReferences {
			if o.Kind == "CronJob" {
				ownedByCronJob = true
			}
		}
		if ownedByCronJob {
			continue // assessed once, through its CronJob
		}
		addWorkload("Job", &j.ObjectMeta, j.Spec.Template.Spec, false)
	}
	for i := range src.Pods {
		p := &src.Pods[i]
		// Anything with an owner is assessed through it (ReplicaSets through
		// their Deployment, static pods through the node that runs them).
		if len(p.OwnerReferences) > 0 {
			continue
		}
		if p.Status.Phase == corev1.PodSucceeded || p.Status.Phase == corev1.PodFailed {
			continue
		}
		rp := p.Spec.RestartPolicy
		addWorkload("Pod", &p.ObjectMeta, p.Spec, rp == "" || rp == corev1.RestartPolicyAlways)
	}

	for i := range src.ClusterRoles {
		r := &src.ClusterRoles[i]
		if postureRBACExcluded(&r.ObjectMeta) {
			continue
		}
		inv.Roles = append(inv.Roles, postureRole{Kind: "ClusterRole", Name: r.Name, Rules: r.Rules})
	}
	for i := range src.Roles {
		r := &src.Roles[i]
		if postureRBACExcluded(&r.ObjectMeta) {
			continue
		}
		inv.Roles = append(inv.Roles, postureRole{Kind: "Role", Namespace: r.Namespace, Name: r.Name, Rules: r.Rules})
	}
	for i := range src.ClusterRoleBindings {
		b := &src.ClusterRoleBindings[i]
		if postureRBACExcluded(&b.ObjectMeta) {
			continue
		}
		inv.Bindings = append(inv.Bindings, postureBinding{
			Kind: "ClusterRoleBinding", Name: b.Name, RoleRef: b.RoleRef, Subjects: b.Subjects,
		})
	}
	for i := range src.RoleBindings {
		b := &src.RoleBindings[i]
		if postureRBACExcluded(&b.ObjectMeta) {
			continue
		}
		inv.Bindings = append(inv.Bindings, postureBinding{
			Kind: "RoleBinding", Namespace: b.Namespace, Name: b.Name, RoleRef: b.RoleRef, Subjects: b.Subjects,
		})
	}

	for i := range src.Namespaces {
		ns := &src.Namespaces[i]
		if postureNamespaceExcluded(ns.Name) {
			continue
		}
		inv.Namespaces = append(inv.Namespaces, ns.Name)
	}
	for i := range src.NetworkPolicies {
		if !postureNamespaceExcluded(src.NetworkPolicies[i].Namespace) {
			inv.NetworkPolicies = append(inv.NetworkPolicies, src.NetworkPolicies[i])
		}
	}
	for i := range src.ServiceAccounts {
		sa := &src.ServiceAccounts[i]
		if postureNamespaceExcluded(sa.Namespace) {
			continue
		}
		inv.ServiceAccounts[sa.Namespace+"/"+sa.Name] = sa
	}
	return inv
}

// ---- rule helpers --------------------------------------------------------------

type postureRule struct {
	ID          string
	Title       string
	Severity    string // critical | high | medium | low
	Category    string
	Description string
	Remediation string
	Check       func(inv *postureInventory) []postureOutcome
}

func postureWorkloadRef(w *postureWorkload) postureRef {
	return postureRef{Kind: w.Kind, Namespace: w.Namespace, Name: w.Name}
}

func workloadRule(check func(w *postureWorkload, inv *postureInventory) string) func(*postureInventory) []postureOutcome {
	return func(inv *postureInventory) []postureOutcome {
		out := make([]postureOutcome, 0, len(inv.Workloads))
		for i := range inv.Workloads {
			w := &inv.Workloads[i]
			out = append(out, postureOutcome{Ref: postureWorkloadRef(w), Detail: check(w, inv)})
		}
		return out
	}
}

// longRunningRule only assesses workloads that are meant to keep running.
func longRunningRule(check func(w *postureWorkload) string) func(*postureInventory) []postureOutcome {
	return func(inv *postureInventory) []postureOutcome {
		out := []postureOutcome{}
		for i := range inv.Workloads {
			w := &inv.Workloads[i]
			if w.LongRunning {
				out = append(out, postureOutcome{Ref: postureWorkloadRef(w), Detail: check(w)})
			}
		}
		return out
	}
}

func roleRule(check func(r *postureRole) string) func(*postureInventory) []postureOutcome {
	return func(inv *postureInventory) []postureOutcome {
		out := make([]postureOutcome, 0, len(inv.Roles))
		for i := range inv.Roles {
			r := &inv.Roles[i]
			out = append(out, postureOutcome{
				Ref:    postureRef{Kind: r.Kind, Namespace: r.Namespace, Name: r.Name},
				Detail: check(r),
			})
		}
		return out
	}
}

func bindingRule(check func(b *postureBinding) string) func(*postureInventory) []postureOutcome {
	return func(inv *postureInventory) []postureOutcome {
		out := make([]postureOutcome, 0, len(inv.Bindings))
		for i := range inv.Bindings {
			b := &inv.Bindings[i]
			out = append(out, postureOutcome{
				Ref:    postureRef{Kind: b.Kind, Namespace: b.Namespace, Name: b.Name},
				Detail: check(b),
			})
		}
		return out
	}
}

// Namespaces are cluster-scoped objects, but each one is recorded under its
// own name as the namespace so that a scoped user sees the namespaces they
// were given and nothing else.
func namespaceRule(check func(ns string, inv *postureInventory) string) func(*postureInventory) []postureOutcome {
	return func(inv *postureInventory) []postureOutcome {
		out := make([]postureOutcome, 0, len(inv.Namespaces))
		for _, ns := range inv.Namespaces {
			out = append(out, postureOutcome{
				Ref:    postureRef{Kind: "Namespace", Namespace: ns, Name: ns},
				Detail: check(ns, inv),
			})
		}
		return out
	}
}

// eachContainer runs f over the containers of a pod spec and joins the
// failures, prefixed with the container name.
func eachContainer(spec *corev1.PodSpec, withInit bool, f func(c *corev1.Container) string) string {
	var parts []string
	visit := func(cs []corev1.Container) {
		for i := range cs {
			if d := f(&cs[i]); d != "" {
				parts = append(parts, fmt.Sprintf("%s: %s", cs[i].Name, d))
			}
		}
	}
	if withInit {
		visit(spec.InitContainers)
	}
	visit(spec.Containers)
	return strings.Join(parts, "; ")
}

func containsFold(list []string, want string) bool {
	for _, v := range list {
		if strings.EqualFold(v, want) {
			return true
		}
	}
	return false
}

func containsStr(list []string, want string) bool {
	for _, v := range list {
		if v == want {
			return true
		}
	}
	return false
}

// policyRuleGrants reports which of verbs a PolicyRule grants on any of the
// given group/resource pairs, honouring "*" in every position.
//
// A rule limited by resourceNames grants access to named objects only --
// which is precisely the remediation these rules recommend -- so it is not
// counted. (create and list cannot be narrowed that way at all.)
func policyRuleGrants(r *rbacv1.PolicyRule, groups, resources, verbs []string) []string {
	if len(r.ResourceNames) > 0 || len(r.Resources) == 0 {
		return nil
	}
	groupOK := containsStr(r.APIGroups, "*")
	for _, g := range groups {
		if containsStr(r.APIGroups, g) {
			groupOK = true
		}
	}
	if !groupOK {
		return nil
	}
	resOK := containsStr(r.Resources, "*")
	for _, res := range resources {
		if containsStr(r.Resources, res) {
			resOK = true
		}
	}
	if !resOK {
		return nil
	}
	if containsStr(r.Verbs, "*") {
		return []string{"*"}
	}
	var out []string
	for _, v := range verbs {
		if containsStr(r.Verbs, v) {
			out = append(out, v)
		}
	}
	return out
}

// roleGrants is policyRuleGrants over every rule of a role, as a detail
// string: "" when nothing matched.
func roleGrants(role *postureRole, groups, resources, verbs []string, what string) string {
	seen := map[string]bool{}
	var got []string
	for i := range role.Rules {
		for _, v := range policyRuleGrants(&role.Rules[i], groups, resources, verbs) {
			if !seen[v] {
				seen[v] = true
				got = append(got, v)
			}
		}
	}
	if len(got) == 0 {
		return ""
	}
	sort.Strings(got)
	return fmt.Sprintf("grants %s on %s", strings.Join(got, ", "), what)
}

func joinDetails(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "; ")
}

func subjectLabel(s rbacv1.Subject) string {
	if s.Kind == "ServiceAccount" {
		return fmt.Sprintf("ServiceAccount %s/%s", s.Namespace, s.Name)
	}
	return s.Kind + " " + s.Name
}

// postureSubjectExcluded mirrors the object exclusions for binding subjects.
func postureSubjectExcluded(s rbacv1.Subject) bool {
	if strings.HasPrefix(s.Name, postureSystemPrefix) {
		return true
	}
	return s.Kind == "ServiceAccount" && postureNamespaceExcluded(s.Namespace)
}

// ---- container helpers -------------------------------------------------------

func effectiveRunAsNonRoot(pod *corev1.PodSecurityContext, sc *corev1.SecurityContext) (nonRoot *bool, uid *int64) {
	if pod != nil {
		nonRoot, uid = pod.RunAsNonRoot, pod.RunAsUser
	}
	if sc != nil {
		if sc.RunAsNonRoot != nil {
			nonRoot = sc.RunAsNonRoot
		}
		if sc.RunAsUser != nil {
			uid = sc.RunAsUser
		}
	}
	return nonRoot, uid
}

func effectiveSeccomp(pod *corev1.PodSecurityContext, sc *corev1.SecurityContext) *corev1.SeccompProfile {
	if sc != nil && sc.SeccompProfile != nil {
		return sc.SeccompProfile
	}
	if pod != nil {
		return pod.SeccompProfile
	}
	return nil
}

// imageUnpinned is true for ":latest" and for an image with no tag at all.
// A digest pins it regardless of the tag. A registry port ("host:5000/app")
// is not a tag, which is why only the last path segment is read.
func imageUnpinned(image string) bool {
	if strings.Contains(image, "@") {
		return false
	}
	last := image[strings.LastIndex(image, "/")+1:]
	i := strings.LastIndex(last, ":")
	if i < 0 {
		return true
	}
	return last[i+1:] == "latest"
}

// sensitiveHostPath says whether mounting p exposes one of the paths in
// sensitiveHostPaths: the path itself, something beneath it, or a parent of
// it (mounting /var/run hands over /var/run/docker.sock just the same).
func sensitiveHostPath(p string) (string, bool) {
	clean := path.Clean("/" + p)
	if why, ok := sensitiveHostPaths[clean]; ok {
		return why, true
	}
	for s, why := range sensitiveHostPaths {
		if s == "/" {
			continue
		}
		if strings.HasPrefix(clean, s+"/") || strings.HasPrefix(s, clean+"/") {
			return why, true
		}
	}
	return "", false
}

// automountsToken resolves whether a pod gets an API token: the pod's own
// field wins, then its service account's, and the default is yes.
func automountsToken(w *postureWorkload, inv *postureInventory) bool {
	if w.Spec.AutomountServiceAccountToken != nil {
		return *w.Spec.AutomountServiceAccountToken
	}
	name := w.Spec.ServiceAccountName
	if name == "" {
		name = "default"
	}
	if sa, ok := inv.ServiceAccounts[w.Namespace+"/"+name]; ok && sa.AutomountServiceAccountToken != nil {
		return *sa.AutomountServiceAccountToken
	}
	return true
}

func isDefaultDenyIngress(np *networkingv1.NetworkPolicy) bool {
	if len(np.Spec.PodSelector.MatchLabels) > 0 || len(np.Spec.PodSelector.MatchExpressions) > 0 {
		return false
	}
	ingressType := len(np.Spec.PolicyTypes) == 0 // no policyTypes implies Ingress
	for _, t := range np.Spec.PolicyTypes {
		if t == networkingv1.PolicyTypeIngress {
			ingressType = true
		}
	}
	return ingressType && len(np.Spec.Ingress) == 0
}

// ---- the catalog -----------------------------------------------------------------

var (
	rbacGroup      = []string{"rbac.authorization.k8s.io"}
	coreGroup      = []string{""}
	writeVerbs     = []string{"create", "update", "patch", "delete", "deletecollection"}
	readSecretVerb = []string{"get", "list", "watch"}
)

var postureCatalog = []postureRule{
	// ---- RBAC, critical ------------------------------------------------------
	{
		ID: "KSE-RBAC-001", Severity: "critical", Category: "RBAC",
		Title:       "Roles and ClusterRoles should limit access to secrets",
		Description: "Reading Secrets yields every credential stored in them: database passwords, API keys, TLS keys and, through service account token Secrets, the identities of other workloads. list and watch return the full contents of every Secret in scope, not just their names.",
		Remediation: "Remove get, list and watch on secrets from the role, or narrow the rule with resourceNames to the specific Secrets the workload needs. Prefer mounting Secrets into the pod over reading them through the API.",
		Check: roleRule(func(r *postureRole) string {
			return roleGrants(r, coreGroup, []string{"secrets"}, readSecretVerb, "secrets")
		}),
	},
	{
		ID: "KSE-RBAC-002", Severity: "critical", Category: "RBAC",
		Title:       "Roles and ClusterRoles should limit the impersonate, bind and escalate verbs",
		Description: "impersonate lets a subject act as any user, group or service account. bind and escalate let it grant itself, or create, roles with permissions it does not hold. Each one is a direct path to cluster-admin.",
		Remediation: "Remove impersonate, bind and escalate from the role. If a controller genuinely needs them, restrict the rule with resourceNames to the exact roles or identities involved and bind it to that controller alone.",
		Check: roleRule(func(r *postureRole) string {
			return joinDetails(
				roleGrants(r, []string{"", "authentication.k8s.io"},
					[]string{"users", "groups", "serviceaccounts", "uids", "userextras/scopes"},
					[]string{"impersonate"}, "users/groups/serviceaccounts"),
				roleGrants(r, rbacGroup, []string{"roles", "clusterroles"},
					[]string{"bind", "escalate"}, "roles/clusterroles"),
			)
		}),
	},
	{
		ID: "KSE-RBAC-003", Severity: "critical", Category: "RBAC",
		Title:       "Roles and ClusterRoles should limit node proxy access",
		Description: "nodes/proxy reaches the kubelet API directly. Through it a subject can run commands in any container on the node, bypassing admission control and most audit logging.",
		Remediation: "Remove nodes/proxy from the role. Monitoring agents that need kubelet metrics can usually use nodes/metrics or nodes/stats instead.",
		Check: roleRule(func(r *postureRole) string {
			return roleGrants(r, coreGroup, []string{"nodes/proxy"},
				[]string{"get", "list", "watch", "create", "update", "patch", "delete"}, "nodes/proxy")
		}),
	},
	{
		ID: "KSE-RBAC-004", Severity: "critical", Category: "RBAC",
		Title:       "Roles and ClusterRoles should limit certificate approval",
		Description: "A subject that can both update certificatesigningrequests/approval and approve for a signer can issue itself a client certificate for any identity -- including system:masters, which no RBAC rule can restrict.",
		Remediation: "Remove update/patch on certificatesigningrequests/approval or approve on signers. Where approval is automated, restrict the signers rule with resourceNames to the specific signer.",
		Check: roleRule(func(r *postureRole) string {
			approval := roleGrants(r, []string{"certificates.k8s.io"}, []string{"certificatesigningrequests/approval"},
				[]string{"update", "patch"}, "certificatesigningrequests/approval")
			signers := roleGrants(r, []string{"certificates.k8s.io"}, []string{"signers"},
				[]string{"approve"}, "signers")
			if approval == "" || signers == "" {
				return ""
			}
			return joinDetails(approval, signers)
		}),
	},
	{
		ID: "KSE-RBAC-005", Severity: "critical", Category: "RBAC",
		Title:       "Roles and ClusterRoles should limit webhook configuration permissions",
		Description: "A mutating webhook sees, and can rewrite, every object it is registered for -- including Secrets and pod specs -- and a validating one can block them. Whoever can edit webhook configurations controls what the cluster admits.",
		Remediation: "Remove create, update, patch and delete on mutatingwebhookconfigurations and validatingwebhookconfigurations from every role except the controllers that own those webhooks, and restrict those with resourceNames.",
		Check: roleRule(func(r *postureRole) string {
			return roleGrants(r, []string{"admissionregistration.k8s.io"},
				[]string{"mutatingwebhookconfigurations", "validatingwebhookconfigurations"},
				writeVerbs, "webhook configurations")
		}),
	},

	// ---- RBAC, high / medium -------------------------------------------------
	{
		ID: "KSE-RBAC-006", Severity: "high", Category: "RBAC",
		Title:       "Roles and ClusterRoles should limit pod creation permissions",
		Description: "Creating a pod -- directly or through a Deployment, Job or any other controller -- means choosing its service account, its volumes and its security context. In practice that is access to every Secret and service account in the namespace, and with a permissive admission policy, to the node.",
		Remediation: "Grant create on pods and workload controllers only to deployment pipelines and the controllers that need it. Enforce Pod Security Admission (restricted or baseline) on namespaces where people can create pods.",
		Check: roleRule(func(r *postureRole) string {
			return joinDetails(
				roleGrants(r, coreGroup, []string{"pods", "replicationcontrollers"}, []string{"create"}, "pods/replicationcontrollers"),
				roleGrants(r, []string{"apps"}, []string{"deployments", "statefulsets", "daemonsets", "replicasets"}, []string{"create"}, "apps workloads"),
				roleGrants(r, []string{"batch"}, []string{"jobs", "cronjobs"}, []string{"create"}, "jobs/cronjobs"),
			)
		}),
	},
	{
		ID: "KSE-RBAC-007", Severity: "medium", Category: "RBAC",
		Title:       "Roles and ClusterRoles should not use wildcards for verbs or resources",
		Description: "A wildcard grants everything that exists today and everything installed tomorrow: a new CRD, a new subresource or a new verb is covered without anyone deciding it should be.",
		Remediation: "Replace \"*\" with the explicit verbs and resources the subject needs.",
		Check: roleRule(func(r *postureRole) string {
			var parts []string
			for _, rule := range r.Rules {
				if len(rule.Resources) == 0 {
					continue // non-resource URLs
				}
				if containsStr(rule.Verbs, "*") {
					parts = append(parts, "verbs: * on "+strings.Join(rule.Resources, ", "))
				} else if containsStr(rule.Resources, "*") {
					parts = append(parts, "resources: * for "+strings.Join(rule.Verbs, ", "))
				}
			}
			return strings.Join(parts, "; ")
		}),
	},
	{
		ID: "KSE-RBAC-008", Severity: "high", Category: "RBAC",
		Title:       "cluster-admin should not be bound to non-system subjects",
		Description: "cluster-admin is unrestricted access to every resource in every namespace. Any user, group or service account bound to it is one leaked credential away from full cluster compromise.",
		Remediation: "Bind subjects to roles scoped to what they do. Reserve cluster-admin for break-glass access and remove standing bindings.",
		Check: bindingRule(func(b *postureBinding) string {
			if b.RoleRef.Kind != "ClusterRole" || b.RoleRef.Name != "cluster-admin" {
				return ""
			}
			var subjects []string
			for _, s := range b.Subjects {
				if !postureSubjectExcluded(s) {
					subjects = append(subjects, subjectLabel(s))
				}
			}
			if len(subjects) == 0 {
				return ""
			}
			return "binds cluster-admin to " + strings.Join(subjects, ", ")
		}),
	},
	{
		ID: "KSE-RBAC-009", Severity: "high", Category: "RBAC",
		Title:       "Bindings should not grant roles to anonymous or all authenticated users",
		Description: "system:anonymous and system:unauthenticated cover any request without credentials; system:authenticated covers every user and every service account in the cluster. A role bound to them is a role granted to everyone.",
		Remediation: "Bind the role to the specific users, groups or service accounts that need it.",
		Check: bindingRule(func(b *postureBinding) string {
			var hits []string
			for _, s := range b.Subjects {
				switch {
				case s.Kind == "Group" && (s.Name == "system:anonymous" || s.Name == "system:unauthenticated" || s.Name == "system:authenticated"):
					hits = append(hits, s.Name)
				case s.Kind == "User" && s.Name == "system:anonymous":
					hits = append(hits, s.Name)
				}
			}
			if len(hits) == 0 {
				return ""
			}
			return fmt.Sprintf("binds %s %s to %s", b.RoleRef.Kind, b.RoleRef.Name, strings.Join(hits, ", "))
		}),
	},

	// ---- Workloads, high -----------------------------------------------------
	{
		ID: "KSE-WL-001", Severity: "high", Category: "Workloads",
		Title:       "Workloads should not run privileged containers",
		Description: "A privileged container has every Linux capability and access to every host device. It is root on the node with extra steps.",
		Remediation: "Set securityContext.privileged: false (or remove it) and add only the specific capabilities the container needs.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
					return "privileged: true"
				}
				return ""
			})
		}),
	},
	{
		ID: "KSE-WL-002", Severity: "high", Category: "Workloads",
		Title:       "Workloads should not use the host network",
		Description: "With hostNetwork the pod shares the node's network namespace: it can bind the node's ports, sniff its traffic and reach anything the node can, and NetworkPolicy does not apply to it.",
		Remediation: "Remove hostNetwork: true. Expose the workload through a Service, or a hostPort if it really must be on the node's address.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			if w.Spec.HostNetwork {
				return "hostNetwork: true"
			}
			return ""
		}),
	},
	{
		ID: "KSE-WL-003", Severity: "high", Category: "Workloads",
		Title:       "Workloads should not allow privilege escalation",
		Description: "Unless allowPrivilegeEscalation is explicitly false, a process can gain more privileges than its parent through setuid binaries or file capabilities, which defeats running as a non-root user. The Kubernetes default is to allow it.",
		Remediation: "Set securityContext.allowPrivilegeEscalation: false on every container.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				sc := c.SecurityContext
				if sc == nil || sc.AllowPrivilegeEscalation == nil {
					return "allowPrivilegeEscalation not set (defaults to true)"
				}
				if *sc.AllowPrivilegeEscalation {
					return "allowPrivilegeEscalation: true"
				}
				return ""
			})
		}),
	},
	{
		ID: "KSE-WL-004", Severity: "high", Category: "Workloads",
		Title:       "Workloads should not share the host PID namespace",
		Description: "With hostPID the pod sees and can signal every process on the node, read their environment through /proc, and with ptrace, their memory.",
		Remediation: "Remove hostPID: true.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			if w.Spec.HostPID {
				return "hostPID: true"
			}
			return ""
		}),
	},
	{
		ID: "KSE-WL-005", Severity: "high", Category: "Workloads",
		Title:       "Workloads should not share the host IPC namespace",
		Description: "With hostIPC the pod shares shared-memory segments and semaphores with the node and every other process using them.",
		Remediation: "Remove hostIPC: true.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			if w.Spec.HostIPC {
				return "hostIPC: true"
			}
			return ""
		}),
	},
	{
		ID: "KSE-WL-006", Severity: "high", Category: "Workloads",
		Title:       "Workloads should not mount sensitive host paths",
		Description: "Mounting the node's root, /etc, /proc, the kubelet directory or the container runtime socket hands the pod the node: its credentials, its processes, or the ability to start any container it likes.",
		Remediation: "Remove the hostPath volume. Use a PersistentVolume, a ConfigMap or a projected volume for data, and a purpose-built API (CSI, device plugin) for node integration.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			var parts []string
			for _, v := range w.Spec.Volumes {
				if v.HostPath == nil {
					continue
				}
				if why, ok := sensitiveHostPath(v.HostPath.Path); ok {
					parts = append(parts, fmt.Sprintf("volume %s mounts %s (%s)", v.Name, v.HostPath.Path, why))
				}
			}
			return strings.Join(parts, "; ")
		}),
	},
	{
		ID: "KSE-WL-007", Severity: "high", Category: "Workloads",
		Title:       "Workloads should not add dangerous capabilities",
		Description: "Capabilities such as SYS_ADMIN, SYS_PTRACE, SYS_MODULE and NET_ADMIN each give a container a way out of its isolation; adding ALL is the same as running privileged.",
		Remediation: "Remove the capability from securityContext.capabilities.add. If something narrower would do (NET_BIND_SERVICE for a low port), add that instead.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
					return ""
				}
				var caps []string
				for _, capability := range c.SecurityContext.Capabilities.Add {
					name := strings.TrimPrefix(strings.ToUpper(string(capability)), "CAP_")
					if _, bad := dangerousCapabilities[corev1.Capability(name)]; bad || name == "ALL" {
						caps = append(caps, name)
					}
				}
				if len(caps) == 0 {
					return ""
				}
				return "adds " + strings.Join(caps, ", ")
			})
		}),
	},
	{
		ID: "KSE-SEC-001", Severity: "high", Category: "Secrets",
		Title:       "Workloads should mount secrets as files instead of environment variables",
		Description: "Environment variables are visible in kubectl describe, inherited by every child process, written into crash dumps and printed by any library that logs its environment. They also cannot be rotated without restarting the pod.",
		Remediation: "Mount the Secret as a volume and read the value from the file. Replace env[].valueFrom.secretKeyRef and envFrom[].secretRef.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				var refs []string
				for _, e := range c.Env {
					if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil {
						refs = append(refs, fmt.Sprintf("%s from %s", e.Name, e.ValueFrom.SecretKeyRef.Name))
					}
				}
				for _, ef := range c.EnvFrom {
					if ef.SecretRef != nil {
						refs = append(refs, "envFrom "+ef.SecretRef.Name)
					}
				}
				return strings.Join(refs, ", ")
			})
		}),
	},

	// ---- Workloads, medium ---------------------------------------------------
	{
		ID: "KSE-WL-008", Severity: "medium", Category: "Workloads",
		Title:       "Workloads should not mount host paths",
		Description: "Anything written to a hostPath outlives the pod, is visible to the node and to every other pod mounting the same path, and ties the workload to one node.",
		Remediation: "Use emptyDir for scratch space and a PersistentVolume for data that must survive the pod.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			var parts []string
			for _, v := range w.Spec.Volumes {
				if v.HostPath != nil {
					parts = append(parts, fmt.Sprintf("volume %s mounts %s", v.Name, v.HostPath.Path))
				}
			}
			return strings.Join(parts, "; ")
		}),
	},
	{
		ID: "KSE-WL-009", Severity: "medium", Category: "Workloads",
		Title:       "Workloads should drop all capabilities",
		Description: "Container runtimes grant a default set of capabilities (NET_RAW, CHOWN, SETUID and more) that almost no application needs. Dropping them all and adding back what is required removes a whole class of escalation.",
		Remediation: "Set securityContext.capabilities.drop: [\"ALL\"] and add back only what the container needs.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				if c.SecurityContext != nil && c.SecurityContext.Capabilities != nil {
					for _, d := range c.SecurityContext.Capabilities.Drop {
						if strings.EqualFold(string(d), "ALL") {
							return ""
						}
					}
				}
				return "does not drop ALL"
			})
		}),
	},
	{
		ID: "KSE-WL-010", Severity: "medium", Category: "Workloads",
		Title:       "Workloads should not run as root",
		Description: "Without runAsNonRoot or a non-zero runAsUser, the container runs as whatever the image says, which is usually uid 0. Root inside the container is root on the node the moment anything else goes wrong.",
		Remediation: "Set securityContext.runAsNonRoot: true and a non-zero runAsUser at the pod or container level, and build the image to run as an unprivileged user.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				nonRoot, uid := effectiveRunAsNonRoot(w.Spec.SecurityContext, c.SecurityContext)
				if uid != nil && *uid == 0 {
					return "runAsUser: 0"
				}
				if nonRoot != nil && *nonRoot {
					return ""
				}
				if uid != nil && *uid > 0 {
					return ""
				}
				return "neither runAsNonRoot: true nor a non-zero runAsUser is set"
			})
		}),
	},
	{
		ID: "KSE-WL-011", Severity: "medium", Category: "Workloads",
		Title:       "Workloads should use a read-only root filesystem",
		Description: "A writable root filesystem lets anything that gains execution drop tools and binaries into the container and persist them for its lifetime.",
		Remediation: "Set securityContext.readOnlyRootFilesystem: true and mount an emptyDir for the directories the application writes to (/tmp, caches).",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				if c.SecurityContext != nil && c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem {
					return ""
				}
				return "readOnlyRootFilesystem not true"
			})
		}),
	},
	{
		ID: "KSE-WL-012", Severity: "medium", Category: "Workloads",
		Title:       "Workloads should set CPU and memory limits",
		Description: "A container without limits can consume the whole node, starving its neighbours or getting them evicted. One compromised or runaway pod becomes a node-wide outage.",
		Remediation: "Set resources.limits.cpu and resources.limits.memory on every container, or a LimitRange on the namespace that applies defaults.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, false, func(c *corev1.Container) string {
				var missing []string
				if _, ok := c.Resources.Limits[corev1.ResourceCPU]; !ok {
					missing = append(missing, "cpu")
				}
				if _, ok := c.Resources.Limits[corev1.ResourceMemory]; !ok {
					missing = append(missing, "memory")
				}
				if len(missing) == 0 {
					return ""
				}
				return "no " + strings.Join(missing, "/") + " limit"
			})
		}),
	},
	{
		ID: "KSE-WL-013", Severity: "medium", Category: "Workloads",
		Title:       "Workloads should use a seccomp profile",
		Description: "Without a seccomp profile a container can make every system call the kernel offers, including the rarely used ones behind most container escapes. RuntimeDefault blocks those at no cost to normal applications.",
		Remediation: "Set securityContext.seccompProfile.type: RuntimeDefault at the pod level (or Localhost with a custom profile).",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				p := effectiveSeccomp(w.Spec.SecurityContext, c.SecurityContext)
				if p != nil && (p.Type == corev1.SeccompProfileTypeRuntimeDefault || p.Type == corev1.SeccompProfileTypeLocalhost) {
					return ""
				}
				if p != nil {
					return "seccompProfile: " + string(p.Type)
				}
				return "no seccompProfile"
			})
		}),
	},
	{
		ID: "KSE-WL-014", Severity: "medium", Category: "Workloads",
		Title:       "Container images should use a fixed tag",
		Description: "An image with :latest or no tag resolves to whatever the tag points at when the node pulls it, so the image that was reviewed and scanned and the image that is running can differ -- and two replicas can run different code.",
		Remediation: "Reference images by an immutable version tag, or better, by digest (image@sha256:...).",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				if imageUnpinned(c.Image) {
					return c.Image
				}
				return ""
			})
		}),
	},
	{
		ID: "KSE-WL-015", Severity: "medium", Category: "Workloads",
		Title:       "Workloads should not use host ports",
		Description: "A hostPort binds the container to a port on the node's address, bypassing Services and exposing the workload to anything that can reach the node.",
		Remediation: "Remove hostPort and expose the workload through a Service.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, true, func(c *corev1.Container) string {
				var ports []string
				for _, p := range c.Ports {
					if p.HostPort != 0 {
						ports = append(ports, strconv.Itoa(int(p.HostPort)))
					}
				}
				if len(ports) == 0 {
					return ""
				}
				return "hostPort " + strings.Join(ports, ", ")
			})
		}),
	},

	// ---- Workloads, low ------------------------------------------------------
	{
		ID: "KSE-WL-016", Severity: "low", Category: "Workloads",
		Title:       "Workloads should not automount service account tokens",
		Description: "Every pod gets an API token by default, whether or not it ever talks to Kubernetes. A compromised container then holds credentials it never needed.",
		Remediation: "Set automountServiceAccountToken: false on the pod spec (or on its service account) unless the workload calls the Kubernetes API.",
		Check: workloadRule(func(w *postureWorkload, inv *postureInventory) string {
			if automountsToken(w, inv) {
				return "service account token is mounted"
			}
			return ""
		}),
	},
	{
		ID: "KSE-WL-017", Severity: "low", Category: "Workloads",
		Title:       "Workloads should not run in the default namespace",
		Description: "The default namespace is where everything lands when nobody chose a namespace. Policies, quotas and RBAC are rarely configured for it, and workloads there share it with whatever else was applied without one.",
		Remediation: "Move the workload into a namespace of its own, with its own RBAC, NetworkPolicies and quotas.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			if w.Namespace == "default" {
				return "runs in namespace default"
			}
			return ""
		}),
	},
	{
		ID: "KSE-WL-018", Severity: "low", Category: "Workloads",
		Title:       "Workloads should not use the default service account",
		Description: "Every pod in the namespace that does not choose otherwise shares the default service account, so any permission granted to it is granted to all of them.",
		Remediation: "Create a dedicated service account per workload and set serviceAccountName.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			if w.Spec.ServiceAccountName == "" || w.Spec.ServiceAccountName == "default" {
				return "uses service account default"
			}
			return ""
		}),
	},
	{
		ID: "KSE-WL-019", Severity: "low", Category: "Workloads",
		Title:       "Workloads should set CPU and memory requests",
		Description: "Without requests the scheduler cannot place the pod sensibly and it is first in line for eviction under pressure.",
		Remediation: "Set resources.requests.cpu and resources.requests.memory on every container.",
		Check: workloadRule(func(w *postureWorkload, _ *postureInventory) string {
			return eachContainer(&w.Spec, false, func(c *corev1.Container) string {
				var missing []string
				if _, ok := c.Resources.Requests[corev1.ResourceCPU]; !ok {
					missing = append(missing, "cpu")
				}
				if _, ok := c.Resources.Requests[corev1.ResourceMemory]; !ok {
					missing = append(missing, "memory")
				}
				if len(missing) == 0 {
					return ""
				}
				return "no " + strings.Join(missing, "/") + " request"
			})
		}),
	},
	{
		ID: "KSE-WL-020", Severity: "low", Category: "Workloads",
		Title:       "Long-running workloads should define a liveness probe",
		Description: "Without a liveness probe a container that has hung but not exited keeps its slot forever, and nothing restarts it.",
		Remediation: "Add a livenessProbe to every long-running container.",
		Check: longRunningRule(func(w *postureWorkload) string {
			return eachContainer(&w.Spec, false, func(c *corev1.Container) string {
				if c.LivenessProbe == nil {
					return "no livenessProbe"
				}
				return ""
			})
		}),
	},
	{
		ID: "KSE-WL-021", Severity: "low", Category: "Workloads",
		Title:       "Long-running workloads should define a readiness probe",
		Description: "Without a readiness probe traffic is sent to a container the moment it starts, and keeps being sent to it while it is unable to serve.",
		Remediation: "Add a readinessProbe to every long-running container that serves traffic.",
		Check: longRunningRule(func(w *postureWorkload) string {
			return eachContainer(&w.Spec, false, func(c *corev1.Container) string {
				if c.ReadinessProbe == nil {
					return "no readinessProbe"
				}
				return ""
			})
		}),
	},
	{
		ID: "KSE-SA-001", Severity: "low", Category: "Service accounts",
		Title:       "Default service accounts should not automount API tokens",
		Description: "The default service account is used by every pod that does not name another one. Turning off its token automount makes \"no API access\" the default for the namespace.",
		Remediation: "Set automountServiceAccountToken: false on the default ServiceAccount of each namespace; workloads that need a token opt in explicitly.",
		Check: func(inv *postureInventory) []postureOutcome {
			out := []postureOutcome{}
			keys := make([]string, 0, len(inv.ServiceAccounts))
			for k, sa := range inv.ServiceAccounts {
				if sa.Name == "default" {
					keys = append(keys, k)
				}
			}
			sort.Strings(keys)
			for _, k := range keys {
				sa := inv.ServiceAccounts[k]
				detail := ""
				if sa.AutomountServiceAccountToken == nil || *sa.AutomountServiceAccountToken {
					detail = "automountServiceAccountToken is not false"
				}
				out = append(out, postureOutcome{
					Ref:    postureRef{Kind: "ServiceAccount", Namespace: sa.Namespace, Name: sa.Name},
					Detail: detail,
				})
			}
			return out
		},
	},

	// ---- Network -------------------------------------------------------------
	{
		ID: "KSE-NET-001", Severity: "medium", Category: "Network",
		Title:       "Namespaces should have a NetworkPolicy",
		Description: "Without any NetworkPolicy every pod in the namespace accepts traffic from every pod in the cluster, and can reach any of them. A single compromised pod anywhere can talk to everything here.",
		Remediation: "Add NetworkPolicies to the namespace, starting with a default-deny policy and allowing the flows the workloads actually need.",
		Check: namespaceRule(func(ns string, inv *postureInventory) string {
			for i := range inv.NetworkPolicies {
				if inv.NetworkPolicies[i].Namespace == ns {
					return ""
				}
			}
			return "no NetworkPolicy in the namespace"
		}),
	},
	{
		ID: "KSE-NET-002", Severity: "low", Category: "Network",
		Title:       "Namespaces should have a default-deny ingress policy",
		Description: "Policies that only allow specific flows still leave every pod they do not select open. A default-deny policy makes new workloads closed until someone opens them deliberately.",
		Remediation: "Add a NetworkPolicy with an empty podSelector, policyTypes: [Ingress] and no ingress rules.",
		Check: namespaceRule(func(ns string, inv *postureInventory) string {
			for i := range inv.NetworkPolicies {
				np := &inv.NetworkPolicies[i]
				if np.Namespace == ns && isDefaultDenyIngress(np) {
					return ""
				}
			}
			return "no default-deny ingress policy"
		}),
	},
}

var postureRuleByID = func() map[string]*postureRule {
	m := map[string]*postureRule{}
	for i := range postureCatalog {
		m[postureCatalog[i].ID] = &postureCatalog[i]
	}
	return m
}()

// ---- evaluation -----------------------------------------------------------------

var postureSeverityRank = map[string]int{"critical": 0, "high": 1, "medium": 2, "low": 3}

// postureResult is a rule outcome in decoded form, the shape every summary
// and scope computation works on.
type postureResult struct {
	RuleID          string
	Severity        string
	Category        string
	Result          string
	Failed, Passed  int
	Failures        []PostureFailure
	Truncated       bool
	NamespaceCounts map[string][2]int // ns -> [failed, passed]
}

// evaluatePosture runs the catalog over an inventory. Pure.
func evaluatePosture(inv *postureInventory, catalog []postureRule) ([]postureResult, map[string][2]int) {
	type resState struct {
		ns     string
		failed bool
	}
	resources := map[postureRef]*resState{}
	results := make([]postureResult, 0, len(catalog))

	for i := range catalog {
		rule := &catalog[i]
		r := postureResult{
			RuleID: rule.ID, Severity: rule.Severity, Category: rule.Category,
			NamespaceCounts: map[string][2]int{},
		}
		for _, o := range rule.Check(inv) {
			st := resources[o.Ref]
			if st == nil {
				st = &resState{ns: o.Ref.Namespace}
				resources[o.Ref] = st
			}
			counts := r.NamespaceCounts[o.Ref.Namespace]
			if o.Detail != "" {
				r.Failed++
				counts[0]++
				st.failed = true
				r.Failures = append(r.Failures, PostureFailure{
					Kind: o.Ref.Kind, Namespace: o.Ref.Namespace, Name: o.Ref.Name, Detail: o.Detail,
				})
			} else {
				r.Passed++
				counts[1]++
			}
			r.NamespaceCounts[o.Ref.Namespace] = counts
		}
		sort.SliceStable(r.Failures, func(a, b int) bool {
			fa, fb := r.Failures[a], r.Failures[b]
			if fa.Namespace != fb.Namespace {
				return fa.Namespace < fb.Namespace
			}
			if fa.Kind != fb.Kind {
				return fa.Kind < fb.Kind
			}
			return fa.Name < fb.Name
		})
		if len(r.Failures) > postureFailedResourceCap {
			r.Failures = r.Failures[:postureFailedResourceCap]
			r.Truncated = true
		}
		r.Result = postureResultOf(r.Failed, r.Passed)
		results = append(results, r)
	}

	nsResources := map[string][2]int{}
	for _, st := range resources {
		c := nsResources[st.ns]
		if st.failed {
			c[0]++
		}
		c[1]++
		nsResources[st.ns] = c
	}
	return results, nsResources
}

func postureResultOf(failed, passed int) string {
	switch {
	case failed > 0:
		return "failed"
	case passed > 0:
		return "passed"
	default:
		return "not_relevant"
	}
}

// summarizePosture fills the summary fields of an assessment from its rule
// results. The same function serves the stored, cluster-wide numbers and the
// recomputed, scoped ones, so the two can never be calculated differently.
func summarizePosture(a *models.PostureAssessment, results []postureResult, nsResources map[string][2]int) {
	a.RulesPassed, a.RulesFailed, a.RulesNotRelevant = 0, 0, 0
	a.FailedCritical, a.FailedHigh, a.FailedMedium, a.FailedLow = 0, 0, 0, 0
	for _, r := range results {
		switch r.Result {
		case "passed":
			a.RulesPassed++
		case "failed":
			a.RulesFailed++
			switch r.Severity {
			case "critical":
				a.FailedCritical++
			case "high":
				a.FailedHigh++
			case "medium":
				a.FailedMedium++
			case "low":
				a.FailedLow++
			}
		default:
			a.RulesNotRelevant++
		}
	}
	a.RulesAssessed = a.RulesPassed + a.RulesFailed
	a.Score = 0
	if a.RulesAssessed > 0 {
		a.Score = float64(a.RulesPassed) / float64(a.RulesAssessed) * 100
	}
	a.ResourcesFailed, a.ResourcesAssessed = 0, 0
	for _, c := range nsResources {
		a.ResourcesFailed += c[0]
		a.ResourcesAssessed += c[1]
	}
}

// scopePosture restricts results to the namespaces a caller may see.
//
// Persisted assessments are cluster-wide: they are collected by the poller
// with the cluster's collector identity, exactly like the workload and pod
// history, and -- like that history -- they are protected by CommitKube's
// namespace scope rather than by the cluster's own RBAC (see requestClients).
// Rather than refuse a scoped user outright, every count is recomputed from
// the per-namespace counts stored with each rule, so the score, the
// per-severity numbers and the pass/fail of each rule are exactly what an
// assessment of their namespaces alone would give. Cluster-scoped resources
// (ClusterRoles, ClusterRoleBindings) are recorded under "" and are never
// visible to a scoped user: they describe the whole cluster, and pod_security
// draws the same line by filtering on namespace. Namespaced RBAC objects
// (Roles, RoleBindings) in their namespaces are shown.
//
// One approximation: failing resources are stored capped per rule, so in a
// very large cluster a scoped user can see a Failed count higher than the
// rows listed. The counts are exact; the list is a sample.
func scopePosture(results []postureResult, nsResources map[string][2]int, allowed map[string]bool) ([]postureResult, map[string][2]int) {
	out := make([]postureResult, 0, len(results))
	for _, r := range results {
		s := r
		s.Failed, s.Passed = 0, 0
		s.NamespaceCounts = map[string][2]int{}
		for ns, c := range r.NamespaceCounts {
			if ns == "" || !allowed[ns] {
				continue
			}
			s.Failed += c[0]
			s.Passed += c[1]
			s.NamespaceCounts[ns] = c
		}
		s.Failures = nil
		for _, f := range r.Failures {
			if f.Namespace != "" && allowed[f.Namespace] {
				s.Failures = append(s.Failures, f)
			}
		}
		s.Truncated = r.Truncated && len(s.Failures) < s.Failed
		s.Result = postureResultOf(s.Failed, s.Passed)
		out = append(out, s)
	}
	scopedRes := map[string][2]int{}
	for ns, c := range nsResources {
		if ns != "" && allowed[ns] {
			scopedRes[ns] = c
		}
	}
	return out, scopedRes
}

// ---- persistence ----------------------------------------------------------------

func encodeJSON(v interface{}) string {
	b, err := json.Marshal(v)
	if err != nil {
		return ""
	}
	return string(b)
}

func toPostureRows(results []postureResult) []models.PostureRuleResult {
	rows := make([]models.PostureRuleResult, 0, len(results))
	for _, r := range results {
		failures := r.Failures
		if failures == nil {
			failures = []PostureFailure{}
		}
		rows = append(rows, models.PostureRuleResult{
			RuleID: r.RuleID, Severity: r.Severity, Category: r.Category, Result: r.Result,
			Failed: r.Failed, Passed: r.Passed,
			FailedResources: encodeJSON(failures),
			NamespaceCounts: encodeJSON(r.NamespaceCounts),
		})
	}
	return rows
}

func fromPostureRow(row *models.PostureRuleResult) postureResult {
	r := postureResult{
		RuleID: row.RuleID, Severity: row.Severity, Category: row.Category, Result: row.Result,
		Failed: row.Failed, Passed: row.Passed, NamespaceCounts: map[string][2]int{},
	}
	if row.FailedResources != "" {
		_ = json.Unmarshal([]byte(row.FailedResources), &r.Failures)
	}
	if row.NamespaceCounts != "" {
		_ = json.Unmarshal([]byte(row.NamespaceCounts), &r.NamespaceCounts)
	}
	r.Truncated = len(r.Failures) < r.Failed
	return r
}

func decodeNamespaceResources(s string) map[string][2]int {
	m := map[string][2]int{}
	if s != "" {
		_ = json.Unmarshal([]byte(s), &m)
	}
	return m
}

// persistPosture writes one assessment and its rule results in a single
// transaction: one lock acquisition per pass, as the other pollers do, and a
// failed write leaves no half-assessment for the timeline to plot.
func persistPosture(clusterID uint, trigger string, now time.Time, results []postureResult, nsResources map[string][2]int) (*models.PostureAssessment, error) {
	a := &models.PostureAssessment{
		CreatedAt: now, ClusterID: clusterID, Trigger: trigger,
		NamespaceResources: encodeJSON(nsResources),
	}
	summarizePosture(a, results, nsResources)
	rows := toPostureRows(results)
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Create(a).Error; err != nil {
			return err
		}
		for i := range rows {
			rows[i].AssessmentID = a.ID
		}
		if len(rows) > 0 {
			return tx.CreateInBatches(&rows, 100).Error
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return a, nil
}

// collectPostureSources lists everything one assessment reads. Any failed
// listing fails the assessment: an RBAC listing that silently came back empty
// would plot as every RBAC rule turning green, which is worse than a gap.
func collectPostureSources(ctx context.Context, typed kubernetes.Interface) (*postureSources, error) {
	src := &postureSources{}
	opts := metav1.ListOptions{}
	step := func(what string, err error) error {
		if err != nil {
			return fmt.Errorf("listing %s: %w", what, err)
		}
		return nil
	}

	if l, err := typed.AppsV1().Deployments("").List(ctx, opts); err != nil {
		return nil, step("deployments", err)
	} else {
		src.Deployments = l.Items
	}
	if l, err := typed.AppsV1().StatefulSets("").List(ctx, opts); err != nil {
		return nil, step("statefulsets", err)
	} else {
		src.StatefulSets = l.Items
	}
	if l, err := typed.AppsV1().DaemonSets("").List(ctx, opts); err != nil {
		return nil, step("daemonsets", err)
	} else {
		src.DaemonSets = l.Items
	}
	if l, err := typed.BatchV1().Jobs("").List(ctx, opts); err != nil {
		return nil, step("jobs", err)
	} else {
		src.Jobs = l.Items
	}
	if l, err := typed.BatchV1().CronJobs("").List(ctx, opts); err != nil {
		return nil, step("cronjobs", err)
	} else {
		src.CronJobs = l.Items
	}
	if l, err := typed.CoreV1().Pods("").List(ctx, opts); err != nil {
		return nil, step("pods", err)
	} else {
		src.Pods = l.Items
	}
	if l, err := typed.RbacV1().Roles("").List(ctx, opts); err != nil {
		return nil, step("roles", err)
	} else {
		src.Roles = l.Items
	}
	if l, err := typed.RbacV1().ClusterRoles().List(ctx, opts); err != nil {
		return nil, step("clusterroles", err)
	} else {
		src.ClusterRoles = l.Items
	}
	if l, err := typed.RbacV1().RoleBindings("").List(ctx, opts); err != nil {
		return nil, step("rolebindings", err)
	} else {
		src.RoleBindings = l.Items
	}
	if l, err := typed.RbacV1().ClusterRoleBindings().List(ctx, opts); err != nil {
		return nil, step("clusterrolebindings", err)
	} else {
		src.ClusterRoleBindings = l.Items
	}
	if l, err := typed.CoreV1().Namespaces().List(ctx, opts); err != nil {
		return nil, step("namespaces", err)
	} else {
		src.Namespaces = l.Items
	}
	if l, err := typed.NetworkingV1().NetworkPolicies("").List(ctx, opts); err != nil {
		return nil, step("networkpolicies", err)
	} else {
		src.NetworkPolicies = l.Items
	}
	if l, err := typed.CoreV1().ServiceAccounts("").List(ctx, opts); err != nil {
		return nil, step("serviceaccounts", err)
	} else {
		src.ServiceAccounts = l.Items
	}
	return src, nil
}

// One assessment per cluster at a time: a manual run that lands while the
// scheduled one is in flight waits for it instead of listing everything twice.
var (
	postureLocksMu sync.Mutex
	postureLocks   = map[uint]*sync.Mutex{}
)

func postureLock(clusterID uint) *sync.Mutex {
	postureLocksMu.Lock()
	defer postureLocksMu.Unlock()
	m := postureLocks[clusterID]
	if m == nil {
		m = &sync.Mutex{}
		postureLocks[clusterID] = m
	}
	return m
}

// runPostureAssessment always uses the collector identity, never the
// caller's: the result is stored and plotted for everyone, and a run whose
// listings depended on who pressed the button would make the timeline jump
// with the person rather than with the cluster.
func runPostureAssessment(cl *models.Cluster, trigger string) (*models.PostureAssessment, error) {
	lock := postureLock(cl.ID)
	lock.Lock()
	defer lock.Unlock()
	return runPostureAssessmentLocked(cl, trigger)
}

func runPostureAssessmentLocked(cl *models.Cluster, trigger string) (*models.PostureAssessment, error) {
	typed, _, err := collectorClients(cl)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	src, err := collectPostureSources(ctx, typed)
	if err != nil {
		return nil, err
	}
	results, nsResources := evaluatePosture(buildPostureInventory(src), postureCatalog)
	return persistPosture(cl.ID, trigger, time.Now(), results, nsResources)
}

// PollPosture assesses every cluster and applies retention. A cluster that
// fails is logged and skipped; the others are still assessed.
func PollPosture() {
	retentionDays := 365
	if v := os.Getenv("POSTURE_RETENTION_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			retentionDays = d
		}
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	if err := db.DB.Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("DELETE FROM posture_rule_results WHERE assessment_id IN (SELECT id FROM posture_assessments WHERE created_at < ?)", cutoff).Error; err != nil {
			return err
		}
		return tx.Where("created_at < ?", cutoff).Delete(&models.PostureAssessment{}).Error
	}); err != nil {
		fmt.Printf("Security posture: retention failed: %v\n", err)
	}

	for _, cl := range allClusters() {
		if _, err := runPostureAssessment(&cl, "scheduled"); err != nil {
			fmt.Printf("Security posture: cluster %s: %v\n", cl.Name, err)
		}
	}
}

// ---- HTTP -----------------------------------------------------------------------

type postureRuleView struct {
	ID              string           `json:"rule_id"`
	Title           string           `json:"title"`
	Description     string           `json:"description"`
	Remediation     string           `json:"remediation"`
	Standard        string           `json:"standard"`
	Severity        string           `json:"severity"`
	Category        string           `json:"category"`
	Result          string           `json:"result"`
	Failed          int              `json:"failed"`
	Passed          int              `json:"passed"`
	FailedResources []PostureFailure `json:"failed_resources"`
	Truncated       bool             `json:"truncated"`
}

// postureScope returns the allowed-namespace set, or nil for an unrestricted
// caller.
func postureScope(c *fiber.Ctx) (map[string]bool, error) {
	allowed, restricted, err := requestNamespaces(c)
	if err != nil || !restricted {
		return nil, err
	}
	set := map[string]bool{}
	for _, ns := range allowed {
		set[ns] = true
	}
	return set, nil
}

func renderPosture(c *fiber.Ctx, cl *models.Cluster, a *models.PostureAssessment) error {
	scope, err := postureScope(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	var rows []models.PostureRuleResult
	db.DB.Where("assessment_id = ?", a.ID).Find(&rows)
	results := make([]postureResult, 0, len(rows))
	for i := range rows {
		results = append(results, fromPostureRow(&rows[i]))
	}
	nsResources := decodeNamespaceResources(a.NamespaceResources)

	view := *a
	if scope != nil {
		results, nsResources = scopePosture(results, nsResources, scope)
		summarizePosture(&view, results, nsResources)
	}

	rules := make([]postureRuleView, 0, len(results))
	for _, r := range results {
		v := postureRuleView{
			ID: r.RuleID, Title: r.RuleID, Standard: postureStandard,
			Severity: r.Severity, Category: r.Category, Result: r.Result,
			Failed: r.Failed, Passed: r.Passed, FailedResources: r.Failures, Truncated: r.Truncated,
		}
		// Metadata comes from the catalog as it is now, so a reworded
		// remediation applies to old assessments too. A rule since removed
		// still shows, under its id.
		if meta := postureRuleByID[r.RuleID]; meta != nil {
			v.Title, v.Description, v.Remediation = meta.Title, meta.Description, meta.Remediation
		}
		if v.FailedResources == nil {
			v.FailedResources = []PostureFailure{}
		}
		rules = append(rules, v)
	}
	sort.SliceStable(rules, func(i, j int) bool {
		ri, rj := rules[i].Result == "failed", rules[j].Result == "failed"
		if ri != rj {
			return ri
		}
		if postureSeverityRank[rules[i].Severity] != postureSeverityRank[rules[j].Severity] {
			return postureSeverityRank[rules[i].Severity] < postureSeverityRank[rules[j].Severity]
		}
		return rules[i].ID < rules[j].ID
	})

	excluded := make([]string, 0, len(postureExcludedNamespaces))
	for ns := range postureExcludedNamespaces {
		excluded = append(excluded, ns)
	}
	sort.Strings(excluded)

	return c.JSON(fiber.Map{
		"assessment":          view,
		"rules":               rules,
		"restricted":          scope != nil,
		"standard":            postureStandard,
		"cluster":             cl.Name,
		"excluded_namespaces": excluded,
	})
}

func latestPosture(clusterID uint) (*models.PostureAssessment, bool) {
	var a models.PostureAssessment
	err := db.DB.Where("cluster_id = ?", clusterID).Order("created_at desc, id desc").Limit(1).Find(&a).Error
	if err != nil || a.ID == 0 {
		return nil, false
	}
	return &a, true
}

// GetPosture returns the latest assessment of the selected cluster, running
// the first one on demand so the page is never empty on a fresh install.
func GetPosture(c *fiber.Ctx) error {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	a, ok := latestPosture(cl.ID)
	if !ok {
		lock := postureLock(cl.ID)
		lock.Lock()
		// Re-checked under the lock: two first page loads must not both run.
		a, ok = latestPosture(cl.ID)
		if !ok {
			a, err = runPostureAssessmentLocked(cl, "manual")
		}
		lock.Unlock()
		if err != nil {
			return clusterUnreachable(c, err)
		}
	}
	return renderPosture(c, cl, a)
}

// RunPostureAssessment runs one now and returns it.
func RunPostureAssessment(c *fiber.Ctx) error {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	a, err := runPostureAssessment(cl, "manual")
	if err != nil {
		return clusterUnreachable(c, err)
	}
	return renderPosture(c, cl, a)
}

// GetPostureHistory is the timeline: summary fields only, oldest first.
func GetPostureHistory(c *fiber.Ctx) error {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	scope, err := postureScope(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	days := c.QueryInt("days", 90)
	if days < 1 {
		days = 1
	}
	if days > 365 {
		days = 365
	}
	since := time.Now().AddDate(0, 0, -days)

	var list []models.PostureAssessment
	db.DB.Where("cluster_id = ? AND created_at >= ?", cl.ID, since).Order("created_at asc, id asc").Find(&list)
	if list == nil {
		list = []models.PostureAssessment{}
	}

	if scope != nil && len(list) > 0 {
		ids := make([]uint, len(list))
		for i := range list {
			ids[i] = list[i].ID
		}
		// The failing-resource lists are not needed to recount, and they are
		// most of the bytes, so they are left out of the query.
		var rows []models.PostureRuleResult
		db.DB.Select("assessment_id", "rule_id", "severity", "category", "result", "failed", "passed", "namespace_counts").
			Where("assessment_id IN ?", ids).Find(&rows)
		byAssessment := map[uint][]postureResult{}
		for i := range rows {
			byAssessment[rows[i].AssessmentID] = append(byAssessment[rows[i].AssessmentID], fromPostureRow(&rows[i]))
		}
		for i := range list {
			results, nsRes := scopePosture(byAssessment[list[i].ID], decodeNamespaceResources(list[i].NamespaceResources), scope)
			summarizePosture(&list[i], results, nsRes)
		}
	}

	return c.JSON(fiber.Map{"assessments": list, "restricted": scope != nil, "days": days})
}
