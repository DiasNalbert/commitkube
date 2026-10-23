package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/gofiber/fiber/v2"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"sigs.k8s.io/yaml"
)

// A failing posture rule used to end at a paragraph of advice. This turns it
// into the command that fixes that resource, written against the object as
// it is in the cluster now -- its real container names, its real rules --
// and checked before it is shown: the fix is applied to a copy and the
// rule's own check runs on the result. "Verified" means that check passes;
// it does not mean the application will keep working, which is why every
// fix carries what it may break.

type remediationStep struct {
	Title   string `json:"title"`
	Command string `json:"command"`
}

type postureRemediation struct {
	Rule      string            `json:"rule"`
	Kind      string            `json:"kind"`
	Namespace string            `json:"namespace"`
	Name      string            `json:"name"`
	Steps     []remediationStep `json:"steps"`
	// Verified: the rule's own check passes on the fixed copy.
	Verified bool `json:"verified"`
	// ManagedBy names what owns the object -- a Helm release, an ArgoCD
	// application, a controller -- and will undo a change made in place.
	ManagedBy string   `json:"managed_by,omitempty"`
	Warnings  []string `json:"warnings"`
	// Guidance is the advice when no command can be generated safely.
	Guidance string `json:"guidance,omitempty"`
}

// ---- who owns it -------------------------------------------------------------

func managedBy(meta *metav1.ObjectMeta) string {
	if rel := meta.Annotations["meta.helm.sh/release-name"]; rel != "" {
		return fmt.Sprintf("Helm release %s", rel)
	}
	if meta.Labels["app.kubernetes.io/managed-by"] == "Helm" {
		if inst := meta.Labels["app.kubernetes.io/instance"]; inst != "" {
			return fmt.Sprintf("Helm release %s", inst)
		}
		return "Helm"
	}
	if id := meta.Annotations["argocd.argoproj.io/tracking-id"]; id != "" {
		app, _, _ := strings.Cut(id, ":")
		return fmt.Sprintf("ArgoCD application %s", app)
	}
	if inst := meta.Labels["argocd.argoproj.io/instance"]; inst != "" {
		return fmt.Sprintf("ArgoCD application %s", inst)
	}
	for _, o := range meta.OwnerReferences {
		if o.Controller != nil && *o.Controller {
			return fmt.Sprintf("%s %s", o.Kind, o.Name)
		}
	}
	if m := meta.Labels["app.kubernetes.io/managed-by"]; m != "" {
		return m
	}
	return ""
}

func revertWarning(owner string) string {
	return fmt.Sprintf("This object belongs to %s, which will put it back on its next sync. Make the same change in its source -- the chart values or the manifest in Git -- or it will not last.", owner)
}

// ---- workloads ---------------------------------------------------------------

// workloadFix records what a fix changed, as the pieces of a strategic
// merge patch, while it changes a copy of the pod spec.
type workloadFix struct {
	spec        *corev1.PodSpec
	annotations map[string]string

	podFields   map[string]any
	podSC       map[string]any
	containers  map[string]map[string]any // name -> patch fragment
	initNames   map[string]bool
	annotPatch  map[string]any
	warnings    []string
	preSteps    []remediationStep
	unpatchable string
}

func newWorkloadFix(spec *corev1.PodSpec, annotations map[string]string) *workloadFix {
	cp := spec.DeepCopy()
	ann := map[string]string{}
	for k, v := range annotations {
		ann[k] = v
	}
	init := map[string]bool{}
	for _, c := range cp.InitContainers {
		init[c.Name] = true
	}
	return &workloadFix{
		spec: cp, annotations: ann, podFields: map[string]any{}, podSC: map[string]any{},
		containers: map[string]map[string]any{}, initNames: init, annotPatch: map[string]any{},
	}
}

func (f *workloadFix) container(name string) map[string]any {
	if f.containers[name] == nil {
		f.containers[name] = map[string]any{"name": name}
	}
	return f.containers[name]
}

func (f *workloadFix) containerSC(name string) map[string]any {
	c := f.container(name)
	sc, _ := c["securityContext"].(map[string]any)
	if sc == nil {
		sc = map[string]any{}
		c["securityContext"] = sc
	}
	return sc
}

// eachC runs fn over every container and init container of the copy.
func (f *workloadFix) eachC(fn func(c *corev1.Container)) {
	for i := range f.spec.InitContainers {
		fn(&f.spec.InitContainers[i])
	}
	for i := range f.spec.Containers {
		fn(&f.spec.Containers[i])
	}
}

func ensureSC(c *corev1.Container) *corev1.SecurityContext {
	if c.SecurityContext == nil {
		c.SecurityContext = &corev1.SecurityContext{}
	}
	return c.SecurityContext
}

func boolp(b bool) *bool    { return &b }
func int64p(i int64) *int64 { return &i }

func capNames(cs []corev1.Capability) []string {
	out := make([]string, 0, len(cs))
	for _, c := range cs {
		out = append(out, string(c))
	}
	return out
}

// applyWorkloadRule changes the copy so the rule passes. It returns false
// when the rule has no fix that can be written as a patch.
func applyWorkloadRule(rule, workload string, f *workloadFix) bool {
	switch rule {
	case "KSE-WL-001": // privileged
		f.eachC(func(c *corev1.Container) {
			if c.SecurityContext != nil && c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				c.SecurityContext.Privileged = boolp(false)
				f.containerSC(c.Name)["privileged"] = false
			}
		})
		f.warnings = append(f.warnings, "A container that needed privileged mode (device access, kernel settings) will fail to start. Give it the specific capability it needs instead.")
	case "KSE-WL-002":
		f.spec.HostNetwork = false
		f.podFields["hostNetwork"] = false
		f.warnings = append(f.warnings, "The pod gets its own network namespace: anything that reached it on the node's IP, or that it reached as the node, needs a Service now.")
	case "KSE-WL-004":
		f.spec.HostPID = false
		f.podFields["hostPID"] = false
		f.warnings = append(f.warnings, "The pod no longer sees the node's processes; monitoring agents that need them will stop reporting.")
	case "KSE-WL-005":
		f.spec.HostIPC = false
		f.podFields["hostIPC"] = false
	case "KSE-WL-003":
		f.eachC(func(c *corev1.Container) {
			sc := ensureSC(c)
			if sc.AllowPrivilegeEscalation == nil || *sc.AllowPrivilegeEscalation {
				sc.AllowPrivilegeEscalation = boolp(false)
				f.containerSC(c.Name)["allowPrivilegeEscalation"] = false
			}
		})
		f.warnings = append(f.warnings, "Safe for almost every application. It breaks only a process that uses setuid binaries (sudo, ping on some images) to gain privileges.")
	case "KSE-WL-009":
		f.eachC(func(c *corev1.Container) {
			sc := ensureSC(c)
			if sc.Capabilities == nil {
				sc.Capabilities = &corev1.Capabilities{}
			}
			for _, d := range sc.Capabilities.Drop {
				if strings.EqualFold(string(d), "ALL") {
					return
				}
			}
			sc.Capabilities.Drop = append(sc.Capabilities.Drop, "ALL")
			f.containerSC(c.Name)["capabilities"] = map[string]any{"drop": capNames(sc.Capabilities.Drop), "add": capNames(sc.Capabilities.Add)}
		})
		f.warnings = append(f.warnings, "Capabilities the container adds explicitly are kept. One it used implicitly (binding a port below 1024 as root, changing file ownership) has to be added back by name.")
	case "KSE-WL-022":
		f.eachC(func(c *corev1.Container) {
			if c.SecurityContext == nil || c.SecurityContext.Capabilities == nil {
				return
			}
			var keep, removed []corev1.Capability
			for _, a := range c.SecurityContext.Capabilities.Add {
				if baselineCapabilities[strings.TrimPrefix(strings.ToUpper(string(a)), "CAP_")] {
					keep = append(keep, a)
				} else {
					removed = append(removed, a)
				}
			}
			if len(removed) == 0 {
				return
			}
			c.SecurityContext.Capabilities.Add = keep
			f.containerSC(c.Name)["capabilities"] = map[string]any{"drop": capNames(c.SecurityContext.Capabilities.Drop), "add": capNames(keep)}
			f.warnings = append(f.warnings, fmt.Sprintf("Container %s loses %s. Check what it does with them before applying.", c.Name, strings.Join(capNames(removed), ", ")))
		})
	case "KSE-WL-024":
		f.eachC(func(c *corev1.Container) {
			sc := ensureSC(c)
			changed := false
			if sc.Privileged != nil && *sc.Privileged {
				sc.Privileged = boolp(false)
				f.containerSC(c.Name)["privileged"] = false
				changed = true
			}
			if sc.Capabilities == nil {
				sc.Capabilities = &corev1.Capabilities{}
			}
			var add []corev1.Capability
			for _, a := range sc.Capabilities.Add {
				n := strings.TrimPrefix(strings.ToUpper(string(a)), "CAP_")
				if n == "NET_RAW" || n == "ALL" {
					changed = true
					continue
				}
				add = append(add, a)
			}
			sc.Capabilities.Add = add
			dropped := false
			for _, d := range sc.Capabilities.Drop {
				n := strings.TrimPrefix(strings.ToUpper(string(d)), "CAP_")
				if n == "NET_RAW" || n == "ALL" {
					dropped = true
				}
			}
			if !dropped {
				sc.Capabilities.Drop = append(sc.Capabilities.Drop, "NET_RAW")
				changed = true
			}
			if changed {
				f.containerSC(c.Name)["capabilities"] = map[string]any{"drop": capNames(sc.Capabilities.Drop), "add": capNames(sc.Capabilities.Add)}
			}
		})
		f.warnings = append(f.warnings, "ping and raw-socket tools stop working inside the container; normal TCP and UDP traffic is unaffected.")
	case "KSE-WL-010":
		if f.spec.SecurityContext == nil {
			f.spec.SecurityContext = &corev1.PodSecurityContext{}
		}
		f.spec.SecurityContext.RunAsNonRoot = boolp(true)
		f.podSC["runAsNonRoot"] = true
		f.eachC(func(c *corev1.Container) {
			if c.SecurityContext != nil && c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				c.SecurityContext.RunAsUser = int64p(10001)
				f.containerSC(c.Name)["runAsUser"] = 10001
			}
			if c.SecurityContext != nil && c.SecurityContext.RunAsNonRoot != nil && !*c.SecurityContext.RunAsNonRoot {
				c.SecurityContext.RunAsNonRoot = boolp(true)
				f.containerSC(c.Name)["runAsNonRoot"] = true
			}
		})
		f.warnings = append(f.warnings, "If the image's user is root, the pod will not start (the kubelet refuses it). Set USER to a non-root uid in the Dockerfile, or add runAsUser to the patch, and make sure files the app writes are owned by that uid.")
	case "KSE-WL-011":
		f.eachC(func(c *corev1.Container) {
			sc := ensureSC(c)
			if sc.ReadOnlyRootFilesystem == nil || !*sc.ReadOnlyRootFilesystem {
				sc.ReadOnlyRootFilesystem = boolp(true)
				f.containerSC(c.Name)["readOnlyRootFilesystem"] = true
			}
		})
		f.warnings = append(f.warnings, "Anything the app writes outside a volume -- /tmp, caches, pid files -- now fails. Mount an emptyDir on each such path before applying.")
	case "KSE-WL-013":
		if f.spec.SecurityContext == nil {
			f.spec.SecurityContext = &corev1.PodSecurityContext{}
		}
		f.spec.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
		f.podSC["seccompProfile"] = map[string]any{"type": "RuntimeDefault"}
		f.eachC(func(c *corev1.Container) {
			if c.SecurityContext != nil && c.SecurityContext.SeccompProfile != nil && c.SecurityContext.SeccompProfile.Type == corev1.SeccompProfileTypeUnconfined {
				c.SecurityContext.SeccompProfile = &corev1.SeccompProfile{Type: corev1.SeccompProfileTypeRuntimeDefault}
				f.containerSC(c.Name)["seccompProfile"] = map[string]any{"type": "RuntimeDefault"}
			}
		})
		f.warnings = append(f.warnings, "RuntimeDefault blocks a small set of rarely used system calls; ordinary applications are unaffected.")
	case "KSE-WL-015":
		f.eachC(func(c *corev1.Container) {
			var ports []any
			for i := range c.Ports {
				if c.Ports[i].HostPort != 0 {
					ports = append(ports, map[string]any{"containerPort": c.Ports[i].ContainerPort, "hostPort": nil})
					c.Ports[i].HostPort = 0
				}
			}
			if len(ports) > 0 {
				f.container(c.Name)["ports"] = ports
			}
		})
		f.warnings = append(f.warnings, "The port is no longer reachable on the node's IP. Expose it with a Service (NodePort or LoadBalancer) if something outside needs it.")
	case "KSE-WL-016":
		f.spec.AutomountServiceAccountToken = boolp(false)
		f.podFields["automountServiceAccountToken"] = false
		f.warnings = append(f.warnings, "An application that calls the Kubernetes API (operators, controllers, anything using client-go in-cluster) loses its credentials. Leave those as they are.")
	case "KSE-WL-018":
		// The new service account is named after the workload.
		f.preSteps = append(f.preSteps, remediationStep{Title: "Create a service account of its own", Command: "kubectl -n %[2]s create serviceaccount %[1]s"})
		f.spec.ServiceAccountName = workload
		f.podFields["serviceAccountName"] = workload
		f.warnings = append(f.warnings, "If the workload relied on permissions granted to the namespace's default service account, bind them to the new one first.")
	case "KSE-WL-025":
		if sc := f.spec.SecurityContext; sc != nil && seLinuxViolation(sc.SELinuxOptions) != "" {
			sc.SELinuxOptions = nil
			f.podSC["seLinuxOptions"] = nil
		}
		f.eachC(func(c *corev1.Container) {
			if c.SecurityContext != nil && seLinuxViolation(c.SecurityContext.SELinuxOptions) != "" {
				c.SecurityContext.SELinuxOptions = nil
				f.containerSC(c.Name)["seLinuxOptions"] = nil
			}
		})
	case "KSE-WL-026":
		for k, v := range f.annotations {
			if strings.HasPrefix(k, "container.apparmor.security.beta.kubernetes.io/") && v != "runtime/default" && !strings.HasPrefix(v, "localhost/") {
				f.annotations[k] = "runtime/default"
				f.annotPatch[k] = "runtime/default"
			}
		}
	case "KSE-WL-027":
		f.eachC(func(c *corev1.Container) {
			if c.SecurityContext != nil && c.SecurityContext.ProcMount != nil && *c.SecurityContext.ProcMount != corev1.DefaultProcMount {
				c.SecurityContext.ProcMount = nil
				f.containerSC(c.Name)["procMount"] = nil
			}
		})
	default:
		return false
	}
	return true
}

// patchBody builds the strategic merge patch for the workload kind.
func (f *workloadFix) patchBody(kind string) map[string]any {
	podSpec := map[string]any{}
	for k, v := range f.podFields {
		podSpec[k] = v
	}
	if len(f.podSC) > 0 {
		podSpec["securityContext"] = f.podSC
	}
	var cs, ics []any
	names := make([]string, 0, len(f.containers))
	for n := range f.containers {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		if f.initNames[n] {
			ics = append(ics, f.containers[n])
		} else {
			cs = append(cs, f.containers[n])
		}
	}
	if len(cs) > 0 {
		podSpec["containers"] = cs
	}
	if len(ics) > 0 {
		podSpec["initContainers"] = ics
	}
	tpl := map[string]any{"spec": podSpec}
	if len(f.annotPatch) > 0 {
		tpl["metadata"] = map[string]any{"annotations": f.annotPatch}
	}
	if kind == "CronJob" {
		return map[string]any{"spec": map[string]any{"jobTemplate": map[string]any{"spec": map[string]any{"template": tpl}}}}
	}
	return map[string]any{"spec": map[string]any{"template": tpl}}
}

// workloadSource reads a workload as the posture inventory sees it.
func workloadSource(ctx context.Context, cs kubernetes.Interface, kind, ns, name string) (*corev1.PodSpec, map[string]string, *metav1.ObjectMeta, error) {
	switch kind {
	case "Deployment":
		o, err := cs.AppsV1().Deployments(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Spec.Template.Spec, o.Spec.Template.Annotations, &o.ObjectMeta, nil
	case "StatefulSet":
		o, err := cs.AppsV1().StatefulSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Spec.Template.Spec, o.Spec.Template.Annotations, &o.ObjectMeta, nil
	case "DaemonSet":
		o, err := cs.AppsV1().DaemonSets(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Spec.Template.Spec, o.Spec.Template.Annotations, &o.ObjectMeta, nil
	case "CronJob":
		o, err := cs.BatchV1().CronJobs(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Spec.JobTemplate.Spec.Template.Spec, o.Spec.JobTemplate.Spec.Template.Annotations, &o.ObjectMeta, nil
	case "Job":
		o, err := cs.BatchV1().Jobs(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Spec.Template.Spec, o.Spec.Template.Annotations, &o.ObjectMeta, nil
	case "Pod":
		o, err := cs.CoreV1().Pods(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return nil, nil, nil, err
		}
		return &o.Spec, o.Annotations, &o.ObjectMeta, nil
	}
	return nil, nil, nil, fmt.Errorf("unsupported kind %s", kind)
}

func ruleCheckPasses(rule *postureRule, inv *postureInventory) bool {
	for _, o := range rule.Check(inv) {
		if o.Detail != "" {
			return false
		}
	}
	return true
}

func remediateWorkload(rule *postureRule, kind, ns, name string, spec *corev1.PodSpec, annotations map[string]string, meta *metav1.ObjectMeta) postureRemediation {
	r := postureRemediation{Rule: rule.ID, Kind: kind, Namespace: ns, Name: name, Warnings: []string{}, Steps: []remediationStep{}}
	f := newWorkloadFix(spec, annotations)
	if !applyWorkloadRule(rule.ID, name, f) {
		r.Guidance = rule.Remediation
		if rule.ID == "KSE-SEC-001" {
			r.Guidance = secretsAsFilesGuidance(spec) + "\n\n" + rule.Remediation
		}
		return r
	}

	w := postureWorkload{Kind: kind, Namespace: ns, Name: name, Spec: *f.spec, Annotations: f.annotations, LongRunning: kind != "Job" && kind != "CronJob"}
	r.Verified = ruleCheckPasses(rule, &postureInventory{Workloads: []postureWorkload{w}, ServiceAccounts: map[string]*corev1.ServiceAccount{}})
	r.Warnings = append(r.Warnings, f.warnings...)

	switch kind {
	case "Job":
		r.Guidance = "A Job's pod template cannot be changed once it exists. Apply the same change to the manifest or CronJob that creates it; the next run picks it up."
		return r
	case "Pod":
		r.Guidance = "A running Pod cannot take this change. Make it in the manifest that creates the Pod and recreate it -- or, better, run it from a Deployment."
		return r
	}

	for _, s := range f.preSteps {
		r.Steps = append(r.Steps, remediationStep{Title: s.Title, Command: fmt.Sprintf(s.Command, name, ns)})
	}
	raw, _ := json.Marshal(f.patchBody(kind))
	r.Steps = append(r.Steps, remediationStep{
		Title:   "Patch the workload (this rolls its pods)",
		Command: fmt.Sprintf("kubectl -n %s patch %s %s --type=strategic -p '%s'", ns, strings.ToLower(kind), name, raw),
	})
	r.Steps = append(r.Steps, remediationStep{
		Title:   "Watch the rollout",
		Command: fmt.Sprintf("kubectl -n %s rollout status %s/%s", ns, strings.ToLower(kind), name),
	})
	if kind == "CronJob" {
		r.Steps = r.Steps[:len(r.Steps)-1] // a CronJob has no rollout; the next run uses the new template
	}
	if owner := managedBy(meta); owner != "" {
		r.ManagedBy = owner
		r.Warnings = append([]string{revertWarning(owner)}, r.Warnings...)
	}
	return r
}

// secretsAsFilesGuidance writes the volume for the Secrets a workload reads
// into environment variables. It cannot be a command: the application has
// to read files instead of variables, which is a code change.
func secretsAsFilesGuidance(spec *corev1.PodSpec) string {
	seen := map[string]bool{}
	var secrets []string
	for _, c := range append(append([]corev1.Container{}, spec.InitContainers...), spec.Containers...) {
		for _, e := range c.Env {
			if e.ValueFrom != nil && e.ValueFrom.SecretKeyRef != nil && !seen[e.ValueFrom.SecretKeyRef.Name] {
				seen[e.ValueFrom.SecretKeyRef.Name] = true
				secrets = append(secrets, e.ValueFrom.SecretKeyRef.Name)
			}
		}
		for _, ef := range c.EnvFrom {
			if ef.SecretRef != nil && !seen[ef.SecretRef.Name] {
				seen[ef.SecretRef.Name] = true
				secrets = append(secrets, ef.SecretRef.Name)
			}
		}
	}
	if len(secrets) == 0 {
		return ""
	}
	var b strings.Builder
	b.WriteString("Mount the Secrets as files and have the application read them from there:\n\nvolumes:\n")
	for _, s := range secrets {
		fmt.Fprintf(&b, "  - name: %s\n    secret:\n      secretName: %s\n", s, s)
	}
	b.WriteString("# and in the container:\nvolumeMounts:\n")
	for _, s := range secrets {
		fmt.Fprintf(&b, "  - name: %s\n    mountPath: /etc/secrets/%s\n    readOnly: true\n", s, s)
	}
	return strings.TrimRight(b.String(), "\n")
}

// ---- roles ---------------------------------------------------------------------

var expandableVerbs = []string{"get", "list", "watch", "create", "update", "patch", "delete", "deletecollection"}

// narrowRoleRules removes from a role exactly what the rule objects to, by
// asking the rule itself: each resource and verb is kept only if the rule's
// check passes with it alone. What cannot be narrowed this way -- a rule
// on "*" resources -- is reported, not guessed.
func narrowRoleRules(rule *postureRule, kind, ns, name string, rules []rbacv1.PolicyRule) (out []rbacv1.PolicyRule, removed []string, manual []string) {
	passes := func(rs []rbacv1.PolicyRule) bool {
		return ruleCheckPasses(rule, &postureInventory{Roles: []postureRole{{Kind: kind, Namespace: ns, Name: name, Rules: rs}}})
	}
	for i, r := range rules {
		if passes([]rbacv1.PolicyRule{r}) {
			out = append(out, r)
			continue
		}
		if len(r.NonResourceURLs) > 0 {
			byVerbs := map[string][]string{}
			for _, u := range r.NonResourceURLs {
				one := rbacv1.PolicyRule{NonResourceURLs: []string{u}, Verbs: r.Verbs}
				switch {
				case passes([]rbacv1.PolicyRule{one}):
					byVerbs[strings.Join(r.Verbs, ",")] = append(byVerbs[strings.Join(r.Verbs, ",")], u)
				case passes([]rbacv1.PolicyRule{{NonResourceURLs: []string{u}, Verbs: []string{"get"}}}):
					byVerbs["get"] = append(byVerbs["get"], u)
					removed = append(removed, fmt.Sprintf("rule %d: only get on %s", i+1, u))
				default:
					removed = append(removed, fmt.Sprintf("rule %d: %s on %s", i+1, strings.Join(r.Verbs, ", "), u))
				}
			}
			for verbs, urls := range byVerbs {
				out = append(out, rbacv1.PolicyRule{NonResourceURLs: urls, Verbs: strings.Split(verbs, ",")})
			}
			continue
		}
		if containsStr(r.APIGroups, "*") || containsStr(r.Resources, "*") {
			manual = append(manual, fmt.Sprintf("rule %d grants %s on %s in API groups %s: list the specific resources it needs instead of *",
				i+1, strings.Join(r.Verbs, ", "), strings.Join(r.Resources, ", "), strings.Join(r.APIGroups, ", ")))
			out = append(out, r)
			continue
		}
		verbs := r.Verbs
		if containsStr(verbs, "*") {
			verbs = expandableVerbs
		}
		// Resources that end up with the same verbs share a rule again.
		groups := map[string][]string{}
		var order []string
		for _, res := range r.Resources {
			var allowed, dropped []string
			for _, v := range verbs {
				one := rbacv1.PolicyRule{APIGroups: r.APIGroups, Resources: []string{res}, Verbs: []string{v}, ResourceNames: r.ResourceNames}
				if passes([]rbacv1.PolicyRule{one}) {
					allowed = append(allowed, v)
				} else {
					dropped = append(dropped, v)
				}
			}
			if len(dropped) > 0 {
				removed = append(removed, fmt.Sprintf("rule %d: %s on %s", i+1, strings.Join(dropped, ", "), res))
			}
			if len(allowed) == 0 {
				continue
			}
			key := strings.Join(allowed, ",")
			if _, ok := groups[key]; !ok {
				order = append(order, key)
			}
			groups[key] = append(groups[key], res)
		}
		for _, key := range order {
			out = append(out, rbacv1.PolicyRule{APIGroups: r.APIGroups, Resources: groups[key], Verbs: strings.Split(key, ","), ResourceNames: r.ResourceNames})
		}
	}
	return out, removed, manual
}

func cleanMeta(m metav1.ObjectMeta) metav1.ObjectMeta {
	ann := map[string]string{}
	for k, v := range m.Annotations {
		if k != "kubectl.kubernetes.io/last-applied-configuration" {
			ann[k] = v
		}
	}
	out := metav1.ObjectMeta{Name: m.Name, Namespace: m.Namespace, Labels: m.Labels}
	if len(ann) > 0 {
		out.Annotations = ann
	}
	return out
}

func remediateRole(rule *postureRule, kind string, meta metav1.ObjectMeta, rules []rbacv1.PolicyRule, aggregated bool) postureRemediation {
	r := postureRemediation{Rule: rule.ID, Kind: kind, Namespace: meta.Namespace, Name: meta.Name, Warnings: []string{}, Steps: []remediationStep{}}
	owner := managedBy(&meta)
	if owner != "" {
		r.ManagedBy = owner
		r.Warnings = append(r.Warnings,
			fmt.Sprintf("This role ships with %s. The software it belongs to uses these permissions on purpose; narrowing them in place breaks it, and the next sync undoes the change anyway. If the access is expected, accept the finding instead.", owner))
	}
	if aggregated {
		r.Guidance = "This ClusterRole is aggregated: its rules are copied from other ClusterRoles by a controller and cannot be edited here. Narrow the ClusterRoles it aggregates."
		return r
	}
	fixed, removed, manual := narrowRoleRules(rule, kind, meta.Namespace, meta.Name, rules)
	r.Verified = len(manual) == 0 && ruleCheckPasses(rule, &postureInventory{Roles: []postureRole{{Kind: kind, Namespace: meta.Namespace, Name: meta.Name, Rules: fixed}}})
	for _, m := range manual {
		r.Warnings = append(r.Warnings, "Not narrowed automatically: "+m)
	}
	if len(removed) > 0 {
		r.Warnings = append(r.Warnings, "The new version removes: "+strings.Join(removed, "; ")+". Whatever is bound to this role loses exactly that.")
	}
	if rule.ID == "KSE-RBAC-001" {
		r.Warnings = append(r.Warnings, "If it needs a few specific Secrets, add a rule with resourceNames listing them: access to named Secrets passes this check.")
	}

	var obj any
	if kind == "ClusterRole" {
		obj = rbacv1.ClusterRole{TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "ClusterRole"}, ObjectMeta: cleanMeta(meta), Rules: fixed}
	} else {
		obj = rbacv1.Role{TypeMeta: metav1.TypeMeta{APIVersion: "rbac.authorization.k8s.io/v1", Kind: "Role"}, ObjectMeta: cleanMeta(meta), Rules: fixed}
	}
	y, _ := yaml.Marshal(obj)
	y = []byte(strings.Replace(string(y), "  creationTimestamp: null\n", "", 1))
	nsFlag := ""
	if meta.Namespace != "" {
		nsFlag = " -n " + meta.Namespace
	}
	r.Steps = append(r.Steps,
		remediationStep{Title: "Keep a copy of the current version", Command: fmt.Sprintf("kubectl%s get %s %s -o yaml > %s-%s.backup.yaml", nsFlag, strings.ToLower(kind), meta.Name, strings.ToLower(kind), meta.Name)},
		remediationStep{Title: "Apply the narrowed version", Command: "kubectl apply -f - <<'EOF'\n" + strings.TrimRight(string(y), "\n") + "\nEOF"},
	)
	return r
}

// ---- bindings, namespaces ------------------------------------------------------

func remediateBinding(rule *postureRule, kind string, meta metav1.ObjectMeta, subjects []rbacv1.Subject) postureRemediation {
	r := postureRemediation{Rule: rule.ID, Kind: kind, Namespace: meta.Namespace, Name: meta.Name, Warnings: []string{}, Steps: []remediationStep{}}
	var who []string
	for _, s := range subjects {
		if !postureSubjectExcluded(s) {
			who = append(who, subjectLabel(s))
		}
	}
	nsFlag := ""
	if meta.Namespace != "" {
		nsFlag = " -n " + meta.Namespace
	}
	r.Steps = append(r.Steps,
		remediationStep{Title: "Keep a copy", Command: fmt.Sprintf("kubectl%s get %s %s -o yaml > %s.backup.yaml", nsFlag, strings.ToLower(kind), meta.Name, meta.Name)},
		remediationStep{Title: "Remove the binding", Command: fmt.Sprintf("kubectl%s delete %s %s", nsFlag, strings.ToLower(kind), meta.Name)},
	)
	r.Warnings = append(r.Warnings, fmt.Sprintf("%s lose(s) everything this binding gives, at once. Bind them to a role with only what they use before removing it.", strings.Join(who, ", ")))
	if owner := managedBy(&meta); owner != "" {
		r.ManagedBy = owner
		r.Warnings = append(r.Warnings, revertWarning(owner))
	}
	return r
}

func remediateNamespace(rule *postureRule, ns string) postureRemediation {
	r := postureRemediation{Rule: rule.ID, Kind: "Namespace", Namespace: ns, Name: ns, Warnings: []string{}, Steps: []remediationStep{}}
	r.Steps = append(r.Steps,
		remediationStep{Title: "Allow traffic between pods of the namespace (apply first)", Command: fmt.Sprintf(`kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-same-namespace
  namespace: %s
spec:
  podSelector: {}
  policyTypes: [Ingress]
  ingress:
    - from:
        - podSelector: {}
EOF`, ns)},
		remediationStep{Title: "Deny all other ingress", Command: fmt.Sprintf(`kubectl apply -f - <<'EOF'
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: %s
spec:
  podSelector: {}
  policyTypes: [Ingress]
EOF`, ns)},
	)
	r.Verified = true
	r.Warnings = append(r.Warnings, "Traffic from other namespaces stops, including the ingress controller and monitoring. Add an allow policy for each before the deny one, or the services behind an Ingress go down.")
	return r
}

// ---- HTTP ------------------------------------------------------------------------

// GetPostureRemediation answers "how do I fix this one", for one rule and
// one failing resource, from the object as it is now.
func GetPostureRemediation(c *fiber.Ctx) error {
	ruleID, kind, ns, name := c.Query("rule"), c.Query("kind"), c.Query("namespace"), c.Query("name")
	rule := postureRuleByID[ruleID]
	if rule == nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "unknown rule"})
	}
	if ns != "" && !namespaceAllowed(c, ns) {
		return forbidNamespace(c)
	}
	cs, err := requestTyped(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	ctx := context.Background()
	notFound := func(err error) error {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": fmt.Sprintf("%s %s: %v", kind, name, err)})
	}

	switch kind {
	case "Deployment", "StatefulSet", "DaemonSet", "CronJob", "Job", "Pod":
		spec, ann, meta, err := workloadSource(ctx, cs, kind, ns, name)
		if err != nil {
			return notFound(err)
		}
		return c.JSON(remediateWorkload(rule, kind, ns, name, spec, ann, meta))
	case "Role":
		o, err := cs.RbacV1().Roles(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return notFound(err)
		}
		return c.JSON(remediateRole(rule, kind, o.ObjectMeta, o.Rules, false))
	case "ClusterRole":
		o, err := cs.RbacV1().ClusterRoles().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return notFound(err)
		}
		return c.JSON(remediateRole(rule, kind, o.ObjectMeta, o.Rules, o.AggregationRule != nil))
	case "RoleBinding":
		o, err := cs.RbacV1().RoleBindings(ns).Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return notFound(err)
		}
		return c.JSON(remediateBinding(rule, kind, o.ObjectMeta, o.Subjects))
	case "ClusterRoleBinding":
		o, err := cs.RbacV1().ClusterRoleBindings().Get(ctx, name, metav1.GetOptions{})
		if err != nil {
			return notFound(err)
		}
		return c.JSON(remediateBinding(rule, kind, o.ObjectMeta, o.Subjects))
	case "Namespace":
		if rule.ID == "KSE-NET-001" {
			return c.JSON(remediateNamespace(rule, ns))
		}
	}
	return c.JSON(postureRemediation{Rule: rule.ID, Kind: kind, Namespace: ns, Name: name, Warnings: []string{}, Steps: []remediationStep{}, Guidance: rule.Remediation})
}
