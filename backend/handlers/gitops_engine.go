package handlers

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"

	"github.com/kubecommit/backend/models"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

// The engine compares what a repository path declares with what the cluster
// holds, and makes the cluster match. Its design follows Argo CD's
// gitops-engine where that one has already learned the hard way:
//
//   - the comparison is a server-side apply in dry-run, so the API server --
//     defaults, admission, the merge itself -- decides what applying would
//     produce, and validation comes with it;
//   - objects are applied in the same kind order (namespaced kinds only);
//   - an object is the engine's to delete only if the engine applied it and
//     it still carries the engine's tracking annotation for that app.
//
// By default it is narrower on purpose: namespaced objects, in the
// application's own namespace, which keeps the access it needs grantable
// one namespace at a time. An application with ClusterScope may also
// manage cluster-scoped objects and other namespaces.

const (
	gitopsFieldManager    = "commitkube"
	gitopsTrackingLabel   = "commitkube.io/app"
	gitopsTrackingIDAnnot = "commitkube.io/tracking-id"
)

const (
	ResSynced     = "Synced"
	ResOutOfSync  = "OutOfSync"
	ResMissing    = "Missing"
	ResExtraneous = "Extraneous"
	ResInvalid    = "Invalid"
)

// gitopsKube is the cluster as the engine needs it. The real one is backed
// by the dynamic client; tests use a fake.
type gitopsKube interface {
	// Mapping resolves a kind to its resource and scope.
	Mapping(gvk schema.GroupVersionKind) (gvr schema.GroupVersionResource, namespaced bool, err error)
	// Get returns nil, nil when the object does not exist.
	Get(ctx context.Context, gvr schema.GroupVersionResource, ns, name string) (*unstructured.Unstructured, error)
	// Apply is a server-side apply with the engine's field manager, forced
	// (the engine owns what Git declares), optionally as a dry run.
	Apply(ctx context.Context, gvr schema.GroupVersionResource, ns string, obj *unstructured.Unstructured, dryRun bool) (*unstructured.Unstructured, error)
	Delete(ctx context.Context, gvr schema.GroupVersionResource, ns, name string) error
}

// ---- reading the repository ----------------------------------------------------

type gitopsManifest struct {
	Obj  *unstructured.Unstructured
	File string
}

// readManifests reads every Kubernetes object under dir.
func readManifests(dir string) ([]gitopsManifest, error) {
	return readManifestsFiltered(dir, nil, nil)
}

// readManifestsFiltered reads the YAML files under dir that the include
// globs admit (all, when there are none) and the exclude globs do not.
// Kustomization files and Helm charts below dir are skipped: they are not
// plain manifests, and an application points at them directly instead.
func readManifestsFiltered(dir string, include, exclude []string) ([]gitopsManifest, error) {
	var out []gitopsManifest
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel := relPath(dir, p)
		if d.IsDir() {
			if p == dir {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") || isHelmChart(p) || globMatch(exclude, rel) {
				return filepath.SkipDir
			}
			return nil
		}
		name := d.Name()
		if !isYAML(name) || name == "kustomization.yaml" || name == "kustomization.yml" {
			return nil
		}
		if (len(include) > 0 && !globMatch(include, rel)) || globMatch(exclude, rel) {
			return nil
		}
		m, err := readManifestFile(p, rel)
		if err != nil {
			return err
		}
		out = append(out, m...)
		return nil
	})
	return out, err
}

func relPath(base, p string) string {
	if r, err := filepath.Rel(base, p); err == nil {
		return r
	}
	return p
}

// ---- preparing what will be applied -----------------------------------------------

// gitopsTarget is one object the application declares, resolved.
type gitopsTarget struct {
	Obj        *unstructured.Unstructured
	GVR        schema.GroupVersionResource
	File       string
	trackingID string
}

type gitopsResult struct {
	Group, Version, Kind, Namespace, Name string
	Status, Health, Message, Diff         string
	Applied                               bool
}

func (r gitopsResult) key() string {
	return r.Group + "/" + r.Kind + "/" + r.Namespace + "/" + r.Name
}

func trackingID(app, group, kind, ns, name string) string {
	return fmt.Sprintf("%s:%s/%s:%s/%s", app, group, kind, ns, name)
}

// prepareTargets resolves and checks every manifest against the engine's
// rules, and stamps it with the tracking label and annotation. What breaks
// a rule comes back as an Invalid result instead of being applied.
func prepareTargets(app *models.GitOpsApp, kube gitopsKube, manifests []gitopsManifest) ([]gitopsTarget, []gitopsResult) {
	var targets []gitopsTarget
	var invalid []gitopsResult
	seen := map[string]string{}
	for _, m := range manifests {
		obj := m.Obj
		gvk := obj.GroupVersionKind()
		res := gitopsResult{Group: gvk.Group, Version: gvk.Version, Kind: gvk.Kind, Namespace: obj.GetNamespace(), Name: obj.GetName(), Status: ResInvalid, Health: GHealthUnknown}
		fail := func(msg string) { res.Message = m.File + ": " + msg; invalid = append(invalid, res) }

		if obj.GetName() == "" {
			if obj.GetGenerateName() != "" {
				fail("generateName is not supported: every object needs a fixed name to be kept in sync")
			} else {
				fail("the object has no metadata.name")
			}
			continue
		}
		gvr, namespaced, err := kube.Mapping(gvk)
		if err != nil {
			fail(fmt.Sprintf("the cluster does not know %s %s (%s)", gvk.GroupVersion(), gvk.Kind, unknownKindHint))
			continue
		}
		switch {
		case !namespaced && !app.ClusterScope:
			fail(fmt.Sprintf("%s is cluster-scoped; turn on cluster scope for this application to manage it", gvk.Kind))
			continue
		case !namespaced:
			obj.SetNamespace("")
		case obj.GetNamespace() == "":
			obj.SetNamespace(app.Namespace)
		case obj.GetNamespace() != app.Namespace && !app.ClusterScope:
			fail(fmt.Sprintf("it is in namespace %s; this application deploys to %s (turn on cluster scope to allow other namespaces)", obj.GetNamespace(), app.Namespace))
			continue
		}
		res.Namespace = obj.GetNamespace()
		k := res.key()
		if prev, dup := seen[k]; dup {
			fail(fmt.Sprintf("%s %s is also declared in %s", gvk.Kind, obj.GetName(), prev))
			continue
		}
		seen[k] = m.File

		id := trackingID(app.Name, gvk.Group, gvk.Kind, app.Namespace, obj.GetName())
		labels := obj.GetLabels()
		if labels == nil {
			labels = map[string]string{}
		}
		labels[gitopsTrackingLabel] = app.Name
		obj.SetLabels(labels)
		ann := obj.GetAnnotations()
		if ann == nil {
			ann = map[string]string{}
		}
		ann[gitopsTrackingIDAnnot] = id
		obj.SetAnnotations(ann)

		targets = append(targets, gitopsTarget{Obj: obj, GVR: gvr, File: m.File, trackingID: id})
	}
	return targets, invalid
}

// ---- comparing ---------------------------------------------------------------------

// normalizeForDiff drops what changes without anyone changing the object:
// bookkeeping the API server writes, and status, which the engine does not
// declare. What is left is what Git and the cluster can disagree on.
func normalizeForDiff(obj *unstructured.Unstructured) *unstructured.Unstructured {
	o := obj.DeepCopy()
	for _, f := range [][]string{
		{"metadata", "managedFields"}, {"metadata", "resourceVersion"}, {"metadata", "generation"},
		{"metadata", "uid"}, {"metadata", "creationTimestamp"}, {"metadata", "selfLink"}, {"status"},
	} {
		unstructured.RemoveNestedField(o.Object, f...)
	}
	return o
}

func gitopsYAML(obj *unstructured.Unstructured) string {
	b, err := yaml.Marshal(obj.Object)
	if err != nil {
		return fmt.Sprintf("# could not render: %v\n", err)
	}
	return string(b)
}

// compareApp is one refresh: every declared object against the cluster, plus
// every object the engine applied before that Git no longer declares.
func compareApp(ctx context.Context, app *models.GitOpsApp, kube gitopsKube, manifests []gitopsManifest, inventory []models.GitOpsResource) []gitopsResult {
	targets, results := prepareTargets(app, kube, manifests)
	declared := map[string]bool{}
	applied := map[string]bool{}
	for _, r := range inventory {
		if r.Applied {
			applied[r.Group+"/"+r.Kind+"/"+r.Namespace+"/"+r.Name] = true
		}
	}

	for _, t := range targets {
		gvk := t.Obj.GroupVersionKind()
		res := gitopsResult{Group: gvk.Group, Version: gvk.Version, Kind: gvk.Kind, Namespace: t.Obj.GetNamespace(), Name: t.Obj.GetName()}
		declared[res.key()] = true
		res.Applied = applied[res.key()]

		live, err := kube.Get(ctx, t.GVR, t.Obj.GetNamespace(), t.Obj.GetName())
		if err != nil {
			res.Status, res.Health, res.Message = ResInvalid, GHealthUnknown, err.Error()
			results = append(results, res)
			continue
		}
		predicted, err := kube.Apply(ctx, t.GVR, t.Obj.GetNamespace(), t.Obj, true)
		if err != nil {
			// The API server refused it: a schema error, an admission
			// policy, a missing namespace. That is validation, and it is the
			// message the person needs.
			res.Status, res.Health, res.Message = ResInvalid, GHealthUnknown, t.File+": "+apiMessage(err)
			results = append(results, res)
			continue
		}
		if live == nil {
			res.Status, res.Health, res.Message = ResMissing, GHealthMissing, "declared in "+t.File+", not in the cluster yet"
			results = append(results, res)
			continue
		}
		res.Health, res.Message = gitopsObjectHealth(live)
		a, b := gitopsYAML(normalizeForDiff(live)), gitopsYAML(normalizeForDiff(predicted))
		if a == b {
			res.Status = ResSynced
		} else {
			res.Status = ResOutOfSync
			res.Diff = unifiedDiff(a, b, 3)
		}
		results = append(results, res)
	}

	// What the engine applied and Git no longer declares.
	for _, r := range inventory {
		k := r.Group + "/" + r.Kind + "/" + r.Namespace + "/" + r.Name
		if !r.Applied || declared[k] {
			continue
		}
		gvr, _, err := kube.Mapping(schema.GroupVersionKind{Group: r.Group, Version: r.Version, Kind: r.Kind})
		if err != nil {
			continue
		}
		live, err := kube.Get(ctx, gvr, r.Namespace, r.Name)
		if err != nil || live == nil {
			continue // already gone
		}
		if live.GetAnnotations()[gitopsTrackingIDAnnot] != trackingID(app.Name, r.Group, r.Kind, r.Namespace, r.Name) {
			continue // someone else owns it now; never the engine's to delete
		}
		h, _ := gitopsObjectHealth(live)
		results = append(results, gitopsResult{Group: r.Group, Version: r.Version, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name,
			Status: ResExtraneous, Health: h, Applied: true, Message: "removed from Git; deleted on the next sync when prune is on"})
	}

	sort.SliceStable(results, func(i, j int) bool {
		return lessByKindOrder(results[i].Kind, results[i].Name, results[j].Kind, results[j].Name)
	})
	return results
}

// summarize turns the per-object results into the application's status.
func summarize(results []gitopsResult) (sync, health, message string) {
	sync, health = ResSynced, GHealthHealthy
	invalid := 0
	for _, r := range results {
		switch r.Status {
		case ResOutOfSync, ResMissing, ResExtraneous:
			sync = ResOutOfSync
		case ResInvalid:
			invalid++
		}
		if r.Status != ResInvalid {
			health = gitopsWorseHealth(health, r.Health)
		}
	}
	if invalid > 0 {
		sync = "Unknown"
		message = fmt.Sprintf("%d object(s) cannot be applied", invalid)
	}
	if len(results) == 0 {
		sync, health, message = "Unknown", GHealthUnknown, "the path has no Kubernetes objects"
	}
	return sync, health, message
}

func apiMessage(err error) string {
	var st apierrors.APIStatus
	if errors.As(err, &st) {
		return st.Status().Message
	}
	return err.Error()
}

// ---- syncing -----------------------------------------------------------------------

// kindOrder is the order in which kinds are applied, from gitops-engine
// (pkg/sync/sync_tasks.go, Apache-2.0): namespaces and CRDs before what
// lives in them, config before the workloads that read it. Kinds it does
// not list -- custom resources -- go last.
var gitopsKindOrder = func() map[string]int {
	kinds := []string{
		"Namespace", "NetworkPolicy", "ResourceQuota", "LimitRange", "PodSecurityPolicy", "PodDisruptionBudget",
		"ServiceAccount", "Secret", "SecretList", "ConfigMap", "StorageClass", "PersistentVolume",
		"PersistentVolumeClaim", "CustomResourceDefinition", "ClusterRole", "ClusterRoleList",
		"ClusterRoleBinding", "ClusterRoleBindingList", "Role", "RoleList", "RoleBinding", "RoleBindingList",
		"Service", "DaemonSet", "Pod", "ReplicationController", "ReplicaSet", "Deployment",
		"HorizontalPodAutoscaler", "StatefulSet", "Job", "CronJob", "IngressClass", "Ingress", "APIService",
	}
	m := map[string]int{}
	for i, k := range kinds {
		m[k] = i - len(kinds) // all negative, so unknown kinds (0) sort last
	}
	return m
}()

// unknownKindHint ends the message for a kind the cluster does not serve;
// a sync recognizes it to retry once the CRDs it applied are established.
const unknownKindHint = "is its CRD installed?"

func lessByKindOrder(kindA, nameA, kindB, nameB string) bool {
	if d := gitopsKindOrder[kindA] - gitopsKindOrder[kindB]; d != 0 {
		return d < 0
	}
	return nameA < nameB
}

type gitopsSyncOutcome struct {
	Lines  []string
	Failed bool
	// Applied and Pruned feed the inventory.
	Applied []gitopsResult
	Pruned  []gitopsResult
}

// syncApp applies every declared object in kind order and, when the app
// prunes, deletes what the engine applied before and Git no longer has.
// An object that fails does not stop the others: one bad Ingress should not
// hold back the Deployment fix that is the reason for the sync.
func syncApp(ctx context.Context, app *models.GitOpsApp, kube gitopsKube, manifests []gitopsManifest, inventory []models.GitOpsResource) gitopsSyncOutcome {
	var out gitopsSyncOutcome
	targets, invalid := prepareTargets(app, kube, manifests)
	for _, r := range invalid {
		out.Failed = true
		out.Lines = append(out.Lines, fmt.Sprintf("skipped %s %s: %s", r.Kind, r.Name, r.Message))
	}
	sort.SliceStable(targets, func(i, j int) bool {
		return lessByKindOrder(targets[i].Obj.GetKind(), targets[i].Obj.GetName(), targets[j].Obj.GetKind(), targets[j].Obj.GetName())
	})

	declared := map[string]bool{}
	for _, t := range targets {
		gvk := t.Obj.GroupVersionKind()
		res := gitopsResult{Group: gvk.Group, Version: gvk.Version, Kind: gvk.Kind, Namespace: t.Obj.GetNamespace(), Name: t.Obj.GetName()}
		declared[res.key()] = true
		if _, err := kube.Apply(ctx, t.GVR, t.Obj.GetNamespace(), t.Obj, false); err != nil {
			out.Failed = true
			out.Lines = append(out.Lines, fmt.Sprintf("failed %s %s: %s", gvk.Kind, t.Obj.GetName(), apiMessage(err)))
			continue
		}
		res.Applied = true
		out.Applied = append(out.Applied, res)
		out.Lines = append(out.Lines, fmt.Sprintf("applied %s %s", gvk.Kind, t.Obj.GetName()))
	}

	for _, r := range inventory {
		k := r.Group + "/" + r.Kind + "/" + r.Namespace + "/" + r.Name
		if !r.Applied || declared[k] {
			continue
		}
		gvr, _, err := kube.Mapping(schema.GroupVersionKind{Group: r.Group, Version: r.Version, Kind: r.Kind})
		if err != nil {
			continue
		}
		live, err := kube.Get(ctx, gvr, r.Namespace, r.Name)
		if err != nil || live == nil {
			out.Pruned = append(out.Pruned, gitopsResult{Group: r.Group, Version: r.Version, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name})
			continue
		}
		if live.GetAnnotations()[gitopsTrackingIDAnnot] != trackingID(app.Name, r.Group, r.Kind, r.Namespace, r.Name) {
			out.Lines = append(out.Lines, fmt.Sprintf("left %s %s: it no longer carries this application's tracking id", r.Kind, r.Name))
			out.Pruned = append(out.Pruned, gitopsResult{Group: r.Group, Version: r.Version, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name})
			continue
		}
		if !app.Prune {
			out.Lines = append(out.Lines, fmt.Sprintf("kept %s %s: removed from Git, prune is off", r.Kind, r.Name))
			continue
		}
		if err := kube.Delete(ctx, gvr, r.Namespace, r.Name); err != nil && !apierrors.IsNotFound(err) {
			out.Failed = true
			out.Lines = append(out.Lines, fmt.Sprintf("failed to prune %s %s: %s", r.Kind, r.Name, apiMessage(err)))
			continue
		}
		out.Pruned = append(out.Pruned, gitopsResult{Group: r.Group, Version: r.Version, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name})
		out.Lines = append(out.Lines, fmt.Sprintf("pruned %s %s", r.Kind, r.Name))
	}
	return out
}

// ---- diff ----------------------------------------------------------------------------

// unifiedDiff is a line diff of a against b with context lines, in the
// familiar -/+ form. Objects are small; a plain LCS is enough.
func unifiedDiff(a, b string, context int) string {
	x, y := strings.Split(strings.TrimRight(a, "\n"), "\n"), strings.Split(strings.TrimRight(b, "\n"), "\n")
	if len(x)*len(y) > 4_000_000 {
		return "(object too large to diff here)"
	}
	n, m := len(x), len(y)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if x[i] == y[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	type line struct {
		op   byte
		text string
	}
	var ops []line
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case x[i] == y[j]:
			ops = append(ops, line{' ', x[i]})
			i, j = i+1, j+1
		case lcs[i+1][j] >= lcs[i][j+1]:
			ops = append(ops, line{'-', x[i]})
			i++
		default:
			ops = append(ops, line{'+', y[j]})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, line{'-', x[i]})
	}
	for ; j < m; j++ {
		ops = append(ops, line{'+', y[j]})
	}
	// Keep changed lines and their context; mark skipped runs.
	keep := make([]bool, len(ops))
	for k, o := range ops {
		if o.op != ' ' {
			for d := -context; d <= context; d++ {
				if k+d >= 0 && k+d < len(ops) {
					keep[k+d] = true
				}
			}
		}
	}
	var b2 strings.Builder
	skipped := false
	for k, o := range ops {
		if !keep[k] {
			skipped = true
			continue
		}
		if skipped {
			b2.WriteString("…\n")
			skipped = false
		}
		b2.WriteByte(o.op)
		b2.WriteByte(' ')
		b2.WriteString(o.text)
		b2.WriteByte('\n')
	}
	return b2.String()
}
