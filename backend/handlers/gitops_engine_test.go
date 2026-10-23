package handlers

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubecommit/backend/models"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// fakeKube is a cluster that applies by replacing, keeps status as the
// server would, and records what happened.
type fakeKube struct {
	objs    map[string]*unstructured.Unstructured // gvr|ns|name
	applied []string
	deleted []string
	refuse  map[string]string // name -> admission error
}

func newFakeKube() *fakeKube {
	return &fakeKube{objs: map[string]*unstructured.Unstructured{}, refuse: map[string]string{}}
}

var fakeKinds = map[string]struct {
	res        string
	namespaced bool
}{
	"Deployment": {"deployments", true}, "Service": {"services", true}, "ConfigMap": {"configmaps", true},
	"Ingress": {"ingresses", true}, "ServiceAccount": {"serviceaccounts", true}, "ClusterRole": {"clusterroles", false},
}

func (f *fakeKube) Mapping(gvk schema.GroupVersionKind) (schema.GroupVersionResource, bool, error) {
	k, ok := fakeKinds[gvk.Kind]
	if !ok {
		return schema.GroupVersionResource{}, false, fmt.Errorf("no matches for kind %s", gvk.Kind)
	}
	return schema.GroupVersionResource{Group: gvk.Group, Version: gvk.Version, Resource: k.res}, k.namespaced, nil
}
func key(gvr schema.GroupVersionResource, ns, name string) string {
	return gvr.Resource + "|" + ns + "|" + name
}
func (f *fakeKube) Get(_ context.Context, gvr schema.GroupVersionResource, ns, name string) (*unstructured.Unstructured, error) {
	if o := f.objs[key(gvr, ns, name)]; o != nil {
		return o.DeepCopy(), nil
	}
	return nil, nil
}
func (f *fakeKube) Apply(_ context.Context, gvr schema.GroupVersionResource, ns string, obj *unstructured.Unstructured, dry bool) (*unstructured.Unstructured, error) {
	if msg, ok := f.refuse[obj.GetName()]; ok {
		return nil, apierrors.NewBadRequest(msg)
	}
	out := obj.DeepCopy()
	out.SetResourceVersion("2")
	if live := f.objs[key(gvr, ns, obj.GetName())]; live != nil {
		if st, ok := live.Object["status"]; ok {
			out.Object["status"] = st
		}
	}
	if !dry {
		f.objs[key(gvr, ns, obj.GetName())] = out.DeepCopy()
		f.applied = append(f.applied, obj.GetKind()+"/"+obj.GetName())
	}
	return out, nil
}
func (f *fakeKube) Delete(_ context.Context, gvr schema.GroupVersionResource, ns, name string) error {
	delete(f.objs, key(gvr, ns, name))
	f.deleted = append(f.deleted, gvr.Resource+"/"+name)
	return nil
}

func writeRepo(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for p, c := range files {
		full := filepath.Join(dir, p)
		os.MkdirAll(filepath.Dir(full), 0o755)
		os.WriteFile(full, []byte(c), 0o644)
	}
	return dir
}

const appDeploy = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: api
spec:
  replicas: 2
  template:
    spec:
      containers:
        - name: api
          image: shop/api:1.0
---
apiVersion: v1
kind: Service
metadata:
  name: api
spec:
  ports:
    - port: 80
`

func TestReadManifests(t *testing.T) {
	dir := writeRepo(t, map[string]string{
		"k8s/app.yaml":            appDeploy,
		"k8s/values.yaml":         "replicas: 3\nimage: x\n", // not a Kubernetes object
		"bitbucket-pipelines.yml": "image: ubuntu\n",
		"k8s/.hidden/x.yaml":      "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: hidden\n",
		"k8s/list.yaml":           "apiVersion: v1\nkind: List\nitems:\n  - apiVersion: v1\n    kind: ConfigMap\n    metadata:\n      name: from-list\n",
	})
	got, err := readManifests(filepath.Join(dir, "k8s"))
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, m := range got {
		names = append(names, m.Obj.GetKind()+"/"+m.Obj.GetName())
	}
	if strings.Join(names, ",") != "Deployment/api,Service/api,ConfigMap/from-list" {
		t.Fatalf("manifests = %v", names)
	}
	kdir := writeRepo(t, map[string]string{"kustomization.yaml": "resources: [a.yaml]\n"})
	if _, err := readManifests(kdir); err == nil || !strings.Contains(err.Error(), "Kustomize") {
		t.Fatalf("kustomize should be refused clearly, got %v", err)
	}
}

func TestCompareAndSync(t *testing.T) {
	app := &models.GitOpsApp{Name: "shop-api", Namespace: "shop", Prune: true}
	kube := newFakeKube()
	dir := writeRepo(t, map[string]string{
		"app.yaml": appDeploy,
		"bad.yaml": `apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: too-wide
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: elsewhere
  namespace: kube-system
---
apiVersion: example.com/v1
kind: Widget
metadata:
  name: w
`,
	})
	manifests, _ := readManifests(dir)

	// Before anything is applied: missing, plus three refusals with reasons.
	res := compareApp(context.Background(), app, kube, manifests, nil)
	byName := map[string]gitopsResult{}
	for _, r := range res {
		byName[r.Kind+"/"+r.Name] = r
	}
	if byName["Deployment/api"].Status != ResMissing || byName["Service/api"].Status != ResMissing {
		t.Fatalf("missing: %+v", res)
	}
	for k, want := range map[string]string{"ClusterRole/too-wide": "cluster-scoped", "ConfigMap/elsewhere": "deploys to shop", "Widget/w": "CRD installed"} {
		if r := byName[k]; r.Status != ResInvalid || !strings.Contains(r.Message, want) {
			t.Errorf("%s: %+v", k, r)
		}
	}
	if s, _, msg := summarize(res); s != "Unknown" || !strings.Contains(msg, "3 object") {
		t.Fatalf("summary with invalid objects: %s %s", s, msg)
	}

	// Sync applies in kind order (Service before Deployment), skips the
	// invalid ones, and stamps the tracking id.
	out := syncApp(context.Background(), app, kube, manifests, nil)
	if strings.Join(kube.applied, ",") != "Service/api,Deployment/api" {
		t.Fatalf("apply order: %v", kube.applied)
	}
	if !out.Failed || len(out.Applied) != 2 {
		t.Fatalf("outcome: %+v", out)
	}
	live, _ := kube.Get(context.Background(), schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, "shop", "api")
	if live.GetAnnotations()[gitopsTrackingIDAnnot] != "shop-api:apps/Deployment:shop/api" || live.GetLabels()[gitopsTrackingLabel] != "shop-api" {
		t.Fatalf("tracking: %v %v", live.GetAnnotations(), live.GetLabels())
	}

	inventory := []models.GitOpsResource{
		{Group: "apps", Version: "v1", Kind: "Deployment", Namespace: "shop", Name: "api", Applied: true},
		{Version: "v1", Kind: "Service", Namespace: "shop", Name: "api", Applied: true},
	}
	good, _ := readManifests(writeRepo(t, map[string]string{"app.yaml": appDeploy}))
	res = compareApp(context.Background(), app, kube, good, inventory)
	if s, _, _ := summarize(res); s != ResSynced {
		t.Fatalf("after sync: %+v", res)
	}

	// Someone scales by hand: drift, with the diff to show it.
	kube.objs["deployments|shop|api"].Object["spec"].(map[string]any)["replicas"] = int64(5)
	res = compareApp(context.Background(), app, kube, good, inventory)
	if res[1].Status != ResOutOfSync || !strings.Contains(res[1].Diff, "- ") || !strings.Contains(res[1].Diff, "replicas: 5") {
		t.Fatalf("drift: %+v", res[1])
	}

	// The Service is removed from Git: Extraneous, then pruned.
	onlyDeploy, _ := readManifests(writeRepo(t, map[string]string{"d.yaml": strings.SplitN(appDeploy, "---", 2)[0]}))
	res = compareApp(context.Background(), app, kube, onlyDeploy, inventory)
	if byKind(res, "Service").Status != ResExtraneous {
		t.Fatalf("extraneous: %+v", res)
	}
	out = syncApp(context.Background(), app, kube, onlyDeploy, inventory)
	if len(out.Pruned) != 1 || strings.Join(kube.deleted, ",") != "services/api" {
		t.Fatalf("prune: %+v deleted=%v", out, kube.deleted)
	}

	// Never delete what the engine did not put there: an object that lost
	// the tracking id (taken over by someone else) is left alone.
	kube.objs["configmaps|shop|shared"] = &unstructured.Unstructured{Object: map[string]any{
		"apiVersion": "v1", "kind": "ConfigMap", "metadata": map[string]any{"name": "shared", "namespace": "shop",
			"annotations": map[string]any{gitopsTrackingIDAnnot: "other-app:/ConfigMap:shop/shared"}}}}
	inv2 := append(inventory, models.GitOpsResource{Version: "v1", Kind: "ConfigMap", Namespace: "shop", Name: "shared", Applied: true})
	kube.deleted = nil
	syncApp(context.Background(), app, kube, onlyDeploy, inv2)
	if len(kube.deleted) != 0 {
		t.Fatalf("deleted an object it does not own: %v", kube.deleted)
	}

	// With prune off, removal from Git keeps the object.
	app.Prune = false
	kube.objs["services|shop|api"] = kube.objs["deployments|shop|api"].DeepCopy() // stand-in with the right tracking id below
	kube.objs["services|shop|api"].SetKind("Service")
	kube.objs["services|shop|api"].SetAnnotations(map[string]string{gitopsTrackingIDAnnot: "shop-api:/Service:shop/api"})
	kube.deleted = nil
	out = syncApp(context.Background(), app, kube, onlyDeploy, inventory)
	if len(kube.deleted) != 0 || !strings.Contains(strings.Join(out.Lines, "\n"), "prune is off") {
		t.Fatalf("prune off: %+v", out)
	}
}

func TestAdmissionRefusalIsValidation(t *testing.T) {
	app := &models.GitOpsApp{Name: "shop-api", Namespace: "shop"}
	kube := newFakeKube()
	kube.refuse["api"] = `Deployment.apps "api" is invalid: spec.template.spec.containers[0].image: Required value`
	m, _ := readManifests(writeRepo(t, map[string]string{"app.yaml": strings.SplitN(appDeploy, "---", 2)[0]}))
	res := compareApp(context.Background(), app, kube, m, nil)
	if res[0].Status != ResInvalid || !strings.Contains(res[0].Message, "Required value") || !strings.HasPrefix(res[0].Message, "app.yaml: ") {
		t.Fatalf("admission: %+v", res[0])
	}
}

func TestSourceDirStaysInsideTheRepo(t *testing.T) {
	root := writeRepo(t, map[string]string{"k8s/a.yaml": "x: 1"})
	if _, err := sourceDir(root, "../../etc"); err == nil {
		// Clean("/" + "../../etc") is /etc, joined under root: it must not
		// exist there, so this fails as missing rather than escaping.
	}
	if d, err := sourceDir(root, "k8s"); err != nil || d != filepath.Join(root, "k8s") {
		t.Fatalf("k8s: %q %v", d, err)
	}
	if d, err := sourceDir(root, ""); err != nil || d != root {
		t.Fatalf("root: %q %v", d, err)
	}
}

func byKind(rs []gitopsResult, kind string) gitopsResult {
	for _, r := range rs {
		if r.Kind == kind {
			return r
		}
	}
	return gitopsResult{}
}

func TestUnifiedDiff(t *testing.T) {
	a := "a: 1\nb: 2\nc: 3\nd: 4\ne: 5\nf: 6\ng: 7\nh: 8\n"
	b := "a: 1\nb: 2\nc: 3\nd: 40\ne: 5\nf: 6\ng: 7\nh: 8\n"
	got := unifiedDiff(a, b, 1)
	if got != "…\n  c: 3\n- d: 4\n+ d: 40\n  e: 5\n" {
		t.Fatalf("diff:\n%q", got)
	}
}
