package handlers

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/kubecommit/backend/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
	"k8s.io/client-go/tools/clientcmd"
)

// Runs the engine against a real API server: the server-side dry run, the
// defaults it fills in, the annotations controllers add -- the things a fake
// cannot show. Skipped unless GITOPS_KUBECONFIG points at a disposable
// cluster (kind create cluster --kubeconfig ...).
func TestGitopsAgainstARealCluster(t *testing.T) {
	kc := os.Getenv("GITOPS_KUBECONFIG")
	if kc == "" {
		t.Skip("GITOPS_KUBECONFIG not set")
	}
	cfg, err := clientcmd.BuildConfigFromFlags("", kc)
	if err != nil {
		t.Fatal(err)
	}
	typed := kubernetes.NewForConfigOrDie(cfg)
	dyn := dynamic.NewForConfigOrDie(cfg)
	groups, err := restmapper.GetAPIGroupResources(typed.Discovery())
	if err != nil {
		t.Fatal(err)
	}
	kube := &dynamicKube{dyn: dyn, mapper: restmapper.NewDiscoveryRESTMapper(groups)}
	ctx := context.Background()

	ns := "gitops-it-" + time.Now().Format("150405")
	if _, err := typed.CoreV1().Namespaces().Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { typed.CoreV1().Namespaces().Delete(context.Background(), ns, metav1.DeleteOptions{}) })

	app := &models.GitOpsApp{Name: "web", Namespace: ns, Prune: true}
	repo := t.TempDir()
	write := func(files map[string]string) []gitopsManifest {
		os.RemoveAll(repo)
		for p, c := range files {
			os.MkdirAll(filepath.Dir(filepath.Join(repo, p)), 0o755)
			os.WriteFile(filepath.Join(repo, p), []byte(c), 0o644)
		}
		m, err := readManifests(repo)
		if err != nil {
			t.Fatal(err)
		}
		return m
	}
	deploy := `apiVersion: apps/v1
kind: Deployment
metadata:
  name: web
spec:
  replicas: 1
  selector:
    matchLabels: {app: web}
  template:
    metadata:
      labels: {app: web}
    spec:
      containers:
        - name: web
          image: registry.k8s.io/pause:3.9
`
	svc := `apiVersion: v1
kind: Service
metadata:
  name: web
spec:
  selector: {app: web}
  ports:
    - port: 80
`
	cm := `apiVersion: v1
kind: ConfigMap
metadata:
  name: web-config
data:
  LOG_LEVEL: info
`
	all := write(map[string]string{"deploy.yaml": deploy, "svc.yaml": svc, "cm.yaml": cm})

	res := compareApp(ctx, app, kube, all, nil)
	for _, r := range res {
		if r.Status != ResMissing {
			t.Fatalf("before sync %s/%s = %s %s", r.Kind, r.Name, r.Status, r.Message)
		}
	}
	out := syncApp(ctx, app, kube, all, nil)
	if out.Failed {
		t.Fatalf("sync failed: %v", out.Lines)
	}
	inv := []models.GitOpsResource{}
	for _, a := range out.Applied {
		inv = append(inv, models.GitOpsResource{Group: a.Group, Version: a.Version, Kind: a.Kind, Namespace: a.Namespace, Name: a.Name, Applied: true})
	}

	// Wait for the Deployment to roll out; meanwhile it is Progressing.
	deadline := time.Now().Add(150 * time.Second)
	var health string
	for time.Now().Before(deadline) {
		res = compareApp(ctx, app, kube, all, inv)
		_, health, _ = summarize(res)
		if health == GHealthHealthy {
			break
		}
		time.Sleep(3 * time.Second)
	}
	if health != GHealthHealthy {
		t.Fatalf("never healthy: %+v", res)
	}
	// The controller has now written status, the revision annotation and
	// its own managed fields. None of that is drift.
	for _, r := range res {
		if r.Status != ResSynced {
			t.Fatalf("after rollout %s/%s = %s\n%s", r.Kind, r.Name, r.Status, r.Diff)
		}
	}

	// Someone scales it by hand, with kubectl's field manager: drift.
	if _, err := typed.AppsV1().Deployments(ns).Patch(ctx, "web", types.MergePatchType, []byte(`{"spec":{"replicas":3}}`), metav1.PatchOptions{FieldManager: "kubectl-edit"}); err != nil {
		t.Fatal(err)
	}
	res = compareApp(ctx, app, kube, all, inv)
	d := byKind(res, "Deployment")
	if d.Status != ResOutOfSync || !strings.Contains(d.Diff, "replicas: 3") {
		t.Fatalf("hand edit not seen as drift: %+v", d)
	}
	if out := syncApp(ctx, app, kube, all, inv); out.Failed {
		t.Fatalf("self-heal sync: %v", out.Lines)
	}
	live, _ := typed.AppsV1().Deployments(ns).Get(ctx, "web", metav1.GetOptions{})
	if *live.Spec.Replicas != 1 {
		t.Fatalf("replicas after heal = %d", *live.Spec.Replicas)
	}

	// The ConfigMap leaves Git: extraneous, then pruned.
	noCM := write(map[string]string{"deploy.yaml": deploy, "svc.yaml": svc})
	if r := byKind(compareApp(ctx, app, kube, noCM, inv), "ConfigMap"); r.Status != ResExtraneous {
		t.Fatalf("configmap: %+v", r)
	}
	if out := syncApp(ctx, app, kube, noCM, inv); len(out.Pruned) != 1 {
		t.Fatalf("prune: %+v", out)
	}
	if _, err := typed.CoreV1().ConfigMaps(ns).Get(ctx, "web-config", metav1.GetOptions{}); err == nil {
		t.Fatal("the configmap is still there")
	}

	// A manifest the API server rejects is reported, not applied.
	bad := write(map[string]string{"deploy.yaml": strings.Replace(deploy, "replicas: 1", "replicas: lots", 1)})
	r := byKind(compareApp(ctx, app, kube, bad, inv), "Deployment")
	if r.Status != ResInvalid || r.Message == "" {
		t.Fatalf("invalid manifest: %+v", r)
	}
	t.Logf("server said: %s", r.Message)
	_ = schema.GroupVersionResource{}
}
