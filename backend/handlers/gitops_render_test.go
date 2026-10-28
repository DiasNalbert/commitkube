package handlers

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kubecommit/backend/models"
)

func manifestNames(ms []gitopsManifest) string {
	var names []string
	for _, m := range ms {
		names = append(names, m.Obj.GetKind()+"/"+m.Obj.GetName())
	}
	return strings.Join(names, ",")
}

const cm = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: %s\n"

func cmNamed(n string) string { return strings.Replace(cm, "%s", n, 1) }

func TestDirectorySkipsWhatIsNotAPlainManifest(t *testing.T) {
	dir := writeRepo(t, map[string]string{
		"a.yaml":                       cmNamed("a"),
		"kustomization.yaml":           "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [a.yaml]\n",
		"chart/Chart.yaml":             "apiVersion: v2\nname: c\nversion: 0.1.0\n",
		"chart/templates/x.yaml":       "{{ .Values.broken }}",
		"nested/b.yml":                 cmNamed("b"),
		"nested/deeper/c.yaml":         cmNamed("c"),
		"nested/deeper/values.yaml":    "replicas: 2\n",
		"nested/deeper/.git/HEAD.yaml": cmNamed("git"),
	})
	got, err := readManifests(dir)
	if err != nil {
		t.Fatal(err)
	}
	if manifestNames(got) != "ConfigMap/a,ConfigMap/b,ConfigMap/c" {
		t.Fatalf("manifests = %s", manifestNames(got))
	}
}

func TestIncludeAndExcludeGlobs(t *testing.T) {
	dir := writeRepo(t, map[string]string{
		"app.yaml":           cmNamed("app"),
		"app.test.yaml":      cmNamed("test"),
		"prod/db.yaml":       cmNamed("prod-db"),
		"staging/db.yaml":    cmNamed("staging-db"),
		"staging/extra.yaml": cmNamed("staging-extra"),
	})
	cases := []struct{ include, exclude, want string }{
		{"", "", "ConfigMap/test,ConfigMap/app,ConfigMap/prod-db,ConfigMap/staging-db,ConfigMap/staging-extra"},
		{"", "*.test.yaml, staging/**", "ConfigMap/app,ConfigMap/prod-db"},
		{"prod/*", "", "ConfigMap/prod-db"},
		{"db.yaml", "", "ConfigMap/prod-db,ConfigMap/staging-db"},
	}
	for _, c := range cases {
		got, err := readManifestsFiltered(dir, splitGlobs(c.include), splitGlobs(c.exclude))
		if err != nil {
			t.Fatal(err)
		}
		if manifestNames(got) != c.want {
			t.Errorf("include=%q exclude=%q: %s, want %s", c.include, c.exclude, manifestNames(got), c.want)
		}
	}
}

func TestRenderAppDetectsTheSource(t *testing.T) {
	root := writeRepo(t, map[string]string{
		"k8s/a.yaml":              cmNamed("a"),
		"k8s/b.yaml":              cmNamed("b"),
		"one/only.yaml":           cmNamed("only"),
		"kust/kustomization.yaml": "resources: [a.yaml]\n",
		"empty/README.md":         "nothing",
	})
	ctx := context.Background()
	app := &models.GitOpsApp{Name: "x", Namespace: "ns", Path: "k8s"}
	got, kind, err := renderApp(ctx, app, root)
	if err != nil || kind != SourceDirectory || manifestNames(got) != "ConfigMap/a,ConfigMap/b" {
		t.Fatalf("dir: %s %s %v", manifestNames(got), kind, err)
	}
	app.Path = "one/only.yaml"
	got, kind, err = renderApp(ctx, app, root)
	if err != nil || kind != SourceDirectory || manifestNames(got) != "ConfigMap/only" {
		t.Fatalf("file: %s %s %v", manifestNames(got), kind, err)
	}
	if detectSourceType(filepath.Join(root, "kust")) != SourceKustomize {
		t.Fatal("kustomization.yaml not detected")
	}
	if detectSourceType(filepath.Join(root, "empty")) != "" {
		t.Fatal("a directory without manifests was detected as one")
	}
	app.Path, app.SourceType = "k8s", SourceHelm
	if _, _, err := renderApp(ctx, app, root); err == nil || !strings.Contains(err.Error(), "Chart.yaml") {
		t.Fatalf("helm without a chart: %v", err)
	}
}

func TestRenderHelm(t *testing.T) {
	if _, err := exec.LookPath("helm"); err != nil {
		t.Skip("helm not installed")
	}
	root := writeRepo(t, map[string]string{
		"charts/web/Chart.yaml":  "apiVersion: v2\nname: web\nversion: 0.1.0\n",
		"charts/web/values.yaml": "replicas: 1\nextra: false\n",
		"charts/web/templates/cm.yaml": `apiVersion: v1
kind: ConfigMap
metadata:
  name: {{ .Release.Name }}-config
data:
  replicas: "{{ .Values.replicas }}"
  ns: {{ .Release.Namespace }}
`,
		"charts/web/templates/extra.yaml": "{{ if .Values.extra }}\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: extra\n{{ end }}\n",
		"envs/prod.yaml":                  "replicas: 5\n",
	})
	app := &models.GitOpsApp{Name: "shop", Namespace: "prod", Path: "charts/web", SourceType: SourceAuto,
		HelmValueFiles: "envs/prod.yaml", HelmValues: "extra: true\n"}
	got, kind, err := renderApp(context.Background(), app, root)
	if err != nil {
		t.Fatal(err)
	}
	if kind != SourceHelm || manifestNames(got) != "ConfigMap/shop-config,ConfigMap/extra" {
		t.Fatalf("%s %s", kind, manifestNames(got))
	}
	data := got[0].Obj.Object["data"].(map[string]any)
	if data["replicas"] != "5" || data["ns"] != "prod" {
		t.Fatalf("values not applied: %v", data)
	}
	if got[0].File != "web/templates/cm.yaml" {
		t.Fatalf("object attributed to %q, want its template", got[0].File)
	}

	app.HelmValueFiles = "../../../etc/passwd"
	if _, _, err := renderApp(context.Background(), app, root); err == nil {
		t.Fatal("a values file outside the repository was read")
	}
}

func TestEscapingSymlinksAreDropped(t *testing.T) {
	root := writeRepo(t, map[string]string{"k8s/a.yaml": cmNamed("a")})
	outside := filepath.Join(t.TempDir(), "secret.yaml")
	os.WriteFile(outside, []byte(cmNamed("secret")), 0o644)
	os.Symlink(outside, filepath.Join(root, "k8s/leak.yaml"))
	os.Symlink(filepath.Join(root, "k8s/a.yaml"), filepath.Join(root, "k8s/inside.yaml"))
	if err := dropEscapingSymlinks(root); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(root, "k8s/leak.yaml")); !os.IsNotExist(err) {
		t.Fatal("a symlink out of the checkout survived")
	}
	if _, err := os.Lstat(filepath.Join(root, "k8s/inside.yaml")); err != nil {
		t.Fatal("a symlink inside the checkout was removed")
	}
}

func TestCheckoutAndTreeFromALocalRepository(t *testing.T) {
	src := writeRepo(t, map[string]string{
		"deploy/app.yaml":             cmNamed("app"),
		"deploy/kustomization.yaml":   "resources: [app.yaml]\n",
		"charts/web/Chart.yaml":       "apiVersion: v2\nname: web\nversion: 0.1.0\n",
		"charts/web/templates/a.yaml": cmNamed("tpl"),
		"envs/prod.yaml":              "replicas: 4\n",
		"docs/readme.md":              "x",
	})
	for _, args := range [][]string{{"init", "-q", "-b", "main"}, {"add", "."}, {"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-qm", "init"}} {
		if out, err := exec.Command("git", append([]string{"-C", src}, args...)...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %s", args, out)
		}
	}
	key := filepath.Join(t.TempDir(), "key")
	os.WriteFile(key, []byte("unused"), 0o600)
	acc := &gitopsRepoAccess{url: src, keyFile: key, knownHosts: key + ".kh"}
	dir, rev, cleanup, err := gitopsCheckout(acc, "main")
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if len(rev) != 40 {
		t.Fatalf("revision %q", rev)
	}
	entries, _ := gitopsTree(dir)
	got := map[string]string{}
	for _, e := range entries {
		if e.Dir {
			got[e.Path] = "dir:" + e.Kind
		} else {
			got[e.Path] = "file"
		}
	}
	want := map[string]string{"deploy": "dir:kustomize", "deploy/app.yaml": "file", "deploy/kustomization.yaml": "file",
		"charts": "dir:", "charts/web": "dir:helm", "charts/web/Chart.yaml": "file", "docs": "dir:",
		"charts/web/templates": "dir:", "envs": "dir:"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, want %q", k, got[k], v)
		}
	}
	if _, ok := got["docs/readme.md"]; ok {
		t.Error("a non-YAML file was listed")
	}
	if _, _, _, err := gitopsCheckout(acc, "--upload-pack=touch /tmp/x"); err == nil {
		t.Fatal("an option was accepted as a branch")
	}
}

func TestRenderKustomizeOverlay(t *testing.T) {
	if _, err := exec.LookPath("kustomize"); err != nil {
		t.Skip("kustomize not installed")
	}
	root := writeRepo(t, map[string]string{
		"base/kustomization.yaml":          "resources: [cm.yaml]\n",
		"base/cm.yaml":                     cmNamed("settings"),
		"overlays/prod/kustomization.yaml": "resources: [../../base]\nnamePrefix: prod-\ncommonLabels:\n  env: prod\n",
	})
	app := &models.GitOpsApp{Name: "shop", Namespace: "prod", Path: "overlays/prod"}
	got, kind, err := renderApp(context.Background(), app, root)
	if err != nil {
		t.Fatal(err)
	}
	if kind != SourceKustomize || manifestNames(got) != "ConfigMap/prod-settings" || got[0].Obj.GetLabels()["env"] != "prod" {
		t.Fatalf("%s %s %v", kind, manifestNames(got), got[0].Obj.GetLabels())
	}
}
