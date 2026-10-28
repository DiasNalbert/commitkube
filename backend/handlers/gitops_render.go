package handlers

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/kubecommit/backend/models"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	k8syaml "k8s.io/apimachinery/pkg/util/yaml"
)

// Rendering turns an application's path into the objects it declares. A
// directory is read as it is; a Kustomize root goes through kustomize build
// and a Helm chart through helm template, both run locally on the checkout
// -- neither ever talks to the cluster, so the engine's comparison and its
// scope rules apply to their output exactly as to plain manifests.

const (
	SourceAuto      = "auto"
	SourceDirectory = "directory"
	SourceKustomize = "kustomize"
	SourceHelm      = "helm"
)

var gitopsSourceTypes = map[string]bool{SourceAuto: true, SourceDirectory: true, SourceKustomize: true, SourceHelm: true}

func isYAML(name string) bool {
	return strings.HasSuffix(name, ".yaml") || strings.HasSuffix(name, ".yml")
}

func isKustomizeRoot(dir string) bool {
	for _, n := range []string{"kustomization.yaml", "kustomization.yml", "Kustomization"} {
		if st, err := os.Stat(filepath.Join(dir, n)); err == nil && !st.IsDir() {
			return true
		}
	}
	return false
}

func isHelmChart(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, "Chart.yaml"))
	return err == nil && !st.IsDir()
}

// detectSourceType is what auto makes of a directory.
func detectSourceType(dir string) string {
	switch {
	case isKustomizeRoot(dir):
		return SourceKustomize
	case isHelmChart(dir):
		return SourceHelm
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if !e.IsDir() && isYAML(e.Name()) && looksLikeManifest(filepath.Join(dir, e.Name())) {
			return SourceDirectory
		}
	}
	return ""
}

var (
	topLevelAPIVersion = regexp.MustCompile(`(?m)^apiVersion:\s*\S`)
	topLevelKind       = regexp.MustCompile(`(?m)^kind:\s*\S`)
)

// looksLikeManifest: the file declares a top-level apiVersion and kind
// somewhere in its first 64 KiB, so a directory of Helm values or CI
// configuration is not offered as something to apply.
func looksLikeManifest(p string) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	b, _ := io.ReadAll(io.LimitReader(f, 64<<10))
	return topLevelAPIVersion.Match(b) && topLevelKind.Match(b)
}

// sourcePath resolves the app's path inside the checkout, refusing one that
// leaves it. It may name a directory or a single manifest file.
func sourcePath(root, p string) (full string, isDir bool, err error) {
	clean := filepath.Clean("/" + strings.TrimSpace(p))
	full = filepath.Join(root, clean)
	if !strings.HasPrefix(full+string(filepath.Separator), root+string(filepath.Separator)) && full != root {
		return "", false, fmt.Errorf("path %q leaves the repository", p)
	}
	st, err := os.Stat(full)
	if err != nil {
		return "", false, fmt.Errorf("path %q does not exist on the branch", p)
	}
	if !st.IsDir() && !isYAML(full) {
		return "", false, fmt.Errorf("path %q is a file but not a YAML manifest", p)
	}
	return full, st.IsDir(), nil
}

// renderApp reads the app's objects from a checkout, and says how it read
// them (what auto resolved to).
func renderApp(ctx context.Context, app *models.GitOpsApp, root string) ([]gitopsManifest, string, error) {
	full, isDir, err := sourcePath(root, app.Path)
	if err != nil {
		return nil, "", err
	}
	if !isDir {
		m, err := readManifestFile(full, relPath(root, full))
		return m, SourceDirectory, err
	}
	kind := app.SourceType
	if kind == "" || kind == SourceAuto {
		kind = detectSourceType(full)
		if kind == "" {
			kind = SourceDirectory
		}
	}
	switch kind {
	case SourceKustomize:
		if !isKustomizeRoot(full) {
			return nil, kind, fmt.Errorf("%s has no kustomization.yaml", displayPath(app.Path))
		}
		m, err := renderKustomize(ctx, full)
		return m, kind, err
	case SourceHelm:
		if !isHelmChart(full) {
			return nil, kind, fmt.Errorf("%s has no Chart.yaml", displayPath(app.Path))
		}
		m, err := renderHelm(ctx, app, root, full)
		return m, kind, err
	default:
		m, err := readManifestsFiltered(full, splitGlobs(app.Include), splitGlobs(app.Exclude))
		return m, SourceDirectory, err
	}
}

func displayPath(p string) string {
	if strings.Trim(p, "/. ") == "" {
		return "the repository root"
	}
	return p
}

func splitGlobs(s string) []string {
	var out []string
	for _, g := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == '\n' }) {
		if g = strings.TrimSpace(g); g != "" {
			out = append(out, g)
		}
	}
	return out
}

// globMatch matches a file's path inside the source, and its bare name, so
// "*.yaml" and "overlays/prod/*" both mean what they look like. A trailing
// "/**" matches everything under that directory.
func globMatch(globs []string, rel string) bool {
	rel = filepath.ToSlash(rel)
	for _, g := range globs {
		if strings.HasSuffix(g, "/**") && strings.HasPrefix(rel, strings.TrimSuffix(g, "**")) {
			return true
		}
		if ok, _ := path.Match(g, rel); ok {
			return true
		}
		if ok, _ := path.Match(g, path.Base(rel)); ok {
			return true
		}
	}
	return false
}

// ---- decoding ---------------------------------------------------------------------------------

// decodeManifests reads every Kubernetes object in a YAML or JSON stream.
// A document without apiVersion and kind -- a values file, a pipeline
// definition -- is not a manifest and is skipped.
func decodeManifests(r io.Reader, file string) ([]gitopsManifest, error) {
	var out []gitopsManifest
	dec := k8syaml.NewYAMLOrJSONDecoder(r, 4096)
	for {
		var doc map[string]any
		if err := dec.Decode(&doc); err != nil {
			if errors.Is(err, io.EOF) {
				return out, nil
			}
			return nil, fmt.Errorf("%s: %v", file, err)
		}
		if doc == nil {
			continue
		}
		if _, ok := doc["apiVersion"].(string); !ok {
			continue
		}
		if _, ok := doc["kind"].(string); !ok {
			continue
		}
		obj := &unstructured.Unstructured{Object: doc}
		if obj.IsList() {
			if err := obj.EachListItem(func(o runtime.Object) error {
				out = append(out, gitopsManifest{Obj: o.(*unstructured.Unstructured).DeepCopy(), File: file})
				return nil
			}); err != nil {
				return nil, fmt.Errorf("%s: %v", file, err)
			}
			continue
		}
		out = append(out, gitopsManifest{Obj: obj, File: file})
	}
}

func readManifestFile(full, rel string) ([]gitopsManifest, error) {
	f, err := os.Open(full)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return decodeManifests(f, rel)
}

// decodeRendered reads a renderer's output. helm template marks each
// document with "# Source: chart/templates/x.yaml"; that becomes the file
// an object is reported against, so an error points at the template.
func decodeRendered(out []byte, fallback string) ([]gitopsManifest, error) {
	var all []gitopsManifest
	for _, doc := range splitYAMLDocuments(out) {
		file := fallback
		for _, line := range strings.SplitN(doc, "\n", 6) {
			if s, ok := strings.CutPrefix(strings.TrimSpace(line), "# Source: "); ok {
				file = s
				break
			}
		}
		m, err := decodeManifests(strings.NewReader(doc), file)
		if err != nil {
			return nil, err
		}
		all = append(all, m...)
	}
	return all, nil
}

func splitYAMLDocuments(b []byte) []string {
	var docs []string
	var cur strings.Builder
	for _, line := range strings.SplitAfter(string(b), "\n") {
		if strings.TrimRight(line, "\r\n") == "---" {
			docs = append(docs, cur.String())
			cur.Reset()
			continue
		}
		cur.WriteString(line)
	}
	return append(docs, cur.String())
}

// ---- renderers -------------------------------------------------------------------------------

// runRenderer runs a renderer with a home of its own (Helm keeps caches
// and repository lists there) and a deadline.
func runRenderer(ctx context.Context, dir string, name string, args ...string) ([]byte, error) {
	bin, err := exec.LookPath(name)
	if err != nil {
		return nil, fmt.Errorf("%s is not installed in this CommitKube image", name)
	}
	home, err := os.MkdirTemp("", "gitops-render-home-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(home)
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = dir
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + home,
		"HELM_CACHE_HOME=" + filepath.Join(home, "cache"), "HELM_CONFIG_HOME=" + filepath.Join(home, "config"),
		"HELM_DATA_HOME=" + filepath.Join(home, "data"), "GIT_TERMINAL_PROMPT=0",
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		msg := strings.TrimSpace(stderr.String())
		if ctx.Err() == context.DeadlineExceeded {
			msg = "took longer than 2 minutes"
		} else if msg == "" {
			msg = err.Error()
		}
		return nil, fmt.Errorf("%s: %s", name, msg)
	}
	return stdout.Bytes(), nil
}

func renderKustomize(ctx context.Context, dir string) ([]gitopsManifest, error) {
	out, err := runRenderer(ctx, dir, "kustomize", "build", ".")
	if err != nil {
		return nil, err
	}
	return decodeRendered(out, "kustomize build")
}

// renderHelm runs helm template. Value files are resolved inside the chart
// first and then from the repository root (a shared values/ directory is
// common), and must stay inside the checkout; inline values go last, so
// they win.
func renderHelm(ctx context.Context, app *models.GitOpsApp, root, chart string) ([]gitopsManifest, error) {
	release := app.HelmReleaseName
	if release == "" {
		release = app.Name
	}
	args := []string{"template", release, ".", "--namespace", app.Namespace, "--include-crds"}
	for _, vf := range splitGlobs(app.HelmValueFiles) {
		p, err := helmValuesPath(root, chart, vf)
		if err != nil {
			return nil, err
		}
		args = append(args, "--values", p)
	}
	if strings.TrimSpace(app.HelmValues) != "" {
		f, err := os.CreateTemp("", "gitops-values-*.yaml")
		if err != nil {
			return nil, err
		}
		defer os.Remove(f.Name())
		_, werr := f.WriteString(app.HelmValues)
		f.Close()
		if werr != nil {
			return nil, werr
		}
		args = append(args, "--values", f.Name())
	}
	if needsHelmDependencies(chart) {
		if _, err := runRenderer(ctx, chart, "helm", "dependency", "build", "."); err != nil {
			return nil, fmt.Errorf("the chart's dependencies could not be fetched: %v", err)
		}
	}
	out, err := runRenderer(ctx, chart, "helm", args...)
	if err != nil {
		return nil, err
	}
	return decodeRendered(out, "helm template")
}

func helmValuesPath(root, chart, vf string) (string, error) {
	// Cleaning against "/" first clamps any ../ to the base, so the joined
	// path can never leave it.
	clean := filepath.Clean("/" + vf)
	for _, base := range []string{chart, root} {
		p := filepath.Join(base, clean)
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	return "", fmt.Errorf("values file %q is neither in the chart nor at that path in the repository", vf)
}

// needsHelmDependencies: the chart declares dependencies and they were not
// committed under charts/.
func needsHelmDependencies(chart string) bool {
	b, err := os.ReadFile(filepath.Join(chart, "Chart.yaml"))
	if err != nil || !bytes.Contains(b, []byte("dependencies:")) {
		return false
	}
	entries, err := os.ReadDir(filepath.Join(chart, "charts"))
	return err != nil || len(entries) == 0
}
