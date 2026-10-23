package handlers

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"text/template"

	"github.com/kubecommit/backend/models"
	"gopkg.in/yaml.v3"
	"k8s.io/apimachinery/pkg/api/resource"
)

// A golden path is a way of creating a service that comes out right: the
// files it brings, the questions it asks, and the rules what it produces
// must follow. This file holds the three pieces that make it more than a
// form -- answering the questions, rendering the path's own templates with
// the answers, and checking the rendered manifests against the rules --
// before anything is created in the SCM, so a refusal never leaves half a
// repository behind.

// ---- the questions ---------------------------------------------------------

func goldenFields(gp *models.GoldenPath) []models.FieldDef {
	var fields []models.FieldDef
	if gp.FieldsSchema != "" {
		_ = json.Unmarshal([]byte(gp.FieldsSchema), &fields)
	}
	return fields
}

func parseBoolInput(v string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(v)) {
	case "true", "yes", "y", "on", "1", "sim":
		return true, true
	case "false", "no", "n", "off", "0", "nao", "não", "":
		return false, true
	}
	return false, false
}

// splitPatterns reads a comma-separated list: "apis, apps-*".
func splitPatterns(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func namespaceAllowedBy(patterns []string, ns string) bool {
	for _, p := range patterns {
		if ok, _ := path.Match(p, ns); ok {
			return true
		}
	}
	return false
}

// goldenNamespace picks the namespace a repository created on this path
// deploys to. With one exact allowed namespace it is that one; otherwise the
// person chooses, and the choice must match one of the allowed patterns.
func goldenNamespace(gp *models.GoldenPath, requested string) (string, error) {
	allowed := splitPatterns(gp.AllowedNamespaces)
	requested = strings.TrimSpace(requested)
	if len(allowed) == 0 {
		return requested, nil
	}
	if requested == "" {
		if len(allowed) == 1 && !strings.ContainsAny(allowed[0], "*?[") {
			return allowed[0], nil
		}
		return "", fmt.Errorf("choose a namespace: this golden path allows %s", strings.Join(allowed, ", "))
	}
	if !namespaceAllowedBy(allowed, requested) {
		return "", fmt.Errorf("namespace %q is not allowed by this golden path (allowed: %s)", requested, strings.Join(allowed, ", "))
	}
	return requested, nil
}

// resolveGoldenInputs applies defaults and checks every answer against its
// field: required, type, options and pattern. Yes/No answers become real
// booleans, so a template can say {{if .Inputs.expose}} -- the string
// "false" would otherwise count as true.
func resolveGoldenInputs(gp *models.GoldenPath, raw map[string]string) (map[string]any, error) {
	out := map[string]any{}
	for _, f := range goldenFields(gp) {
		if f.Key == "" {
			continue
		}
		label := f.Label
		if label == "" {
			label = f.Key
		}
		v := strings.TrimSpace(raw[f.Key])
		if v == "" {
			v = strings.TrimSpace(f.Default)
		}
		if v == "" && f.Required && f.Type != "bool" {
			return nil, fmt.Errorf("%s is required", label)
		}
		switch f.Type {
		case "bool":
			b, ok := parseBoolInput(v)
			if !ok {
				return nil, fmt.Errorf("%s must be yes or no", label)
			}
			out[f.Key] = b
			continue
		case "number":
			if v != "" {
				if _, err := strconv.ParseFloat(v, 64); err != nil {
					return nil, fmt.Errorf("%s must be a number", label)
				}
			}
		case "select":
			if v != "" && len(f.Options) > 0 && !containsStr(f.Options, v) {
				return nil, fmt.Errorf("%s must be one of: %s", label, strings.Join(f.Options, ", "))
			}
		}
		if v != "" && f.Validation != "" {
			re, err := regexp.Compile(f.Validation)
			if err != nil {
				return nil, fmt.Errorf("the validation pattern of %s is not a valid regex: %v", label, err)
			}
			if !re.MatchString(v) {
				return nil, fmt.Errorf("%s does not match %s", label, f.Validation)
			}
		}
		out[f.Key] = v
	}
	return out, nil
}

// ---- the templates ---------------------------------------------------------

// goldenData is what a golden path template can read.
type goldenData struct {
	// Name is the repository name; ProjectName the same, under the name the
	// older templates already use.
	Name        string
	ProjectName string
	Namespace   string
	Inputs      map[string]any
	// Limits is the path's resource ceiling ("cpu", "memory"), handy as the
	// value a template sets.
	Limits map[string]string
}

var goldenFuncs = template.FuncMap{
	"lower":   strings.ToLower,
	"upper":   strings.ToUpper,
	"trim":    strings.TrimSpace,
	"replace": func(old, new, s string) string { return strings.ReplaceAll(s, old, new) },
	"quote":   func(v any) string { return strconv.Quote(fmt.Sprint(v)) },
	"default": func(def, v any) any {
		if v == nil || fmt.Sprint(v) == "" {
			return def
		}
		return v
	},
}

// parseGoldenTemplate is also how a template is checked when it is saved:
// a broken one is refused then, not discovered when someone creates a
// repository with it.
func parseGoldenTemplate(name, content string) (*template.Template, error) {
	return template.New(name).Funcs(goldenFuncs).Option("missingkey=error").Parse(content)
}

func renderGoldenTemplate(name, content string, d goldenData) (string, error) {
	// The placeholder every template in the product already uses keeps
	// working here too.
	content = strings.ReplaceAll(content, "<your_application>", d.Name)
	t, err := parseGoldenTemplate(name, content)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, d); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// parseLimits reads "cpu=1, memory=1Gi".
func parseLimits(s string) (map[string]string, error) {
	out := map[string]string{}
	for _, part := range splitPatterns(s) {
		k, v, ok := strings.Cut(part, "=")
		k, v = strings.TrimSpace(strings.ToLower(k)), strings.TrimSpace(v)
		if !ok || (k != "cpu" && k != "memory") {
			return nil, fmt.Errorf("resource limits are written cpu=1, memory=1Gi; %q is not", part)
		}
		if _, err := resource.ParseQuantity(v); err != nil {
			return nil, fmt.Errorf("%s=%s is not a Kubernetes quantity", k, v)
		}
		out[k] = v
	}
	return out, nil
}

// ---- the rules -------------------------------------------------------------

var workloadKinds = map[string]bool{
	"Deployment": true, "StatefulSet": true, "DaemonSet": true,
	"Job": true, "CronJob": true, "Pod": true, "ReplicaSet": true,
}

var clusterScopedKinds = map[string]bool{
	"Namespace": true, "ClusterRole": true, "ClusterRoleBinding": true,
	"CustomResourceDefinition": true, "PersistentVolume": true, "StorageClass": true,
	"IngressClass": true, "PriorityClass": true, "MutatingWebhookConfiguration": true,
	"ValidatingWebhookConfiguration": true,
}

// k8sDocs reads every Kubernetes object in a YAML file. A file that is not
// YAML -- a Helm template, a Dockerfile named .yml by accident -- yields
// nothing rather than an error: only what is plainly a manifest is checked.
func k8sDocs(content string) []map[string]any {
	dec := yaml.NewDecoder(strings.NewReader(content))
	var out []map[string]any
	for {
		var doc map[string]any
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil
		}
		if doc == nil {
			continue
		}
		if _, ok := doc["kind"].(string); !ok {
			continue
		}
		if _, ok := doc["metadata"].(map[string]any); !ok {
			continue
		}
		out = append(out, doc)
	}
	return out
}

func mapAt(m map[string]any, keys ...string) map[string]any {
	cur := m
	for _, k := range keys {
		next, ok := cur[k].(map[string]any)
		if !ok {
			return nil
		}
		cur = next
	}
	return cur
}

func podSpecOf(doc map[string]any) map[string]any {
	switch doc["kind"] {
	case "Pod":
		return mapAt(doc, "spec")
	case "CronJob":
		return mapAt(doc, "spec", "jobTemplate", "spec", "template", "spec")
	default:
		return mapAt(doc, "spec", "template", "spec")
	}
}

// checkGoldenPolicy checks the rendered files against the path's rules and
// returns one line per violation, file and object named, so the fix is
// obvious from the message alone.
func checkGoldenPolicy(gp *models.GoldenPath, namespace string, files map[string]string) []string {
	allowed := splitPatterns(gp.AllowedNamespaces)
	labels := splitPatterns(gp.RequiredLabels)
	limits, _ := parseLimits(gp.ResourceLimits)
	if len(allowed) == 0 && len(labels) == 0 && len(limits) == 0 {
		return nil
	}

	paths := make([]string, 0, len(files))
	for p := range files {
		if strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml") {
			paths = append(paths, p)
		}
	}
	sort.Strings(paths)

	var problems []string
	for _, p := range paths {
		for _, doc := range k8sDocs(files[p]) {
			kind, _ := doc["kind"].(string)
			meta := mapAt(doc, "metadata")
			name, _ := meta["name"].(string)
			where := fmt.Sprintf("%s: %s %s", p, kind, name)

			if len(allowed) > 0 && !clusterScopedKinds[kind] {
				ns, _ := meta["namespace"].(string)
				if ns == "" {
					ns = namespace
				}
				if ns != "" && !namespaceAllowedBy(allowed, ns) {
					problems = append(problems, fmt.Sprintf("%s is in namespace %q, which this golden path does not allow", where, ns))
				}
			}
			if !workloadKinds[kind] {
				continue
			}
			if len(labels) > 0 {
				have := mapAt(meta, "labels")
				var missing []string
				for _, l := range labels {
					if v, ok := have[l]; !ok || fmt.Sprint(v) == "" {
						missing = append(missing, l)
					}
				}
				if len(missing) > 0 {
					problems = append(problems, fmt.Sprintf("%s is missing the label(s) %s", where, strings.Join(missing, ", ")))
				}
			}
			if len(limits) > 0 {
				spec := podSpecOf(doc)
				for _, list := range []string{"initContainers", "containers"} {
					cs, _ := spec[list].([]any)
					for _, c := range cs {
						cm, _ := c.(map[string]any)
						cname, _ := cm["name"].(string)
						set := mapAt(cm, "resources", "limits")
						for _, res := range []string{"cpu", "memory"} {
							max, ok := limits[res]
							if !ok {
								continue
							}
							raw, has := set[res]
							if !has {
								problems = append(problems, fmt.Sprintf("%s container %s has no %s limit (this golden path caps it at %s)", where, cname, res, max))
								continue
							}
							q, err := resource.ParseQuantity(fmt.Sprint(raw))
							if err != nil {
								problems = append(problems, fmt.Sprintf("%s container %s has an unreadable %s limit %v", where, cname, res, raw))
								continue
							}
							if q.Cmp(resource.MustParse(max)) > 0 {
								problems = append(problems, fmt.Sprintf("%s container %s asks for %s %s, above the %s this golden path allows", where, cname, res, q.String(), max))
							}
						}
					}
				}
			}
		}
	}
	return problems
}

// ---- putting it together ---------------------------------------------------

// goldenPlan is a golden path resolved for one repository: the answers, the
// namespace and the rendered files the path brings.
type goldenPlan struct {
	Path      *models.GoldenPath
	Namespace string
	Inputs    map[string]any
	Files     map[string]string
	// ManifestPath is where the path keeps its manifests, for ArgoCD.
	ManifestPath string
}

// planGoldenPath answers the questions and renders the path's templates.
// edited holds per-template overrides from the creation form.
func planGoldenPath(gp *models.GoldenPath, repoName string, raw map[string]string, edited map[uint]string, tmpls []models.YamlTemplate) (*goldenPlan, error) {
	inputs, err := resolveGoldenInputs(gp, raw)
	if err != nil {
		return nil, err
	}
	ns, err := goldenNamespace(gp, raw["namespace"])
	if err != nil {
		return nil, err
	}
	limits, err := parseLimits(gp.ResourceLimits)
	if err != nil {
		return nil, err
	}
	d := goldenData{Name: repoName, ProjectName: repoName, Namespace: ns, Inputs: inputs, Limits: limits}
	plan := &goldenPlan{Path: gp, Namespace: ns, Inputs: inputs, Files: map[string]string{}}
	for _, t := range tmpls {
		if !t.IsActive {
			continue
		}
		content := t.Content
		if e, ok := edited[t.ID]; ok {
			content = e
		}
		file := strings.TrimPrefix(strings.TrimSuffix(t.Path, "/")+"/"+t.Name, "/")
		out, err := renderGoldenTemplate(file, content, d)
		if err != nil {
			return nil, fmt.Errorf("template %s: %v", file, err)
		}
		plan.Files[file] = out
		if t.Type == "manifest" && t.Path != "" {
			plan.ManifestPath = strings.Trim(t.Path, "/")
		}
	}
	return plan, nil
}
