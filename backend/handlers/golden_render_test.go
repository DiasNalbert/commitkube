package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func apiGoPath(t *testing.T) models.GoldenPath {
	t.Helper()
	fields, _ := json.Marshal([]models.FieldDef{
		{Key: "team", Label: "Team", Type: "string", Required: true, Validation: "^[a-z][a-z0-9-]+$"},
		{Key: "port", Label: "Port", Type: "number", Default: "8080"},
		{Key: "tier", Label: "Tier", Type: "select", Options: []string{"gold", "silver"}, Default: "silver"},
		{Key: "expose", Label: "Expose publicly", Type: "bool"},
	})
	return models.GoldenPath{
		Name: "API Go", FieldsSchema: string(fields), AllowedNamespaces: "apis, apps-*",
		RequiredLabels: "team", ResourceLimits: "cpu=1, memory=512Mi", ApprovalWorkflow: "none", IsActive: true,
	}
}

const apiGoDeployment = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
  labels:
    team: {{.Inputs.team}}
spec:
  template:
    spec:
      containers:
        - name: app
          image: registry/{{.Name}}:latest
          ports:
            - containerPort: {{.Inputs.port}}
          resources:
            limits:
              cpu: 500m
              memory: {{.Limits.memory}}
{{- if .Inputs.expose}}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{.Name}}
  namespace: {{.Namespace}}
spec:
  rules:
    - host: {{.Name}}.apps.example.com
{{- end}}
`

func TestResolveGoldenInputs(t *testing.T) {
	gp := apiGoPath(t)
	in, err := resolveGoldenInputs(&gp, map[string]string{"team": "payments", "expose": "yes"})
	if err != nil {
		t.Fatal(err)
	}
	if in["port"] != "8080" || in["tier"] != "silver" || in["expose"] != true {
		t.Fatalf("defaults and booleans: %#v", in)
	}
	if in2, _ := resolveGoldenInputs(&gp, map[string]string{"team": "payments"}); in2["expose"] != false {
		t.Fatal("an unanswered yes/no must be false, not the string \"\"")
	}
	for name, raw := range map[string]map[string]string{
		"required missing": {},
		"regex":            {"team": "Payments!"},
		"number":           {"team": "payments", "port": "eighty"},
		"select":           {"team": "payments", "tier": "bronze"},
		"bool":             {"team": "payments", "expose": "maybe"},
	} {
		if _, err := resolveGoldenInputs(&gp, raw); err == nil {
			t.Errorf("%s: accepted %v", name, raw)
		}
	}

	if ns, err := goldenNamespace(&gp, "apps-payments"); err != nil || ns != "apps-payments" {
		t.Fatalf("wildcard namespace: %q %v", ns, err)
	}
	if _, err := goldenNamespace(&gp, "default"); err == nil {
		t.Fatal("a namespace outside the allowed list was accepted")
	}
	if _, err := goldenNamespace(&gp, ""); err == nil {
		t.Fatal("with several allowed namespaces one must be chosen")
	}
	one := models.GoldenPath{AllowedNamespaces: "apis"}
	if ns, _ := goldenNamespace(&one, ""); ns != "apis" {
		t.Fatalf("a single allowed namespace is the default, got %q", ns)
	}
}

func TestPlanGoldenPathRendersConditionalsAndChecksRules(t *testing.T) {
	gp := apiGoPath(t)
	tmpls := []models.YamlTemplate{{ID: 1, Name: "app.yaml", Path: "k8s", Type: "manifest", Content: apiGoDeployment, IsActive: true}}

	plan, err := planGoldenPath(&gp, "orders-api", map[string]string{"team": "payments", "namespace": "apis", "expose": "true"}, nil, tmpls)
	if err != nil {
		t.Fatal(err)
	}
	out := plan.Files["k8s/app.yaml"]
	if !strings.Contains(out, "containerPort: 8080") || !strings.Contains(out, "host: orders-api.apps.example.com") || !strings.Contains(out, "memory: 512Mi") {
		t.Fatalf("rendered:\n%s", out)
	}
	if plan.ManifestPath != "k8s" {
		t.Fatalf("manifest path = %q", plan.ManifestPath)
	}
	if v := checkGoldenPolicy(&gp, plan.Namespace, plan.Files); len(v) != 0 {
		t.Fatalf("a compliant render was refused: %v", v)
	}

	noIngress, _ := planGoldenPath(&gp, "orders-api", map[string]string{"team": "payments", "namespace": "apis"}, nil, tmpls)
	if strings.Contains(noIngress.Files["k8s/app.yaml"], "kind: Ingress") {
		t.Fatal("expose=no still produced an Ingress")
	}

	// A template naming an input that does not exist fails loudly instead
	// of writing "<no value>" into a manifest.
	bad := []models.YamlTemplate{{ID: 2, Name: "x.yaml", Content: "port: {{.Inputs.prot}}", IsActive: true}}
	if _, err := planGoldenPath(&gp, "x", map[string]string{"team": "a1", "namespace": "apis"}, nil, bad); err == nil {
		t.Fatal("a misspelled input rendered silently")
	}

	// The rules catch what a person edits by hand: wrong namespace, no
	// team label, a limit above the ceiling.
	files := map[string]string{"k8s/app.yaml": `apiVersion: apps/v1
kind: Deployment
metadata:
  name: x
  namespace: kube-system
spec:
  template:
    spec:
      containers:
        - name: app
          resources:
            limits:
              cpu: "2"
`, "pipeline.yml": "image: ubuntu\n", "chart/templates/d.yaml": "{{ .Values.x }}: [\n"}
	v := checkGoldenPolicy(&gp, "apis", files)
	joined := strings.Join(v, "\n")
	for _, want := range []string{`namespace "kube-system"`, "missing the label(s) team", "asks for cpu 2", "has no memory limit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("violations do not mention %q:\n%s", want, joined)
		}
	}
	if len(v) != 4 {
		t.Errorf("violations = %d, want 4 (non-manifests ignored):\n%s", len(v), joined)
	}
}

// Golden path templates never leak into other repositories, and override
// project templates writing the same file.
func TestAssembleRepoFilesWithGoldenPath(t *testing.T) {
	useScanDB(t)
	if err := db.DB.AutoMigrate(&models.YamlTemplate{}, &models.GoldenPath{}, &models.BitbucketWorkspace{}); err != nil {
		t.Fatal(err)
	}
	gp := apiGoPath(t)
	db.DB.Create(&gp)
	db.DB.Create(&models.YamlTemplate{Name: "app.yaml", Path: "k8s", Type: "manifest", Content: "kind: ConfigMap\nmetadata:\n  name: global\n", IsActive: true})
	db.DB.Create(&models.YamlTemplate{Name: "pipeline.yml", Type: "pipeline", Content: "image: ubuntu # <your_application>\n", IsActive: true})
	db.DB.Create(&models.YamlTemplate{GoldenPathID: &gp.ID, Name: "app.yaml", Path: "k8s", Type: "manifest", Content: apiGoDeployment, IsActive: true})

	plain, err := assembleRepoFiles(&CreateRepoRequest{Name: "svc"}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(plain.Files["k8s/app.yaml"], "name: global") || plain.Golden != nil {
		t.Fatalf("without a golden path its templates must not apply: %v", plain.Files)
	}

	req := &CreateRepoRequest{Name: "orders-api", GoldenPathID: gp.ID, GoldenPathInputs: map[string]string{"team": "payments", "namespace": "apis"}}
	got, err := assembleRepoFiles(req, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(got.Files["k8s/app.yaml"], "kind: Deployment") || got.Files["pipeline.yml"] != "image: ubuntu # orders-api\n" {
		t.Fatalf("golden path files: %v", got.Files)
	}
	if got.Golden.Namespace != "apis" || got.ArgoAppPath != "k8s" {
		t.Fatalf("namespace %q, argo path %q", got.Golden.Namespace, got.ArgoAppPath)
	}

	// An uploaded file that breaks the rules refuses the whole request.
	req.UploadedFiles = []UploadedFile{{Path: "k8s/extra.yaml", Content: "kind: Deployment\nmetadata:\n  name: extra\n  namespace: default\n"}}
	if _, err := assembleRepoFiles(req, "", ""); err == nil {
		t.Fatal("a file outside the rules was accepted")
	} else if _, ok := err.(*goldenPolicyError); !ok {
		t.Fatalf("want a policy error, got %v", err)
	}
}
