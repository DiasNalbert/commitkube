package handlers

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/ssh"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
)

func TestGitopsURLValidation(t *testing.T) {
	good := []string{
		"git@github.com:acme/shop.git", "git@bitbucket.org:acme/shop.git", "git@gitlab.example.com:group/sub/repo.git",
		"ssh://git@github.com/acme/shop.git", "ssh://git@git.example.com:2222/acme/shop.git", "ssh://host.example.com/repo",
	}
	for _, u := range good {
		if msg := validGitopsURL(u); msg != "" {
			t.Errorf("%s refused: %s", u, msg)
		}
	}
	bad := []string{
		"", "https://github.com/acme/shop.git", "-oProxyCommand=touch /tmp/x:repo", "git@-oProxyCommand=x:repo",
		"ssh://-oProxyCommand=x/repo", "ext::sh -c touch% /tmp/x", "file:///etc", "/srv/repo.git", "git@host:repo with space",
	}
	for _, u := range bad {
		if validGitopsURL(u) == "" {
			t.Errorf("%q accepted", u)
		}
	}
	for b, ok := range map[string]bool{"main": true, "release/1.2": true, "feat_x-y": true,
		"-x": false, "a..b": false, "x/": false, "a b": false, "x.lock": false, "": false} {
		if validBranch(b) != ok {
			t.Errorf("validBranch(%q) = %v", b, !ok)
		}
	}
}

func TestImportedKey(t *testing.T) {
	k, err := generateRepoDeployKey("t")
	if err != nil {
		t.Fatal(err)
	}
	pub, fp, err := importedKey(strings.ReplaceAll(k.PrivateKey, "\n", "\r\n"))
	if err != nil {
		t.Fatal(err)
	}
	if fp != k.Fingerprint || !strings.HasPrefix(k.PublicKey, pub) {
		t.Fatalf("derived %s %s, generated %s %s", pub, fp, k.PublicKey, k.Fingerprint)
	}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, _ := ssh.MarshalPrivateKeyWithPassphrase(priv, "", []byte("secret"))
	if _, _, err := importedKey(string(pem.EncodeToMemory(block))); err == nil || !strings.Contains(err.Error(), "passphrase") {
		t.Fatalf("passphrase-protected key: %v", err)
	}
	if _, _, err := importedKey("not a key"); err == nil {
		t.Fatal("garbage accepted as a key")
	}
}

func TestPushedBranches(t *testing.T) {
	cases := []struct {
		name, body string
		want       []string // nil: could not tell
	}{
		{"github", `{"ref":"refs/heads/main","after":"abc"}`, []string{"main"}},
		{"gitlab", `{"object_kind":"push","ref":"refs/heads/release/1.2"}`, []string{"release/1.2"}},
		{"tag", `{"ref":"refs/tags/v1"}`, []string{}},
		{"bitbucket cloud", `{"push":{"changes":[{"new":{"type":"branch","name":"dev"}},{"new":null}]}}`, []string{"dev"}},
		{"bitbucket dc", `{"eventKey":"repo:refs_changed","changes":[{"ref":{"id":"refs/heads/main","displayId":"main","type":"BRANCH"}}]}`, []string{"main"}},
		{"ping", `{"zen":"Keep it logically awesome."}`, nil},
		{"not json", `payload=x`, nil},
	}
	for _, c := range cases {
		got := pushedBranches([]byte(c.body))
		if c.want == nil {
			if got != nil {
				t.Errorf("%s: %v, want nil", c.name, got)
			}
			continue
		}
		if got == nil || len(got) != len(c.want) {
			t.Errorf("%s: %v, want %v", c.name, got, c.want)
			continue
		}
		for _, b := range c.want {
			if !got[b] {
				t.Errorf("%s: missing %s in %v", c.name, b, got)
			}
		}
	}
}

func TestClusterScopeIsOptIn(t *testing.T) {
	kube := newFakeKube()
	obj := func(kind, ns, name string) gitopsManifest {
		u := &unstructured.Unstructured{Object: map[string]any{"apiVersion": "v1", "kind": kind, "metadata": map[string]any{"name": name}}}
		if kind == "ClusterRole" {
			u.SetAPIVersion("rbac.authorization.k8s.io/v1")
		}
		if ns != "" {
			u.SetNamespace(ns)
		}
		return gitopsManifest{Obj: u, File: "x.yaml"}
	}
	manifests := func() []gitopsManifest {
		return []gitopsManifest{obj("ClusterRole", "", "reader"), obj("ConfigMap", "other", "cfg"), obj("ConfigMap", "", "mine")}
	}

	app := &models.GitOpsApp{Name: "web", Namespace: "shop"}
	targets, invalid := prepareTargets(app, kube, manifests())
	if len(targets) != 1 || targets[0].Obj.GetNamespace() != "shop" || len(invalid) != 2 {
		t.Fatalf("namespace-only: %d targets, %d invalid", len(targets), len(invalid))
	}
	for _, r := range invalid {
		if !strings.Contains(r.Message, "cluster scope") {
			t.Errorf("refusal does not say how to allow it: %s", r.Message)
		}
	}

	app.ClusterScope = true
	targets, invalid = prepareTargets(app, kube, manifests())
	if len(invalid) != 0 || len(targets) != 3 {
		t.Fatalf("cluster scope: %d targets, %v", len(targets), invalid)
	}
	got := map[string]string{}
	for _, tg := range targets {
		got[tg.Obj.GetKind()+"/"+tg.Obj.GetName()] = tg.Obj.GetNamespace()
	}
	if got["ClusterRole/reader"] != "" || got["ConfigMap/cfg"] != "other" || got["ConfigMap/mine"] != "shop" {
		t.Fatalf("namespaces: %v", got)
	}
}

func TestKindOrderPutsNamespacesAndCRDsFirst(t *testing.T) {
	order := []string{"Namespace", "CustomResourceDefinition", "ClusterRole", "Deployment", "Ingress", "Widget"}
	for i := 0; i < len(order)-1; i++ {
		if !lessByKindOrder(order[i], "a", order[i+1], "a") {
			t.Errorf("%s should apply before %s", order[i], order[i+1])
		}
	}
}

func setupGitopsWebhookTest(t *testing.T) (*fiber.App, models.GitOpsRepo, string) {
	t.Helper()
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "gitops.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(&models.GitOpsRepo{}, &models.GitOpsApp{}); err != nil {
		t.Fatal(err)
	}
	db.DB = gdb
	secret := "s3cret"
	r := models.GitOpsRepo{Name: "shop", URL: "git@example.com:a/b.git", WebhookID: "hook-1",
		WebhookSecret: crypto.EncryptField(crypto.MasterKey(), secret)}
	gdb.Create(&r)
	app := fiber.New()
	app.Post("/api/gitops/webhook/:id", GitopsWebhook)
	return app, r, secret
}

func TestGitopsWebhookVerifiesTheSender(t *testing.T) {
	app, _, secret := setupGitopsWebhookTest(t)
	body := `{"ref":"refs/tags/v1"}` // a tag: verified, nothing queued
	sign := func(key string) string {
		mac := hmac.New(sha256.New, []byte(key))
		mac.Write([]byte(body))
		return "sha256=" + hex.EncodeToString(mac.Sum(nil))
	}
	send := func(id string, headers map[string]string) int {
		req := httptest.NewRequest("POST", "/api/gitops/webhook/"+id, strings.NewReader(body))
		for k, v := range headers {
			req.Header.Set(k, v)
		}
		res, err := app.Test(req)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}
	cases := []struct {
		name    string
		id      string
		headers map[string]string
		want    int
	}{
		{"github", "hook-1", map[string]string{"X-Hub-Signature-256": sign(secret)}, 202},
		{"bitbucket", "hook-1", map[string]string{"X-Hub-Signature": sign(secret)}, 202},
		{"gitlab", "hook-1", map[string]string{"X-Gitlab-Token": secret}, 202},
		{"wrong secret", "hook-1", map[string]string{"X-Hub-Signature-256": sign("guess")}, 401},
		{"wrong token", "hook-1", map[string]string{"X-Gitlab-Token": "guess"}, 401},
		{"sha1 only", "hook-1", map[string]string{"X-Hub-Signature": "sha1=abc"}, 401},
		{"unsigned", "hook-1", nil, 401},
		{"unknown hook", "hook-2", map[string]string{"X-Gitlab-Token": secret}, 404},
	}
	for _, c := range cases {
		if got := send(c.id, c.headers); got != c.want {
			t.Errorf("%s: %d, want %d", c.name, got, c.want)
		}
	}
	var r models.GitOpsRepo
	db.DB.First(&r)
	if r.LastPushAt == nil {
		t.Error("an accepted push was not recorded")
	}
}

// The queries that find an application by its connection are written by
// hand; this is what catches them naming a column GORM does not create.
func TestAppsAreFoundByTheirConnection(t *testing.T) {
	app, r, secret := setupGitopsWebhookTest(t)
	gdb := db.DB
	gdb.AutoMigrate(&models.Repository{})
	id := r.ID
	gdb.Create(&models.GitOpsApp{Name: "web", GitOpsRepoID: &id, Branch: "main", Namespace: "shop", ClusterID: 1})
	gdb.Create(&models.GitOpsApp{Name: "web-rc", GitOpsRepoID: &id, Branch: "release", Namespace: "shop", ClusterID: 1})
	gdb.Create(&models.GitOpsApp{Name: "legacy", RepoName: "shop-api", Branch: "main", Namespace: "shop", ClusterID: 1})

	var refreshed []string
	prev := enqueueGitopsRefresh
	enqueueGitopsRefresh = func(a models.GitOpsApp, trigger string) { refreshed = append(refreshed, a.Name+":"+trigger) }
	t.Cleanup(func() { enqueueGitopsRefresh = prev })

	body := `{"ref":"refs/heads/main"}`
	req := httptest.NewRequest("POST", "/api/gitops/webhook/hook-1", strings.NewReader(body))
	req.Header.Set("X-Gitlab-Token", secret)
	if res, err := app.Test(req); err != nil || res.StatusCode != 202 {
		t.Fatalf("push: %v %v", res, err)
	}
	if strings.Join(refreshed, ",") != "web:webhook" {
		t.Fatalf("a push to main refreshed %v", refreshed)
	}

	if v := viewGitopsRepo(r); v.Apps != 2 {
		t.Fatalf("connection reports %d apps, want 2", v.Apps)
	}

	del := fiber.New()
	del.Delete("/r/:id", DeleteGitopsRepo)
	res, _ := del.Test(httptest.NewRequest("DELETE", fmt.Sprintf("/r/%d", r.ID), nil))
	if res.StatusCode != 409 {
		t.Fatalf("deleting a connection with apps: %d, want 409", res.StatusCode)
	}

	var legacy []models.GitOpsApp
	if err := gdb.Where("repo_name = ? AND gitops_repo_id IS NULL", "shop-api").Find(&legacy).Error; err != nil || len(legacy) != 1 {
		t.Fatalf("legacy lookup: %v %d", err, len(legacy))
	}
}
