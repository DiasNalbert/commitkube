package handlers

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// fakeArgoCD knows two tokens: alice's and the old shared one.
func fakeArgoCD(t *testing.T) *httptest.Server {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/session/userinfo" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		switch r.Header.Get("Authorization") {
		case "Bearer alice-token":
			json.NewEncoder(w).Encode(map[string]interface{}{"loggedIn": true, "username": "alice"})
		case "Bearer shared-token":
			json.NewEncoder(w).Encode(map[string]interface{}{"loggedIn": true, "username": "commitkube"})
		default:
			w.WriteHeader(http.StatusUnauthorized)
			w.Write([]byte(`{"error":"invalid session: account password has changed since token issued","code":16}`))
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func setupArgoTokenTest(t *testing.T) (*fiber.App, models.ArgoCDInstance) {
	t.Helper()
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "argo.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	if err := gdb.AutoMigrate(&models.ArgoCDInstance{}, &models.UserArgoCDToken{}, &models.UserKeys{}, &models.User{}, &models.AuditLog{}); err != nil {
		t.Fatal(err)
	}
	db.DB = gdb
	srv := fakeArgoCD(t)
	inst := models.ArgoCDInstance{Alias: "prod", ServerURL: srv.URL, AuthToken: crypto.EncryptField(crypto.MasterKey(), "shared-token")}
	gdb.Create(&inst)

	app := fiber.New()
	as := func(userID uint, role string) fiber.Handler {
		return func(c *fiber.Ctx) error {
			c.Locals("user_id", float64(userID))
			c.Locals("role", role)
			return c.Next()
		}
	}
	app.Get("/u/:uid/instances", func(c *fiber.Ctx) error {
		uid, _ := c.ParamsInt("uid")
		c.Locals("user_id", float64(uid))
		c.Locals("role", c.Query("role", "user"))
		return ListArgoCDInstances(c)
	})
	app.Put("/alice/:id/my-token", as(1, "user"), SetMyArgoCDToken)
	app.Delete("/alice/:id/my-token", as(1, "user"), DeleteMyArgoCDToken)
	return app, inst
}

func call(t *testing.T, app *fiber.App, method, path string, body interface{}) (int, map[string]interface{}) {
	t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req := httptest.NewRequest(method, path, r)
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := io.ReadAll(res.Body)
	out := map[string]interface{}{}
	json.Unmarshal(raw, &out)
	return res.StatusCode, out
}

func TestArgoCredentialIsNeverTheSharedToken(t *testing.T) {
	_, inst := setupArgoTokenTest(t)
	if token, _ := argoCredential(1, inst); token != "" {
		t.Fatalf("a user without a token of their own got %q -- the shared token must never be used", token)
	}
}

func TestSetMyArgoCDToken(t *testing.T) {
	app, inst := setupArgoTokenTest(t)
	id := itoa(inst.ID)

	if code, body := call(t, app, "PUT", "/alice/"+id+"/my-token", map[string]string{"token": "stale-token"}); code != 422 {
		t.Errorf("a token ArgoCD refuses must not be saved: %d %v", code, body)
	}
	code, body := call(t, app, "PUT", "/alice/"+id+"/my-token", map[string]string{"token": "alice-token"})
	if code != 200 || body["username"] != "alice" {
		t.Fatalf("valid token: %d %v", code, body)
	}
	if token, user := argoCredential(1, inst); token != "alice-token" || user != "alice" {
		t.Errorf("credential = %q as %q, want alice's", token, user)
	}
	if token, _ := argoCredential(2, inst); token != "" {
		t.Error("one person's token answered for another")
	}

	// The list tells each person about their own token only.
	var list []map[string]interface{}
	req := httptest.NewRequest("GET", "/u/1/instances", nil)
	res, _ := app.Test(req, -1)
	json.NewDecoder(res.Body).Decode(&list)
	if list[0]["has_my_token"] != true || list[0]["my_username"] != "alice" || list[0]["has_shared_token"] != nil {
		t.Errorf("alice's view: %v", list[0])
	}
	req = httptest.NewRequest("GET", "/u/2/instances?role=admin", nil)
	res, _ = app.Test(req, -1)
	json.NewDecoder(res.Body).Decode(&list)
	if list[0]["has_my_token"] != false || list[0]["has_shared_token"] != true {
		t.Errorf("an admin without a token should see none of their own, and the leftover shared one: %v", list[0])
	}

	if code, _ := call(t, app, "DELETE", "/alice/"+id+"/my-token", nil); code != 200 {
		t.Fatal("delete failed")
	}
	if token, _ := argoCredential(1, inst); token != "" {
		t.Error("the token is still used after its owner removed it")
	}
}

func TestLegacyPersonalTokenMigrates(t *testing.T) {
	_, inst := setupArgoTokenTest(t)
	db.DB.Create(&models.UserKeys{UserID: 7, ArgoCDServerURL: inst.ServerURL + "/", ArgoCDAuthToken: crypto.EncryptField(crypto.MasterKey(), "alice-token")})
	db.DB.Create(&models.UserKeys{UserID: 8, ArgoCDServerURL: "https://elsewhere.example", ArgoCDAuthToken: "x"})
	db.MigratePersonalArgoCDTokens()

	var n int64
	db.DB.Model(&models.UserArgoCDToken{}).Where("user_id = 7 AND instance_id = ?", inst.ID).Count(&n)
	if n != 1 {
		t.Errorf("the old personal token for this URL should have become a per-instance token")
	}
	db.DB.Model(&models.UserArgoCDToken{}).Where("user_id = 8").Count(&n)
	if n != 0 {
		t.Error("a token for a URL that is no instance must not be attached to one")
	}
}

func itoa(n uint) string {
	b, _ := json.Marshal(n)
	return string(b)
}
