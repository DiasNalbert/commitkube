package handlers

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

func secretsApp(sid string) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", float64(1))
		c.Locals("role", "admin")
		c.Locals("session_id", sid)
		return c.Next()
	})
	app.Post("/secrets/unlock", UnlockSecrets)
	app.Post("/secrets/list", ListSecrets)
	return app
}

func secretsCall(t *testing.T, app *fiber.App, path, ticket string, body any) (int, map[string]any) {
	t.Helper()
	b, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", path, bytes.NewReader(b))
	req.Header.Set("Content-Type", "application/json")
	if ticket != "" {
		req.Header.Set(secretsTicketHeader, ticket)
	}
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

// Cluster secrets open with the password and a code, never the password
// alone, and the ticket that comes back is bound to the sign-in session.
func TestSecretsUnlockNeedsPasswordAndCode(t *testing.T) {
	useVaultDB(t)
	usedSteps = map[uint]int64{}
	secret := "JBSWY3DPEHPK3PXP"
	hash, _ := bcrypt.GenerateFromPassword([]byte("right-password"), 4)
	db.DB.Create(&models.User{Email: "a@example.com", PasswordHash: string(hash), MFASecret: secret, MFAEnabled: true, IsActive: true, Role: "admin"})
	app := secretsApp("session-1")
	code, _ := totp.GenerateCode(secret, time.Now())

	if st, _ := secretsCall(t, app, "/secrets/unlock", "", map[string]string{"password": "right-password"}); st != 400 {
		t.Fatalf("password without a code: %d, want 400", st)
	}
	if st, b := secretsCall(t, app, "/secrets/unlock", "", map[string]string{"password": "wrong", "code": code}); st != 403 || b["secrets_unlock_required"] != true {
		t.Fatalf("wrong password: %d %v (must be 403, never 401)", st, b)
	}
	if st, _ := secretsCall(t, app, "/secrets/unlock", "", map[string]string{"password": "right-password", "code": "000000"}); st != 403 {
		t.Fatalf("wrong code: %d", st)
	}
	st, b := secretsCall(t, app, "/secrets/unlock", "", map[string]string{"password": "right-password", "code": code})
	ticket, _ := b["ticket"].(string)
	if st != 200 || ticket == "" {
		t.Fatalf("right password and code: %d %v", st, b)
	}
	if st, _ := secretsCall(t, app, "/secrets/unlock", "", map[string]string{"password": "right-password", "code": code}); st != 403 {
		t.Fatalf("the same code twice was accepted: %d", st)
	}

	// Without a ticket, or with an old password in the body, nothing.
	if st, _ := secretsCall(t, app, "/secrets/list", "", map[string]string{"password": "right-password"}); st != 403 {
		t.Fatalf("list without a ticket: %d", st)
	}
	// With it, the request reaches the cluster (absent here, hence 503).
	if st, _ := secretsCall(t, app, "/secrets/list", ticket, map[string]string{}); st != 503 {
		t.Fatalf("list with a ticket: %d, want it past the check", st)
	}
	// A ticket from another sign-in is refused.
	if st, _ := secretsCall(t, secretsApp("session-2"), "/secrets/list", ticket, map[string]string{}); st != 403 {
		t.Fatalf("ticket from an earlier session: %d", st)
	}
}
