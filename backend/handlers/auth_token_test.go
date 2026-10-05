package handlers

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/middleware"
	"github.com/kubecommit/backend/models"
)

// Between the password and the MFA code the account holds a stage ticket.
// It is signed with the same secret as a session and names the same user, and
// it used to be accepted as one: the password alone was a way into the API.
func TestOnlyAccessTokensPassAuth(t *testing.T) {
	useVaultDB(t)
	if err := db.DB.AutoMigrate(&models.RefreshToken{}); err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Get("/x", middleware.AuthRequired(), func(c *fiber.Ctx) error { return c.SendString("ok") })
	status := func(tok string) int {
		req := httptest.NewRequest("GET", "/x", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		res, err := app.Test(req, -1)
		if err != nil {
			t.Fatal(err)
		}
		return res.StatusCode
	}

	for _, stage := range []string{"mfa", "setup"} {
		tok, err := issueStageToken(1, stage)
		if err != nil {
			t.Fatal(err)
		}
		if code := status(tok); code != http.StatusUnauthorized {
			t.Errorf("a %q stage ticket was accepted as a session: %d", stage, code)
		}
	}

	access, _, err := issueTokens(models.User{ID: 1, Role: "user"})
	if err != nil {
		t.Fatal(err)
	}
	if code := status(access); code != http.StatusOK {
		t.Errorf("a real access token was refused: %d", code)
	}
}
