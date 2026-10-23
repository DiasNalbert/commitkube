package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func sessionApp(t *testing.T) *fiber.App {
	t.Helper()
	useVaultDB(t)
	if err := db.DB.AutoMigrate(&models.RefreshToken{}); err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Post("/auth/refresh", RefreshTokenHandler)
	app.Post("/auth/logout", Logout)
	app.Post("/signin/:id", func(c *fiber.Ctx) error {
		var u models.User
		if err := db.DB.First(&u, c.Params("id")).Error; err != nil {
			return err
		}
		return signedIn(c, u)
	})
	return app
}

func activeUser(t *testing.T) models.User {
	t.Helper()
	u := models.User{Email: "ana@example.com", Role: "admin", IsActive: true, MFAEnabled: true}
	if err := db.DB.Create(&u).Error; err != nil {
		t.Fatal(err)
	}
	return u
}

type authResult struct {
	status int
	token  string
	cookie *http.Cookie // the ck_session cookie the response set, if any
	body   map[string]any
}

func authCall(t *testing.T, app *fiber.App, path, cookie string) authResult {
	t.Helper()
	req := httptest.NewRequest("POST", path, nil)
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})
	}
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	out := authResult{status: res.StatusCode}
	_ = json.NewDecoder(res.Body).Decode(&out.body)
	if tok, ok := out.body["token"].(string); ok {
		out.token = tok
	}
	for _, c := range res.Cookies() {
		if c.Name == SessionCookie {
			out.cookie = c
		}
	}
	return out
}

func signIn(t *testing.T, app *fiber.App, u models.User) string {
	t.Helper()
	r := authCall(t, app, "/signin/"+uitoa(u.ID), "")
	if r.status != 200 || r.token == "" || r.cookie == nil || r.cookie.Value == "" {
		t.Fatalf("sign-in: %d %v", r.status, r.body)
	}
	return r.cookie.Value
}

func uitoa(n uint) string { return strconv.FormatUint(uint64(n), 10) }

// The cookie is what makes a session end with the browser: httpOnly so no
// script reads it, SameSite=Strict, and no expiry date.
func TestSignInSetsASessionCookieAndNoRefreshTokenInTheBody(t *testing.T) {
	app := sessionApp(t)
	u := activeUser(t)
	r := authCall(t, app, "/signin/"+uitoa(u.ID), "")
	if r.cookie == nil {
		t.Fatal("no session cookie")
	}
	if !r.cookie.HttpOnly || r.cookie.SameSite != http.SameSiteStrictMode || r.cookie.Path != "/" {
		t.Fatalf("cookie attributes: %+v", r.cookie)
	}
	if !r.cookie.Expires.IsZero() || r.cookie.MaxAge != 0 {
		t.Fatalf("the cookie must die with the browser, got expires=%v maxAge=%d", r.cookie.Expires, r.cookie.MaxAge)
	}
	if _, leaked := r.body["refresh_token"]; leaked {
		t.Fatal("the refresh token is in the response body, readable by scripts")
	}
	// Stored hashed, never as the value the browser holds.
	var n int64
	db.DB.Model(&models.RefreshToken{}).Where("token = ?", r.cookie.Value).Count(&n)
	if n != 0 {
		t.Fatal("the refresh token is stored in clear")
	}
}

func TestRefreshRotatesAndToleratesARaceButNotAReplay(t *testing.T) {
	app := sessionApp(t)
	u := activeUser(t)
	first := signIn(t, app, u)

	r := authCall(t, app, "/auth/refresh", first)
	if r.status != 200 || r.token == "" || r.cookie == nil || r.cookie.Value == first {
		t.Fatalf("refresh should rotate: %d cookie=%v", r.status, r.cookie)
	}
	second := r.cookie.Value

	// A second tab still holding the old cookie, a moment later: it gets an
	// access token and no new cookie.
	race := authCall(t, app, "/auth/refresh", first)
	if race.status != 200 || race.token == "" {
		t.Fatalf("a refresh racing a rotation was refused: %d %v", race.status, race.body)
	}
	if race.cookie != nil && race.cookie.Value != "" {
		t.Fatal("the late request should not mint another token")
	}

	// The same spent token, long after: someone else has it. The whole
	// session ends, including the token the real user holds now.
	db.DB.Model(&models.RefreshToken{}).Where("token = ?", hashToken(first)).
		Update("rotated_at", time.Now().Add(-time.Hour))
	replay := authCall(t, app, "/auth/refresh", first)
	if replay.status != 401 {
		t.Fatalf("a replayed token was accepted: %d", replay.status)
	}
	if authCall(t, app, "/auth/refresh", second).status != 401 {
		t.Fatal("after a replay the legitimate token should be dead too")
	}
	var audit int64
	db.DB.Model(&models.AuditLog{}).Where("action = ?", "session_token_reuse").Count(&audit)
	if audit != 1 {
		t.Fatal("the replay is not in the audit log")
	}
}

func TestSessionEndsWhenIdleOrTooOld(t *testing.T) {
	app := sessionApp(t)
	u := activeUser(t)

	idle := signIn(t, app, u)
	db.DB.Model(&models.RefreshToken{}).Where("token = ?", hashToken(idle)).
		Update("expires_at", time.Now().Add(-time.Second))
	if authCall(t, app, "/auth/refresh", idle).status != 401 {
		t.Fatal("an idle session was renewed")
	}

	old := signIn(t, app, u)
	db.DB.Model(&models.RefreshToken{}).Where("token = ?", hashToken(old)).
		Update("session_started_at", time.Now().Add(-sessionMax()-time.Minute))
	if authCall(t, app, "/auth/refresh", old).status != 401 {
		t.Fatal("a session past its maximum age was renewed")
	}

	// The idle deadline never passes the hard one.
	start := time.Now().Add(-sessionMax() + time.Minute)
	if got := idleDeadline(start, time.Now()); got.After(start.Add(sessionMax())) {
		t.Fatalf("idle deadline %v is past the hard limit", got)
	}
}

func TestRefreshRefusesAnAccountThatChanged(t *testing.T) {
	app := sessionApp(t)
	u := activeUser(t)
	tok := signIn(t, app, u)
	db.DB.Model(&u).Update("is_active", false)
	if authCall(t, app, "/auth/refresh", tok).status != 401 {
		t.Fatal("a suspended account kept its session")
	}

	u2 := models.User{Email: "joao@example.com", Role: "user", IsActive: true, MFAEnabled: true}
	db.DB.Create(&u2)
	tok2 := signIn(t, app, u2)
	revokeUserSessions(u2.ID)
	if authCall(t, app, "/auth/refresh", tok2).status != 401 {
		t.Fatal("a revoked session was renewed")
	}
}

func TestLogoutEndsTheSessionOnTheServer(t *testing.T) {
	app := sessionApp(t)
	u := activeUser(t)
	tok := signIn(t, app, u)
	r := authCall(t, app, "/auth/logout", tok)
	if r.status != 200 || r.cookie == nil || r.cookie.Value != "" {
		t.Fatalf("logout should clear the cookie: %d %+v", r.status, r.cookie)
	}
	if authCall(t, app, "/auth/refresh", tok).status != 401 {
		t.Fatal("the session survived the logout")
	}
	// No cookie at all is simply no session.
	if authCall(t, app, "/auth/refresh", "").status != 401 {
		t.Fatal("a refresh without a cookie succeeded")
	}
}

// The refresh limit counts per session. The cookie changes on every refresh,
// so keying on it would never limit anything; keying on the address signed
// out a whole office behind one NAT.
func TestRefreshLimitKeyFollowsTheSessionAcrossRotation(t *testing.T) {
	app := sessionApp(t)
	u := activeUser(t)
	first := signIn(t, app, u)
	r := authCall(t, app, "/auth/refresh", first)
	second := r.cookie.Value

	keyFor := func(cookie string) string {
		k := fiber.New()
		var got string
		k.Post("/", func(c *fiber.Ctx) error { got = RefreshLimitKey(c); return nil })
		req := httptest.NewRequest("POST", "/", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: SessionCookie, Value: cookie})
		}
		if _, err := k.Test(req, -1); err != nil {
			t.Fatal(err)
		}
		return got
	}
	a, b := keyFor(first), keyFor(second)
	if a != b || !strings.HasPrefix(a, "session|") {
		t.Fatalf("keys across rotation: %q %q", a, b)
	}
	if k := keyFor("not-a-session"); !strings.HasPrefix(k, "ip|") {
		t.Fatalf("unknown cookie should fall back to the address, got %q", k)
	}
}
