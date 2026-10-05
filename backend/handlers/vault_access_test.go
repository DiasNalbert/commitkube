package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/middleware"
	"github.com/kubecommit/backend/models"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Team vaults are given to people by name and to IAM groups. A group grant is
// a standing decision the server cannot carry out by itself -- only a browser
// holding the vault key can seal a copy -- so what is tested here is that the
// server keeps the decision honest: who is owed a key, what role they get, and
// that leaving the group takes the key away.

func teamVault(t *testing.T, app *fiber.App) string {
	t.Helper()
	id := uuid.NewString()
	if code, body := do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": id, "name": "Platform", "kind": "team", "wrapped_key": blob(80),
	}); code != http.StatusCreated {
		t.Fatalf("create team vault: %d %v", code, body)
	}
	return id
}

func doList(t *testing.T, app *fiber.App, path string) (int, []map[string]any) {
	t.Helper()
	res, err := app.Test(httptest.NewRequest("GET", path, nil), -1)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	var out []map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func TestTeamVaultNeedsSharePermission(t *testing.T) {
	useVaultDB(t)
	app := vaultAppAs(func() uint { return 1 }, func() string { return "user" })
	enroll(t, app)

	code, _ := do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": uuid.NewString(), "name": "Ops", "kind": "team", "wrapped_key": blob(80),
	})
	if code != http.StatusForbidden {
		t.Fatalf("a plain account created a team vault: %d", code)
	}
	if code, _ := do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": uuid.NewString(), "name": "Mine", "kind": "personal", "wrapped_key": blob(80),
	}); code != http.StatusCreated {
		t.Fatalf("a plain account could not create a personal vault: %d", code)
	}
}

func TestGroupAccessQueuesKeysForEnrolledMembersOnly(t *testing.T) {
	useVaultDB(t)
	actor := uint(1)
	app := vaultApp(func() uint { return actor })
	enroll(t, app)
	actor = 2
	enroll(t, app) // 3 stays unenrolled
	actor = 1

	db.DB.Create(&models.UserGroup{Name: "platform"})
	db.DB.Create(&models.UserGroupMember{GroupID: 1, UserID: 2})
	db.DB.Create(&models.UserGroupMember{GroupID: 1, UserID: 3})
	id := teamVault(t, app)

	if code, body := do(t, app, "POST", "/vaults/"+id+"/groups", fiber.Map{"group_id": 1, "role": "reader"}); code != http.StatusOK {
		t.Fatalf("grant group: %d %v", code, body)
	}

	_, pending := doList(t, app, "/vault/pending-keys")
	if len(pending) != 1 || pending[0]["user_id"].(float64) != 2 {
		t.Fatalf("pending keys = %v, want exactly user 2", pending)
	}

	// Before the key arrives, the member sees the vault as waiting, with no key.
	actor = 2
	_, list := doList(t, app, "/vaults")
	if len(list) != 1 || list[0]["pending"] != true || list[0]["wrapped_key"] != "" {
		t.Fatalf("an entitled member should see the vault as pending: %v", list)
	}
	if code, _ := do(t, app, "GET", "/vaults/"+id+"/items", nil); code != http.StatusNotFound {
		t.Errorf("a member without a key could list items: %d", code)
	}

	// The owner's browser delivers it. The role asked for is ignored: the
	// group's grant decides it.
	actor = 1
	if code, body := do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 2, "role": "writer", "wrapped_key": blob(80), "via_group_id": 1,
	}); code != http.StatusOK {
		t.Fatalf("deliver group key: %d %v", code, body)
	}
	var m models.VaultMember
	db.DB.Where("user_id = ?", 2).First(&m)
	if m.Role != "reader" || m.ViaGroupID == nil {
		t.Errorf("delivered member = role %q via %v, want reader via the group", m.Role, m.ViaGroupID)
	}
	if _, pending := doList(t, app, "/vault/pending-keys"); len(pending) != 0 {
		t.Errorf("the queue still holds %v after delivery", pending)
	}

	// Changing the group's role reaches the people already in through it.
	do(t, app, "POST", "/vaults/"+id+"/groups", fiber.Map{"group_id": 1, "role": "writer"})
	db.DB.Where("user_id = ?", 2).First(&m)
	if m.Role != "writer" {
		t.Errorf("group role change did not reach its members: %q", m.Role)
	}
}

func TestDeliveringToSomeoneOutsideTheGroupIsRefused(t *testing.T) {
	useVaultDB(t)
	actor := uint(1)
	app := vaultApp(func() uint { return actor })
	enroll(t, app)
	actor = 2
	enroll(t, app)
	actor = 1

	db.DB.Create(&models.UserGroup{Name: "platform"})
	id := teamVault(t, app)
	do(t, app, "POST", "/vaults/"+id+"/groups", fiber.Map{"group_id": 1, "role": "reader"})

	if code, _ := do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 2, "wrapped_key": blob(80), "via_group_id": 1,
	}); code != http.StatusBadRequest {
		t.Fatalf("a key was delivered through a group the person is not in: %d", code)
	}
}

// Leaving the group has to mean leaving the vault, without anybody having to
// remember to remove them from it as well.
func TestLeavingTheGroupTakesTheKeyAway(t *testing.T) {
	useVaultDB(t)
	actor := uint(1)
	app := vaultApp(func() uint { return actor })
	enroll(t, app)
	actor = 2
	enroll(t, app)
	actor = 1

	db.DB.Create(&models.UserGroup{Name: "platform"})
	db.DB.Create(&models.UserGroupMember{GroupID: 1, UserID: 2})
	id := teamVault(t, app)
	do(t, app, "POST", "/vaults/"+id+"/groups", fiber.Map{"group_id": 1, "role": "writer"})
	do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{"user_id": 2, "wrapped_key": blob(80), "via_group_id": 1})

	// Removed from the group by any path, not only through the group handler.
	db.DB.Where("group_id = 1 AND user_id = 2").Delete(&models.UserGroupMember{})

	actor = 2
	if code, _ := do(t, app, "GET", "/vaults/"+id+"/items", nil); code != http.StatusNotFound {
		t.Fatalf("a former group member still reached the vault: %d", code)
	}
	var left int64
	db.DB.Model(&models.VaultMember{}).Where("user_id = ?", 2).Count(&left)
	if left != 0 {
		t.Error("the sealed key of a former group member was kept")
	}
}

// Removing a group's access removes the people who came with it, and only
// them: someone also added by name is a separate decision.
func TestRemovingAGroupKeepsPeopleAddedByName(t *testing.T) {
	useVaultDB(t)
	actor := uint(1)
	app := vaultApp(func() uint { return actor })
	for _, u := range []uint{1, 2, 3} {
		actor = u
		enroll(t, app)
	}
	actor = 1

	db.DB.Create(&models.UserGroup{Name: "platform"})
	db.DB.Create(&models.UserGroupMember{GroupID: 1, UserID: 2})
	db.DB.Create(&models.UserGroupMember{GroupID: 1, UserID: 3})
	id := teamVault(t, app)
	do(t, app, "POST", "/vaults/"+id+"/groups", fiber.Map{"group_id": 1, "role": "reader"})
	do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{"user_id": 2, "wrapped_key": blob(80), "via_group_id": 1})
	do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{"user_id": 3, "role": "writer", "wrapped_key": blob(80)})

	// A person who reached the vault through a group cannot be removed one
	// at a time; the group would hand the key straight back.
	if code, _ := do(t, app, "DELETE", "/vaults/"+id+"/members/2", nil); code != http.StatusBadRequest {
		t.Errorf("removing a group-sourced member individually: %d, want 400", code)
	}

	if code, body := do(t, app, "DELETE", "/vaults/"+id+"/groups/1", nil); code != http.StatusOK {
		t.Fatalf("remove group: %d %v", code, body)
	}
	var two, three int64
	db.DB.Model(&models.VaultMember{}).Where("user_id = ?", 2).Count(&two)
	db.DB.Model(&models.VaultMember{}).Where("user_id = ?", 3).Count(&three)
	if two != 0 {
		t.Error("the group member kept their key after the group was removed")
	}
	if three != 1 {
		t.Error("a person added by name lost access when a group was removed")
	}
}

// A writer holds the key and can deliver what a group is owed, but deciding
// who is owed is the owner's.
func TestWriterDeliversButDoesNotChoose(t *testing.T) {
	useVaultDB(t)
	actor := uint(1)
	app := vaultApp(func() uint { return actor })
	for _, u := range []uint{1, 2, 3} {
		actor = u
		enroll(t, app)
	}
	actor = 1
	db.DB.Create(&models.UserGroup{Name: "platform"})
	db.DB.Create(&models.UserGroupMember{GroupID: 1, UserID: 3})
	id := teamVault(t, app)
	do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{"user_id": 2, "role": "writer", "wrapped_key": blob(80)})
	do(t, app, "POST", "/vaults/"+id+"/groups", fiber.Map{"group_id": 1, "role": "reader"})

	actor = 2
	if code, _ := do(t, app, "POST", "/vaults/"+id+"/groups", fiber.Map{"group_id": 1, "role": "writer"}); code != http.StatusForbidden {
		t.Errorf("a writer changed group access: %d", code)
	}
	if code, _ := do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 3, "role": "reader", "wrapped_key": blob(80),
	}); code != http.StatusForbidden {
		t.Errorf("a writer added somebody by name: %d", code)
	}
	if code, body := do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 3, "wrapped_key": blob(80), "via_group_id": 1,
	}); code != http.StatusOK {
		t.Errorf("a writer could not deliver a key the group is owed: %d %v", code, body)
	}
}

func TestPersonalVaultIsCreatedOnceAndKept(t *testing.T) {
	useVaultDB(t)
	app := vaultAppAs(func() uint { return 1 }, func() string { return "user" })
	enroll(t, app)

	id := uuid.NewString()
	if code, body := do(t, app, "POST", "/vault/personal", fiber.Map{"uuid": id, "wrapped_key": blob(80)}); code != http.StatusCreated {
		t.Fatalf("create personal vault: %d %v", code, body)
	}
	if code, _ := do(t, app, "POST", "/vault/personal", fiber.Map{"uuid": uuid.NewString(), "wrapped_key": blob(80)}); code != http.StatusConflict {
		t.Errorf("a second default personal vault was created: %d", code)
	}
	if code, _ := do(t, app, "DELETE", "/vaults/"+id, nil); code != http.StatusBadRequest {
		t.Errorf("the only personal vault was deleted: %d", code)
	}
}

// ---- vault MFA ------------------------------------------------------------

func mfaApp(actAs func() uint) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", float64(actAs()))
		c.Locals("role", "admin")
		return c.Next()
	})
	app.Get("/vault/status", GetVaultStatus)
	app.Post("/vault/mfa/setup", SetupVaultMFA)
	app.Post("/vault/mfa/confirm", ConfirmVaultMFA)
	app.Post("/vault/mfa/verify", VerifyVaultMFA)
	app.Delete("/users/:id/vault-mfa", ResetUserVaultMFA)
	app.Get("/vaults", VaultSessionRequired(), ListVaults)
	return app
}

func codeFor(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := totp.GenerateCodeCustom(secret, at, totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func getWithSession(t *testing.T, app *fiber.App, path, session string) int {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if session != "" {
		req.Header.Set(vaultSessionHeader, session)
	}
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatal(err)
	}
	return res.StatusCode
}

// enableVaultMFA runs the setup and returns the seed and a live session.
func enableVaultMFA(t *testing.T, app *fiber.App) (string, string) {
	t.Helper()
	code, body := do(t, app, "POST", "/vault/mfa/setup", nil)
	if code != http.StatusOK {
		t.Fatalf("setup: %d %v", code, body)
	}
	secret := body["secret"].(string)
	code, body = do(t, app, "POST", "/vault/mfa/confirm", fiber.Map{"code": codeFor(t, secret, time.Now())})
	if code != http.StatusOK {
		t.Fatalf("confirm: %d %v", code, body)
	}
	return secret, body["session"].(string)
}

func TestVaultMFAIsSeparateFromSignIn(t *testing.T) {
	useVaultDB(t)
	db.DB.Create(&models.User{Email: "a@x", MFASecret: "JBSWY3DPEHPK3PXP", MFAEnabled: true, Role: "user"})
	app := mfaApp(func() uint { return 1 })

	code, body := do(t, app, "POST", "/vault/mfa/setup", nil)
	if code != http.StatusOK {
		t.Fatalf("setup: %d %v", code, body)
	}
	if body["secret"] == "JBSWY3DPEHPK3PXP" {
		t.Fatal("the vault reused the sign-in seed")
	}
	// A code from the sign-in authenticator entry does not open the vault.
	login := codeFor(t, "JBSWY3DPEHPK3PXP", time.Now())
	if code, _ := do(t, app, "POST", "/vault/mfa/confirm", fiber.Map{"code": login}); code == http.StatusOK {
		t.Fatal("the sign-in code was accepted as the vault code")
	}

	var f models.VaultMFA
	db.DB.First(&f)
	if f.SecretEnc == body["secret"] || crypto.DecryptField(crypto.MasterKey(), f.SecretEnc) != body["secret"] {
		t.Error("the vault seed is not encrypted at rest")
	}
}

func TestVaultRoutesNeedASession(t *testing.T) {
	useVaultDB(t)
	db.DB.Create(&models.User{Email: "a@x", Role: "user"})
	db.DB.Create(&models.User{Email: "b@x", Role: "user"})
	actor := uint(1)
	app := mfaApp(func() uint { return actor })

	if code := getWithSession(t, app, "/vaults", ""); code != http.StatusForbidden {
		t.Fatalf("no session reached the vault: %d", code)
	}
	_, session := enableVaultMFA(t, app)
	if code := getWithSession(t, app, "/vaults", session); code != http.StatusOK {
		t.Fatalf("a valid session was refused: %d", code)
	}
	actor = 2
	if code := getWithSession(t, app, "/vaults", session); code != http.StatusForbidden {
		t.Errorf("one account's vault session worked for another: %d", code)
	}
}

// AuthRequired accepts anything signed with the JWT secret. A vault session
// signed with it would double as a sign-in token.
func TestVaultSessionIsNotAnAccessToken(t *testing.T) {
	useVaultDB(t)
	tok, err := issueVaultSession(1, 1)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	app.Get("/x", middleware.AuthRequired(), func(c *fiber.Ctx) error { return c.SendString("ok") })
	req := httptest.NewRequest("GET", "/x", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	res, _ := app.Test(req, -1)
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("a vault session was accepted as an API token: %d", res.StatusCode)
	}
}

func TestVaultCodeIsSingleUse(t *testing.T) {
	useVaultDB(t)
	db.DB.Create(&models.User{Email: "a@x", Role: "user"})
	app := mfaApp(func() uint { return 1 })
	secret, _ := enableVaultMFA(t, app)

	// Pinned to the window the confirm actually used, so the test does not
	// depend on which side of a 30-second boundary it runs.
	var f models.VaultMFA
	db.DB.First(&f)
	used := time.Unix(f.LastStep*vaultMFAPeriod, 0)
	if code, _ := do(t, app, "POST", "/vault/mfa/verify", fiber.Map{"code": codeFor(t, secret, used)}); code != http.StatusUnauthorized {
		t.Fatalf("a used code was accepted again: %d", code)
	}
	// The next window's code is fine (one step of clock skew is allowed).
	if code, body := do(t, app, "POST", "/vault/mfa/verify", fiber.Map{"code": codeFor(t, secret, used.Add(30*time.Second))}); code != http.StatusOK {
		t.Fatalf("a fresh code was refused: %d %v", code, body)
	}
}

func TestVaultCodeLocksAfterRepeatedFailures(t *testing.T) {
	useVaultDB(t)
	db.DB.Create(&models.User{Email: "a@x", Role: "user"})
	app := mfaApp(func() uint { return 1 })
	secret, _ := enableVaultMFA(t, app)

	for i := 0; i < vaultMFAMaxFailures; i++ {
		do(t, app, "POST", "/vault/mfa/verify", fiber.Map{"code": "000000"})
	}
	code, _ := do(t, app, "POST", "/vault/mfa/verify", fiber.Map{"code": codeFor(t, secret, time.Now().Add(30*time.Second))})
	if code != http.StatusTooManyRequests {
		t.Fatalf("a right code was accepted during the lockout: %d", code)
	}
}

// Once active, the seed cannot be swapped by whoever holds a session --
// that would be the vault code moving to the attacker's phone.
func TestVaultMFACannotBeReplacedWhileActive(t *testing.T) {
	useVaultDB(t)
	db.DB.Create(&models.User{Email: "a@x", Role: "user"})
	app := mfaApp(func() uint { return 1 })
	enableVaultMFA(t, app)
	if code, _ := do(t, app, "POST", "/vault/mfa/setup", nil); code != http.StatusConflict {
		t.Fatalf("an active vault code was replaced: %d", code)
	}
}

func TestResetEndsLiveVaultSessions(t *testing.T) {
	useVaultDB(t)
	db.DB.Create(&models.User{Email: "a@x", Role: "user"})
	db.DB.Create(&models.User{Email: "admin@x", Role: "admin"})
	actor := uint(1)
	app := mfaApp(func() uint { return actor })
	_, session := enableVaultMFA(t, app)

	actor = 2
	if code, body := do(t, app, "DELETE", "/users/1/vault-mfa", nil); code != http.StatusOK {
		t.Fatalf("reset: %d %v", code, body)
	}
	actor = 1
	if code := getWithSession(t, app, "/vaults", session); code != http.StatusForbidden {
		t.Errorf("a session from before the reset still worked: %d", code)
	}
	// And setting it up again does not revive the old session.
	enableVaultMFA(t, app)
	if code := getWithSession(t, app, "/vaults", session); code != http.StatusForbidden {
		t.Errorf("an old session came back after re-enrolling: %d", code)
	}
}

// A denial is how an administrator takes vault.create away from one person.
// /me/permissions has to leave it out, or the page keeps offering the button.
func TestMyPermissionsLeavesOutDenials(t *testing.T) {
	useVaultDB(t)
	db.DB.Create(&models.PermissionGrant{SubjectType: "user", SubjectID: 1, Permission: PermVaultCreate, Denied: true})
	app := vaultAppAs(func() uint { return 1 }, func() string { return "user" })
	app.Get("/me/permissions", GetMyPermissions)

	_, body := do(t, app, "GET", "/me/permissions", nil)
	for _, p := range body["permissions"].([]any) {
		if p == PermVaultCreate {
			t.Error("a denied permission was reported as held")
		}
		if p == PermIAMManage {
			t.Error("iam.manage was reported for a non-root account")
		}
	}
}
