package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// The vault's promise is that the server cannot read what it stores. Most of
// that lives in the browser and cannot be tested here. What can be tested is
// everything the server is still responsible for: that it will not accept a
// weakened KDF, that a membership row is what grants access rather than a
// permission, and that the audited half of an item is actually the audited one.

func useVaultDB(t *testing.T) {
	t.Helper()
	// A real key, so the at-rest layer is exercised rather than skipped.
	t.Setenv("ENCRYPTION_KEY", strings.Repeat("ab", 32))

	prev := db.DB
	t.Cleanup(func() { db.DB = prev })

	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "vault.db")), &gorm.Config{})
	if err != nil {
		t.Fatalf("open test db: %v", err)
	}
	if err := gdb.AutoMigrate(
		&models.User{}, &models.UserGroup{}, &models.UserGroupMember{}, &models.AuditLog{},
		&models.VaultKeyring{}, &models.Vault{}, &models.VaultMember{}, &models.VaultItem{},
	); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db.DB = gdb
}

// vaultApp mounts the handlers under a middleware that plays the part the JWT
// normally does, so the tests exercise the real routing and parameter parsing.
func vaultApp(actAs func() uint) *fiber.App {
	app := fiber.New()
	app.Use(func(c *fiber.Ctx) error {
		c.Locals("user_id", float64(actAs()))
		return c.Next()
	})
	app.Get("/vault/keyring", GetVaultKeyring)
	app.Post("/vault/keyring", EnrollVaultKeyring)
	app.Put("/vault/keyring", RekeyVaultKeyring)
	app.Get("/vaults", ListVaults)
	app.Post("/vaults", CreateVault)
	app.Delete("/vaults/:uuid", DeleteVault)
	app.Get("/vaults/:uuid/members", ListVaultMembers)
	app.Post("/vaults/:uuid/members", AddVaultMember)
	app.Delete("/vaults/:uuid/members/:user_id", RemoveVaultMember)
	app.Get("/vaults/:uuid/items", ListVaultItems)
	app.Post("/vaults/:uuid/items", CreateVaultItem)
	app.Put("/vaults/:uuid/items/:item_uuid", UpdateVaultItem)
	app.Get("/vaults/:uuid/items/:item_uuid/secret", RevealVaultItem)
	return app
}

func blob(n int) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x2a}, n))
}

func do(t *testing.T, app *fiber.App, method, path string, body any) (int, map[string]any) {
	t.Helper()
	var rdr *bytes.Reader
	if body != nil {
		raw, _ := json.Marshal(body)
		rdr = bytes.NewReader(raw)
	} else {
		rdr = bytes.NewReader(nil)
	}
	req := httptest.NewRequest(method, path, rdr)
	req.Header.Set("Content-Type", "application/json")
	res, err := app.Test(req, -1)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	var out map[string]any
	_ = json.NewDecoder(res.Body).Decode(&out)
	return res.StatusCode, out
}

func enroll(t *testing.T, app *fiber.App) {
	t.Helper()
	code, body := do(t, app, "POST", "/vault/keyring", fiber.Map{
		"public_key": blob(91), "fingerprint": strings.Repeat("a", 64),
		"private_key_enc": blob(200), "kdf_salt": blob(16),
		"kdf_params":       `{"alg":"argon2id","m":65536,"t":3,"p":1}`,
		"recovery_key_enc": blob(200), "recovery_salt": blob(16),
	})
	if code != http.StatusCreated {
		t.Fatalf("enroll failed: %d %v", code, body)
	}
}

// A tampered client could store parameters that make the passphrase trivial to
// grind offline, and the sealed blob would look no different. The floor is the
// only thing standing between that and a silent downgrade for one account.
func TestVaultKDFFloorIsEnforced(t *testing.T) {
	cases := []struct {
		name, params string
		ok           bool
	}{
		{"the accepted baseline", `{"alg":"argon2id","m":65536,"t":3,"p":1}`, true},
		{"stronger than the floor", `{"alg":"argon2id","m":262144,"t":4,"p":2}`, true},
		{"too little memory", `{"alg":"argon2id","m":1024,"t":3,"p":1}`, false},
		{"too few passes", `{"alg":"argon2id","m":65536,"t":1,"p":1}`, false},
		{"a fast hash in disguise", `{"alg":"pbkdf2","m":65536,"t":3,"p":1}`, false},
		{"not json at all", `argon2id`, false},
	}
	for _, tc := range cases {
		err := validKDFParams(tc.params)
		if tc.ok && err != nil {
			t.Errorf("%s: rejected, %v", tc.name, err)
		}
		if !tc.ok && err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
	}
}

// Size limits are what stop a vault from becoming an unaudited file host, and
// the base64 check is what stops a blob that could never decrypt from being
// stored as though it might.
func TestVaultBlobValidation(t *testing.T) {
	if !validVaultBlob(blob(32), maxWrappedKeyBytes) {
		t.Error("a well-formed wrapped key was rejected")
	}
	if validVaultBlob(blob(maxSecretBytes+1), maxSecretBytes) {
		t.Error("an oversized secret was accepted")
	}
	if validVaultBlob("", maxSecretBytes) {
		t.Error("an empty blob was accepted")
	}
	if validVaultBlob("not base64 at all!!", maxSecretBytes) {
		t.Error("a non-base64 blob was accepted")
	}
}

// Holding vault.read is permission to use the API, not permission to see
// somebody's vault. The membership row is the real boundary, and a vault the
// caller is not in has to be indistinguishable from one that does not exist.
func TestNonMemberCannotTellAVaultExists(t *testing.T) {
	useVaultDB(t)
	actor := uint(1)
	app := vaultApp(func() uint { return actor })
	enroll(t, app)

	id := uuid.NewString()
	if code, body := do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": id, "name": "Infra", "kind": "personal", "wrapped_key": blob(80),
	}); code != http.StatusCreated {
		t.Fatalf("create: %d %v", code, body)
	}

	actor = 2 // a different signed-in account, with the same permission
	if code, _ := do(t, app, "GET", "/vaults/"+id+"/items", nil); code != http.StatusNotFound {
		t.Errorf("a non-member got %d; it must be 404, not 403", code)
	}
	if code, _ := do(t, app, "GET", "/vaults/"+id+"/members", nil); code != http.StatusNotFound {
		t.Errorf("a non-member could enumerate members: %d", code)
	}
}

// Sharing a personal vault would mean sealing its key to a second person while
// the UI still calls it personal. Refusing is clearer than silently promoting.
func TestPersonalVaultCannotBeShared(t *testing.T) {
	useVaultDB(t)
	app := vaultApp(func() uint { return 1 })
	enroll(t, app)
	id := uuid.NewString()
	do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": id, "name": "Mine", "kind": "personal", "wrapped_key": blob(80),
	})

	code, body := do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 2, "role": "reader", "wrapped_key": blob(80),
	})
	if code != http.StatusBadRequest {
		t.Fatalf("a personal vault was shared: %d %v", code, body)
	}
}

// Sealing a key to someone who never enrolled produces a vault entry nobody
// can open, which looks like a working share until the day it is needed.
func TestSharingRequiresAnEnrolledRecipient(t *testing.T) {
	useVaultDB(t)
	actor := uint(1)
	app := vaultApp(func() uint { return actor })
	enroll(t, app)

	db.DB.Create(&models.UserGroup{Name: "platform"})
	db.DB.Create(&models.UserGroupMember{GroupID: 1, UserID: 2})
	gid := uint(1)
	id := uuid.NewString()
	if code, body := do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": id, "name": "Platform", "kind": "group", "group_id": gid, "wrapped_key": blob(80),
	}); code != http.StatusCreated {
		t.Fatalf("create group vault: %d %v", code, body)
	}

	code, _ := do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 2, "role": "reader", "wrapped_key": blob(80),
	})
	if code != http.StatusBadRequest {
		t.Fatalf("shared with an unenrolled account: %d", code)
	}

	// Enrol them, and the same call now works.
	actor = 2
	enroll(t, app)
	actor = 1
	if code, body := do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 2, "role": "reader", "wrapped_key": blob(80),
	}); code != http.StatusOK {
		t.Fatalf("share to an enrolled member failed: %d %v", code, body)
	}

	// And somebody outside the group still cannot be added to the group vault.
	actor = 3
	enroll(t, app)
	actor = 1
	if code, _ := do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 3, "role": "reader", "wrapped_key": blob(80),
	}); code != http.StatusBadRequest {
		t.Errorf("a non-member of the group was added to its vault: %d", code)
	}
}

func TestReaderCannotWrite(t *testing.T) {
	useVaultDB(t)
	actor := uint(1)
	app := vaultApp(func() uint { return actor })
	enroll(t, app)
	actor = 2
	enroll(t, app)
	actor = 1

	db.DB.Create(&models.UserGroup{Name: "platform"})
	db.DB.Create(&models.UserGroupMember{GroupID: 1, UserID: 2})
	gid := uint(1)
	id := uuid.NewString()
	do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": id, "name": "Platform", "kind": "group", "group_id": gid, "wrapped_key": blob(80),
	})
	do(t, app, "POST", "/vaults/"+id+"/members", fiber.Map{
		"user_id": 2, "role": "reader", "wrapped_key": blob(80),
	})

	actor = 2
	code, _ := do(t, app, "POST", "/vaults/"+id+"/items", fiber.Map{
		"uuid": uuid.NewString(), "overview_enc": blob(60), "secret_enc": blob(120),
	})
	if code != http.StatusForbidden {
		t.Fatalf("a reader wrote to the vault: %d", code)
	}
}

// Two people rotating the same credential is the ordinary case in a shared
// vault. Last write wins there means one of them restores the password the
// other just replaced, and nothing in the product would ever say so.
func TestStaleUpdateIsRefused(t *testing.T) {
	useVaultDB(t)
	app := vaultApp(func() uint { return 1 })
	enroll(t, app)
	vid := uuid.NewString()
	do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": vid, "name": "Infra", "kind": "personal", "wrapped_key": blob(80),
	})
	iid := uuid.NewString()
	do(t, app, "POST", "/vaults/"+vid+"/items", fiber.Map{
		"uuid": iid, "overview_enc": blob(60), "secret_enc": blob(120),
	})

	if code, _ := do(t, app, "PUT", "/vaults/"+vid+"/items/"+iid, fiber.Map{
		"overview_enc": blob(60), "secret_enc": blob(130), "base_version": 1,
	}); code != http.StatusOK {
		t.Fatalf("the first writer was refused: %d", code)
	}
	code, body := do(t, app, "PUT", "/vaults/"+vid+"/items/"+iid, fiber.Map{
		"overview_enc": blob(60), "secret_enc": blob(140), "base_version": 1,
	})
	if code != http.StatusConflict {
		t.Fatalf("a stale write was accepted: %d %v", code, body)
	}
}

// The split exists so the audit log has something honest to record. If the
// list carried secrets, every reveal row would be a lie about when somebody
// actually went looking.
func TestListCarriesNoSecretsAndRevealIsAudited(t *testing.T) {
	useVaultDB(t)
	app := vaultApp(func() uint { return 1 })
	enroll(t, app)
	vid := uuid.NewString()
	do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": vid, "name": "Infra", "kind": "personal", "wrapped_key": blob(80),
	})
	iid := uuid.NewString()
	secret := blob(120)
	do(t, app, "POST", "/vaults/"+vid+"/items", fiber.Map{
		"uuid": iid, "overview_enc": blob(60), "secret_enc": secret,
	})

	req := httptest.NewRequest("GET", "/vaults/"+vid+"/items", nil)
	res, _ := app.Test(req, -1)
	raw := new(bytes.Buffer)
	_, _ = raw.ReadFrom(res.Body)
	if strings.Contains(raw.String(), secret) {
		t.Error("the list response carried the secret half")
	}
	var audits int64
	db.DB.Model(&models.AuditLog{}).Where("action = ?", "vault_item_reveal").Count(&audits)
	if audits != 0 {
		t.Errorf("listing wrote %d reveal rows", audits)
	}

	code, body := do(t, app, "GET", "/vaults/"+vid+"/items/"+iid+"/secret", nil)
	if code != http.StatusOK {
		t.Fatalf("reveal failed: %d %v", code, body)
	}
	// The at-rest layer has to be transparent: what the browser sealed is
	// exactly what it gets back, or nothing decrypts.
	if body["secret_enc"] != secret {
		t.Error("the sealed bytes did not survive the at-rest wrapping")
	}
	db.DB.Model(&models.AuditLog{}).Where("action = ?", "vault_item_reveal").Count(&audits)
	if audits != 1 {
		t.Errorf("reveal wrote %d audit rows, want 1", audits)
	}
}

// The column on disk must not be the blob the browser sent: that second
// wrapping is what a stolen database file runs into before it can even start
// on the passphrase.
func TestCiphertextIsWrappedAgainAtRest(t *testing.T) {
	useVaultDB(t)
	app := vaultApp(func() uint { return 1 })
	enroll(t, app)
	vid := uuid.NewString()
	do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": vid, "name": "Infra", "kind": "personal", "wrapped_key": blob(80),
	})
	secret := blob(120)
	do(t, app, "POST", "/vaults/"+vid+"/items", fiber.Map{
		"uuid": uuid.NewString(), "overview_enc": blob(60), "secret_enc": secret,
	})

	var stored models.VaultItem
	db.DB.First(&stored)
	if stored.SecretEnc == secret {
		t.Error("the sealed blob was stored verbatim, with no at-rest wrapping")
	}
	if !strings.HasPrefix(stored.SecretEnc, "enc:") {
		t.Errorf("stored value is not server-encrypted: %.12q", stored.SecretEnc)
	}
}

// Re-enrolling would mint a second identity while every vault key is still
// sealed to the first, which presents to the person as a vault that emptied
// itself. Changing a passphrase is a different operation and keeps the key.
func TestEnrollIsOnceOnly(t *testing.T) {
	useVaultDB(t)
	app := vaultApp(func() uint { return 1 })
	enroll(t, app)
	code, _ := do(t, app, "POST", "/vault/keyring", fiber.Map{
		"public_key": blob(91), "fingerprint": strings.Repeat("b", 64),
		"private_key_enc": blob(200), "kdf_salt": blob(16),
		"kdf_params":       `{"alg":"argon2id","m":65536,"t":3,"p":1}`,
		"recovery_key_enc": blob(200), "recovery_salt": blob(16),
	})
	if code != http.StatusConflict {
		t.Fatalf("a second enrolment was accepted: %d", code)
	}
}

// A recovery code has been typed, so it has been somewhere it can be read.
// Letting the reset finish without issuing a new one leaves the account with
// one way in and no second chance.
func TestRecoveryResetMustIssueANewCode(t *testing.T) {
	useVaultDB(t)
	app := vaultApp(func() uint { return 1 })
	enroll(t, app)

	code, _ := do(t, app, "PUT", "/vault/keyring", fiber.Map{
		"private_key_enc": blob(200), "kdf_salt": blob(16),
		"kdf_params":   `{"alg":"argon2id","m":65536,"t":3,"p":1}`,
		"via_recovery": true,
	})
	if code != http.StatusBadRequest {
		t.Fatalf("a recovery reset left no new recovery code: %d", code)
	}

	code, _ = do(t, app, "PUT", "/vault/keyring", fiber.Map{
		"private_key_enc": blob(200), "kdf_salt": blob(16),
		"kdf_params":       `{"alg":"argon2id","m":65536,"t":3,"p":1}`,
		"recovery_key_enc": blob(200), "recovery_salt": blob(16),
		"via_recovery": true,
	})
	if code != http.StatusOK {
		t.Fatalf("a complete recovery reset was refused: %d", code)
	}
	var kr models.VaultKeyring
	db.DB.First(&kr)
	if kr.RecoveryUsedAt == nil {
		t.Error("the recovery code was not marked as used")
	}
}

// The recovery wrapping is the one blob worth stealing without a passphrase,
// so asking for it is recorded even though the caller is its owner.
func TestRecoveryFetchIsAudited(t *testing.T) {
	useVaultDB(t)
	app := vaultApp(func() uint { return 1 })
	enroll(t, app)

	_, body := do(t, app, "GET", "/vault/keyring", nil)
	if _, leaked := body["recovery_key_enc"]; leaked {
		t.Error("an ordinary unlock handed out the recovery wrapping")
	}
	var rows int64
	db.DB.Model(&models.AuditLog{}).Where("action = ?", "vault_recovery_fetch").Count(&rows)
	if rows != 0 {
		t.Errorf("an ordinary unlock wrote %d recovery rows", rows)
	}

	_, body = do(t, app, "GET", "/vault/keyring?recovery=1", nil)
	if _, ok := body["recovery_key_enc"]; !ok {
		t.Error("the recovery wrapping was not returned when asked for")
	}
	db.DB.Model(&models.AuditLog{}).Where("action = ?", "vault_recovery_fetch").Count(&rows)
	if rows != 1 {
		t.Errorf("the recovery fetch wrote %d audit rows, want 1", rows)
	}
}

func TestOwnerCannotBeRemovedFromTheirOwnVault(t *testing.T) {
	useVaultDB(t)
	app := vaultApp(func() uint { return 1 })
	enroll(t, app)
	vid := uuid.NewString()
	do(t, app, "POST", "/vaults", fiber.Map{
		"uuid": vid, "name": "Infra", "kind": "personal", "wrapped_key": blob(80),
	})
	if code, _ := do(t, app, "DELETE", "/vaults/"+vid+"/members/1", nil); code != http.StatusBadRequest {
		t.Fatalf("the owner was removed from their own vault: %d", code)
	}
}

// The vault permissions have to be grantable, or the only way to give somebody
// access to a shared vault is to make them an admin of everything.
func TestVaultPermissionsAreGrantable(t *testing.T) {
	for _, p := range []string{PermVaultRead, PermVaultWrite, PermVaultShare} {
		if !validPermission(p) {
			t.Errorf("%s is not in the catalog, so it can never be granted", p)
		}
	}
	held := map[string]bool{}
	for _, p := range rolePermissions["user"] {
		held[p] = true
	}
	if !held[PermVaultRead] || !held[PermVaultWrite] {
		t.Error("a plain account cannot keep a personal vault")
	}
	if held[PermVaultShare] {
		t.Error("a plain account can share vaults by default")
	}
}
