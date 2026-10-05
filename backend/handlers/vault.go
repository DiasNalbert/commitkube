package handlers

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// The vault endpoints move sealed bytes and nothing else. The server cannot
// check that a blob decrypts, so it checks the things it still can: that the
// base64 is real, that it is small enough not to turn the vault into a file
// host, that the person asking holds a membership row, and that the identity a
// key is being sealed to belongs to somebody who actually enrolled. Everything
// past that is the browser's job, and deliberately so.

const (
	maxWrappedKeyBytes = 512       // ephemeral pubkey + nonce + 32-byte key
	maxPublicKeyBytes  = 256       // SPKI P-256 is 91
	maxPrivateKeyBytes = 4 * 1024  // sealed PKCS#8
	maxOverviewBytes   = 8 * 1024  // name, username, url, tags
	maxSecretBytes     = 64 * 1024 // password, notes, custom fields
	maxVaultNameLen    = 120
	maxVaultDescLen    = 500
)

// vaultRoles that may change what a vault holds. A reader can open every item
// they have a key for and change none of them.
var vaultWriterRoles = map[string]bool{"owner": true, "writer": true}

func validVaultBlob(b64 string, max int) bool {
	raw, err := base64.StdEncoding.DecodeString(b64)
	return err == nil && len(raw) > 0 && len(raw) <= max
}

func validVaultUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// vaultFor resolves a vault by its UUID together with the caller's membership.
// Both in one place, because every handler below needs both and a vault
// without a membership row has to answer 404 rather than 403: telling somebody
// a vault exists is already telling them something.
//
// It reports ok rather than returning an error, because c.JSON returns nil
// when it succeeds -- so a helper that handed back its own response would hand
// back nil on every rejection, and every caller would read that as success and
// carry on with a nil vault. When ok is false the response is already written
// and the handler returns nil.
func vaultFor(c *fiber.Ctx, userID uint) (*models.Vault, *models.VaultMember, bool) {
	ref := c.Params("uuid")
	if !validVaultUUID(ref) {
		_ = c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid vault id"})
		return nil, nil, false
	}
	var v models.Vault
	if err := db.DB.Where("uuid = ?", ref).First(&v).Error; err != nil {
		_ = c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "vault not found"})
		return nil, nil, false
	}
	var m models.VaultMember
	if err := db.DB.Where("vault_id = ? AND user_id = ?", v.ID, userID).First(&m).Error; err != nil ||
		!groupMembershipHolds(&m) {
		_ = c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "vault not found"})
		return nil, nil, false
	}
	return &v, &m, true
}

// callerHolds answers an IAM question from inside a handler, for the routes
// whose requirement depends on the request: creating a team vault needs more
// than creating a personal one.
func callerHolds(c *fiber.Ctx, permission string) bool {
	role, _ := c.Locals("role").(string)
	return permissionsFor(currentUserID(c), role)[permission]
}

// groupMembershipHolds checks that somebody who is in a vault because of a
// group still is in that group, and that the group still has the vault. When
// either has gone the sealed key is deleted on the spot. Doing it at the door
// rather than only when a group changes is what keeps it true whichever path
// the change took -- an IAM edit, a deleted group, a database restored from
// before either.
func groupMembershipHolds(m *models.VaultMember) bool {
	if m.ViaGroupID == nil {
		return true
	}
	var grants, inGroup int64
	db.DB.Model(&models.VaultGroupAccess{}).
		Where("vault_id = ? AND group_id = ?", m.VaultID, *m.ViaGroupID).Count(&grants)
	db.DB.Model(&models.UserGroupMember{}).
		Where("group_id = ? AND user_id = ?", *m.ViaGroupID, m.UserID).Count(&inGroup)
	if grants > 0 && inGroup > 0 {
		return true
	}
	db.DB.Delete(m)
	return false
}

// RevokeGroupVaultKeys deletes the sealed keys a group handed out: every one
// when the group itself is gone, or one person's when they leave it. Called
// from the group handlers so the change is immediate rather than waiting for
// the person's next request to find it.
func RevokeGroupVaultKeys(groupID uint, userID *uint) {
	q := db.DB.Where("via_group_id = ?", groupID)
	if userID != nil {
		q = q.Where("user_id = ?", *userID)
	}
	q.Delete(&models.VaultMember{})
	if userID == nil {
		db.DB.Where("group_id = ?", groupID).Delete(&models.VaultGroupAccess{})
	}
}

// ---- keyring --------------------------------------------------------------

// GetVaultKeyring hands back the caller's own sealed identity so a second
// machine can unlock with the passphrase. The recovery wrapping is left out
// unless it is asked for by name, and asking is audited: fetching it is the
// one move that precedes losing a passphrase or stealing an account.
func GetVaultKeyring(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var kr models.VaultKeyring
	if err := db.DB.Where("user_id = ?", userID).First(&kr).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not enrolled"})
	}
	encKey := crypto.MasterKey()
	out := fiber.Map{
		"user_id":         kr.UserID,
		"public_key":      kr.PublicKey,
		"fingerprint":     kr.Fingerprint,
		"private_key_enc": crypto.DecryptField(encKey, kr.PrivateKeyEnc),
		"kdf_salt":        kr.KDFSalt,
		"kdf_params":      kr.KDFParams,
		"recovery_used":   kr.RecoveryUsedAt != nil,
	}
	if c.Query("recovery") == "1" {
		out["recovery_key_enc"] = crypto.DecryptField(encKey, kr.RecoveryKeyEnc)
		out["recovery_salt"] = kr.RecoverySalt
		db.LogAudit(userID, "vault_recovery_fetch", "vault", "keyring", "recovery wrapping requested", c.IP())
	}
	return c.JSON(out)
}

// EnrollVaultKeyring records a keypair the browser generated. It runs once:
// re-enrolling would mint a new identity while every existing vault key is
// still sealed to the old one, which reads as "my vault emptied itself".
// Changing the passphrase is a different operation, below.
func EnrollVaultKeyring(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var existing models.VaultKeyring
	if err := db.DB.Where("user_id = ?", userID).First(&existing).Error; err == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "already enrolled; change the passphrase instead"})
	}

	var req struct {
		PublicKey      string `json:"public_key"`
		Fingerprint    string `json:"fingerprint"`
		PrivateKeyEnc  string `json:"private_key_enc"`
		KDFSalt        string `json:"kdf_salt"`
		KDFParams      string `json:"kdf_params"`
		RecoveryKeyEnc string `json:"recovery_key_enc"`
		RecoverySalt   string `json:"recovery_salt"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if !validVaultBlob(req.PublicKey, maxPublicKeyBytes) ||
		!validVaultBlob(req.PrivateKeyEnc, maxPrivateKeyBytes) ||
		!validVaultBlob(req.RecoveryKeyEnc, maxPrivateKeyBytes) ||
		!validVaultBlob(req.KDFSalt, 64) || !validVaultBlob(req.RecoverySalt, 64) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "malformed key material"})
	}
	if err := validKDFParams(req.KDFParams); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if len(req.Fingerprint) != 64 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "fingerprint must be a sha-256 hex digest"})
	}

	encKey := crypto.MasterKey()
	kr := models.VaultKeyring{
		UserID:      userID,
		PublicKey:   req.PublicKey,
		Fingerprint: strings.ToLower(req.Fingerprint),
		// Sealed again under the server key. It buys nothing against this
		// server, and everything against a copied database file: the layer
		// the browser applied is what an attacker then still has to break.
		PrivateKeyEnc:  crypto.EncryptField(encKey, req.PrivateKeyEnc),
		KDFSalt:        req.KDFSalt,
		KDFParams:      req.KDFParams,
		RecoveryKeyEnc: crypto.EncryptField(encKey, req.RecoveryKeyEnc),
		RecoverySalt:   req.RecoverySalt,
	}
	if err := db.DB.Create(&kr).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	db.LogAudit(userID, "vault_enroll", "vault", "keyring", "fingerprint "+kr.Fingerprint, c.IP())
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"fingerprint": kr.Fingerprint})
}

// RekeyVaultKeyring reseals the same private key under a new passphrase. The
// identity is untouched on purpose: every vault key stays sealed to the same
// public key, so changing a passphrase does not require re-sharing anything.
func RekeyVaultKeyring(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var kr models.VaultKeyring
	if err := db.DB.Where("user_id = ?", userID).First(&kr).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not enrolled"})
	}

	var req struct {
		PrivateKeyEnc  string `json:"private_key_enc"`
		KDFSalt        string `json:"kdf_salt"`
		KDFParams      string `json:"kdf_params"`
		RecoveryKeyEnc string `json:"recovery_key_enc"`
		RecoverySalt   string `json:"recovery_salt"`
		ViaRecovery    bool   `json:"via_recovery"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if !validVaultBlob(req.PrivateKeyEnc, maxPrivateKeyBytes) || !validVaultBlob(req.KDFSalt, 64) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "malformed key material"})
	}
	if err := validKDFParams(req.KDFParams); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	encKey := crypto.MasterKey()
	kr.PrivateKeyEnc = crypto.EncryptField(encKey, req.PrivateKeyEnc)
	kr.KDFSalt = req.KDFSalt
	kr.KDFParams = req.KDFParams

	// A recovery code is single use by intent: it has been typed, so it has
	// been somewhere it can be read. Replacing it is part of the same step,
	// and refusing to continue without a new one is what stops a vault from
	// quietly ending up with no second way in.
	if req.ViaRecovery {
		if !validVaultBlob(req.RecoveryKeyEnc, maxPrivateKeyBytes) || !validVaultBlob(req.RecoverySalt, 64) {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "a recovery reset must issue a new recovery code"})
		}
		now := time.Now()
		kr.RecoveryUsedAt = &now
	}
	if validVaultBlob(req.RecoveryKeyEnc, maxPrivateKeyBytes) && validVaultBlob(req.RecoverySalt, 64) {
		kr.RecoveryKeyEnc = crypto.EncryptField(encKey, req.RecoveryKeyEnc)
		kr.RecoverySalt = req.RecoverySalt
	}
	db.DB.Save(&kr)

	action, detail := "vault_rekey", "passphrase changed"
	if req.ViaRecovery {
		action, detail = "vault_recovery_used", "passphrase reset with the recovery code"
	}
	db.LogAudit(userID, action, "vault", "keyring", detail, c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// validKDFParams refuses anything weaker than the browser is asked to use.
// The client picks the parameters and the server stores them, which means a
// tampered client could store "argon2id, one iteration, one kilobyte" and the
// blob would look identical. Checking the floor here is what keeps that from
// being a silent downgrade of everyone's passphrase.
func validKDFParams(raw string) error {
	var p struct {
		Alg string `json:"alg"`
		M   int    `json:"m"`
		T   int    `json:"t"`
		P   int    `json:"p"`
	}
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		return fiber.NewError(fiber.StatusBadRequest, "kdf_params must be json")
	}
	if p.Alg != "argon2id" {
		return fiber.NewError(fiber.StatusBadRequest, "kdf must be argon2id")
	}
	if p.M < 65536 || p.T < 3 || p.P < 1 {
		return fiber.NewError(fiber.StatusBadRequest, "kdf parameters are below the accepted floor (m>=65536, t>=3, p>=1)")
	}
	return nil
}

// ListVaultPublicKeys is the directory sharing reads from. It carries the
// fingerprint next to every key precisely because this endpoint is the point
// a malicious server would substitute one: a key nobody ever compares is a
// key the person handing it out can choose.
func ListVaultPublicKeys(c *fiber.Ctx) error {
	var krs []models.VaultKeyring
	db.DB.Find(&krs)
	type entry struct {
		UserID      uint   `json:"user_id"`
		Email       string `json:"email"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
	}
	out := make([]entry, 0, len(krs))
	for _, kr := range krs {
		out = append(out, entry{
			UserID: kr.UserID, Email: db.GetUserEmail(kr.UserID),
			PublicKey: kr.PublicKey, Fingerprint: kr.Fingerprint,
		})
	}
	return c.JSON(out)
}

// ---- vaults ---------------------------------------------------------------

// ListVaults returns the vaults the caller holds a key for, and after them
// the ones a group has given them but nobody has sealed a key for yet. Those
// come without a key, flagged as waiting: saying "your team has a vault, the
// next owner to unlock will hand you its key" beats a vault that is simply
// missing until then.
func ListVaults(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var members []models.VaultMember
	db.DB.Where("user_id = ?", userID).Find(&members)
	ids := make([]uint, 0, len(members))
	byVault := map[uint]models.VaultMember{}
	for i := range members {
		if !groupMembershipHolds(&members[i]) {
			continue
		}
		ids = append(ids, members[i].VaultID)
		byVault[members[i].VaultID] = members[i]
	}

	type entry struct {
		UUID        string `json:"uuid"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Kind        string `json:"kind"`
		Role        string `json:"role"`
		WrappedKey  string `json:"wrapped_key"`
		ItemCount   int64  `json:"item_count"`
		MemberCount int64  `json:"member_count"`
		Owner       string `json:"owner"`
		Pending     bool   `json:"pending"`
	}
	out := []entry{}

	if len(ids) > 0 {
		var vaults []models.Vault
		db.DB.Where("id IN ?", ids).Order("kind, name").Find(&vaults)
		encKey := crypto.MasterKey()
		for _, v := range vaults {
			m := byVault[v.ID]
			var items, mem int64
			db.DB.Model(&models.VaultItem{}).Where("vault_id = ?", v.ID).Count(&items)
			db.DB.Model(&models.VaultMember{}).Where("vault_id = ?", v.ID).Count(&mem)
			out = append(out, entry{
				UUID: v.UUID, Name: v.Name, Description: v.Description, Kind: v.Kind,
				Role:       m.Role,
				WrappedKey: crypto.DecryptField(encKey, m.WrappedKey),
				ItemCount:  items, MemberCount: mem,
				Owner: db.GetUserEmail(v.OwnerID),
			})
		}
	}

	var groupIDs []uint
	db.DB.Model(&models.UserGroupMember{}).Where("user_id = ?", userID).Pluck("group_id", &groupIDs)
	if len(groupIDs) > 0 {
		var grants []models.VaultGroupAccess
		db.DB.Where("group_id IN ?", groupIDs).Find(&grants)
		seen := map[uint]bool{}
		for _, g := range grants {
			if _, held := byVault[g.VaultID]; held || seen[g.VaultID] {
				continue
			}
			seen[g.VaultID] = true
			var v models.Vault
			if db.DB.First(&v, g.VaultID).Error != nil {
				continue
			}
			out = append(out, entry{
				UUID: v.UUID, Name: v.Name, Description: v.Description, Kind: v.Kind,
				Role: g.Role, Owner: db.GetUserEmail(v.OwnerID), Pending: true,
			})
		}
	}
	return c.JSON(out)
}

// CreateVault makes a personal or a team vault. A team vault needs
// vault.share on top of vault.create: the whole point of one is choosing who
// else gets in, and that choice is what vault.share governs.
func CreateVault(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var req struct {
		UUID        string `json:"uuid"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Kind        string `json:"kind"`
		WrappedKey  string `json:"wrapped_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.Kind == "" {
		req.Kind = "personal"
	}
	if req.Kind == "group" {
		req.Kind = "team" // the old name, from clients built before the rename
	}
	if req.Kind != "personal" && req.Kind != "team" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "kind must be personal or team"})
	}
	if req.Kind == "team" && !callerHolds(c, PermVaultShare) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error":               "creating a team vault needs permission to share vaults",
			"required_permission": PermVaultShare,
		})
	}
	return createVault(c, userID, req.UUID, req.Name, req.Description, req.Kind, req.WrappedKey)
}

// CreatePersonalVault gives somebody the personal vault every account is
// meant to have. It needs only vault.read, because it is not a decision to
// create something -- an administrator who takes vault.create away is saying
// "no new vaults", not "no vault at all". It creates one, once: anyone who
// already owns a personal vault is pointed at the ordinary route.
func CreatePersonalVault(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var owned int64
	db.DB.Model(&models.Vault{}).Where("owner_id = ? AND kind = ?", userID, "personal").Count(&owned)
	if owned > 0 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "you already have a personal vault"})
	}
	var req struct {
		UUID       string `json:"uuid"`
		WrappedKey string `json:"wrapped_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	return createVault(c, userID, req.UUID, "Personal", "", "personal", req.WrappedKey)
}

func createVault(c *fiber.Ctx, userID uint, id, name, description, kind, wrappedKey string) error {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > maxVaultNameLen || len(description) > maxVaultDescLen {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "a name is required, up to 120 characters"})
	}
	if !validVaultUUID(id) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "uuid must be generated by the client"})
	}
	if !validVaultBlob(wrappedKey, maxWrappedKeyBytes) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "malformed wrapped key"})
	}

	// The creator has to be enrolled, or the key they just sealed was sealed
	// to nothing and the vault would be unopenable from the first item.
	var kr models.VaultKeyring
	if err := db.DB.Where("user_id = ?", userID).First(&kr).Error; err != nil {
		return c.Status(fiber.StatusPreconditionRequired).JSON(fiber.Map{"error": "set up your vault passphrase first"})
	}

	v := models.Vault{
		UUID: id, Name: name, Description: description,
		Kind: kind, OwnerID: userID,
	}
	if err := db.DB.Create(&v).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "a vault with that id already exists"})
	}
	db.DB.Create(&models.VaultMember{
		VaultID: v.ID, UserID: userID, Role: "owner",
		WrappedKey: crypto.EncryptField(crypto.MasterKey(), wrappedKey),
		AddedBy:    userID,
	})
	db.LogAudit(userID, "vault_create", "vault", v.Name, kind+" vault", c.IP())
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"uuid": v.UUID})
}

func DeleteVault(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if m.Role != "owner" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the owner can delete a vault"})
	}
	// Every account keeps one personal vault. Deleting the last would only
	// have it created again, empty, on the next unlock -- which reads as the
	// vault having lost everything rather than as a deletion.
	if v.Kind == "personal" {
		var others int64
		db.DB.Model(&models.Vault{}).
			Where("owner_id = ? AND kind = ? AND id <> ?", userID, "personal", v.ID).Count(&others)
		if others == 0 {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "this is your only personal vault; it cannot be deleted"})
		}
	}
	db.DB.Where("vault_id = ?", v.ID).Delete(&models.VaultItem{})
	db.DB.Where("vault_id = ?", v.ID).Delete(&models.VaultMember{})
	db.DB.Where("vault_id = ?", v.ID).Delete(&models.VaultGroupAccess{})
	db.DB.Delete(v)
	db.LogAudit(userID, "vault_delete", "vault", v.Name, "", c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

func ListVaultMembers(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, _, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	var members []models.VaultMember
	db.DB.Where("vault_id = ?", v.ID).Find(&members)
	type entry struct {
		UserID      uint   `json:"user_id"`
		Email       string `json:"email"`
		Role        string `json:"role"`
		Fingerprint string `json:"fingerprint"`
		AddedAt     string `json:"added_at"`
		ViaGroupID  *uint  `json:"via_group_id"`
		ViaGroup    string `json:"via_group"`
	}
	out := make([]entry, 0, len(members))
	for i := range members {
		m := members[i]
		if !groupMembershipHolds(&m) {
			continue
		}
		var kr models.VaultKeyring
		db.DB.Where("user_id = ?", m.UserID).First(&kr)
		e := entry{
			UserID: m.UserID, Email: db.GetUserEmail(m.UserID), Role: m.Role,
			Fingerprint: kr.Fingerprint, AddedAt: m.CreatedAt.Format(time.RFC3339),
			ViaGroupID: m.ViaGroupID,
		}
		if m.ViaGroupID != nil {
			var g models.UserGroup
			if db.DB.First(&g, *m.ViaGroupID).Error == nil {
				e.ViaGroup = g.Name
			}
		}
		out = append(out, e)
	}
	return c.JSON(out)
}

// AddVaultMember stores a copy of the vault key that only the new member can
// open. The browser sealed it; the server checks who it was sealed to is real
// and enrolled, and that the person sending it is entitled to:
//
//   - Adding somebody by name is a decision, and only the owner makes it.
//   - Delivering a key to somebody a group already entitles is carrying out a
//     decision the owner made when they gave the group access. Any owner or
//     writer can do that -- they hold the key -- and the role comes from the
//     group's grant, never from the request.
func AddVaultMember(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if v.Kind != "team" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "a personal vault cannot be shared; create a team vault instead"})
	}

	var req struct {
		UserID     uint   `json:"user_id"`
		Role       string `json:"role"`
		WrappedKey string `json:"wrapped_key"`
		ViaGroupID *uint  `json:"via_group_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id and wrapped_key are required"})
	}
	if !validVaultBlob(req.WrappedKey, maxWrappedKeyBytes) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "malformed wrapped key"})
	}
	var kr models.VaultKeyring
	if err := db.DB.Where("user_id = ?", req.UserID).First(&kr).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "that person has not set up a vault passphrase yet"})
	}

	var existing models.VaultMember
	hasRow := db.DB.Where("vault_id = ? AND user_id = ?", v.ID, req.UserID).First(&existing).Error == nil

	if req.ViaGroupID != nil {
		if !vaultWriterRoles[m.Role] {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only an owner or a writer can hand out keys"})
		}
		var grant models.VaultGroupAccess
		if err := db.DB.Where("vault_id = ? AND group_id = ?", v.ID, *req.ViaGroupID).First(&grant).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "that group does not have access to this vault"})
		}
		var gm models.UserGroupMember
		if err := db.DB.Where("group_id = ? AND user_id = ?", *req.ViaGroupID, req.UserID).First(&gm).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "that person is not in the group"})
		}
		// Somebody already holding a key keeps it, and keeps the role they
		// were given by name: a decision about one person outranks one made
		// about a team they happen to be in.
		if hasRow {
			return c.JSON(fiber.Map{"ok": true, "already_member": true})
		}
		gid := *req.ViaGroupID
		if err := db.DB.Create(&models.VaultMember{
			VaultID: v.ID, UserID: req.UserID, Role: grant.Role,
			WrappedKey: crypto.EncryptField(crypto.MasterKey(), req.WrappedKey),
			AddedBy:    userID, ViaGroupID: &gid,
		}).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
		}
		db.LogAudit(userID, "vault_share", "vault", v.Name,
			"key delivered to "+db.GetUserEmail(req.UserID)+" through a group, as "+grant.Role+
				" (key fingerprint "+kr.Fingerprint+")", c.IP())
		return c.JSON(fiber.Map{"ok": true})
	}

	if m.Role != "owner" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the owner can share a vault"})
	}
	if req.Role != "writer" && req.Role != "reader" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role must be writer or reader"})
	}
	if hasRow && existing.Role == "owner" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "that person owns this vault"})
	}
	// Naming somebody who was already here through a group turns their
	// access into a direct one, so it survives them leaving the group.
	member := models.VaultMember{VaultID: v.ID, UserID: req.UserID}
	if err := db.DB.Where("vault_id = ? AND user_id = ?", v.ID, req.UserID).
		Assign(map[string]interface{}{
			"role":         req.Role,
			"wrapped_key":  crypto.EncryptField(crypto.MasterKey(), req.WrappedKey),
			"added_by":     userID,
			"via_group_id": nil,
		}).FirstOrCreate(&member).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	db.LogAudit(userID, "vault_share", "vault", v.Name,
		"shared with "+db.GetUserEmail(req.UserID)+" as "+req.Role+" (key fingerprint "+kr.Fingerprint+")", c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// UpdateVaultMemberRole changes what somebody added by name may do. People
// who are here through a group take the group's role, so their role is
// changed on the group.
func UpdateVaultMemberRole(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if m.Role != "owner" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the owner can change sharing"})
	}
	var req struct {
		Role string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil || (req.Role != "writer" && req.Role != "reader") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role must be writer or reader"})
	}
	var target models.VaultMember
	if err := db.DB.Where("vault_id = ? AND user_id = ?", v.ID, c.Params("user_id")).First(&target).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not a member"})
	}
	if target.Role == "owner" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "the owner's role cannot be changed"})
	}
	if target.ViaGroupID != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "this person is here through a group; change the group's role instead"})
	}
	db.DB.Model(&target).Update("role", req.Role)
	db.LogAudit(userID, "vault_share", "vault", v.Name,
		db.GetUserEmail(target.UserID)+" is now "+req.Role, c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// RemoveVaultMember destroys the only copy of the key that person could open.
// It does not reach into what they already read, and it does not rotate the
// vault key -- anyone who kept a copy of an item still has it. The UI says so
// rather than implying a removal is a revocation.
func RemoveVaultMember(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if m.Role != "owner" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the owner can change sharing"})
	}
	target := c.Params("user_id")
	if target == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id required"})
	}
	var victim models.VaultMember
	if err := db.DB.Where("vault_id = ? AND user_id = ?", v.ID, target).First(&victim).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not a member"})
	}
	if victim.Role == "owner" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "the owner cannot be removed; delete the vault instead"})
	}
	// Deleting the key of somebody a group still entitles would last until
	// the next unlock delivered it again. Saying where their access comes
	// from is the honest answer.
	if victim.ViaGroupID != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "this person has access through a group; remove the group from the vault or take them out of the group",
		})
	}
	db.DB.Delete(&victim)
	db.LogAudit(userID, "vault_unshare", "vault", v.Name, "removed "+db.GetUserEmail(victim.UserID), c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// ---- groups ---------------------------------------------------------------

// ListVaultGroupDirectory is the list of IAM groups a team vault can be given
// to. /groups needs user.manage, which is administering people; choosing a
// group to share with is not, so this answers with names and counts only.
func ListVaultGroupDirectory(c *fiber.Ctx) error {
	var groups []models.UserGroup
	db.DB.Order("name").Find(&groups)
	type entry struct {
		ID          uint   `json:"id"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Members     int64  `json:"members"`
		Enrolled    int64  `json:"enrolled"`
	}
	out := make([]entry, 0, len(groups))
	for _, g := range groups {
		var members, enrolled int64
		db.DB.Model(&models.UserGroupMember{}).Where("group_id = ?", g.ID).Count(&members)
		db.DB.Model(&models.UserGroupMember{}).
			Joins("JOIN vault_keyrings ON vault_keyrings.user_id = user_group_members.user_id").
			Where("user_group_members.group_id = ?", g.ID).Count(&enrolled)
		out = append(out, entry{ID: g.ID, Name: g.Name, Description: g.Description, Members: members, Enrolled: enrolled})
	}
	return c.JSON(out)
}

// ListVaultGroupAccess shows each group a vault was given to, and for each
// one who is still waiting: members whose key nobody has sealed yet, and
// members who cannot be given one until they set up their own vault.
func ListVaultGroupAccess(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, _, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	var grants []models.VaultGroupAccess
	db.DB.Where("vault_id = ?", v.ID).Find(&grants)
	type entry struct {
		GroupID    uint     `json:"group_id"`
		Name       string   `json:"name"`
		Role       string   `json:"role"`
		Members    int      `json:"members"`
		WithKey    int      `json:"with_key"`
		AwaitKey   []string `json:"awaiting_key"`
		Unenrolled []string `json:"unenrolled"`
	}
	out := make([]entry, 0, len(grants))
	for _, g := range grants {
		var group models.UserGroup
		if db.DB.First(&group, g.GroupID).Error != nil {
			continue
		}
		var userIDs []uint
		db.DB.Model(&models.UserGroupMember{}).Where("group_id = ?", g.GroupID).Pluck("user_id", &userIDs)
		e := entry{GroupID: g.GroupID, Name: group.Name, Role: g.Role, Members: len(userIDs),
			AwaitKey: []string{}, Unenrolled: []string{}}
		for _, uid := range userIDs {
			var held int64
			db.DB.Model(&models.VaultMember{}).Where("vault_id = ? AND user_id = ?", v.ID, uid).Count(&held)
			if held > 0 {
				e.WithKey++
				continue
			}
			var enrolled int64
			db.DB.Model(&models.VaultKeyring{}).Where("user_id = ?", uid).Count(&enrolled)
			if enrolled > 0 {
				e.AwaitKey = append(e.AwaitKey, db.GetUserEmail(uid))
			} else {
				e.Unenrolled = append(e.Unenrolled, db.GetUserEmail(uid))
			}
		}
		out = append(out, e)
	}
	return c.JSON(out)
}

// SetVaultGroupAccess gives a group access to a team vault, or changes the
// role it has. The role change reaches everyone already in through the group
// straight away; new keys are sealed by the owner's browser right after this
// returns, and by any owner or writer who unlocks later.
func SetVaultGroupAccess(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if m.Role != "owner" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the owner can change sharing"})
	}
	if v.Kind != "team" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "a personal vault cannot be shared; create a team vault instead"})
	}
	var req struct {
		GroupID uint   `json:"group_id"`
		Role    string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil || req.GroupID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "group_id is required"})
	}
	if req.Role != "writer" && req.Role != "reader" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role must be writer or reader"})
	}
	var g models.UserGroup
	if err := db.DB.First(&g, req.GroupID).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unknown group"})
	}
	grant := models.VaultGroupAccess{VaultID: v.ID, GroupID: g.ID}
	if err := db.DB.Where("vault_id = ? AND group_id = ?", v.ID, g.ID).
		Assign(map[string]interface{}{"role": req.Role, "added_by": userID}).
		FirstOrCreate(&grant).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	db.DB.Model(&models.VaultMember{}).
		Where("vault_id = ? AND via_group_id = ?", v.ID, g.ID).Update("role", req.Role)
	db.LogAudit(userID, "vault_share", "vault", v.Name, "group "+g.Name+" given "+req.Role+" access", c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// RemoveVaultGroupAccess takes a group's access away, and with it the key of
// everyone who was here only through that group. People added by name stay.
func RemoveVaultGroupAccess(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if m.Role != "owner" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the owner can change sharing"})
	}
	var grant models.VaultGroupAccess
	if err := db.DB.Where("vault_id = ? AND group_id = ?", v.ID, c.Params("group_id")).First(&grant).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "that group does not have access"})
	}
	db.DB.Delete(&grant)
	removed := db.DB.Where("vault_id = ? AND via_group_id = ?", v.ID, grant.GroupID).Delete(&models.VaultMember{})
	var g models.UserGroup
	db.DB.Unscoped().First(&g, grant.GroupID)
	db.LogAudit(userID, "vault_unshare", "vault", v.Name,
		fmt.Sprintf("group %s removed; %d key(s) deleted", g.Name, removed.RowsAffected), c.IP())
	return c.JSON(fiber.Map{"ok": true, "keys_removed": removed.RowsAffected})
}

// ListPendingVaultKeys is the work queue for the caller's browser: everyone
// a group entitles to a vault the caller can hand keys out for, who has
// enrolled, and who does not hold a key yet. The browser shows the list and
// seals a key only for the rows the person approves -- group membership is
// managed by whoever holds user.manage, and without that review anyone who
// can edit a group could add themselves to it and be handed the key on the
// owner's next unlock.
func ListPendingVaultKeys(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var mine []models.VaultMember
	db.DB.Where("user_id = ? AND role IN ?", userID, []string{"owner", "writer"}).Find(&mine)

	type entry struct {
		VaultUUID   string `json:"vault_uuid"`
		UserID      uint   `json:"user_id"`
		Email       string `json:"email"`
		PublicKey   string `json:"public_key"`
		Fingerprint string `json:"fingerprint"`
		GroupID     uint   `json:"group_id"`
		Group       string `json:"group"`
		VaultName   string `json:"vault_name"`
		Role        string `json:"role"`
	}
	out := []entry{}
	for i := range mine {
		if !groupMembershipHolds(&mine[i]) {
			continue
		}
		var v models.Vault
		if db.DB.First(&v, mine[i].VaultID).Error != nil || v.Kind != "team" {
			continue
		}
		var grants []models.VaultGroupAccess
		db.DB.Where("vault_id = ?", v.ID).Find(&grants)
		queued := map[uint]bool{}
		for _, g := range grants {
			var group models.UserGroup
			db.DB.First(&group, g.GroupID)
			var userIDs []uint
			db.DB.Model(&models.UserGroupMember{}).Where("group_id = ?", g.GroupID).Pluck("user_id", &userIDs)
			for _, uid := range userIDs {
				if queued[uid] {
					continue
				}
				var held int64
				db.DB.Model(&models.VaultMember{}).Where("vault_id = ? AND user_id = ?", v.ID, uid).Count(&held)
				if held > 0 {
					continue
				}
				var kr models.VaultKeyring
				if db.DB.Where("user_id = ?", uid).First(&kr).Error != nil {
					continue
				}
				queued[uid] = true
				out = append(out, entry{
					VaultUUID: v.UUID, UserID: uid, Email: db.GetUserEmail(uid),
					PublicKey: kr.PublicKey, Fingerprint: kr.Fingerprint,
					GroupID: g.GroupID, Group: group.Name, VaultName: v.Name, Role: g.Role,
				})
			}
		}
	}
	return c.JSON(out)
}

// ---- items ----------------------------------------------------------------

// ListVaultItems returns overviews only. The secret half is fetched one item
// at a time through RevealVaultItem, which is what gives the audit log
// something truer than "opened the vault page" to record.
func ListVaultItems(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, _, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	var items []models.VaultItem
	db.DB.Where("vault_id = ?", v.ID).Order("updated_at desc").Find(&items)

	encKey := crypto.MasterKey()
	type entry struct {
		UUID        string `json:"uuid"`
		OverviewEnc string `json:"overview_enc"`
		Version     uint   `json:"version"`
		UpdatedAt   string `json:"updated_at"`
		UpdatedBy   string `json:"updated_by"`
	}
	out := make([]entry, 0, len(items))
	for _, it := range items {
		out = append(out, entry{
			UUID:        it.UUID,
			OverviewEnc: crypto.DecryptField(encKey, it.OverviewEnc),
			Version:     it.Version,
			UpdatedAt:   it.UpdatedAt.Format(time.RFC3339),
			UpdatedBy:   db.GetUserEmail(it.UpdatedBy),
		})
	}
	return c.JSON(out)
}

func CreateVaultItem(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if !vaultWriterRoles[m.Role] {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you have read-only access to this vault"})
	}
	var req struct {
		UUID        string `json:"uuid"`
		OverviewEnc string `json:"overview_enc"`
		SecretEnc   string `json:"secret_enc"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if !validVaultUUID(req.UUID) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "uuid must be generated by the client"})
	}
	if !validVaultBlob(req.OverviewEnc, maxOverviewBytes) || !validVaultBlob(req.SecretEnc, maxSecretBytes) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "malformed or oversized ciphertext"})
	}
	encKey := crypto.MasterKey()
	it := models.VaultItem{
		UUID: req.UUID, VaultID: v.ID, Version: 1,
		OverviewEnc: crypto.EncryptField(encKey, req.OverviewEnc),
		SecretEnc:   crypto.EncryptField(encKey, req.SecretEnc),
		CreatedBy:   userID, UpdatedBy: userID,
	}
	if err := db.DB.Create(&it).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "an item with that id already exists"})
	}
	db.LogAudit(userID, "vault_item_create", "vault", v.Name, "item "+it.UUID, c.IP())
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"uuid": it.UUID, "version": it.Version})
}

// UpdateVaultItem refuses a write whose base version is not the one on disk.
// Two people editing the same credential is the normal case in a shared vault,
// and last-write-wins there means one of them silently restores a password the
// other just rotated.
func UpdateVaultItem(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if !vaultWriterRoles[m.Role] {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you have read-only access to this vault"})
	}
	var it models.VaultItem
	if err := db.DB.Where("vault_id = ? AND uuid = ?", v.ID, c.Params("item_uuid")).First(&it).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "item not found"})
	}
	var req struct {
		OverviewEnc string `json:"overview_enc"`
		SecretEnc   string `json:"secret_enc"`
		BaseVersion uint   `json:"base_version"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if !validVaultBlob(req.OverviewEnc, maxOverviewBytes) || !validVaultBlob(req.SecretEnc, maxSecretBytes) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "malformed or oversized ciphertext"})
	}
	// The version is checked in the UPDATE rather than before it. Reading the
	// row, comparing, and then saving leaves a window both writers can pass
	// through, and the whole point of the check is the case where two people
	// are editing the same credential at the same time.
	encKey := crypto.MasterKey()
	res := db.DB.Model(&models.VaultItem{}).
		Where("id = ? AND version = ?", it.ID, req.BaseVersion).
		Updates(map[string]interface{}{
			"overview_enc": crypto.EncryptField(encKey, req.OverviewEnc),
			"secret_enc":   crypto.EncryptField(encKey, req.SecretEnc),
			"version":      it.Version + 1,
			"updated_by":   userID,
		})
	if res.Error != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": res.Error.Error()})
	}
	if res.RowsAffected == 0 {
		var current models.VaultItem
		db.DB.Where("id = ?", it.ID).First(&current)
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":           "this item changed since you opened it; reload before saving",
			"current_version": current.Version,
		})
	}
	db.LogAudit(userID, "vault_item_update", "vault", v.Name, "item "+it.UUID, c.IP())
	return c.JSON(fiber.Map{"version": it.Version + 1})
}

func DeleteVaultItem(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if !vaultWriterRoles[m.Role] {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "you have read-only access to this vault"})
	}
	var it models.VaultItem
	if err := db.DB.Where("vault_id = ? AND uuid = ?", v.ID, c.Params("item_uuid")).First(&it).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "item not found"})
	}
	db.DB.Delete(&it)
	db.LogAudit(userID, "vault_item_delete", "vault", v.Name, "item "+it.UUID, c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// RevealVaultItem is the audited half. The row it writes names the vault and
// the item's id and stops there -- the item's name is sealed, and the server
// cannot read it to write a friendlier log line. An audit trail that guessed
// would be worse than one that admits what it knows.
func RevealVaultItem(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, _, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	var it models.VaultItem
	if err := db.DB.Where("vault_id = ? AND uuid = ?", v.ID, c.Params("item_uuid")).First(&it).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "item not found"})
	}
	db.LogAudit(userID, "vault_item_reveal", "vault", v.Name, "item "+it.UUID, c.IP())
	return c.JSON(fiber.Map{
		"uuid":       it.UUID,
		"secret_enc": crypto.DecryptField(crypto.MasterKey(), it.SecretEnc),
		"version":    it.Version,
	})
}
