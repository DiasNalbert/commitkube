package handlers

import (
	"encoding/base64"
	"encoding/json"
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
	if err := db.DB.Where("vault_id = ? AND user_id = ?", v.ID, userID).First(&m).Error; err != nil {
		_ = c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "vault not found"})
		return nil, nil, false
	}
	return &v, &m, true
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

func ListVaults(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var members []models.VaultMember
	db.DB.Where("user_id = ?", userID).Find(&members)
	if len(members) == 0 {
		return c.JSON([]any{})
	}
	ids := make([]uint, 0, len(members))
	byVault := map[uint]models.VaultMember{}
	for _, m := range members {
		ids = append(ids, m.VaultID)
		byVault[m.VaultID] = m
	}
	var vaults []models.Vault
	db.DB.Where("id IN ?", ids).Order("kind, name").Find(&vaults)

	encKey := crypto.MasterKey()
	type entry struct {
		UUID        string `json:"uuid"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Kind        string `json:"kind"`
		GroupID     *uint  `json:"group_id"`
		Role        string `json:"role"`
		WrappedKey  string `json:"wrapped_key"`
		ItemCount   int64  `json:"item_count"`
		MemberCount int64  `json:"member_count"`
	}
	out := make([]entry, 0, len(vaults))
	for _, v := range vaults {
		m := byVault[v.ID]
		var items, mem int64
		db.DB.Model(&models.VaultItem{}).Where("vault_id = ?", v.ID).Count(&items)
		db.DB.Model(&models.VaultMember{}).Where("vault_id = ?", v.ID).Count(&mem)
		out = append(out, entry{
			UUID: v.UUID, Name: v.Name, Description: v.Description, Kind: v.Kind,
			GroupID: v.GroupID, Role: m.Role,
			WrappedKey: crypto.DecryptField(encKey, m.WrappedKey),
			ItemCount:  items, MemberCount: mem,
		})
	}
	return c.JSON(out)
}

func CreateVault(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var req struct {
		UUID        string `json:"uuid"`
		Name        string `json:"name"`
		Description string `json:"description"`
		Kind        string `json:"kind"`
		GroupID     *uint  `json:"group_id"`
		WrappedKey  string `json:"wrapped_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" || len(req.Name) > maxVaultNameLen || len(req.Description) > maxVaultDescLen {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "a name is required, up to 120 characters"})
	}
	if !validVaultUUID(req.UUID) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "uuid must be generated by the client"})
	}
	if !validVaultBlob(req.WrappedKey, maxWrappedKeyBytes) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "malformed wrapped key"})
	}
	if req.Kind == "" {
		req.Kind = "personal"
	}
	if req.Kind != "personal" && req.Kind != "group" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "kind must be personal or group"})
	}
	if req.Kind == "group" {
		if req.GroupID == nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "a group vault needs a group"})
		}
		var g models.UserGroup
		if err := db.DB.First(&g, *req.GroupID).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unknown group"})
		}
	} else {
		req.GroupID = nil
	}

	// The creator has to be enrolled, or the key they just sealed was sealed
	// to nothing and the vault would be unopenable from the first item.
	var kr models.VaultKeyring
	if err := db.DB.Where("user_id = ?", userID).First(&kr).Error; err != nil {
		return c.Status(fiber.StatusPreconditionRequired).JSON(fiber.Map{"error": "set up your vault passphrase first"})
	}

	v := models.Vault{
		UUID: req.UUID, Name: req.Name, Description: req.Description,
		Kind: req.Kind, OwnerID: userID, GroupID: req.GroupID,
	}
	if err := db.DB.Create(&v).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "a vault with that id already exists"})
	}
	db.DB.Create(&models.VaultMember{
		VaultID: v.ID, UserID: userID, Role: "owner",
		WrappedKey: crypto.EncryptField(crypto.MasterKey(), req.WrappedKey),
		AddedBy:    userID,
	})
	db.LogAudit(userID, "vault_create", "vault", v.Name, req.Kind+" vault", c.IP())
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
	db.DB.Where("vault_id = ?", v.ID).Delete(&models.VaultItem{})
	db.DB.Where("vault_id = ?", v.ID).Delete(&models.VaultMember{})
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
	}
	out := make([]entry, 0, len(members))
	for _, m := range members {
		var kr models.VaultKeyring
		db.DB.Where("user_id = ?", m.UserID).First(&kr)
		out = append(out, entry{
			UserID: m.UserID, Email: db.GetUserEmail(m.UserID), Role: m.Role,
			Fingerprint: kr.Fingerprint, AddedAt: m.CreatedAt.Format(time.RFC3339),
		})
	}
	return c.JSON(out)
}

// AddVaultMember stores a copy of the vault key that only the new member can
// open. The browser sealed it; the server checks who it was sealed to is real,
// enrolled, and -- for a group vault -- actually in the group, so the member
// list cannot drift away from the group it claims to represent.
func AddVaultMember(c *fiber.Ctx) error {
	userID := currentUserID(c)
	v, m, ok := vaultFor(c, userID)
	if !ok {
		return nil // vaultFor has already answered
	}
	if m.Role != "owner" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only the owner can share a vault"})
	}
	if v.Kind == "personal" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "a personal vault cannot be shared; create a group vault instead"})
	}

	var req struct {
		UserID     uint   `json:"user_id"`
		Role       string `json:"role"`
		WrappedKey string `json:"wrapped_key"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id and wrapped_key are required"})
	}
	if req.Role != "writer" && req.Role != "reader" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role must be writer or reader"})
	}
	if !validVaultBlob(req.WrappedKey, maxWrappedKeyBytes) {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "malformed wrapped key"})
	}
	var kr models.VaultKeyring
	if err := db.DB.Where("user_id = ?", req.UserID).First(&kr).Error; err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "that person has not set up a vault passphrase yet"})
	}
	if v.GroupID != nil {
		var gm models.UserGroupMember
		if err := db.DB.Where("group_id = ? AND user_id = ?", *v.GroupID, req.UserID).First(&gm).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "that person is not in the group this vault belongs to"})
		}
	}

	member := models.VaultMember{VaultID: v.ID, UserID: req.UserID}
	if err := db.DB.Where("vault_id = ? AND user_id = ?", v.ID, req.UserID).
		Assign(map[string]interface{}{
			"role":        req.Role,
			"wrapped_key": crypto.EncryptField(crypto.MasterKey(), req.WrappedKey),
			"added_by":    userID,
		}).FirstOrCreate(&member).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	db.LogAudit(userID, "vault_share", "vault", v.Name,
		"shared with "+db.GetUserEmail(req.UserID)+" as "+req.Role+" (key fingerprint "+kr.Fingerprint+")", c.IP())
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
	db.DB.Delete(&victim)
	db.LogAudit(userID, "vault_unshare", "vault", v.Name, "removed "+db.GetUserEmail(victim.UserID), c.IP())
	return c.JSON(fiber.Map{"ok": true})
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
