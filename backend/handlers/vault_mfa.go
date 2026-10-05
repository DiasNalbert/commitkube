package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/middleware"
	"github.com/kubecommit/backend/models"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// The vault has its own second factor, separate from the one used to sign in.
// A signed-in session is enough to reach everything else in the product; it
// is deliberately not enough to reach the sealed private key. Without this, a
// stolen access token is one passphrase guess away from the vault, and the
// passphrase is the one secret that can be ground offline.
//
// The passphrase still does the cryptography. This factor decides whether the
// server hands over the sealed key to be ground in the first place.

const (
	vaultSessionHeader = "X-Vault-Session"
	vaultSessionTTL    = 15 * time.Minute
	// A session with less than this left is reissued on the next request, so
	// somebody working in the vault is not asked for a code mid-task. The
	// browser locks after ten idle minutes regardless.
	vaultSessionRenewBelow = 10 * time.Minute

	vaultMFAMaxFailures = 5
	vaultMFALockout     = 5 * time.Minute
	vaultMFAPeriod      = 30
)

// vaultSessionKey is derived from the JWT secret rather than equal to it.
// AuthRequired accepts any token signed with that secret, so a vault session
// signed with it too would double as an API token -- and a code typed into
// the vault would become a way to sign in.
func vaultSessionKey() []byte {
	mac := hmac.New(sha256.New, middleware.JWTSecret)
	mac.Write([]byte("commitkube-vault-session-v1"))
	return mac.Sum(nil)
}

func issueVaultSession(userID, generation uint) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"typ": "vault_session",
		"uid": float64(userID),
		"gen": float64(generation),
		"exp": time.Now().Add(vaultSessionTTL).Unix(),
	}).SignedString(vaultSessionKey())
}

// vaultSessionRefusal is a 403 and never a 401: the frontend treats a 401 as
// an expired sign-in and refreshes the access token, which would retry the
// request into the same refusal and say nothing useful.
func vaultSessionRefusal(c *fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error":              msg,
		"vault_mfa_required": true,
	})
}

// VaultSessionRequired stands in front of every route that returns sealed
// material or changes it. It checks that the session was issued to the person
// presenting it, under the second factor they have now -- so a reset ends
// every session issued before it.
func VaultSessionRequired() fiber.Handler {
	return func(c *fiber.Ctx) error {
		raw := c.Get(vaultSessionHeader)
		if raw == "" {
			return vaultSessionRefusal(c, "enter your vault code to continue")
		}
		tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
			if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fiber.ErrUnauthorized
			}
			return vaultSessionKey(), nil
		})
		if err != nil || !tok.Valid {
			return vaultSessionRefusal(c, "your vault session ended; enter a new code")
		}
		claims, ok := tok.Claims.(jwt.MapClaims)
		if !ok || claims["typ"] != "vault_session" {
			return vaultSessionRefusal(c, "that is not a vault session")
		}
		uid, _ := claims["uid"].(float64)
		gen, _ := claims["gen"].(float64)
		userID := currentUserID(c)
		if userID == 0 || uint(uid) != userID {
			return vaultSessionRefusal(c, "that vault session belongs to another account")
		}

		var f models.VaultMFA
		if err := db.DB.Where("user_id = ?", userID).First(&f).Error; err != nil ||
			f.EnabledAt == nil || f.Generation != uint(gen) {
			return vaultSessionRefusal(c, "your vault code was reset; set it up again")
		}

		if exp, err := claims.GetExpirationTime(); err == nil && exp != nil &&
			time.Until(exp.Time) < vaultSessionRenewBelow {
			if fresh, err := issueVaultSession(userID, f.Generation); err == nil {
				c.Set(vaultSessionHeader, fresh)
			}
		}
		return c.Next()
	}
}

// checkVaultCode accepts a code once. The window it came from is recorded,
// and the update only lands if that window is newer than the last one -- in
// the same statement, so two requests racing with one code cannot both win.
func checkVaultCode(f *models.VaultMFA, code string) error {
	now := time.Now()
	if f.LockedUntil != nil && now.Before(*f.LockedUntil) {
		return fiber.NewError(fiber.StatusTooManyRequests,
			"too many wrong codes; try again in a few minutes")
	}
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	secret := crypto.DecryptField(crypto.MasterKey(), f.SecretEnc)
	if len(code) != 6 || secret == "" {
		return failVaultCode(f, now)
	}

	opts := totp.ValidateOpts{Period: vaultMFAPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	current := now.Unix() / vaultMFAPeriod
	// One window either side, the usual allowance for a phone clock that
	// has drifted. Checked oldest first so the step recorded is the one
	// the code really came from.
	for _, step := range []int64{current - 1, current, current + 1} {
		want, err := totp.GenerateCodeCustom(secret, time.Unix(step*vaultMFAPeriod, 0), opts)
		if err != nil || subtle.ConstantTimeCompare([]byte(want), []byte(code)) != 1 {
			continue
		}
		if step <= f.LastStep {
			return fiber.NewError(fiber.StatusUnauthorized,
				"that code was already used; wait for the next one")
		}
		res := db.DB.Model(&models.VaultMFA{}).
			Where("id = ? AND last_step < ?", f.ID, step).
			Updates(map[string]interface{}{"last_step": step, "failures": 0, "locked_until": nil})
		if res.Error != nil || res.RowsAffected == 0 {
			return fiber.NewError(fiber.StatusUnauthorized,
				"that code was already used; wait for the next one")
		}
		f.LastStep = step
		return nil
	}
	return failVaultCode(f, now)
}

func failVaultCode(f *models.VaultMFA, now time.Time) error {
	f.Failures++
	updates := map[string]interface{}{"failures": f.Failures}
	if f.Failures >= vaultMFAMaxFailures {
		until := now.Add(vaultMFALockout)
		updates["failures"] = 0
		updates["locked_until"] = until
		db.LogAudit(f.UserID, "vault_mfa_lockout", "vault", "mfa",
			"too many wrong vault codes; locked for five minutes", "")
	}
	db.DB.Model(&models.VaultMFA{}).Where("id = ?", f.ID).Updates(updates)
	return fiber.NewError(fiber.StatusUnauthorized, "that code is not right")
}

func codeError(c *fiber.Ctx, err error) error {
	status := fiber.StatusUnauthorized
	if fe, ok := err.(*fiber.Error); ok {
		status = fe.Code
	}
	return c.Status(status).JSON(fiber.Map{"error": err.Error()})
}

// ---- HTTP -----------------------------------------------------------------

// GetVaultStatus says which step the page is on without handing over
// anything sealed, which is why it is the one vault route that needs no code.
func GetVaultStatus(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var f models.VaultMFA
	mfa := db.DB.Where("user_id = ?", userID).First(&f).Error == nil && f.EnabledAt != nil
	var enrolled int64
	db.DB.Model(&models.VaultKeyring{}).Where("user_id = ?", userID).Count(&enrolled)
	return c.JSON(fiber.Map{"mfa_enabled": mfa, "enrolled": enrolled > 0})
}

// SetupVaultMFA mints a new seed. It is refused once the factor is active:
// otherwise anyone holding a sign-in session could replace the vault code
// with one on their own phone, which is the exact thing this exists to stop.
// Losing the phone is an administrator's reset, which is audited.
func SetupVaultMFA(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var f models.VaultMFA
	found := db.DB.Where("user_id = ?", userID).First(&f).Error == nil
	if found && f.EnabledAt != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": "your vault code is already set up; ask an administrator to reset it if you lost it",
		})
	}

	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "account not found"})
	}

	// A different issuer, so the authenticator shows two entries that cannot
	// be mistaken for each other -- and a seed that is never the sign-in one.
	var key *otp.Key
	for {
		k, err := totp.Generate(totp.GenerateOpts{
			Issuer: "CommitKube Vault", AccountName: user.Email,
			Period: vaultMFAPeriod, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not generate a vault code"})
		}
		if k.Secret() != user.MFASecret {
			key = k
			break
		}
	}

	f.UserID = userID
	f.SecretEnc = crypto.EncryptField(crypto.MasterKey(), key.Secret())
	f.EnabledAt = nil
	f.Failures = 0
	f.LockedUntil = nil
	// A new seed has no codes spent yet. Keeping the old one's window would
	// refuse the first code from the new phone if it came within 30 seconds.
	f.LastStep = 0
	if f.Generation == 0 {
		f.Generation = 1
	}
	if err := db.DB.Save(&f).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"otpauth_url": key.URL(), "secret": key.Secret()})
}

// ConfirmVaultMFA turns the factor on once a code from the new seed has been
// typed back, which is the only proof the seed reached a phone.
func ConfirmVaultMFA(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var req struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	var f models.VaultMFA
	if err := db.DB.Where("user_id = ?", userID).First(&f).Error; err != nil || f.SecretEnc == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "start the vault code setup first"})
	}
	if f.EnabledAt != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "your vault code is already set up"})
	}
	if err := checkVaultCode(&f, req.Code); err != nil {
		return codeError(c, err)
	}
	now := time.Now()
	db.DB.Model(&models.VaultMFA{}).Where("id = ?", f.ID).Update("enabled_at", now)
	db.LogAudit(userID, "vault_mfa_enable", "vault", "mfa", "vault code set up", c.IP())

	session, err := issueVaultSession(userID, f.Generation)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not start a vault session"})
	}
	return c.JSON(fiber.Map{"session": session, "expires_in": int(vaultSessionTTL.Seconds())})
}

// VerifyVaultMFA exchanges a code for a vault session.
func VerifyVaultMFA(c *fiber.Ctx) error {
	userID := currentUserID(c)
	var req struct {
		Code string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	var f models.VaultMFA
	if err := db.DB.Where("user_id = ?", userID).First(&f).Error; err != nil || f.EnabledAt == nil {
		return c.Status(fiber.StatusPreconditionRequired).JSON(fiber.Map{"error": "set up your vault code first"})
	}
	if err := checkVaultCode(&f, req.Code); err != nil {
		db.LogAudit(userID, "vault_mfa_failed", "vault", "mfa", err.Error(), c.IP())
		return codeError(c, err)
	}
	session, err := issueVaultSession(userID, f.Generation)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not start a vault session"})
	}
	db.LogAudit(userID, "vault_unlock", "vault", "mfa", "vault code accepted", c.IP())
	return c.JSON(fiber.Map{"session": session, "expires_in": int(vaultSessionTTL.Seconds())})
}

// ResetUserVaultMFA is how somebody who lost their phone gets back in. It
// does not open anything -- the passphrase is still needed, and an
// administrator never has it -- but it does let the next person holding that
// account's sign-in enrol a new phone, so it is audited and root accounts are
// left to root. The generation moves on so live sessions end with it.
func ResetUserVaultMFA(c *fiber.Ctx) error {
	caller, err := currentUser(c)
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
	}
	var target models.User
	if err := db.DB.First(&target, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	if target.Role == "root" && caller.Role != "root" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Cannot reset a root account's vault code"})
	}
	var f models.VaultMFA
	if err := db.DB.Where("user_id = ?", target.ID).First(&f).Error; err != nil {
		return c.JSON(fiber.Map{"message": "that account has no vault code to reset"})
	}
	db.DB.Model(&f).Updates(map[string]interface{}{
		"secret_enc":   "",
		"enabled_at":   nil,
		"failures":     0,
		"locked_until": nil,
		"generation":   f.Generation + 1,
	})
	db.LogAudit(caller.ID, "vault_mfa_reset", "user", target.Email, "vault code reset by an administrator", c.IP())
	return c.JSON(fiber.Map{"message": "Vault code reset. They set up a new one the next time they open the vault."})
}
