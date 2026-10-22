package handlers

import (
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/middleware"
	"github.com/kubecommit/backend/models"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

// Cluster secrets used to open with the password alone, sent again with
// every call and kept in the page's memory in between. A password is the
// one factor a phishing page or a shoulder can take, and every value in the
// cluster sat behind it.
//
// Now the page unlocks once with the password and a code from the sign-in
// authenticator, and gets back a ticket good for fifteen minutes, for this
// person, in this sign-in session. The password is not kept anywhere, and a
// ticket stops working when the session it was issued in ends.

const (
	secretsTicketHeader = "X-Secrets-Ticket"
	secretsTicketTTL    = 15 * time.Minute
)

// secretsTicketKey is derived from the JWT secret rather than equal to it,
// so a ticket can never pass for an access token, nor one for a ticket.
func secretsTicketKey() []byte {
	mac := hmac.New(sha256.New, middleware.JWTSecret)
	mac.Write([]byte("commitkube-secrets-unlock-v1"))
	return mac.Sum(nil)
}

// usedSteps remembers the last code window each person unlocked with, so a
// code seen over a shoulder cannot be replayed within its thirty seconds.
var (
	usedStepsMu sync.Mutex
	usedSteps   = map[uint]int64{}
)

// checkSignInCode accepts a code from the sign-in authenticator once, with
// one window of drift either side.
func checkSignInCode(user *models.User, code string) bool {
	code = strings.ReplaceAll(strings.TrimSpace(code), " ", "")
	if len(code) != 6 || user.MFASecret == "" {
		return false
	}
	opts := totp.ValidateOpts{Period: 30, Digits: otp.DigitsSix, Algorithm: otp.AlgorithmSHA1}
	now := time.Now().Unix() / 30
	for _, step := range []int64{now - 1, now, now + 1} {
		want, err := totp.GenerateCodeCustom(user.MFASecret, time.Unix(step*30, 0), opts)
		if err != nil || !hmac.Equal([]byte(want), []byte(code)) {
			continue
		}
		usedStepsMu.Lock()
		defer usedStepsMu.Unlock()
		if step <= usedSteps[user.ID] {
			return false
		}
		usedSteps[user.ID] = step
		return true
	}
	return false
}

// secretsRefusal is a 403, never a 401: the frontend reads a 401 as an
// expired sign-in, refreshes and retries, which would repeat a wrong
// password against the cluster's secrets for nothing.
func secretsRefusal(c *fiber.Ctx, msg string) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": msg, "secrets_unlock_required": true})
}

// UnlockSecrets checks the password and the second factor and hands back a
// ticket for the secrets routes.
func UnlockSecrets(c *fiber.Ctx) error {
	var req struct {
		Password string `json:"password"`
		Code     string `json:"code"`
	}
	if err := c.BodyParser(&req); err != nil || req.Password == "" || req.Code == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "password and authenticator code are required"})
	}
	userID := currentUserID(c)
	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return secretsRefusal(c, "account not found")
	}
	if bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)) != nil {
		db.LogAudit(user.ID, "secrets_unlock_failed", "secrets", "", `{"reason":"password"}`, c.IP())
		return secretsRefusal(c, "wrong password or code")
	}
	if !checkSignInCode(&user, req.Code) {
		db.LogAudit(user.ID, "secrets_unlock_failed", "secrets", "", `{"reason":"code"}`, c.IP())
		return secretsRefusal(c, "wrong password or code")
	}

	sid, _ := c.Locals("session_id").(string)
	exp := time.Now().Add(secretsTicketTTL)
	ticket, err := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"typ": "secrets_unlock",
		"uid": float64(user.ID),
		"sid": sid,
		"exp": exp.Unix(),
	}).SignedString(secretsTicketKey())
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not unlock"})
	}
	db.LogAudit(user.ID, "secrets_unlock", "secrets", "", "", c.IP())
	return c.JSON(fiber.Map{"ticket": ticket, "expires_at": exp})
}

// secretsTicketProblem is the check every secrets route makes in place of
// the password it used to take. Empty means the ticket is good; anything
// else is the reason to refuse, for secretsRefusal to send.
func secretsTicketProblem(c *fiber.Ctx) string {
	raw := c.Get(secretsTicketHeader)
	if raw == "" {
		return "unlock secrets with your password and authenticator code"
	}
	tok, err := jwt.Parse(raw, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fiber.ErrUnauthorized
		}
		return secretsTicketKey(), nil
	})
	if err != nil || !tok.Valid {
		return "the secrets unlock expired; unlock again"
	}
	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || claims["typ"] != "secrets_unlock" {
		return "that is not a secrets unlock"
	}
	uid, _ := claims["uid"].(float64)
	if uint(uid) != currentUserID(c) {
		return "that unlock belongs to another account"
	}
	// Bound to the sign-in it was issued in: signing out, or a session ended
	// for any other reason, ends it too.
	sid, _ := claims["sid"].(string)
	if cur, _ := c.Locals("session_id").(string); sid == "" || sid != cur {
		return "the secrets unlock belongs to an earlier sign-in; unlock again"
	}
	return ""
}
