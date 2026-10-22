package handlers

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/middleware"
	"github.com/kubecommit/backend/models"
	"gorm.io/gorm"
)

// A sign-in used to be two strings in localStorage: an hour-long access token
// and a refresh token good for thirty days, never rotated and never revoked.
// Closing the laptop and opening it a week later opened the product already
// signed in, and nothing -- not a suspension, not a password change, not a
// logout -- could end a session someone else had copied.
//
// Now the refresh token lives in an httpOnly cookie with no expiry date, so
// the browser drops it when it closes and no script can read it. The access
// token lives in the page's memory only. On the server a session has an idle
// deadline and a hard one, every refresh spends the token it was given, and a
// spent token presented again ends the session.

// SessionCookie is the cookie carrying the refresh token. Path=/ so the
// frontend can tell, before rendering anything, that there is no session at
// all; only the auth endpoints ever read it.
const SessionCookie = "ck_session"

// reuseGrace is how long a just-spent token is still accepted. Two requests
// racing to refresh -- two tabs, or a request already in flight when another
// rotated the cookie -- would otherwise look exactly like a replay. Within
// the window the late one gets an access token and no new cookie: the
// browser already holds the newer one.
const reuseGrace = 30 * time.Second

func accessTTL() time.Duration   { return durationEnv("ACCESS_TOKEN_TTL", 10*time.Minute) }
func sessionIdle() time.Duration { return durationEnv("SESSION_IDLE_TIMEOUT", 20*time.Minute) }
func sessionMax() time.Duration  { return durationEnv("SESSION_MAX_AGE", 12*time.Hour) }

func hashToken(raw string) string {
	sum := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(sum[:])
}

func newOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

func signAccessToken(user models.User, sessionID string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"typ":     middleware.AccessTokenType,
		"user_id": user.ID,
		"role":    user.Role,
		"sid":     sessionID,
		"exp":     time.Now().Add(accessTTL()).Unix(),
	}).SignedString(middleware.JWTSecret)
}

// idleDeadline is the next moment the session dies if nobody uses it, capped
// by the hard limit counted from sign-in.
func idleDeadline(startedAt, now time.Time) time.Time {
	idle := now.Add(sessionIdle())
	hard := startedAt.Add(sessionMax())
	if idle.After(hard) {
		return hard
	}
	return idle
}

// issueTokens starts a session: an access token for the response body and a
// refresh token for the cookie. Callers set the cookie with setSessionCookie.
func issueTokens(user models.User) (access, refresh string, err error) {
	refresh, err = newOpaqueToken()
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	sid := uuid.New().String()
	if err := db.DB.Create(&models.RefreshToken{
		UserID: user.ID, Token: hashToken(refresh), SessionID: sid,
		SessionStartedAt: now, LastUsedAt: now, ExpiresAt: idleDeadline(now, now),
	}).Error; err != nil {
		return "", "", err
	}
	access, err = signAccessToken(user, sid)
	if err != nil {
		return "", "", err
	}
	return access, refresh, nil
}

// cookieSecure: over HTTPS the cookie must never travel in clear. Behind
// nginx the scheme comes from X-Forwarded-Proto, which Fiber reads; plain
// http://localhost during development still works, and COOKIE_SECURE forces
// it either way.
func cookieSecure(c *fiber.Ctx) bool {
	switch strings.ToLower(os.Getenv("COOKIE_SECURE")) {
	case "true", "1":
		return true
	case "false", "0":
		return false
	}
	return c.Protocol() == "https"
}

func setSessionCookie(c *fiber.Ctx, refresh string) {
	// No Expires and no MaxAge: a session cookie, gone when the browser
	// closes. The server-side deadlines are what bound it while it is open.
	c.Cookie(&fiber.Cookie{
		Name: SessionCookie, Value: refresh, Path: "/",
		HTTPOnly: true, Secure: cookieSecure(c), SameSite: fiber.CookieSameSiteStrictMode,
	})
}

func clearSessionCookie(c *fiber.Ctx) {
	c.Cookie(&fiber.Cookie{
		Name: SessionCookie, Value: "", Path: "/",
		HTTPOnly: true, Secure: cookieSecure(c), SameSite: fiber.CookieSameSiteStrictMode,
		Expires: time.Unix(0, 0), MaxAge: -1,
	})
}

func sessionUserJSON(u models.User) fiber.Map {
	return fiber.Map{"id": u.ID, "email": u.Email, "role": u.Role}
}

// signedIn answers a successful sign-in: the cookie, and the access token in
// the body. The refresh token is never in the body -- a value a script can
// read is a value an injected script can send somewhere.
func signedIn(c *fiber.Ctx, user models.User) error {
	access, refresh, err := issueTokens(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
	}
	setSessionCookie(c, refresh)
	return c.JSON(fiber.Map{
		"token":      access,
		"expires_in": int(accessTTL().Seconds()),
		"user":       sessionUserJSON(user),
	})
}

var errSessionGone = fmt.Errorf("session expired")

// RefreshTokenHandler is the only way to obtain an access token without a
// password. It is also how the frontend validates the session before it
// renders a page: no valid cookie, no page.
func RefreshTokenHandler(c *fiber.Ctx) error {
	raw := c.Cookies(SessionCookie)
	if raw == "" {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "no session"})
	}
	now := time.Now()

	var (
		user       models.User
		sid        string
		newRefresh string
		reused     *models.RefreshToken
		// endSession is applied after the transaction: every failure path
		// returns an error, which rolls the transaction back, and a
		// revocation written inside it would be rolled back with it.
		endSession string
	)
	err := db.DB.Transaction(func(tx *gorm.DB) error {
		var rt models.RefreshToken
		if err := tx.Where("token = ?", hashToken(raw)).First(&rt).Error; err != nil {
			return errSessionGone
		}

		if rt.Revoked {
			// Spent moments ago by a racing request: let it through without
			// rotating again, as long as the session itself is still alive.
			if rt.RotatedAt != nil && now.Sub(*rt.RotatedAt) <= reuseGrace {
				var live int64
				tx.Model(&models.RefreshToken{}).
					Where("session_id = ? AND revoked = false AND expires_at > ?", rt.SessionID, now).
					Count(&live)
				if live == 0 {
					return errSessionGone
				}
				sid = rt.SessionID
				return loadSessionUser(tx, rt.UserID, &user)
			}
			// Spent long ago and presented again: two parties hold this
			// session. End all of it.
			if rt.RotatedAt != nil {
				r := rt
				reused = &r
				endSession = rt.SessionID
			}
			return errSessionGone
		}

		if !now.Before(rt.ExpiresAt) || !now.Before(rt.SessionStartedAt.Add(sessionMax())) {
			endSession = rt.SessionID
			return errSessionGone
		}
		if err := loadSessionUser(tx, rt.UserID, &user); err != nil {
			endSession = rt.SessionID
			return err
		}

		// Rotate: spend this token, hand out its successor.
		next, err := newOpaqueToken()
		if err != nil {
			return err
		}
		if err := tx.Model(&rt).Updates(map[string]any{"revoked": true, "rotated_at": now}).Error; err != nil {
			return err
		}
		if err := tx.Create(&models.RefreshToken{
			UserID: rt.UserID, Token: hashToken(next), SessionID: rt.SessionID,
			SessionStartedAt: rt.SessionStartedAt, LastUsedAt: now,
			ExpiresAt: idleDeadline(rt.SessionStartedAt, now),
		}).Error; err != nil {
			return err
		}
		sid, newRefresh = rt.SessionID, next
		return nil
	})

	if endSession != "" {
		db.DB.Model(&models.RefreshToken{}).Where("session_id = ?", endSession).Update("revoked", true)
	}
	if reused != nil {
		db.LogAudit(reused.UserID, "session_token_reuse", "session", reused.SessionID,
			`{"action":"session ended: a spent refresh token was presented again"}`, c.IP())
	}
	if err != nil {
		clearSessionCookie(c)
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}

	access, err := signAccessToken(user, sid)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not generate token"})
	}
	if newRefresh != "" {
		setSessionCookie(c, newRefresh)
	}
	return c.JSON(fiber.Map{
		"token":      access,
		"expires_in": int(accessTTL().Seconds()),
		"user":       sessionUserJSON(user),
	})
}

// loadSessionUser refuses an account that was deleted, suspended or sent
// back to setup since the session began. Checked on every refresh, so such a
// change takes effect within one access-token lifetime.
func loadSessionUser(tx *gorm.DB, id uint, into *models.User) error {
	if err := tx.First(into, id).Error; err != nil {
		return errSessionGone
	}
	if !into.IsActive || into.ForcePasswordChange || !into.MFAEnabled || into.Role == "bootstrap" {
		return errSessionGone
	}
	return nil
}

// Logout ends the session the cookie belongs to, on the server. Public: an
// expired access token must not stop someone from signing out.
func Logout(c *fiber.Ctx) error {
	if raw := c.Cookies(SessionCookie); raw != "" {
		var rt models.RefreshToken
		if db.DB.Where("token = ?", hashToken(raw)).First(&rt).Error == nil {
			db.DB.Model(&models.RefreshToken{}).Where("session_id = ?", rt.SessionID).Update("revoked", true)
			db.LogAudit(rt.UserID, "logout", "session", rt.SessionID, "", c.IP())
		}
	}
	clearSessionCookie(c)
	return c.JSON(fiber.Map{"message": "signed out"})
}

// revokeUserSessions ends every session an account holds. Called when what
// a session vouches for has changed: the password, the role, the second
// factor, or the account itself.
func revokeUserSessions(userID uint) {
	db.DB.Model(&models.RefreshToken{}).Where("user_id = ? AND revoked = false", userID).Update("revoked", true)
}

// PruneRefreshTokens deletes session rows that can no longer be used. A
// spent token is kept a day past its deadline so a replay is still
// recognised as one rather than as an unknown token.
func PruneRefreshTokens() {
	cutoff := time.Now().Add(-24 * time.Hour)
	db.DB.Unscoped().Where("expires_at < ?", cutoff).Delete(&models.RefreshToken{})
}
