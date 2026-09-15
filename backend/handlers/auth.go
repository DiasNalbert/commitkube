package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v5"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/middleware"
	"github.com/kubecommit/backend/models"
	"github.com/pquerna/otp/totp"
	"golang.org/x/crypto/bcrypt"
)

type AuthRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type MFARequest struct {
	// MFAToken is issued by Login, which has already checked the password.
	// Naming the account here instead would make the second factor the only
	// factor: a stolen code alone would be enough to sign in.
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

func issueTokens(user models.User) (string, string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(middleware.JWTSecret)
	if err != nil {
		return "", "", err
	}

	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", err
	}
	refreshTokenStr := hex.EncodeToString(b)
	db.DB.Create(&models.RefreshToken{
		UserID:    user.ID,
		Token:     refreshTokenStr,
		ExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	})
	return tokenString, refreshTokenStr, nil
}

func Login(c *fiber.Ctx) error {
	var req AuthRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	var user models.User
	if err := db.DB.Where("email = ?", req.Email).First(&user).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	if !user.IsActive {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Account suspended"})
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(req.Password)); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid credentials"})
	}

	if user.ForcePasswordChange || !user.MFAEnabled {
		ticket, err := issueStageToken(user.ID, "setup")
		if err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not start setup"})
		}
		return c.JSON(fiber.Map{
			"setup_required": true,
			"setup_token":    ticket,
			"is_bootstrap":   user.Role == "bootstrap",
		})
	}

	ticket, err := issueStageToken(user.ID, "mfa")
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not start sign-in"})
	}
	return c.JSON(fiber.Map{
		"require_mfa": true,
		"mfa_token":   ticket,
	})
}

func VerifyMFA(c *fiber.Ctx) error {
	var req MFARequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	found, err := stageUser(req.MFAToken, "mfa")
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	user := *found

	if user.Role == "bootstrap" || user.ForcePasswordChange || !user.MFAEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Please complete account setup first"})
	}

	if !totp.Validate(req.Code, user.MFASecret) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid MFA code"})
	}

	tokenString, refreshTokenStr, err := issueTokens(user)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
	}

	db.LogAudit(user.ID, "login", "user", user.Email, "", c.IP())

	return c.JSON(fiber.Map{
		"token":         tokenString,
		"refresh_token": refreshTokenStr,
		"user": fiber.Map{
			"id":    user.ID,
			"email": user.Email,
			"role":  user.Role,
		},
	})
}

func RefreshTokenHandler(c *fiber.Ctx) error {
	var req struct {
		RefreshToken string `json:"refresh_token"`
	}
	if err := c.BodyParser(&req); err != nil || req.RefreshToken == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "refresh_token required"})
	}

	var rt models.RefreshToken
	if err := db.DB.Where("token = ? AND revoked = false", req.RefreshToken).First(&rt).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid refresh token"})
	}
	if time.Now().After(rt.ExpiresAt) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "refresh token expired"})
	}

	var user models.User
	if err := db.DB.First(&user, rt.UserID).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "user not found"})
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": user.ID,
		"role":    user.Role,
		"exp":     time.Now().Add(time.Hour).Unix(),
	})
	tokenString, err := token.SignedString(middleware.JWTSecret)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "could not generate token"})
	}

	return c.JSON(fiber.Map{"token": tokenString})
}

func SetupInit(c *fiber.Ctx) error {
	var req struct {
		SetupToken  string `json:"setup_token"`
		NewEmail    string `json:"new_email"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	found, err := stageUser(req.SetupToken, "setup")
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	user := *found

	if !user.ForcePasswordChange && user.MFAEnabled {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Setup not required"})
	}

	if req.NewPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "new_password required"})
	}

	accountName := user.Email
	if user.Role == "bootstrap" {
		if req.NewEmail == "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "new_email required for bootstrap setup"})
		}
		var existing models.User
		if err := db.DB.Where("email = ? AND id != ?", req.NewEmail, user.ID).First(&existing).Error; err == nil {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Email already in use"})
		}
		accountName = req.NewEmail
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "CommitKube",
		AccountName: accountName,
	})
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to generate MFA key"})
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 10)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	updates := map[string]interface{}{
		"mfa_secret":            key.Secret(),
		"pending_password_hash": string(hash),
	}
	if user.Role == "bootstrap" {
		updates["pending_email"] = req.NewEmail
	}
	db.DB.Model(&user).Updates(updates)

	return c.JSON(fiber.Map{
		"mfa_url":    key.URL(),
		"mfa_secret": key.Secret(),
	})
}

func SetupConfirm(c *fiber.Ctx) error {
	var req struct {
		SetupToken string `json:"setup_token"`
		TOTPCode   string `json:"totp_code"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	found, err := stageUser(req.SetupToken, "setup")
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": err.Error()})
	}
	user := *found

	if user.MFASecret == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Setup not initiated"})
	}

	if !totp.Validate(req.TOTPCode, user.MFASecret) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Invalid TOTP code"})
	}

	var finalUser models.User

	if user.Role == "bootstrap" {
		newUser := models.User{
			Email:        user.PendingEmail,
			PasswordHash: user.PendingPasswordHash,
			MFASecret:    user.MFASecret,
			MFAEnabled:   true,
			Role:         "root",
			IsActive:     true,
		}
		if err := db.DB.Create(&newUser).Error; err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to create root user"})
		}
		db.DB.Unscoped().Delete(&user)
		finalUser = newUser
	} else {
		db.DB.Model(&user).Updates(map[string]interface{}{
			"password_hash":         user.PendingPasswordHash,
			"pending_password_hash": "",
			"mfa_enabled":           true,
			"force_password_change": false,
		})
		finalUser = user
		finalUser.MFAEnabled = true
		finalUser.ForcePasswordChange = false
	}

	tokenString, refreshTokenStr, err := issueTokens(finalUser)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Could not generate token"})
	}

	return c.JSON(fiber.Map{
		"token":         tokenString,
		"refresh_token": refreshTokenStr,
		"user": fiber.Map{
			"id":    finalUser.ID,
			"email": finalUser.Email,
			"role":  finalUser.Role,
		},
	})
}

// The setup and MFA steps used to be addressed by a user id taken from the
// request body. Anyone who could reach the API could name any account, and
// setup-init would hand back a freshly minted TOTP secret for it -- an
// unauthenticated takeover of every account that had not finished enrolling.
//
// A stage token fixes the shape rather than the symptom: Login already checks
// the password, so it is the only place that may say who the next step is for.
// The token is signed, short-lived and names the stage, so one stage's ticket
// cannot be replayed at another.

const stageTokenTTL = 10 * time.Minute

func issueStageToken(userID uint, stage string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"user_id": float64(userID),
		"stage":   stage,
		"exp":     time.Now().Add(stageTokenTTL).Unix(),
	}).SignedString(middleware.JWTSecret)
}

// stageUser resolves the account a stage token was issued for, refusing a
// token minted for a different step.
func stageUser(tokenString, stage string) (*models.User, error) {
	if tokenString == "" {
		return nil, fmt.Errorf("missing setup token")
	}
	token, err := jwt.Parse(tokenString, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return middleware.JWTSecret, nil
	})
	if err != nil || !token.Valid {
		return nil, fmt.Errorf("expired or invalid setup token; sign in again")
	}
	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok || claims["stage"] != stage {
		return nil, fmt.Errorf("this token is not for this step")
	}
	id, ok := claims["user_id"].(float64)
	if !ok {
		return nil, fmt.Errorf("malformed setup token")
	}

	var user models.User
	if err := db.DB.First(&user, uint(id)).Error; err != nil {
		return nil, fmt.Errorf("account not found")
	}
	return &user, nil
}
