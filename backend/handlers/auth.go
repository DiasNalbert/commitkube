package handlers

import (
	"crypto/rand"
	"encoding/hex"
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
	UserID uint   `json:"user_id"`
	Code   string `json:"code"`
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
		return c.JSON(fiber.Map{
			"setup_required": true,
			"temp_user_id":   user.ID,
			"is_bootstrap":   user.Role == "bootstrap",
		})
	}

	return c.JSON(fiber.Map{
		"require_mfa":  true,
		"temp_user_id": user.ID,
	})
}

func VerifyMFA(c *fiber.Ctx) error {
	var req MFARequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	var user models.User
	if err := db.DB.First(&user, req.UserID).Error; err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "User not found"})
	}

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
		TempUserID  uint   `json:"temp_user_id"`
		NewEmail    string `json:"new_email"`
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	var user models.User
	if err := db.DB.First(&user, req.TempUserID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

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
		TempUserID uint   `json:"temp_user_id"`
		TOTPCode   string `json:"totp_code"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	var user models.User
	if err := db.DB.First(&user, req.TempUserID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

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
