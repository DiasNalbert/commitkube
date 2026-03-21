package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/bcrypt"
)

func currentUser(c *fiber.Ctx) (models.User, error) {
	userID := uint(c.Locals("user_id").(float64))
	var user models.User
	err := db.DB.First(&user, userID).Error
	return user, err
}

func isAdminOrRoot(role string) bool {
	return role == "root" || role == "admin"
}

func GetMe(c *fiber.Ctx) error {
	user, err := currentUser(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	return c.JSON(user)
}

func ListUsers(c *fiber.Ctx) error {
	caller, err := currentUser(c)
	if err != nil || !isAdminOrRoot(caller.Role) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
	}

	var users []models.User
	db.DB.Find(&users)
	return c.JSON(users)
}

func CreateUser(c *fiber.Ctx) error {
	caller, err := currentUser(c)
	if err != nil || !isAdminOrRoot(caller.Role) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
	}

	var req struct {
		Email    string `json:"email"`
		Password string `json:"password"`
		Role     string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil || req.Email == "" || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "email and password required"})
	}

	if req.Role == "admin" && caller.Role != "root" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only root can create admin users"})
	}
	if req.Role == "" || (req.Role != "user" && req.Role != "admin") {
		req.Role = "user"
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), 10)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	user := models.User{
		Email:               req.Email,
		PasswordHash:        string(hash),
		Role:                req.Role,
		ForcePasswordChange: true,
		IsActive:            true,
	}
	if result := db.DB.Create(&user); result.Error != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "Email already exists"})
	}

	return c.Status(fiber.StatusCreated).JSON(user)
}

func DeleteUser(c *fiber.Ctx) error {
	caller, err := currentUser(c)
	if err != nil || !isAdminOrRoot(caller.Role) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
	}

	var target models.User
	if err := db.DB.First(&target, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	if target.ID == caller.ID {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Cannot delete yourself"})
	}
	if target.Role == "root" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Cannot delete root user"})
	}
	if caller.Role == "admin" && target.Role == "admin" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Admins cannot delete other admins"})
	}

	db.DB.Where("user_id = ?", target.ID).Delete(&models.RefreshToken{})
	db.DB.Unscoped().Delete(&target)

	return c.JSON(fiber.Map{"message": "User deleted"})
}

func UpdateUserRole(c *fiber.Ctx) error {
	caller, err := currentUser(c)
	if err != nil || caller.Role != "root" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only root can change roles"})
	}

	var req struct {
		Role string `json:"role"`
	}
	if err := c.BodyParser(&req); err != nil || (req.Role != "user" && req.Role != "admin") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role must be 'user' or 'admin'"})
	}

	var target models.User
	if err := db.DB.First(&target, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	if target.Role == "root" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Cannot change root role"})
	}

	db.DB.Model(&target).Update("role", req.Role)
	return c.JSON(fiber.Map{"message": "Role updated"})
}

func ChangePassword(c *fiber.Ctx) error {
	caller, err := currentUser(c)
	if err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "Unauthorized"})
	}

	targetID := c.Params("id")
	var target models.User
	if err := db.DB.First(&target, targetID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}

	if target.ID != caller.ID && !isAdminOrRoot(caller.Role) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
	}
	if target.Role == "root" && caller.Role == "admin" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Cannot change root password"})
	}

	var req struct {
		NewPassword string `json:"new_password"`
	}
	if err := c.BodyParser(&req); err != nil || req.NewPassword == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "new_password required"})
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), 10)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "Failed to hash password"})
	}

	db.DB.Model(&target).Updates(map[string]interface{}{
		"password_hash":         string(hash),
		"force_password_change": false,
	})
	return c.JSON(fiber.Map{"message": "Password updated"})
}
