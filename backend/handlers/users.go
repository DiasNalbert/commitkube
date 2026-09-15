package handlers

import (
	"fmt"
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

	db.LogAudit(caller.ID, "create_user", "user", user.Email, `{"role":"`+user.Role+`"}`, c.IP())

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
		if caller.Role != "root" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only root can remove a root user"})
		}
		var roots int64
		db.DB.Model(&models.User{}).Where("role = ?", "root").Count(&roots)
		if roots <= 1 {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "this is the only root user; promote another one first",
			})
		}
	}
	if caller.Role == "admin" && target.Role == "admin" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Admins cannot delete other admins"})
	}

	// Everything keyed to this user goes with it. Leaving grants and scopes
	// behind is not just untidy: ids are assigned by the database, and a
	// future user landing on a freed id would silently inherit what this one
	// was allowed to do.
	db.DB.Where("user_id = ?", target.ID).Delete(&models.RefreshToken{})
	db.DB.Where("user_id = ?", target.ID).Delete(&models.UserGroupMember{})
	db.DB.Where("subject_type = ? AND subject_id = ?", "user", target.ID).Delete(&models.PermissionGrant{})
	db.DB.Where("subject_type = ? AND subject_id = ?", "user", target.ID).Delete(&models.NamespaceScope{})
	db.DB.Unscoped().Delete(&target)

	db.LogAudit(caller.ID, "delete_user", "user", target.Email, "", c.IP())

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
	if err := c.BodyParser(&req); err != nil ||
		(req.Role != "user" && req.Role != "admin" && req.Role != "root") {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "role must be 'user', 'admin' or 'root'"})
	}

	var target models.User
	if err := db.DB.First(&target, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	if target.Role == req.Role {
		return c.JSON(fiber.Map{"message": "Role unchanged"})
	}

	var roots int64
	db.DB.Model(&models.User{}).Where("role = ?", "root").Count(&roots)

	if req.Role == "root" {
		// Root edits the policy and authors cluster RBAC, so the holders are
		// capped: two, because one cannot go on holiday, and no more, because
		// each additional holder is another account whose compromise is total.
		if roots >= int64(MaxRootUsers) {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": fmt.Sprintf("there are already %d root users, which is the maximum; demote one first", roots),
			})
		}
	} else if target.Role == "root" {
		// Demoting the last root leaves nobody who can grant anything ever
		// again -- an unrecoverable state, since the permission that fixes it
		// is the one that just disappeared.
		if roots <= 1 {
			return c.Status(fiber.StatusConflict).JSON(fiber.Map{
				"error": "this is the only root user; promote another one before demoting this one",
			})
		}
		if target.ID == caller.ID {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"error": "demote yourself from another root account, so a mistake is someone else's to undo",
			})
		}
	}

	db.DB.Model(&target).Update("role", req.Role)
	db.LogAudit(caller.ID, "update_user_role", "user", target.Email,
		`{"from":"`+target.Role+`","to":"`+req.Role+`"}`, c.IP())
	return c.JSON(fiber.Map{"message": "Role updated"})
}

func GetMyKeys(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	var keys models.UserKeys
	if err := db.DB.Where("user_id = ?", userID).First(&keys).Error; err != nil {
		return c.JSON(fiber.Map{
			"bitbucket_username": "",
			"ssh_pub_key":        "",
			"has_app_pass":       false,
			"has_ssh_key":        false,
		})
	}
	return c.JSON(fiber.Map{
		"bitbucket_username": keys.BitbucketUsername,
		"ssh_pub_key":        keys.BitbucketSSHPubKey,
		"has_app_pass":       keys.BitbucketAppPass != "",
		"has_ssh_key":        keys.BitbucketSSHKey != "",
	})
}

func SaveMyKeys(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))

	var req struct {
		BitbucketUsername string `json:"bitbucket_username"`
		BitbucketAppPass  string `json:"bitbucket_app_pass"`
		SSHPrivKey        string `json:"ssh_priv_key"`
		SSHPubKey         string `json:"ssh_pub_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	var keys models.UserKeys
	isNew := db.DB.Where("user_id = ?", userID).First(&keys).Error != nil
	if isNew {
		keys.UserID = userID
	}

	if req.BitbucketUsername != "" {
		keys.BitbucketUsername = req.BitbucketUsername
	}
	if req.BitbucketAppPass != "" {
		keys.BitbucketAppPass = req.BitbucketAppPass
	}
	if req.SSHPrivKey != "" {
		keys.BitbucketSSHKey = req.SSHPrivKey
	}
	if req.SSHPubKey != "" {
		keys.BitbucketSSHPubKey = req.SSHPubKey
	}

	if isNew {
		db.DB.Create(&keys)
	} else {
		db.DB.Save(&keys)
	}
	return c.JSON(fiber.Map{"message": "Credentials saved"})
}

func ResetUserMFA(c *fiber.Ctx) error {
	caller, err := currentUser(c)
	if err != nil || !isAdminOrRoot(caller.Role) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Forbidden"})
	}

	var target models.User
	if err := db.DB.First(&target, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "User not found"})
	}
	if target.Role == "root" && caller.Role != "root" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Cannot reset root MFA"})
	}

	db.DB.Model(&target).Updates(map[string]interface{}{
		"mfa_secret":  "",
		"mfa_enabled": false,
	})
	return c.JSON(fiber.Map{"message": "MFA reset. User must re-enroll on next login."})
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
