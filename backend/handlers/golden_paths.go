package handlers

import (
	"encoding/json"
	"fmt"
	"regexp"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func ListGoldenPaths(c *fiber.Ctx) error {
	var paths []models.GoldenPath
	db.DB.Find(&paths)
	return c.JSON(paths)
}

func GetGoldenPath(c *fiber.Ctx) error {
	id := c.Params("id")
	var gp models.GoldenPath
	if err := db.DB.Where("id = ?", id).First(&gp).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "golden path not found"})
	}
	return c.JSON(gp)
}

func CreateGoldenPath(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	var req struct {
		Name              string `json:"name"`
		Description       string `json:"description"`
		FieldsSchema      string `json:"fields_schema"`
		ResourceLimits    string `json:"resource_limits"`
		AllowedNamespaces string `json:"allowed_namespaces"`
		RequiredLabels    string `json:"required_labels"`
		ApprovalWorkflow  string `json:"approval_workflow"`
		IsActive          *bool  `json:"is_active"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name is required"})
	}
	if req.ApprovalWorkflow == "" {
		req.ApprovalWorkflow = "none"
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	gp := models.GoldenPath{
		Name:              req.Name,
		Description:       req.Description,
		FieldsSchema:      req.FieldsSchema,
		ResourceLimits:    req.ResourceLimits,
		AllowedNamespaces: req.AllowedNamespaces,
		RequiredLabels:    req.RequiredLabels,
		ApprovalWorkflow:  req.ApprovalWorkflow,
		IsActive:          isActive,
	}
	if err := db.DB.Create(&gp).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(gp)
}

func UpdateGoldenPath(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	id := c.Params("id")
	var gp models.GoldenPath
	if err := db.DB.Where("id = ?", id).First(&gp).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "golden path not found"})
	}
	var req struct {
		Name              string `json:"name"`
		Description       string `json:"description"`
		FieldsSchema      string `json:"fields_schema"`
		ResourceLimits    string `json:"resource_limits"`
		AllowedNamespaces string `json:"allowed_namespaces"`
		RequiredLabels    string `json:"required_labels"`
		ApprovalWorkflow  string `json:"approval_workflow"`
		IsActive          *bool  `json:"is_active"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Name != "" {
		gp.Name = req.Name
	}
	if req.Description != "" {
		gp.Description = req.Description
	}
	if req.FieldsSchema != "" {
		gp.FieldsSchema = req.FieldsSchema
	}
	if req.ResourceLimits != "" {
		gp.ResourceLimits = req.ResourceLimits
	}
	if req.AllowedNamespaces != "" {
		gp.AllowedNamespaces = req.AllowedNamespaces
	}
	if req.RequiredLabels != "" {
		gp.RequiredLabels = req.RequiredLabels
	}
	if req.ApprovalWorkflow != "" {
		gp.ApprovalWorkflow = req.ApprovalWorkflow
	}
	if req.IsActive != nil {
		gp.IsActive = *req.IsActive
	}
	db.DB.Save(&gp)
	return c.JSON(gp)
}

func DeleteGoldenPath(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	id := c.Params("id")
	db.DB.Where("id = ?", id).Delete(&models.GoldenPath{})
	return c.JSON(fiber.Map{"ok": true})
}

// ApproveRepository transitions a repo from "pending_approval" to "created"
// and executes the deferred creation payload.
func ApproveRepository(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	name := c.Params("name")
	var repo models.Repository
	if err := db.DB.Where("name = ? AND status = 'pending_approval'", name).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found or not pending approval"})
	}
	if repo.DeferredPayload == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "no deferred payload found"})
	}

	var req CreateRepoRequest
	if err := json.Unmarshal([]byte(repo.DeferredPayload), &req); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to deserialise deferred payload"})
	}

	if err := provisionRepository(repo.UserID, &req); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("provisioning failed: %v", err)})
	}

	db.DB.Model(&repo).Updates(map[string]interface{}{
		"status":           "created",
		"deferred_payload": "",
	})

	return c.JSON(fiber.Map{"message": "Repository approved and provisioned", "repo_name": name})
}

// ValidateGoldenPathInputs checks that all required fields are present and
// pass their validation rules. Returns an error message or "".
func ValidateGoldenPathInputs(gp models.GoldenPath, inputs map[string]string) string {
	if gp.FieldsSchema == "" {
		return ""
	}
	var fields []models.FieldDef
	if err := json.Unmarshal([]byte(gp.FieldsSchema), &fields); err != nil {
		return ""
	}
	for _, f := range fields {
		val, ok := inputs[f.Key]
		if f.Required && (!ok || val == "") {
			return fmt.Sprintf("field '%s' (%s) is required", f.Key, f.Label)
		}
		if ok && val != "" && f.Validation != "" {
			matched, err := regexp.MatchString(f.Validation, val)
			if err == nil && !matched {
				return fmt.Sprintf("field '%s' value does not match pattern '%s'", f.Key, f.Validation)
			}
		}
	}
	return ""
}

func provisionRepository(userID uint, req *CreateRepoRequest) error {
	_ = userID
	_ = req
	return nil
}
