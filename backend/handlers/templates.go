package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func ListTemplates(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))

	wsIDParam := c.QueryInt("workspace_id", -1)
	projectKey := c.Query("project_key", "")

	var tmplList []models.YamlTemplate
	if wsIDParam > 0 {
		wsID := uint(wsIDParam)
		db.DB.Where("user_id = ? AND workspace_id = ? AND project_key = ?", userID, wsID, projectKey).
			Order("type desc, name asc").Find(&tmplList)
	} else {
		db.DB.Where("user_id = ? AND workspace_id IS NULL", userID).
			Order("type desc, name asc").Find(&tmplList)
	}
	return c.JSON(tmplList)
}

func CreateTemplate(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	var req struct {
		Name        string `json:"name"`
		Path        string `json:"path"`
		Content     string `json:"content"`
		Type        string `json:"type"`
		WorkspaceID *uint  `json:"workspace_id"`
		ProjectKey  string `json:"project_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.Type == "" {
		req.Type = "manifest"
	}
	if req.Path == "" && req.Type == "manifest" {
		req.Path = "manifestos"
	}
	tmpl := models.YamlTemplate{
		UserID:      userID,
		WorkspaceID: req.WorkspaceID,
		ProjectKey:  req.ProjectKey,
		Name:        req.Name,
		Path:        req.Path,
		Content:     req.Content,
		Type:        req.Type,
		IsActive:    true,
	}
	db.DB.Create(&tmpl)
	return c.Status(fiber.StatusCreated).JSON(tmpl)
}

func UpdateTemplate(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")
	var tmpl models.YamlTemplate
	if err := db.DB.Where("id = ? AND user_id = ?", id, userID).First(&tmpl).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "template not found"})
	}
	var req struct {
		Name     string `json:"name"`
		Path     string `json:"path"`
		Content  string `json:"content"`
		IsActive *bool  `json:"is_active"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.Name != "" {
		tmpl.Name = req.Name
	}
	if req.Path != "" {
		tmpl.Path = req.Path
	}
	if req.Content != "" {
		tmpl.Content = req.Content
	}
	if req.IsActive != nil {
		tmpl.IsActive = *req.IsActive
	}
	db.DB.Save(&tmpl)
	return c.JSON(tmpl)
}

func DeleteTemplate(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")
	if err := db.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&models.YamlTemplate{}).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "template not found"})
	}
	return c.JSON(fiber.Map{"message": "template deleted"})
}
