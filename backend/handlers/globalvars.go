package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func ListGlobalVars(c *fiber.Ctx) error {
	var vars []models.GlobalVariable

	wsIDParam := c.QueryInt("workspace_id", -1)
	projectKey := c.Query("project_key", "")

	if wsIDParam > 0 {
		wsID := uint(wsIDParam)
		db.DB.Where("workspace_id = ? AND project_key = ?", wsID, projectKey).
			Order("key asc").Find(&vars)
	} else {
		db.DB.Where("workspace_id IS NULL AND project_key = ''").
			Order("key asc").Find(&vars)
	}

	return c.JSON(vars)
}

func CreateGlobalVar(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	var req struct {
		Key         string `json:"key"`
		Value       string `json:"value"`
		Secured     bool   `json:"secured"`
		WorkspaceID *uint  `json:"workspace_id"`
		ProjectKey  string `json:"project_key"`
	}
	if err := c.BodyParser(&req); err != nil || req.Key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "key is required"})
	}
	v := models.GlobalVariable{
		UserID:      userID,
		WorkspaceID: req.WorkspaceID,
		ProjectKey:  req.ProjectKey,
		Key:         req.Key,
		Value:       req.Value,
		Secured:     req.Secured,
	}
	db.DB.Create(&v)
	return c.Status(fiber.StatusCreated).JSON(v)
}

func UpdateGlobalVar(c *fiber.Ctx) error {
	id := c.Params("id")
	var v models.GlobalVariable
	if err := db.DB.Where("id = ?", id).First(&v).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "variable not found"})
	}
	var req struct {
		Key     string `json:"key"`
		Value   string `json:"value"`
		Secured *bool  `json:"secured"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.Key != "" {
		v.Key = req.Key
	}
	v.Value = req.Value
	if req.Secured != nil {
		v.Secured = *req.Secured
	}
	db.DB.Save(&v)
	return c.JSON(v)
}

func DeleteGlobalVar(c *fiber.Ctx) error {
	id := c.Params("id")
	if err := db.DB.Where("id = ?", id).Delete(&models.GlobalVariable{}).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "variable not found"})
	}
	return c.JSON(fiber.Map{"message": "variable deleted"})
}
