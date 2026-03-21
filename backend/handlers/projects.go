package handlers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func ListProjects(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	wsID := c.Params("workspace_id")
	var projects []models.BitbucketProject
	db.DB.Where("user_id = ? AND workspace_id = ?", userID, wsID).Order("project_key asc").Find(&projects)
	return c.JSON(projects)
}

func CreateProject(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	wsIDStr := c.Params("workspace_id")
	wsID, err := strconv.ParseUint(wsIDStr, 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid workspace_id"})
	}

	var req struct {
		ProjectKey string `json:"project_key"`
		Alias      string `json:"alias"`
	}
	if err := c.BodyParser(&req); err != nil || req.ProjectKey == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "project_key is required"})
	}

	proj := models.BitbucketProject{
		UserID:      userID,
		WorkspaceID: uint(wsID),
		ProjectKey:  req.ProjectKey,
		Alias:       req.Alias,
	}
	db.DB.Create(&proj)
	return c.Status(fiber.StatusCreated).JSON(proj)
}

func DeleteProject(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")
	if err := db.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&models.BitbucketProject{}).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}
	return c.JSON(fiber.Map{"message": "project deleted"})
}
