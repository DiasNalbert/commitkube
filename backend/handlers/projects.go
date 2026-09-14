package handlers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func ListProjects(c *fiber.Ctx) error {
	wsID := c.Params("workspace_id")

	// Find all CommitKube workspace IDs that share the same Bitbucket slug
	var ws models.BitbucketWorkspace
	if err := db.DB.Where("id = ?", wsID).First(&ws).Error; err != nil {
		return c.JSON([]models.BitbucketProject{})
	}

	var allWsIDs []uint
	db.DB.Model(&models.BitbucketWorkspace{}).
		Where("workspace_id = ?", ws.WorkspaceID).
		Pluck("id", &allWsIDs)

	var allProjects []models.BitbucketProject
	db.DB.Where("workspace_id IN ?", allWsIDs).Order("project_key asc").Find(&allProjects)

	seen := map[string]bool{}
	deduped := make([]models.BitbucketProject, 0, len(allProjects))
	for _, p := range allProjects {
		if !seen[p.ProjectKey] {
			seen[p.ProjectKey] = true
			deduped = append(deduped, p)
		}
	}
	return c.JSON(deduped)
}

func CreateProject(c *fiber.Ctx) error {
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

	userID := uint(c.Locals("user_id").(float64))
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
	id := c.Params("id")
	if err := db.DB.Where("id = ?", id).Delete(&models.BitbucketProject{}).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "project not found"})
	}
	return c.JSON(fiber.Map{"message": "project deleted"})
}
