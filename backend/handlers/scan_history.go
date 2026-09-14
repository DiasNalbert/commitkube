package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func GetScanHistory(c *fiber.Ctx) error {
	repoName := c.Params("name")
	limit := c.QueryInt("limit", 10)
	if limit < 1 || limit > 50 {
		limit = 10
	}

	var history []models.ScanHistory
	db.DB.Where("repo_name = ?", repoName).
		Order("created_at desc").
		Limit(limit).
		Find(&history)

	return c.JSON(history)
}
