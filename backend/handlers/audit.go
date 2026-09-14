package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func GetAuditLogs(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	limit := c.QueryInt("limit", 50)
	action := c.Query("action", "")
	search := c.Query("search", "")
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 200 {
		limit = 50
	}

	q := db.DB.Model(&models.AuditLog{})
	if action != "" {
		q = q.Where("action = ?", action)
	}
	if search != "" {
		like := "%" + search + "%"
		q = q.Where("user_email LIKE ? OR resource_name LIKE ? OR details LIKE ?", like, like, like)
	}

	var total int64
	q.Count(&total)

	var logs []models.AuditLog
	q.Order("created_at desc").Limit(limit).Offset((page - 1) * limit).Find(&logs)

	pages := (int(total) + limit - 1) / limit
	return c.JSON(fiber.Map{
		"data":  logs,
		"total": total,
		"page":  page,
		"pages": pages,
	})
}
