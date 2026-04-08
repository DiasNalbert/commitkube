package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func GetSMTPConfig(c *fiber.Ctx) error {
	var cfg models.SMTPConfig
	db.DB.FirstOrCreate(&cfg, models.SMTPConfig{})
	return c.JSON(cfg)
}

func UpdateSMTPConfig(c *fiber.Ctx) error {
	role, _ := c.Locals("role").(string)
	if role != "admin" && role != "root" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}

	var req struct {
		Host     string `json:"host"`
		Port     string `json:"port"`
		User     string `json:"user"`
		Password string `json:"password"`
		From     string `json:"from"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	var cfg models.SMTPConfig
	db.DB.FirstOrCreate(&cfg, models.SMTPConfig{})

	key := crypto.MasterKey()
	cfg.Host = req.Host
	cfg.Port = req.Port
	cfg.User = req.User
	cfg.From = req.From
	if req.Password != "" {
		cfg.Password = crypto.EncryptField(key, req.Password)
	}

	db.DB.Save(&cfg)
	return c.JSON(fiber.Map{"message": "SMTP configuration saved"})
}
