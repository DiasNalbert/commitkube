package handlers

import (
	"encoding/json"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

func ListWebhookConfigs(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	var configs []models.WebhookConfig
	db.DB.Find(&configs)

	type item struct {
		models.WebhookConfig
		HasSecret bool `json:"has_secret"`
	}
	out := make([]item, 0, len(configs))
	encKey := crypto.MasterKey()
	for _, cfg := range configs {
		out = append(out, item{
			WebhookConfig: cfg,
			HasSecret:     crypto.DecryptField(encKey, cfg.Secret) != "",
		})
	}
	return c.JSON(out)
}

func CreateWebhookConfig(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	var req struct {
		Alias            string `json:"alias"`
		URL              string `json:"url"`
		Secret           string `json:"secret"`
		Events           string `json:"events"`
		PayloadTemplates string `json:"payload_templates"`
		Active           *bool  `json:"active"`
	}
	if err := c.BodyParser(&req); err != nil || req.Alias == "" || req.URL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "alias and url are required"})
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	encKey := crypto.MasterKey()
	cfg := models.WebhookConfig{
		Alias:            req.Alias,
		URL:              req.URL,
		Secret:           crypto.EncryptField(encKey, req.Secret),
		Events:           req.Events,
		PayloadTemplates: req.PayloadTemplates,
		Active:           active,
	}
	if err := db.DB.Create(&cfg).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": cfg.ID})
}

func UpdateWebhookConfig(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	id := c.Params("id")
	var cfg models.WebhookConfig
	if err := db.DB.Where("id = ?", id).First(&cfg).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "webhook not found"})
	}
	var req struct {
		Alias            string `json:"alias"`
		URL              string `json:"url"`
		Secret           string `json:"secret"`
		Events           string `json:"events"`
		PayloadTemplates string `json:"payload_templates"`
		Active           *bool  `json:"active"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	encKey := crypto.MasterKey()
	if req.Alias != "" {
		cfg.Alias = req.Alias
	}
	if req.URL != "" {
		cfg.URL = req.URL
	}
	if req.Secret != "" {
		cfg.Secret = crypto.EncryptField(encKey, req.Secret)
	}
	if req.Events != "" {
		cfg.Events = req.Events
	}
	if req.PayloadTemplates != "" {
		cfg.PayloadTemplates = req.PayloadTemplates
	}
	if req.Active != nil {
		cfg.Active = *req.Active
	}

	db.DB.Save(&cfg)
	return c.JSON(fiber.Map{"ok": true})
}

func DeleteWebhookConfig(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	id := c.Params("id")
	db.DB.Where("id = ?", id).Delete(&models.WebhookConfig{})
	return c.JSON(fiber.Map{"ok": true})
}

func TestWebhookConfig(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	id := c.Params("id")
	var cfg models.WebhookConfig
	if err := db.DB.Where("id = ?", id).First(&cfg).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "webhook not found"})
	}

	encKey := crypto.MasterKey()
	targets := []services.WebhookTarget{{
		URL:              cfg.URL,
		Secret:           crypto.DecryptField(encKey, cfg.Secret),
		Events:           `["ping"]`,
		PayloadTemplates: cfg.PayloadTemplates,
	}}
	services.Dispatch(services.WebhookEvent{
		Event:   "ping",
		Payload: map[string]interface{}{"message": "CommitKube webhook test"},
	}, targets)

	return c.JSON(fiber.Map{"message": "ping dispatched to " + cfg.URL})
}

// DispatchWebhook is the internal helper called by other handlers.
// It loads all active WebhookConfigs from DB, decrypts secrets, and calls Dispatch.
func DispatchWebhook(event services.WebhookEvent) {
	var configs []models.WebhookConfig
	db.DB.Where("active = true").Find(&configs)
	if len(configs) == 0 {
		return
	}

	encKey := crypto.MasterKey()
	targets := make([]services.WebhookTarget, 0, len(configs))
	for _, cfg := range configs {
		targets = append(targets, services.WebhookTarget{
			URL:              cfg.URL,
			Secret:           crypto.DecryptField(encKey, cfg.Secret),
			Events:           cfg.Events,
			PayloadTemplates: cfg.PayloadTemplates,
		})
	}
	services.Dispatch(event, targets)
}

// WebhookEventsJSON returns the list of all supported event names.
func WebhookEventsJSON() string {
	events := []string{
		"repo.created",
		"scan.completed",
		"deploy.status_changed",
		"vulnerability.critical_found",
		"ping",
	}
	b, _ := json.Marshal(events)
	return string(b)
}
