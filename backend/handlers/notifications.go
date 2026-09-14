package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/smtp"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func ListNotifications(c *fiber.Ctx) error {
	var configs []models.NotificationConfig
	db.DB.Find(&configs)
	return c.JSON(configs)
}

func CreateNotification(c *fiber.Ctx) error {
	var req struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		URL    string `json:"url"`
		Email  string `json:"email"`
		Events string `json:"events"`
		Active *bool  `json:"active"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" || req.Type == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name and type are required"})
	}

	active := true
	if req.Active != nil {
		active = *req.Active
	}

	cfg := models.NotificationConfig{
		Name:   req.Name,
		Type:   req.Type,
		URL:    req.URL,
		Email:  req.Email,
		Events: req.Events,
		Active: active,
	}
	if err := db.DB.Create(&cfg).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(cfg)
}

func UpdateNotification(c *fiber.Ctx) error {
	id := c.Params("id")
	var cfg models.NotificationConfig
	if err := db.DB.Where("id = ?", id).First(&cfg).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "notification not found"})
	}

	var req struct {
		Name   string `json:"name"`
		Type   string `json:"type"`
		URL    string `json:"url"`
		Email  string `json:"email"`
		Events string `json:"events"`
		Active *bool  `json:"active"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	if req.Name != "" {
		cfg.Name = req.Name
	}
	if req.Type != "" {
		cfg.Type = req.Type
	}
	cfg.URL = req.URL
	cfg.Email = req.Email
	if req.Events != "" {
		cfg.Events = req.Events
	}
	if req.Active != nil {
		cfg.Active = *req.Active
	}

	db.DB.Save(&cfg)
	return c.JSON(cfg)
}

func DeleteNotification(c *fiber.Ctx) error {
	id := c.Params("id")
	db.DB.Where("id = ?", id).Delete(&models.NotificationConfig{})
	return c.JSON(fiber.Map{"ok": true})
}

func TestNotification(c *fiber.Ctx) error {
	id := c.Params("id")
	var cfg models.NotificationConfig
	if err := db.DB.Where("id = ?", id).First(&cfg).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "notification not found"})
	}

	var sendErr error
	switch cfg.Type {
	case "teams":
		sendErr = sendTeamsNotification(cfg.URL, "CommitKube Test", "This is a test notification from CommitKube", "test-repo", "ping", "system")
	case "webhook":
		sendErr = sendWebhookNotification(cfg.URL, "ping", "CommitKube Test", "This is a test notification from CommitKube", "test-repo", "system")
	case "email":
		sendErr = sendEmailNotification(cfg.Email, "CommitKube Test Notification", "This is a test notification from CommitKube")
	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "unknown notification type"})
	}

	if sendErr != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": sendErr.Error()})
	}
	return c.JSON(fiber.Map{"message": "test notification sent"})
}

// SendNotifications is the internal function called from other handlers to dispatch notifications.
func SendNotifications(event, title, message, repoName, actor string) {
	var configs []models.NotificationConfig
	db.DB.Where("active = true").Find(&configs)
	if len(configs) == 0 {
		return
	}

	for _, cfg := range configs {
		if !notificationMatchesEvent(cfg.Events, event) {
			continue
		}
		var err error
		switch cfg.Type {
		case "teams":
			err = sendTeamsNotification(cfg.URL, title, message, repoName, event, actor)
		case "webhook":
			err = sendWebhookNotification(cfg.URL, event, title, message, repoName, actor)
		case "email":
			err = sendEmailNotification(cfg.Email, title, message)
		}
		if err != nil {
			fmt.Printf("[notifications] failed to send %s notification (id=%d type=%s): %v\n", event, cfg.ID, cfg.Type, err)
		}
	}
}

func notificationMatchesEvent(eventsJSON, event string) bool {
	if eventsJSON == "" {
		return false
	}
	var events []string
	if err := json.Unmarshal([]byte(eventsJSON), &events); err != nil {
		return false
	}
	for _, e := range events {
		if e == event {
			return true
		}
	}
	return false
}

func sendTeamsNotification(url, title, message, repoName, event, actor string) error {
	if url == "" {
		return fmt.Errorf("teams URL is empty")
	}

	facts := []map[string]string{
		{"title": "Repository", "value": repoName},
		{"title": "Event", "value": event},
		{"title": "Time", "value": time.Now().UTC().Format("2006-01-02 15:04:05 UTC")},
	}
	if actor != "" && actor != "system" {
		facts = append(facts, map[string]string{"title": "By", "value": actor})
	}

	factItems := make([]interface{}, len(facts))
	for i, f := range facts {
		factItems[i] = f
	}

	payload := map[string]interface{}{
		"type": "message",
		"attachments": []map[string]interface{}{
			{
				"contentType": "application/vnd.microsoft.card.adaptive",
				"content": map[string]interface{}{
					"$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
					"type":    "AdaptiveCard",
					"version": "1.4",
					"body": []map[string]interface{}{
						{
							"type":   "TextBlock",
							"size":   "Medium",
							"weight": "Bolder",
							"text":   title,
							"color":  "Accent",
							"wrap":   true,
						},
						{
							"type": "TextBlock",
							"text": message,
							"wrap": true,
						},
						{
							"type":  "FactSet",
							"facts": factItems,
						},
					},
				},
			},
		},
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("teams webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendWebhookNotification(url, event, title, message, repoName, actor string) error {
	if url == "" {
		return fmt.Errorf("webhook URL is empty")
	}
	payload := map[string]interface{}{
		"event":     event,
		"title":     title,
		"message":   message,
		"repo":      repoName,
		"actor":     actor,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned HTTP %d", resp.StatusCode)
	}
	return nil
}

func sendEmailNotification(to, subject, body string) error {
	if to == "" {
		return fmt.Errorf("email address is empty")
	}

	var cfg models.SMTPConfig
	db.DB.First(&cfg)

	host := cfg.Host
	port := cfg.Port
	user := cfg.User
	pass := crypto.DecryptField(crypto.MasterKey(), cfg.Password)
	from := cfg.From

	if host == "" {
		host = os.Getenv("SMTP_HOST")
	}
	if port == "" {
		port = os.Getenv("SMTP_PORT")
	}
	if user == "" {
		user = os.Getenv("SMTP_USER")
	}
	if pass == "" {
		pass = os.Getenv("SMTP_PASS")
	}
	if from == "" {
		from = os.Getenv("SMTP_FROM")
	}
	if from == "" {
		from = user
	}

	if host == "" || port == "" || user == "" || pass == "" {
		return fmt.Errorf("SMTP not configured")
	}

	html := fmt.Sprintf(`<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;background:#0d1117;color:#e6edf3;padding:24px;">
<div style="max-width:600px;margin:0 auto;background:#161b22;border-radius:8px;padding:24px;border:1px solid #30363d;">
<h2 style="color:#10b981;margin:0 0 12px">%s</h2>
<p style="color:#8b949e;margin:0 0 16px">%s</p>
<div style="margin-top:20px;padding-top:12px;border-top:1px solid #30363d;color:#8b949e;font-size:11px;">Generated by CommitKube</div>
</div></body></html>`, subject, strings.ReplaceAll(body, "\n", "<br>"))

	auth := smtp.PlainAuth("", user, pass, host)
	msg := fmt.Sprintf(
		"From: CommitKube <%s>\r\nTo: %s\r\nSubject: %s\r\nMIME-Version: 1.0\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n%s",
		from, to, subject, html,
	)
	return smtp.SendMail(host+":"+port, auth, from, []string{to}, []byte(msg))
}
