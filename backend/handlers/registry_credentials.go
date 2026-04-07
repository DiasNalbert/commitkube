package handlers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func ListRegistryCredentials(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	var creds []models.RegistryCredential
	db.DB.Where("user_id = ?", userID).Find(&creds)
	type item struct {
		ID          uint   `json:"id"`
		Alias       string `json:"alias"`
		Host        string `json:"host"`
		Type        string `json:"type"`
		Username    string `json:"username"`
		AWSRegion   string `json:"aws_region"`
		WorkspaceID *uint  `json:"workspace_id"`
		HasPassword bool   `json:"has_password"`
		HasAWSKey   bool   `json:"has_aws_key"`
		HasGCRKey   bool   `json:"has_gcr_key"`
	}
	out := make([]item, 0, len(creds))
	for _, c := range creds {
		out = append(out, item{
			ID:          c.ID,
			Alias:       c.Alias,
			Host:        c.Host,
			Type:        c.Type,
			Username:    c.Username,
			AWSRegion:   c.AWSRegion,
			WorkspaceID: c.WorkspaceID,
			HasPassword: c.Password != "",
			HasAWSKey:   c.AWSAccessKey != "",
			HasGCRKey:   c.GCRKeyJSON != "",
		})
	}
	return c.JSON(out)
}

func CreateRegistryCredential(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	var req struct {
		Alias        string `json:"alias"`
		Host         string `json:"host"`
		Type         string `json:"type"`
		WorkspaceID  *uint  `json:"workspace_id"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		AWSAccessKey string `json:"aws_access_key"`
		AWSSecretKey string `json:"aws_secret_key"`
		AWSRegion    string `json:"aws_region"`
		GCRKeyJSON   string `json:"gcr_key_json"`
	}
	if err := c.BodyParser(&req); err != nil || req.Alias == "" || req.Host == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "alias and host are required"})
	}
	if req.Type == "" {
		req.Type = "generic"
	}
	encKey := crypto.MasterKey()
	cred := models.RegistryCredential{
		UserID:       userID,
		WorkspaceID:  req.WorkspaceID,
		Alias:        req.Alias,
		Host:         strings.ToLower(strings.TrimSpace(req.Host)),
		Type:         req.Type,
		Username:     req.Username,
		Password:     crypto.EncryptField(encKey, req.Password),
		AWSAccessKey: crypto.EncryptField(encKey, req.AWSAccessKey),
		AWSSecretKey: crypto.EncryptField(encKey, req.AWSSecretKey),
		AWSRegion:    req.AWSRegion,
		GCRKeyJSON:   crypto.EncryptField(encKey, req.GCRKeyJSON),
	}
	if err := db.DB.Create(&cred).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": cred.ID})
}

func UpdateRegistryCredential(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")
	var cred models.RegistryCredential
	if err := db.DB.Where("id = ? AND user_id = ?", id, userID).First(&cred).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "not found"})
	}
	var req struct {
		Alias        string `json:"alias"`
		Host         string `json:"host"`
		Type         string `json:"type"`
		WorkspaceID  *uint  `json:"workspace_id"`
		Username     string `json:"username"`
		Password     string `json:"password"`
		AWSAccessKey string `json:"aws_access_key"`
		AWSSecretKey string `json:"aws_secret_key"`
		AWSRegion    string `json:"aws_region"`
		GCRKeyJSON   string `json:"gcr_key_json"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.Alias != "" {
		cred.Alias = req.Alias
	}
	if req.Host != "" {
		cred.Host = strings.ToLower(strings.TrimSpace(req.Host))
	}
	if req.Type != "" {
		cred.Type = req.Type
	}
	cred.WorkspaceID = req.WorkspaceID
	if req.Username != "" {
		cred.Username = req.Username
	}
	encKey := crypto.MasterKey()
	if req.Password != "" {
		cred.Password = crypto.EncryptField(encKey, req.Password)
	}
	if req.AWSAccessKey != "" {
		cred.AWSAccessKey = crypto.EncryptField(encKey, req.AWSAccessKey)
	}
	if req.AWSSecretKey != "" {
		cred.AWSSecretKey = crypto.EncryptField(encKey, req.AWSSecretKey)
	}
	if req.AWSRegion != "" {
		cred.AWSRegion = req.AWSRegion
	}
	if req.GCRKeyJSON != "" {
		cred.GCRKeyJSON = crypto.EncryptField(encKey, req.GCRKeyJSON)
	}
	db.DB.Save(&cred)
	return c.JSON(fiber.Map{"ok": true})
}

func DeleteRegistryCredential(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")
	db.DB.Where("id = ? AND user_id = ?", id, userID).Delete(&models.RegistryCredential{})
	return c.JSON(fiber.Map{"ok": true})
}

// ResolveRegistryCredential finds a matching credential for the given image URL
// and returns it with all sensitive fields decrypted.
func ResolveRegistryCredential(image string, userID uint) *models.RegistryCredential {
	host := extractImageHost(image)
	if host == "" {
		return nil
	}
	var creds []models.RegistryCredential
	db.DB.Where("user_id = ?", userID).Find(&creds)
	encKey := crypto.MasterKey()
	for i, c := range creds {
		if strings.EqualFold(c.Host, host) || strings.HasSuffix(host, c.Host) {
			creds[i].Password = crypto.DecryptField(encKey, c.Password)
			creds[i].AWSAccessKey = crypto.DecryptField(encKey, c.AWSAccessKey)
			creds[i].AWSSecretKey = crypto.DecryptField(encKey, c.AWSSecretKey)
			creds[i].GCRKeyJSON = crypto.DecryptField(encKey, c.GCRKeyJSON)
			return &creds[i]
		}
	}
	return nil
}

func extractImageHost(image string) string {
	// Remove tag/digest
	ref := strings.Split(image, ":")[0]
	ref = strings.Split(ref, "@")[0]
	parts := strings.SplitN(ref, "/", 2)
	// If first segment contains a dot or colon it's a registry host
	if len(parts) > 1 && (strings.Contains(parts[0], ".") || strings.Contains(parts[0], ":")) {
		return parts[0]
	}
	// Default to DockerHub
	return "registry-1.docker.io"
}
