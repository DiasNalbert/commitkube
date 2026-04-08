package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func GetSettings(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(float64)
	var keys models.UserKeys
	db.DB.Where("user_id = ?", uint(userID)).FirstOrCreate(&keys, models.UserKeys{UserID: uint(userID)})
	
	return c.JSON(keys)
}

func UpdateSettings(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(float64)
	var keys models.UserKeys
	db.DB.Where("user_id = ?", uint(userID)).FirstOrCreate(&keys, models.UserKeys{UserID: uint(userID)})

	var req struct {
		BitbucketUsername   string `json:"bitbucket_username"`
		BitbucketWorkspace  string `json:"bitbucket_workspace"`
		BitbucketProjectKey string `json:"bitbucket_project_key"`
		BitbucketAppPass    string `json:"bitbucket_app_pass"`
		BitbucketSSHKey     string `json:"bitbucket_ssh_key"`
		BitbucketSSHPubKey  string `json:"bitbucket_ssh_pub_key"`
		ArgoCDServerURL     string `json:"argocd_server_url"`
		ArgoCDAuthToken     string `json:"argocd_auth_token"`
		ArgoCDSSHKey        string `json:"argocd_ssh_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "Invalid request"})
	}

	key := crypto.MasterKey()
	keys.BitbucketUsername = req.BitbucketUsername
	keys.BitbucketWorkspace = req.BitbucketWorkspace
	keys.BitbucketProjectKey = req.BitbucketProjectKey
	if req.BitbucketAppPass != "" {
		keys.BitbucketAppPass = crypto.EncryptField(key, req.BitbucketAppPass)
	}
	if req.BitbucketSSHKey != "" {
		keys.BitbucketSSHKey = crypto.EncryptField(key, req.BitbucketSSHKey)
	}
	if req.BitbucketSSHPubKey != "" {
		keys.BitbucketSSHPubKey = req.BitbucketSSHPubKey
	}
	keys.ArgoCDServerURL = req.ArgoCDServerURL
	if req.ArgoCDAuthToken != "" {
		keys.ArgoCDAuthToken = crypto.EncryptField(key, req.ArgoCDAuthToken)
	}
	if req.ArgoCDSSHKey != "" {
		keys.ArgoCDSSHKey = crypto.EncryptField(key, req.ArgoCDSSHKey)
	}

	db.DB.Save(&keys)
	return c.JSON(fiber.Map{"message": "Settings updated successfully", "data": keys})
}
