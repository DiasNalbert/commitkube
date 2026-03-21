package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func callerIsAdmin(c *fiber.Ctx) bool {
	role, _ := c.Locals("role").(string)
	return role == "root" || role == "admin"
}

func ListWorkspaces(c *fiber.Ctx) error {
	var workspaces []models.BitbucketWorkspace
	db.DB.Find(&workspaces)
	return c.JSON(workspaces)
}

func CreateWorkspace(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Apenas admin pode criar workspaces"})
	}
	userID := uint(c.Locals("user_id").(float64))

	var req struct {
		Alias       string `json:"alias"`
		Username    string `json:"username"`
		AppPass     string `json:"app_pass"`
		WorkspaceID string `json:"workspace_id"`
		ProjectKey  string `json:"project_key"`
		SSHPrivKey  string `json:"ssh_priv_key"`
		SSHPubKey   string `json:"ssh_pub_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Alias == "" || req.WorkspaceID == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "alias and workspace_id are required"})
	}

	ws := models.BitbucketWorkspace{
		UserID:      userID,
		Alias:       req.Alias,
		Username:    req.Username,
		AppPass:     req.AppPass,
		WorkspaceID: req.WorkspaceID,
		ProjectKey:  req.ProjectKey,
		SSHPrivKey:  req.SSHPrivKey,
		SSHPubKey:   req.SSHPubKey,
	}
	db.DB.Create(&ws)
	return c.Status(fiber.StatusCreated).JSON(ws)
}

func UpdateWorkspace(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Apenas admin pode editar workspaces"})
	}
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")

	var ws models.BitbucketWorkspace
	if err := db.DB.Where("id = ? AND user_id = ?", id, userID).First(&ws).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "workspace not found"})
	}

	var req struct {
		Alias       string `json:"alias"`
		Username    string `json:"username"`
		AppPass     string `json:"app_pass"`
		WorkspaceID string `json:"workspace_id"`
		ProjectKey  string `json:"project_key"`
		SSHPrivKey  string `json:"ssh_priv_key"`
		SSHPubKey   string `json:"ssh_pub_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	if req.Alias != "" {
		ws.Alias = req.Alias
	}
	if req.Username != "" {
		ws.Username = req.Username
	}
	if req.AppPass != "" {
		ws.AppPass = req.AppPass
	}
	if req.WorkspaceID != "" {
		ws.WorkspaceID = req.WorkspaceID
	}
	if req.ProjectKey != "" {
		ws.ProjectKey = req.ProjectKey
	}
	if req.SSHPrivKey != "" {
		ws.SSHPrivKey = req.SSHPrivKey
	}
	if req.SSHPubKey != "" {
		ws.SSHPubKey = req.SSHPubKey
	}

	db.DB.Save(&ws)
	return c.JSON(ws)
}

func DeleteWorkspace(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Apenas admin pode excluir workspaces"})
	}
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")

	var ws models.BitbucketWorkspace
	if err := db.DB.Where("id = ? AND user_id = ?", id, userID).First(&ws).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "workspace not found"})
	}
	db.DB.Delete(&ws)
	return c.JSON(fiber.Map{"message": "workspace deleted"})
}

func ListArgoCDInstances(c *fiber.Ctx) error {
	var instances []models.ArgoCDInstance
	db.DB.Find(&instances)
	return c.JSON(instances)
}

func CreateArgoCDInstance(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Apenas admin pode criar instâncias ArgoCD"})
	}
	userID := uint(c.Locals("user_id").(float64))

	var req struct {
		Alias     string `json:"alias"`
		ServerURL string `json:"server_url"`
		AuthToken string `json:"auth_token"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Alias == "" || req.ServerURL == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "alias and server_url are required"})
	}

	inst := models.ArgoCDInstance{
		UserID:    userID,
		Alias:     req.Alias,
		ServerURL: req.ServerURL,
		AuthToken: req.AuthToken,
	}
	db.DB.Create(&inst)
	return c.Status(fiber.StatusCreated).JSON(inst)
}

func UpdateArgoCDInstance(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Apenas admin pode editar instâncias ArgoCD"})
	}
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")

	var inst models.ArgoCDInstance
	if err := db.DB.Where("id = ? AND user_id = ?", id, userID).First(&inst).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}

	var req struct {
		Alias     string `json:"alias"`
		ServerURL string `json:"server_url"`
		AuthToken string `json:"auth_token"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	if req.Alias != "" {
		inst.Alias = req.Alias
	}
	if req.ServerURL != "" {
		inst.ServerURL = req.ServerURL
	}
	if req.AuthToken != "" {
		inst.AuthToken = req.AuthToken
	}

	db.DB.Save(&inst)
	return c.JSON(inst)
}

func DeleteArgoCDInstance(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Apenas admin pode excluir instâncias ArgoCD"})
	}
	userID := uint(c.Locals("user_id").(float64))
	id := c.Params("id")

	var inst models.ArgoCDInstance
	if err := db.DB.Where("id = ? AND user_id = ?", id, userID).First(&inst).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}
	db.DB.Delete(&inst)
	return c.JSON(fiber.Map{"message": "argocd instance deleted"})
}
