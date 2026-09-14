package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

func AnalyzeRepo(c *fiber.Ctx) error {
	repoName := c.Params("name")

	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	currentUserID := uint(c.Locals("user_id").(float64))
	ws, err := resolveWorkspace(currentUserID, repo.WorkspaceID)
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace not found"})
	}

	appPass := crypto.DecryptField(crypto.MasterKey(), ws.AppPass)
	if ws.Username == "" || appPass == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace credentials not configured"})
	}

	var req struct {
		Branch string `json:"branch"`
	}
	c.BodyParser(&req) //nolint — body is optional

	bbClient := services.NewBitbucketClient(ws.Username, appPass, ws.WorkspaceID)
	files, fetchErr := bbClient.FetchAllSrc(repoName, req.Branch)
	if fetchErr != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "failed to fetch repository files: " + fetchErr.Error()})
	}
	if len(files) == 0 {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "no code files found in repository"})
	}

	result, err := services.AnalyzeRepository(repoName, files)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	db.LogAudit(currentUserID, "analyze_repository", "repository", repoName, "", c.IP())

	return c.JSON(result)
}

func ReviewFile(c *fiber.Ctx) error {
	repoName := c.Params("name")

	var req struct {
		Path    string `json:"path"`
		Content string `json:"content"`
		Branch  string `json:"branch"`
	}
	if err := c.BodyParser(&req); err != nil || req.Path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "path is required"})
	}

	content := req.Content
	if content == "" {
		var repo models.Repository
		if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
			return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
		}
		currentUserID := uint(c.Locals("user_id").(float64))
		ws, err := resolveWorkspace(currentUserID, repo.WorkspaceID)
		if err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace not found"})
		}
		appPass := crypto.DecryptField(crypto.MasterKey(), ws.AppPass)
		if ws.Username == "" || appPass == "" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace credentials not configured"})
		}
		bbClient := services.NewBitbucketClient(ws.Username, appPass, ws.WorkspaceID)
		data, status, _, fetchErr := bbClient.ListSrc(repoName, req.Path, req.Branch)
		if fetchErr != nil {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": fetchErr.Error()})
		}
		if status >= 400 {
			return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "could not fetch file from Bitbucket"})
		}
		content = string(data)
	}

	result, err := services.ReviewCode(req.Path, content)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(result)
}
