package handlers

import (
	"bytes"
	"fmt"
	"strings"
	"text/template"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

type EditedTemplate struct {
	ID      uint   `json:"id"`
	Content string `json:"content"`
}

type CreateRepoRequest struct {
	Name             string           `json:"name"`
	EditedTemplates  []EditedTemplate `json:"edited_templates,omitempty"`
	RepoVariables    []RepoVariable   `json:"repo_variables,omitempty"`
	UploadedFiles    []UploadedFile   `json:"uploaded_files,omitempty"`
	WorkspaceID      uint             `json:"workspace_id,omitempty"`
	ArgoCDInstanceID uint             `json:"argocd_instance_id,omitempty"`
	ProjectKey       string           `json:"project_key,omitempty"`
	ExtraBranch      string           `json:"extra_branch,omitempty"`
}

type RepoVariable struct {
	Key     string `json:"key"`
	Value   string `json:"value"`
	Secured bool   `json:"secured"`
}

type UploadedFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

func renderTpl(tmplString, projectName string) string {
	t, err := template.New("t").Parse(tmplString)
	if err != nil {
		return tmplString
	}
	var buf bytes.Buffer
	_ = t.Execute(&buf, map[string]string{"ProjectName": projectName})
	return buf.String()
}

func CreateRepository(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))

	var req CreateRepoRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	var (
		bbUsername   string
		bbAppPass    string
		bbWorkspace  string
		bbProjectKey string
		bbSSHPubKey  string
		bbSSHPrivKey string
	)

	if req.WorkspaceID > 0 {
		var ws models.BitbucketWorkspace
		if err := db.DB.Where("id = ? AND user_id = ?", req.WorkspaceID, userID).First(&ws).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "workspace not found"})
		}
		bbUsername = ws.Username
		bbAppPass = ws.AppPass
		bbWorkspace = ws.WorkspaceID
		bbProjectKey = ws.ProjectKey
		bbSSHPubKey = ws.SSHPubKey
		bbSSHPrivKey = ws.SSHPrivKey
		if req.ProjectKey != "" {
			bbProjectKey = req.ProjectKey
		}
	} else {
		var keys models.UserKeys
		if err := db.DB.Where("user_id = ?", userID).First(&keys).Error; err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Please configure Bitbucket & ArgoCD settings first"})
		}
		bbUsername = keys.BitbucketUsername
		bbAppPass = keys.BitbucketAppPass
		bbWorkspace = keys.BitbucketWorkspace
		bbProjectKey = keys.BitbucketProjectKey
		bbSSHPubKey = keys.BitbucketSSHPubKey
		bbSSHPrivKey = keys.BitbucketSSHKey
	}

	var (
		argoURL   string
		argoToken string
	)

	if req.ArgoCDInstanceID > 0 {
		var inst models.ArgoCDInstance
		if err := db.DB.Where("id = ? AND user_id = ?", req.ArgoCDInstanceID, userID).First(&inst).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "argocd instance not found"})
		}
		argoURL = inst.ServerURL
		argoToken = inst.AuthToken
	} else {
		var keys models.UserKeys
		if db.DB.Where("user_id = ?", userID).First(&keys).Error == nil {
			argoURL = keys.ArgoCDServerURL
			argoToken = keys.ArgoCDAuthToken
		}
	}

	bbClient := services.NewBitbucketClient(bbUsername, bbAppPass, bbWorkspace)
	if err := bbClient.CreateRepository(req.Name, bbProjectKey); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Bitbucket creation failed: %v", err)})
	}

	if err := bbClient.EnablePipelines(req.Name); err != nil {
		fmt.Printf("Warning: failed to enable pipelines for %s: %v\n", req.Name, err)
	}

	if bbSSHPubKey != "" {
		if err := bbClient.AddDeployKey(req.Name, bbSSHPubKey, "CommitKube ArgoCD"); err != nil {
			fmt.Printf("Warning: failed to add deploy key to %s: %v\n", req.Name, err)
		}
	}

	collectVars := func(vars []models.GlobalVariable) {
		for _, v := range vars {
			if err := bbClient.AddRepoVariable(req.Name, v.Key, v.Value, v.Secured); err != nil {
				fmt.Printf("Warning: failed to set var %s on %s: %v\n", v.Key, req.Name, err)
			}
		}
	}

	var userLevelVars []models.GlobalVariable
	db.DB.Where("user_id = ? AND workspace_id IS NULL AND project_key = ''", userID).Find(&userLevelVars)
	collectVars(userLevelVars)

	if req.WorkspaceID > 0 {
		var wsVars []models.GlobalVariable
		db.DB.Where("user_id = ? AND workspace_id = ? AND project_key = ''", userID, req.WorkspaceID).Find(&wsVars)
		collectVars(wsVars)

		pkForVars := req.ProjectKey
		if pkForVars == "" {
			var ws models.BitbucketWorkspace
			if db.DB.Where("id = ? AND user_id = ?", req.WorkspaceID, userID).First(&ws).Error == nil {
				pkForVars = ws.ProjectKey
			}
		}
		if pkForVars != "" {
			var projVars []models.GlobalVariable
			db.DB.Where("user_id = ? AND workspace_id = ? AND project_key = ?", userID, req.WorkspaceID, pkForVars).Find(&projVars)
			collectVars(projVars)
		}
	}

	for _, v := range req.RepoVariables {
		if v.Key == "" {
			continue
		}
		if err := bbClient.AddRepoVariable(req.Name, v.Key, v.Value, v.Secured); err != nil {
			fmt.Printf("Warning: failed to set repo var %s on %s: %v\n", v.Key, req.Name, err)
		}
	}

	files := map[string]string{}
	argoAppPath := "manifests"

	editedMap := map[uint]string{}
	for _, e := range req.EditedTemplates {
		editedMap[e.ID] = e.Content
	}

	applyTemplates := func(tmplList []models.YamlTemplate) {
		for _, tmpl := range tmplList {
			if !tmpl.IsActive {
				continue
			}
			content := tmpl.Content
			if edited, ok := editedMap[tmpl.ID]; ok {
				content = edited
			}
			rendered := renderTpl(content, req.Name)
			filePath := tmpl.Name
			if tmpl.Path != "" {
				filePath = tmpl.Path + "/" + tmpl.Name
			}
			filePath = strings.TrimPrefix(filePath, "/")
			files[filePath] = rendered
			if tmpl.Type == "manifest" && tmpl.Path != "" {
				argoAppPath = strings.TrimPrefix(tmpl.Path, "/")
			}
		}
	}

	var globalTmpls []models.YamlTemplate
	db.DB.Where("user_id = ? AND workspace_id IS NULL AND is_active = true", userID).Find(&globalTmpls)
	applyTemplates(globalTmpls)

	if req.WorkspaceID > 0 {
		var wsTmpls []models.YamlTemplate
		db.DB.Where("user_id = ? AND workspace_id = ? AND project_key = '' AND is_active = true", userID, req.WorkspaceID).Find(&wsTmpls)
		applyTemplates(wsTmpls)
	}

	projectKey := req.ProjectKey
	if projectKey == "" && req.WorkspaceID > 0 {
		var ws models.BitbucketWorkspace
		if db.DB.Where("id = ? AND user_id = ?", req.WorkspaceID, userID).First(&ws).Error == nil {
			projectKey = ws.ProjectKey
		}
	}
	if req.WorkspaceID > 0 && projectKey != "" {
		var projTmpls []models.YamlTemplate
		db.DB.Where("user_id = ? AND workspace_id = ? AND project_key = ? AND is_active = true", userID, req.WorkspaceID, projectKey).Find(&projTmpls)
		applyTemplates(projTmpls)
	}

	for _, f := range req.UploadedFiles {
		if f.Path != "" && f.Content != "" {
			files[f.Path] = f.Content
		}
	}

	if err := bbClient.CommitFiles(req.Name, "Initial commit: CommitKube manifests + source", "main", files); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Failed to commit: %v", err)})
	}

	if req.ExtraBranch != "" && req.ExtraBranch != "main" {
		if err := bbClient.CreateBranch(req.Name, req.ExtraBranch, "main"); err != nil {
			fmt.Printf("Warning: failed to create branch %s on %s: %v\n", req.ExtraBranch, req.Name, err)
		}
	}

	repoURL := fmt.Sprintf("git@bitbucket.org:%s/%s.git", bbWorkspace, req.Name)
	if strings.Contains(bbSSHPrivKey, `\n`) {
		bbSSHPrivKey = strings.ReplaceAll(bbSSHPrivKey, `\n`, "\n")
	}
	if argoURL != "" && argoToken != "" {
		argoClient := services.NewArgoCDClient(argoURL, argoToken)
		if err := argoClient.AddRepository(repoURL, bbSSHPrivKey); err != nil {
			fmt.Printf("Warning: ArgoCD repo registration failed: %v\n", err)
		}
		if err := argoClient.CreateProject(req.Name); err != nil {
			fmt.Printf("Warning: ArgoCD project creation failed: %v\n", err)
		}
		argoTargetRevision := req.ExtraBranch
		if err := argoClient.CreateApplication(req.Name, repoURL, req.Name, argoAppPath, argoTargetRevision); err != nil {
			fmt.Printf("Warning: ArgoCD app creation failed: %v\n", err)
		}
	}

	db.DB.Unscoped().Where("name = ? AND user_id = ?", req.Name, userID).Delete(&models.Repository{})
	repo := models.Repository{
		Name:        req.Name,
		UserID:      userID,
		WorkspaceID: req.WorkspaceID,
		Status:      "created",
		ArgoApp:     req.Name,
	}
	db.DB.Create(&repo)

	return c.JSON(fiber.Map{"message": "Repository created successfully", "repo": repo})
}

func DeleteRepository(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	name := c.Params("name")
	if err := db.DB.Unscoped().Where("name = ? AND user_id = ?", name, userID).Delete(&models.Repository{}).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}
	return c.JSON(fiber.Map{"message": "repository removed from CommitKube"})
}

func ListRepositories(c *fiber.Ctx) error {
	userID := c.Locals("user_id").(float64)
	page := c.QueryInt("page", 1)
	limit := c.QueryInt("limit", 12)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 12
	}
	offset := (page - 1) * limit

	var total int64
	db.DB.Model(&models.Repository{}).Where("user_id = ?", uint(userID)).Count(&total)

	var repos []models.Repository
	db.DB.Where("user_id = ?", uint(userID)).Order("created_at desc").Limit(limit).Offset(offset).Find(&repos)

	pages := (total + int64(limit) - 1) / int64(limit)
	return c.JSON(fiber.Map{
		"data":  repos,
		"total": total,
		"page":  page,
		"pages": pages,
		"limit": limit,
	})
}

func resolveWorkspace(userID, workspaceID uint) (models.BitbucketWorkspace, error) {
	var ws models.BitbucketWorkspace
	q := db.DB.Where("user_id = ?", userID)
	if workspaceID > 0 {
		q = q.Where("id = ?", workspaceID)
	}
	err := q.First(&ws).Error
	return ws, err
}

func GetRepositorySrc(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	repoName := c.Params("name")
	filePath := c.Query("path", "")

	var repo models.Repository
	if err := db.DB.Where("name = ? AND user_id = ?", repoName, userID).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	ws, err := resolveWorkspace(userID, repo.WorkspaceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "workspace not found"})
	}

	bbClient := services.NewBitbucketClient(ws.Username, ws.AppPass, ws.WorkspaceID)
	data, status, contentType, err := bbClient.ListSrc(repoName, filePath)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	c.Status(status)
	c.Set("Content-Type", contentType)
	return c.Send(data)
}

func GetRepositoryPipelines(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	repoName := c.Params("name")

	var repo models.Repository
	if err := db.DB.Where("name = ? AND user_id = ?", repoName, userID).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	ws, err := resolveWorkspace(userID, repo.WorkspaceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "workspace not found"})
	}

	bbClient := services.NewBitbucketClient(ws.Username, ws.AppPass, ws.WorkspaceID)
	data, err := bbClient.ListPipelines(repoName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(data)
}

func GetPipelineSteps(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	repoName := c.Params("name")
	pipelineUUID := c.Params("pipeline_uuid")

	var repo models.Repository
	db.DB.Where("name = ? AND user_id = ?", repoName, userID).First(&repo)

	ws, err := resolveWorkspace(userID, repo.WorkspaceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "workspace not found"})
	}

	bbClient := services.NewBitbucketClient(ws.Username, ws.AppPass, ws.WorkspaceID)
	data, err := bbClient.GetPipelineSteps(repoName, pipelineUUID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(data)
}

func GetStepLog(c *fiber.Ctx) error {
	userID := uint(c.Locals("user_id").(float64))
	repoName := c.Params("name")
	pipelineUUID := c.Params("pipeline_uuid")
	stepUUID := c.Params("step_uuid")

	var repo models.Repository
	db.DB.Where("name = ? AND user_id = ?", repoName, userID).First(&repo)

	ws, err := resolveWorkspace(userID, repo.WorkspaceID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "workspace not found"})
	}

	bbClient := services.NewBitbucketClient(ws.Username, ws.AppPass, ws.WorkspaceID)
	data, err := bbClient.GetStepLog(repoName, pipelineUUID, stepUUID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	c.Set("Content-Type", "text/plain")
	return c.Send(data)
}
