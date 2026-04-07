package handlers

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"text/template"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

func resolveUserBBClient(c *fiber.Ctx, repoWorkspaceID uint, repoUserID uint) (*services.BitbucketClient, string, error) {
	currentUserID := uint(c.Locals("user_id").(float64))
	ws, err := resolveWorkspace(currentUserID, repoWorkspaceID)
	if err != nil {
		return nil, "", fmt.Errorf("workspace not found")
	}

	encKey := crypto.MasterKey()
	appPass := crypto.DecryptField(encKey, ws.AppPass)
	if ws.Username == "" || appPass == "" {
		return nil, "", fmt.Errorf("credentials_not_configured")
	}

	client := services.NewBitbucketClient(ws.Username, appPass, ws.WorkspaceID)
	return client, ws.WorkspaceID, nil
}

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
	// Provider selects the SCM: "bitbucket" (default), "github", "gitlab".
	Provider         string           `json:"provider,omitempty"`
	// GoldenPathID links to a GoldenPath for guardrail enforcement.
	GoldenPathID     uint             `json:"golden_path_id,omitempty"`
	// GoldenPathInputs holds values for the GoldenPath's custom fields.
	GoldenPathInputs map[string]string `json:"golden_path_inputs,omitempty"`
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
	return renderTplWithInputs(tmplString, projectName, nil)
}

func renderTplWithInputs(tmplString, projectName string, inputs map[string]string) string {
	// Support <your_application> as a friendly placeholder for the repo name
	tmplString = strings.ReplaceAll(tmplString, "<your_application>", projectName)

	t, err := template.New("t").Parse(tmplString)
	if err != nil {
		return tmplString
	}
	data := map[string]interface{}{
		"ProjectName": projectName,
		"Inputs":      inputs,
	}
	var buf bytes.Buffer
	_ = t.Execute(&buf, data)
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

	// Golden Path validation
	if req.GoldenPathID > 0 {
		var gp models.GoldenPath
		if err := db.DB.Where("id = ? AND is_active = true", req.GoldenPathID).First(&gp).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "golden path not found or inactive"})
		}
		if errMsg := ValidateGoldenPathInputs(gp, req.GoldenPathInputs); errMsg != "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": errMsg})
		}
		// Manual approval: persist request and return 202
		if gp.ApprovalWorkflow == "manual" {
			payload, _ := json.Marshal(req)
			db.DB.Unscoped().Where("name = ? AND user_id = ?", req.Name, userID).Delete(&models.Repository{})
			goldenPathIDVal := req.GoldenPathID
			pendingRepo := models.Repository{
				Name:            req.Name,
				UserID:          userID,
				WorkspaceID:     req.WorkspaceID,
				Status:          "pending_approval",
				Provider:        req.Provider,
				GoldenPathID:    &goldenPathIDVal,
				DeferredPayload: string(payload),
			}
			db.DB.Create(&pendingRepo)
			return c.Status(fiber.StatusAccepted).JSON(fiber.Map{
				"message": "Repository is pending admin approval",
				"repo":    pendingRepo,
			})
		}
	}

	encKey := crypto.MasterKey()
	if req.WorkspaceID > 0 {
		var ws models.BitbucketWorkspace
		wsQuery := db.DB.Where("id = ?", req.WorkspaceID)
		if !callerIsAdmin(c) {
			wsQuery = wsQuery.Where("user_id = ?", userID)
		}
		if err := wsQuery.First(&ws).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "workspace not found"})
		}
		bbUsername = ws.Username
		bbAppPass = crypto.DecryptField(encKey, ws.AppPass)
		bbWorkspace = ws.WorkspaceID
		bbProjectKey = ws.ProjectKey
		bbSSHPubKey = ws.SSHPubKey
		bbSSHPrivKey = crypto.DecryptField(encKey, ws.SSHPrivKey)
		if req.ProjectKey != "" {
			bbProjectKey = req.ProjectKey
		}
	} else {
		var keys models.UserKeys
		if err := db.DB.Where("user_id = ?", userID).First(&keys).Error; err != nil {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Please configure Bitbucket & ArgoCD settings first"})
		}
		bbUsername = keys.BitbucketUsername
		bbAppPass = crypto.DecryptField(encKey, keys.BitbucketAppPass)
		bbWorkspace = keys.BitbucketWorkspace
		bbProjectKey = keys.BitbucketProjectKey
		bbSSHPubKey = keys.BitbucketSSHPubKey
		bbSSHPrivKey = crypto.DecryptField(encKey, keys.BitbucketSSHKey)
	}

	var (
		argoURL       string
		argoToken     string
		argoNamespace string
		argoProject   string
	)

	if req.ArgoCDInstanceID > 0 {
		var inst models.ArgoCDInstance
		if err := db.DB.Where("id = ?", req.ArgoCDInstanceID).First(&inst).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "argocd instance not found"})
		}
		argoURL = inst.ServerURL
		argoToken = crypto.DecryptField(encKey, inst.AuthToken)
		argoNamespace = inst.DefaultNamespace
		argoProject = inst.DefaultProject
	} else {
		var keys models.UserKeys
		if db.DB.Where("user_id = ?", userID).First(&keys).Error == nil {
			argoURL = keys.ArgoCDServerURL
			argoToken = crypto.DecryptField(encKey, keys.ArgoCDAuthToken)
		}
	}
	if argoNamespace == "" {
		argoNamespace = "default"
	}
	if argoProject == "" {
		argoProject = "default"
	}

	provider := req.Provider
	if provider == "" {
		provider = "bitbucket"
	}
	scmClient := services.NewSCMClient(provider, bbUsername, bbAppPass, bbWorkspace)
	if err := scmClient.CreateRepository(req.Name, bbProjectKey); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Bitbucket creation failed: %v", err)})
	}

	if err := scmClient.EnablePipelines(req.Name); err != nil {
		fmt.Printf("Warning: failed to enable pipelines for %s: %v\n", req.Name, err)
	}

	if bbSSHPubKey != "" {
		if err := scmClient.AddDeployKey(req.Name, bbSSHPubKey, "CommitKube ArgoCD"); err != nil {
			fmt.Printf("Warning: failed to add deploy key to %s: %v\n", req.Name, err)
		}
	}

	collectVars := func(vars []models.GlobalVariable) {
		for _, v := range vars {
			if err := scmClient.AddRepoVariable(req.Name, v.Key, v.Value, v.Secured); err != nil {
				fmt.Printf("Warning: failed to set var %s on %s: %v\n", v.Key, req.Name, err)
			}
		}
	}

	var userLevelVars []models.GlobalVariable
	db.DB.Where("workspace_id IS NULL AND project_key = ''").Find(&userLevelVars)
	collectVars(userLevelVars)

	if req.WorkspaceID > 0 {
		var wsVars []models.GlobalVariable
		db.DB.Where("workspace_id = ? AND project_key = ''", req.WorkspaceID).Find(&wsVars)
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
			db.DB.Where("workspace_id = ? AND project_key = ?", req.WorkspaceID, pkForVars).Find(&projVars)
			collectVars(projVars)
		}
	}

	for _, v := range req.RepoVariables {
		if v.Key == "" {
			continue
		}
		if err := scmClient.AddRepoVariable(req.Name, v.Key, v.Value, v.Secured); err != nil {
			fmt.Printf("Warning: failed to set repo var %s on %s: %v\n", v.Key, req.Name, err)
		}
	}

	files := map[string]string{}
	argoAppPath := "."

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
			rendered := renderTplWithInputs(content, req.Name, req.GoldenPathInputs)
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
	db.DB.Where("workspace_id IS NULL AND is_active = true").Find(&globalTmpls)
	applyTemplates(globalTmpls)

	// Resolve all workspace DB IDs sharing the same Bitbucket slug so that
	// templates registered under any incarnation of the same workspace apply.
	var wsIDsForSlug []uint
	if req.WorkspaceID > 0 && bbWorkspace != "" {
		db.DB.Unscoped().Model(&models.BitbucketWorkspace{}).
			Where("workspace_id = ?", bbWorkspace).
			Pluck("id", &wsIDsForSlug)
	}

	if len(wsIDsForSlug) > 0 {
		var wsTmpls []models.YamlTemplate
		db.DB.Where("workspace_id IN ? AND project_key = '' AND is_active = true", wsIDsForSlug).Find(&wsTmpls)
		applyTemplates(wsTmpls)
	}

	projectKey := req.ProjectKey
	if projectKey == "" && req.WorkspaceID > 0 {
		var ws models.BitbucketWorkspace
		if db.DB.Where("id = ? AND user_id = ?", req.WorkspaceID, userID).First(&ws).Error == nil {
			projectKey = ws.ProjectKey
		}
	}
	if len(wsIDsForSlug) > 0 && projectKey != "" {
		var projTmpls []models.YamlTemplate
		db.DB.Where("workspace_id IN ? AND project_key = ? AND is_active = true", wsIDsForSlug, projectKey).Find(&projTmpls)
		applyTemplates(projTmpls)
	}

	for _, f := range req.UploadedFiles {
		if f.Path != "" && f.Content != "" {
			files[f.Path] = f.Content
		}
	}

	if err := scmClient.CommitFiles(req.Name, "Initial commit: CommitKube manifests + source", "main", files); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Failed to commit: %v", err)})
	}

	if req.ExtraBranch != "" && req.ExtraBranch != "main" {
		if err := scmClient.CreateBranch(req.Name, req.ExtraBranch, "main"); err != nil {
			fmt.Printf("Warning: failed to create branch %s on %s: %v\n", req.ExtraBranch, req.Name, err)
		}
	}

	repoURL := scmClient.CloneURL(bbWorkspace, req.Name)
	if strings.Contains(bbSSHPrivKey, `\n`) {
		bbSSHPrivKey = strings.ReplaceAll(bbSSHPrivKey, `\n`, "\n")
	}
	if argoURL != "" && argoToken != "" {
		argoClient := services.NewArgoCDClient(argoURL, argoToken)
		if err := argoClient.AddRepository(repoURL, bbSSHPrivKey); err != nil {
			fmt.Printf("Warning: ArgoCD repo registration failed: %v\n", err)
		}
		argoTargetRevision := req.ExtraBranch
		if err := argoClient.CreateApplication(req.Name, repoURL, argoProject, argoNamespace, argoAppPath, argoTargetRevision); err != nil {
			fmt.Printf("Warning: ArgoCD app creation failed: %v\n", err)
		}
	}

	goldenPathID := (*uint)(nil)
	if req.GoldenPathID > 0 {
		goldenPathID = &req.GoldenPathID
	}
	db.DB.Unscoped().Where("name = ? AND user_id = ?", req.Name, userID).Delete(&models.Repository{})
	repo := models.Repository{
		Name:         req.Name,
		UserID:       userID,
		WorkspaceID:  req.WorkspaceID,
		Status:       "created",
		ArgoApp:      req.Name,
		Provider:     provider,
		ProjectKey:   req.ProjectKey,
		GoldenPathID: goldenPathID,
	}
	db.DB.Create(&repo)

	TriggerScanBackground(req.Name)

	go DispatchWebhook(services.WebhookEvent{
		Event: "repo.created",
		Payload: map[string]interface{}{
			"repo_name":    repo.Name,
			"workspace_id": repo.WorkspaceID,
			"provider":     repo.Provider,
			"created_at":   repo.CreatedAt,
		},
	})

	return c.JSON(fiber.Map{"message": "Repository created successfully", "repo": repo})
}

type ImportRepoRequest struct {
	Name             string `json:"name"`
	WorkspaceID      uint   `json:"workspace_id,omitempty"`
	ArgoCDInstanceID uint   `json:"argocd_instance_id,omitempty"`
	ArgoApp          string `json:"argo_app,omitempty"`
	ProjectKey       string `json:"project_key,omitempty"`
}

func ImportRepository(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can import repositories"})
	}
	userID := uint(c.Locals("user_id").(float64))

	var req ImportRepoRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name is required"})
	}

	var existing models.Repository
	if db.DB.Where("name = ?", req.Name).First(&existing).Error == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "repository already exists in CommitKube"})
	}

	argoApp := req.ArgoApp
	if argoApp == "" {
		argoApp = req.Name
	}

	repo := models.Repository{
		Name:        req.Name,
		UserID:      userID,
		WorkspaceID: req.WorkspaceID,
		Status:      "imported",
		ArgoApp:     argoApp,
		ProjectKey:  req.ProjectKey,
	}
	if err := db.DB.Create(&repo).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to import repository"})
	}

	TriggerScanBackground(req.Name)

	return c.JSON(fiber.Map{"message": "Repository imported successfully", "repo": repo})
}

func ImportProject(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can import repositories"})
	}
	userID := uint(c.Locals("user_id").(float64))

	var req struct {
		WorkspaceID uint   `json:"workspace_id"`
		ProjectKey  string `json:"project_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.WorkspaceID == 0 || req.ProjectKey == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "workspace_id and project_key are required"})
	}

	ws, err := resolveWorkspace(userID, req.WorkspaceID)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "workspace not found"})
	}

	encKey := crypto.MasterKey()
	appPass := crypto.DecryptField(encKey, ws.AppPass)
	if ws.Username == "" || appPass == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "workspace credentials not configured"})
	}

	bbClient := services.NewBitbucketClient(ws.Username, appPass, ws.WorkspaceID)
	repoNames, err := bbClient.ListRepositoriesByProject(req.ProjectKey)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": fmt.Sprintf("failed to list Bitbucket repositories: %v", err)})
	}

	imported := []string{}
	skipped := []string{}

	for _, name := range repoNames {
		var existing models.Repository
		if db.DB.Where("name = ?", name).First(&existing).Error == nil {
			skipped = append(skipped, name)
			continue
		}
		repo := models.Repository{
			Name:        name,
			UserID:      userID,
			WorkspaceID: req.WorkspaceID,
			Status:      "imported",
			ArgoApp:     name,
			ProjectKey:  req.ProjectKey,
		}
		if err := db.DB.Create(&repo).Error; err == nil {
			imported = append(imported, name)
			TriggerScanBackground(name)
		}
	}

	return c.JSON(fiber.Map{
		"imported": imported,
		"skipped":  skipped,
		"total":    len(repoNames),
	})
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
	page := c.QueryInt("page", 1)
	limit := c.QueryInt("limit", 12)
	wsID := c.QueryInt("workspace_id", 0)
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 12
	}
	offset := (page - 1) * limit

	q := db.DB.Model(&models.Repository{})
	if wsID > 0 {
		q = q.Where("workspace_id = ?", wsID)
	}
	var total int64
	q.Count(&total)

	var repos []models.Repository
	q.Order("created_at desc").Limit(limit).Offset(offset).Find(&repos)

	pages := (total + int64(limit) - 1) / int64(limit)
	return c.JSON(fiber.Map{
		"data":  repos,
		"total": total,
		"page":  page,
		"pages": pages,
		"limit": limit,
	})
}

type CommitFileRequest struct {
	Path    string `json:"path"`
	Content string `json:"content"`
	Message string `json:"message"`
	Branch  string `json:"branch"`
}

func CommitFileEdit(c *fiber.Ctx) error {
	repoName := c.Params("name")

	var req CommitFileRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Path == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "path is required"})
	}
	if req.Message == "" {
		req.Message = "Update " + req.Path
	}
	if req.Branch == "" {
		req.Branch = "main"
	}

	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	bbClient, _, err := resolveUserBBClient(c, repo.WorkspaceID, repo.UserID)
	if err != nil {
		if err.Error() == "credentials_not_configured" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Configure your Bitbucket credentials in Profile to make commits"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if err := bbClient.CommitFiles(repoName, req.Message, req.Branch, map[string]string{req.Path: req.Content}); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	TriggerScanBackground(repoName)

	return c.JSON(fiber.Map{"message": "File committed successfully"})
}

func resolveWorkspace(userID, workspaceID uint) (models.BitbucketWorkspace, error) {
	var ws models.BitbucketWorkspace
	if workspaceID > 0 {
		if err := db.DB.Where("id = ? AND user_id = ?", workspaceID, userID).First(&ws).Error; err == nil {
			return ws, nil
		}
	}
	err := db.DB.Where("user_id = ?", userID).First(&ws).Error
	return ws, err
}

func GetRepositorySrc(c *fiber.Ctx) error {
	repoName := c.Params("name")
	filePath := c.Query("path", "")
	branch := c.Query("branch", "")

	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	currentUserID := uint(c.Locals("user_id").(float64))
	ws, wsErr := resolveWorkspace(currentUserID, repo.WorkspaceID)
	if wsErr != nil {
		fmt.Printf("Src: workspace not found for repo=%s userID=%d workspaceID=%d: %v\n", repoName, repo.UserID, repo.WorkspaceID, wsErr)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace not found — check Settings"})
	}
	wsAppPass := crypto.DecryptField(crypto.MasterKey(), ws.AppPass)
	if ws.Username == "" || wsAppPass == "" {
		fmt.Printf("Src: workspace %d (%s) has no credentials\n", ws.ID, ws.Alias)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Configure your Bitbucket credentials in Settings > Workspaces"})
	}
	bbClient := services.NewBitbucketClient(ws.Username, wsAppPass, ws.WorkspaceID)

	if filePath == "" && branch == "" {
		if hash, err := bbClient.GetBranchHash(repoName, "main"); err == nil && hash != "" && hash != repo.LastCommitHash {
			db.DB.Model(&repo).Update("last_commit_hash", hash)
			TriggerScanBackground(repoName)
		}
	}

	data, status, contentType, err := bbClient.ListSrc(repoName, filePath, branch)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if status == 401 || status == 403 {
		fmt.Printf("Bitbucket src %d for %s (user=%s workspace=%s): %s\n", status, repoName, ws.Username, ws.WorkspaceID, string(data))
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "Bitbucket access denied — check workspace credentials"})
	}
	c.Status(status)
	c.Set("Content-Type", contentType)
	return c.Send(data)
}

func GetRepositoryCommits(c *fiber.Ctx) error {
	repoName := c.Params("name")
	branch := c.Query("branch", "main")
	limit := c.QueryInt("limit", 10)

	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	currentUserID := uint(c.Locals("user_id").(float64))
	ws, wsErr := resolveWorkspace(currentUserID, repo.WorkspaceID)
	if wsErr != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace not found"})
	}
	appPass := crypto.DecryptField(crypto.MasterKey(), ws.AppPass)
	if ws.Username == "" || appPass == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace credentials not configured"})
	}

	bbClient := services.NewBitbucketClient(ws.Username, appPass, ws.WorkspaceID)
	commits, err := bbClient.GetRecentCommits(repoName, branch, limit)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"commits": commits})
}

func GetRepositoryBranches(c *fiber.Ctx) error {
	repoName := c.Params("name")

	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	currentUserID := uint(c.Locals("user_id").(float64))
	ws, wsErr := resolveWorkspace(currentUserID, repo.WorkspaceID)
	branchAppPass := crypto.DecryptField(crypto.MasterKey(), ws.AppPass)
	if wsErr != nil || ws.Username == "" || branchAppPass == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace credentials not configured"})
	}

	bbClient := services.NewBitbucketClient(ws.Username, branchAppPass, ws.WorkspaceID)
	data, err := bbClient.ListBranches(repoName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(data)
}

func GetRepositoryPipelines(c *fiber.Ctx) error {
	repoName := c.Params("name")

	var repo models.Repository
	if err := db.DB.Where("name = ?", repoName).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	currentUserID := uint(c.Locals("user_id").(float64))
	ws, wsErr := resolveWorkspace(currentUserID, repo.WorkspaceID)
	if wsErr != nil {
		fmt.Printf("Pipelines: workspace not found for repo=%s userID=%d workspaceID=%d: %v\n", repoName, repo.UserID, repo.WorkspaceID, wsErr)
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "workspace not found — check Settings"})
	}
	pipAppPass := crypto.DecryptField(crypto.MasterKey(), ws.AppPass)
	if ws.Username == "" || pipAppPass == "" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Configure your Bitbucket credentials in Settings > Workspaces"})
	}
	fmt.Printf("Pipelines: using workspace id=%d alias=%s username=%s workspace_slug=%s for repo=%s\n", ws.ID, ws.Alias, ws.Username, ws.WorkspaceID, repoName)
	bbClient := services.NewBitbucketClient(ws.Username, pipAppPass, ws.WorkspaceID)
	data, status, err := bbClient.ListPipelines(repoName)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if status == 401 || status == 403 {
		fmt.Printf("Bitbucket pipelines %d for %s (user=%s workspace=%s): %s\n", status, repoName, ws.Username, ws.WorkspaceID, string(data))
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "Bitbucket access denied — check workspace credentials"})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(data)
}

func GetPipelineSteps(c *fiber.Ctx) error {
	repoName := c.Params("name")
	pipelineUUID := c.Params("pipeline_uuid")

	var repo models.Repository
	db.DB.Where("name = ?", repoName).First(&repo)

	bbClient, _, err := resolveUserBBClient(c, repo.WorkspaceID, repo.UserID)
	if err != nil {
		if err.Error() == "credentials_not_configured" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Configure your Bitbucket credentials in Profile to access repositories"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	data, err := bbClient.GetPipelineSteps(repoName, pipelineUUID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	c.Set("Content-Type", "application/json")
	return c.Send(data)
}

func GetStepLog(c *fiber.Ctx) error {
	repoName := c.Params("name")
	pipelineUUID := c.Params("pipeline_uuid")
	stepUUID := c.Params("step_uuid")

	var repo models.Repository
	db.DB.Where("name = ?", repoName).First(&repo)

	bbClient, _, err := resolveUserBBClient(c, repo.WorkspaceID, repo.UserID)
	if err != nil {
		if err.Error() == "credentials_not_configured" {
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Configure your Bitbucket credentials in Profile to access repositories"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	data, err := bbClient.GetStepLog(repoName, pipelineUUID, stepUUID)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	c.Set("Content-Type", "text/plain")
	return c.Send(data)
}
