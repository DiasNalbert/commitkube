package handlers

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
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
	Name               string            `json:"name"`
	EditedTemplates    []EditedTemplate  `json:"edited_templates,omitempty"`
	SkippedTemplateIDs []uint            `json:"skipped_template_ids,omitempty"`
	RepoVariables      []RepoVariable    `json:"repo_variables,omitempty"`
	UploadedFiles      []UploadedFile    `json:"uploaded_files,omitempty"`
	WorkspaceID        uint              `json:"workspace_id,omitempty"`
	ArgoCDInstanceID   uint              `json:"argocd_instance_id,omitempty"`
	ProjectKey         string            `json:"project_key,omitempty"`
	ExtraBranch        string            `json:"extra_branch,omitempty"`
	Provider           string            `json:"provider,omitempty"`
	GoldenPathID       uint              `json:"golden_path_id,omitempty"`
	GoldenPathInputs   map[string]string `json:"golden_path_inputs,omitempty"`
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
	tmplString = strings.ReplaceAll(tmplString, "<your_application>", projectName)
	tmplString = strings.ReplaceAll(tmplString, "{{.ProjectName}}", projectName)
	tmplString = strings.ReplaceAll(tmplString, "{{ .ProjectName }}", projectName)

	for k, v := range inputs {
		tmplString = strings.ReplaceAll(tmplString, "{{.Inputs."+k+"}}", v)
		tmplString = strings.ReplaceAll(tmplString, "{{ .Inputs."+k+" }}", v)
	}

	return tmplString
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

	if req.GoldenPathID > 0 {
		var gp models.GoldenPath
		if err := db.DB.Where("id = ? AND is_active = true", req.GoldenPathID).First(&gp).Error; err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "golden path not found or inactive"})
		}
		if errMsg := ValidateGoldenPathInputs(gp, req.GoldenPathInputs); errMsg != "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": errMsg})
		}
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
		if err := db.DB.Where("id = ?", req.WorkspaceID).First(&ws).Error; err != nil {
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

	var setupWarnings []string

	if err := scmClient.EnablePipelines(req.Name); err != nil {
		msg := fmt.Sprintf("enable pipelines: %v", err)
		fmt.Printf("[BITBUCKET ERROR] %s | repo=%s\n", msg, req.Name)
		setupWarnings = append(setupWarnings, msg)
	} else {
		fmt.Printf("[BITBUCKET OK] pipelines enabled for %s\n", req.Name)
	}

	if bbSSHPubKey != "" {
		if err := scmClient.AddDeployKey(req.Name, bbSSHPubKey, "CommitKube ArgoCD"); err != nil {
			msg := fmt.Sprintf("add deploy key: %v", err)
			fmt.Printf("[BITBUCKET ERROR] %s | repo=%s\n", msg, req.Name)
			setupWarnings = append(setupWarnings, msg)
		} else {
			fmt.Printf("[BITBUCKET OK] deploy key added for %s\n", req.Name)
		}
	}

	collectVars := func(vars []models.GlobalVariable) {
		for _, v := range vars {
			if err := scmClient.AddRepoVariable(req.Name, v.Key, v.Value, v.Secured); err != nil {
				msg := fmt.Sprintf("set var %s: %v", v.Key, err)
				fmt.Printf("[BITBUCKET ERROR] %s | repo=%s\n", msg, req.Name)
				setupWarnings = append(setupWarnings, msg)
			}
		}
	}

	// Global variables (no workspace scope) — apply to every repo
	var userLevelVars []models.GlobalVariable
	db.DB.Where("workspace_id IS NULL AND project_key = ''").Find(&userLevelVars)
	collectVars(userLevelVars)

	// Workspace-level variables: query by Bitbucket workspace SLUG so that variables
	// defined under any CommitKube workspace that shares the same Bitbucket org apply,
	// regardless of which CommitKube workspace the creator selected.
	if bbWorkspace != "" {
		var wsVars []models.GlobalVariable
		db.DB.
			Joins("JOIN bitbucket_workspaces bw ON bw.id = global_variables.workspace_id").
			Where("bw.workspace_id = ? AND global_variables.project_key = ''", bbWorkspace).
			Find(&wsVars)
		collectVars(wsVars)

		pkForVars := req.ProjectKey
		if pkForVars == "" && req.WorkspaceID > 0 {
			var ws models.BitbucketWorkspace
			if db.DB.Where("id = ?", req.WorkspaceID).First(&ws).Error == nil {
				pkForVars = ws.ProjectKey
			}
		}
		if pkForVars != "" {
			var projVars []models.GlobalVariable
			db.DB.
				Joins("JOIN bitbucket_workspaces bw ON bw.id = global_variables.workspace_id").
				Where("bw.workspace_id = ? AND global_variables.project_key = ?", bbWorkspace, pkForVars).
				Find(&projVars)
			collectVars(projVars)
		}
	}

	for _, v := range req.RepoVariables {
		if v.Key == "" {
			continue
		}
		if err := scmClient.AddRepoVariable(req.Name, v.Key, v.Value, v.Secured); err != nil {
			msg := fmt.Sprintf("set repo var %s: %v", v.Key, err)
			fmt.Printf("[BITBUCKET ERROR] %s | repo=%s\n", msg, req.Name)
			setupWarnings = append(setupWarnings, msg)
		}
	}

	files := map[string]string{}
	argoAppPath := "."

	editedMap := map[uint]string{}
	for _, e := range req.EditedTemplates {
		editedMap[e.ID] = e.Content
	}

	skippedSet := map[uint]bool{}
	for _, id := range req.SkippedTemplateIDs {
		skippedSet[id] = true
	}

	applyTemplates := func(tmplList []models.YamlTemplate) {
		for _, tmpl := range tmplList {
			if !tmpl.IsActive || skippedSet[tmpl.ID] {
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

	projectKey := req.ProjectKey
	if projectKey == "" && req.WorkspaceID > 0 {
		var ws models.BitbucketWorkspace
		if db.DB.Where("id = ?", req.WorkspaceID).First(&ws).Error == nil {
			projectKey = ws.ProjectKey
		}
	}

	var matched []models.YamlTemplate
	if result := db.DB.Raw(`
		SELECT yt.* FROM yaml_templates yt
		LEFT JOIN bitbucket_workspaces bw ON yt.workspace_id = bw.id
		WHERE yt.is_active = 1
		  AND yt.deleted_at IS NULL
		  AND (
		    bw.workspace_id = ?
		    OR (yt.workspace_id IS NULL AND (yt.project_key = '' OR yt.project_key = ?))
		  )
		ORDER BY yt.type DESC, yt.id ASC
	`, bbWorkspace, projectKey).Scan(&matched); result.Error != nil {
		fmt.Printf("Warning: failed to load templates for repo %s (workspace=%s, project=%s): %v\n", req.Name, bbWorkspace, projectKey, result.Error)
	}
	fmt.Printf("Templates: matched=%d for workspace=%q project=%q\n", len(matched), bbWorkspace, projectKey)
	for _, t := range matched {
		fmt.Printf("  - template id=%d name=%q path=%q type=%q workspace_id=%v project_key=%q\n", t.ID, t.Name, t.Path, t.Type, t.WorkspaceID, t.ProjectKey)
	}
	applyTemplates(matched)

	for _, f := range req.UploadedFiles {
		if f.Path != "" && f.Content != "" {
			files[f.Path] = f.Content
		}
	}

	if len(files) > 0 {
		if err := scmClient.CommitFiles(req.Name, "Initial commit: CommitKube manifests + source", "main", files); err != nil {
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("Failed to commit: %v", err)})
		}
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
		ProjectKey:   projectKey,
		GoldenPathID: goldenPathID,
	}
	db.DB.Create(&repo)

	db.LogAudit(userID, "create_repository", "repository", req.Name, fmt.Sprintf(`{"provider":"%s","workspace_id":%d}`, provider, req.WorkspaceID), c.IP())

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

	go SendNotifications("repo.created", "Repository Created",
		fmt.Sprintf("Repository %s was created by %s", req.Name, db.GetUserEmail(userID)),
		req.Name, db.GetUserEmail(userID))

	resp := fiber.Map{"message": "Repository created successfully", "repo": repo}
	if len(setupWarnings) > 0 {
		resp["warnings"] = setupWarnings
	}
	return c.JSON(resp)
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

	if len(imported) > 0 {
		db.LogAudit(userID, "import_repository", "repository", strings.Join(imported, ","), fmt.Sprintf(`{"count":%d,"project_key":"%s"}`, len(imported), req.ProjectKey), c.IP())
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
	isAdmin := callerIsAdmin(c)

	var repo models.Repository
	q := db.DB.Where("name = ?", name)
	if !isAdmin {
		q = q.Where("user_id = ?", userID)
	}
	if err := q.First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found"})
	}

	encKey := crypto.MasterKey()
	warnings := []string{}

	if isAdmin {
		// Delete from Bitbucket
		ws, wsErr := resolveWorkspace(userID, repo.WorkspaceID)
		if wsErr == nil {
			appPass := crypto.DecryptField(encKey, ws.AppPass)
			if ws.Username != "" && appPass != "" {
				bbClient := services.NewBitbucketClient(ws.Username, appPass, ws.WorkspaceID)
				if err := bbClient.DeleteRepository(name); err != nil {
					warnings = append(warnings, fmt.Sprintf("Bitbucket: %v", err))
				}
			}
		}

		// Delete from ArgoCD
		var inst models.ArgoCDInstance
		if db.DB.First(&inst).Error == nil {
			argoToken := crypto.DecryptField(encKey, inst.AuthToken)
			argoClient := services.NewArgoCDClient(inst.ServerURL, argoToken)
			appName := repo.ArgoApp
			if appName == "" {
				appName = name
			}
			if err := argoClient.DeleteApplication(appName); err != nil {
				warnings = append(warnings, fmt.Sprintf("ArgoCD: %v", err))
			}
		}
	}

	db.DB.Unscoped().Where("name = ?", name).Delete(&models.Repository{})

	db.LogAudit(userID, "delete_repository", "repository", name, "", c.IP())

	go SendNotifications("repo.deleted", "Repository Deleted",
		fmt.Sprintf("Repository %s was deleted by %s", name, db.GetUserEmail(userID)),
		name, db.GetUserEmail(userID))

	resp := fiber.Map{"message": "repository deleted"}
	if len(warnings) > 0 {
		resp["warnings"] = warnings
	}
	return c.JSON(resp)
}

func ListRepositories(c *fiber.Ctx) error {
	page := c.QueryInt("page", 1)
	limit := c.QueryInt("limit", 12)
	wsSlug := c.Query("workspace_slug", "")
	projectKey := c.Query("project_key", "")
	search := c.Query("search", "")
	if page < 1 {
		page = 1
	}
	if limit < 1 || limit > 100 {
		limit = 12
	}
	offset := (page - 1) * limit

	q := db.DB.Model(&models.Repository{})
	if wsSlug != "" {
		var wsIDs []uint
		db.DB.Model(&models.BitbucketWorkspace{}).
			Where("workspace_id = ?", wsSlug).
			Pluck("id", &wsIDs)
		if len(wsIDs) > 0 {
			q = q.Where("workspace_id IN ?", wsIDs)
		}
		if projectKey != "" {
			q = q.Where("project_key = ?", projectKey)
		}
	}
	if search != "" {
		q = q.Where("name LIKE ?", "%"+search+"%")
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

type FileEntry struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type CommitFileRequest struct {
	Path    string      `json:"path"`
	Content string      `json:"content"`
	Message string      `json:"message"`
	Branch  string      `json:"branch"`
	Files   []FileEntry `json:"files"`
}

func CommitFileEdit(c *fiber.Ctx) error {
	repoName := c.Params("name")

	var req CommitFileRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	filesToCommit := map[string]string{}
	if len(req.Files) > 0 {
		for _, f := range req.Files {
			if f.Path != "" {
				filesToCommit[f.Path] = f.Content
			}
		}
	} else if req.Path != "" {
		filesToCommit[req.Path] = req.Content
	}

	if len(filesToCommit) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "path is required"})
	}

	if req.Message == "" {
		if len(req.Files) > 1 {
			req.Message = fmt.Sprintf("Update %d files", len(filesToCommit))
		} else {
			req.Message = "Update " + req.Path
		}
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
			return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Workspace credentials are not configured"})
		}
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	if err := bbClient.CommitFiles(repoName, req.Message, req.Branch, filesToCommit); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	callerID := uint(c.Locals("user_id").(float64))
	db.LogAudit(callerID, "commit_file", "repository", repoName, fmt.Sprintf(`{"branch":"%s","message":%q,"files":%d}`, req.Branch, req.Message, len(filesToCommit)), c.IP())

	TriggerScanBackground(repoName)

	return c.JSON(fiber.Map{"message": "File committed successfully"})
}

func resolveWorkspace(userID, workspaceID uint) (models.BitbucketWorkspace, error) {
	var ws models.BitbucketWorkspace
	if workspaceID > 0 {
		if err := db.DB.Where("id = ?", workspaceID).First(&ws).Error; err == nil {
			return ws, nil
		}
	}
	err := db.DB.First(&ws).Error
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

func TriggerPipeline(c *fiber.Ctx) error {
	repoName := c.Params("name")
	var req struct {
		Branch string `json:"branch"`
	}
	if err := c.BodyParser(&req); err != nil || req.Branch == "" {
		req.Branch = "main"
	}
	var repo models.Repository
	db.DB.Where("name = ?", repoName).First(&repo)
	bbClient, _, err := resolveUserBBClient(c, repo.WorkspaceID, repo.UserID)
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}
	data, err := bbClient.TriggerPipeline(repoName, req.Branch)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	triggerUID := uint(c.Locals("user_id").(float64))
	db.LogAudit(triggerUID, "trigger_pipeline", "repository", repoName, fmt.Sprintf(`{"branch":"%s"}`, req.Branch), c.IP())
	c.Set("Content-Type", "application/json")
	return c.Send(data)
}

func StopPipeline(c *fiber.Ctx) error {
	repoName := c.Params("name")
	pipelineUUID := c.Params("pipeline_uuid")
	var repo models.Repository
	db.DB.Where("name = ?", repoName).First(&repo)
	bbClient, _, err := resolveUserBBClient(c, repo.WorkspaceID, repo.UserID)
	if err != nil {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": err.Error()})
	}
	if err := bbClient.StopPipeline(repoName, pipelineUUID); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"message": "pipeline stopped"})
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

type PreflightFinding struct {
	File     string `json:"file"`
	Type     string `json:"type"`
	ID       string `json:"id"`
	Severity string `json:"severity"`
	Title    string `json:"title"`
}

type PreflightResult struct {
	FilesChecked int                `json:"files_checked"`
	Critical     int                `json:"critical"`
	High         int                `json:"high"`
	Medium       int                `json:"medium"`
	Low          int                `json:"low"`
	Findings     []PreflightFinding `json:"findings"`
	ScanError    string             `json:"scan_error"`
}

func PreflightRepository(c *fiber.Ctx) error {
	var req CreateRepoRequest
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}

	bbWorkspace := ""
	projectKey := req.ProjectKey

	if req.WorkspaceID > 0 {
		var ws models.BitbucketWorkspace
		if db.DB.Where("id = ?", req.WorkspaceID).First(&ws).Error == nil {
			bbWorkspace = ws.WorkspaceID
			if projectKey == "" {
				projectKey = ws.ProjectKey
			}
		}
	}

	files := map[string]string{}

	editedMap := map[uint]string{}
	for _, e := range req.EditedTemplates {
		editedMap[e.ID] = e.Content
	}

	skippedSet := map[uint]bool{}
	for _, id := range req.SkippedTemplateIDs {
		skippedSet[id] = true
	}

	applyTemplates := func(tmplList []models.YamlTemplate) {
		for _, tmpl := range tmplList {
			if !tmpl.IsActive || skippedSet[tmpl.ID] {
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
		}
	}

	var matched []models.YamlTemplate
	db.DB.Raw(`
		SELECT yt.* FROM yaml_templates yt
		LEFT JOIN bitbucket_workspaces bw ON yt.workspace_id = bw.id
		WHERE yt.is_active = 1
		  AND yt.deleted_at IS NULL
		  AND (
		    bw.workspace_id = ?
		    OR (yt.workspace_id IS NULL AND (yt.project_key = '' OR yt.project_key = ?))
		  )
		ORDER BY yt.type DESC, yt.id ASC
	`, bbWorkspace, projectKey).Scan(&matched)
	applyTemplates(matched)

	for _, f := range req.UploadedFiles {
		if f.Path != "" && f.Content != "" {
			files[f.Path] = f.Content
		}
	}

	result := PreflightResult{
		FilesChecked: len(files),
		Findings:     []PreflightFinding{},
	}

	if len(files) == 0 {
		return c.JSON(result)
	}

	scanID := uuid.New().String()
	scanDir := filepath.Join(os.TempDir(), "preflight-"+scanID)
	defer os.RemoveAll(scanDir)

	for path, content := range files {
		fullPath := filepath.Join(scanDir, path)
		if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
			continue
		}
		os.WriteFile(fullPath, []byte(content), 0644)
	}

	reportFile := filepath.Join(os.TempDir(), "preflight-report-"+scanID+".json")
	defer os.Remove(reportFile)

	trivyCmd := exec.Command("trivy", "fs",
		"--format", "json",
		"--output", reportFile,
		"--exit-code", "0",
		"--scanners", "misconfig,secret",
		"--no-progress",
		scanDir,
	)
	trivyOut, trivyErr := trivyCmd.CombinedOutput()

	if trivyErr != nil {
		result.ScanError = fmt.Sprintf("scan failed: %s", strings.TrimSpace(string(trivyOut)))
		return c.JSON(result)
	}

	reportBytes, err := os.ReadFile(reportFile)
	if err != nil {
		result.ScanError = "failed to read scan report"
		return c.JSON(result)
	}

	var report TrivyReport
	if err := json.Unmarshal(reportBytes, &report); err != nil {
		result.ScanError = "failed to parse scan report"
		return c.JSON(result)
	}

	counts := map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
	for _, target := range report.Results {
		for _, m := range target.Misconfigurations {
			if m.Status == "PASS" {
				continue
			}
			counts[m.Severity]++
			result.Findings = append(result.Findings, PreflightFinding{
				File:     target.Target,
				Type:     "misconfiguration",
				ID:       m.ID,
				Severity: m.Severity,
				Title:    m.Title,
			})
		}
		for _, s := range target.Secrets {
			counts[s.Severity]++
			result.Findings = append(result.Findings, PreflightFinding{
				File:     target.Target,
				Type:     "secret",
				ID:       s.RuleID,
				Severity: s.Severity,
				Title:    s.Title,
			})
		}
	}

	result.Critical = counts["CRITICAL"]
	result.High = counts["HIGH"]
	result.Medium = counts["MEDIUM"]
	result.Low = counts["LOW"]

	return c.JSON(result)
}
