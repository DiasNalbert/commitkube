package handlers

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func ListGoldenPaths(c *fiber.Ctx) error {
	var paths []models.GoldenPath
	db.DB.Find(&paths)
	return c.JSON(paths)
}

func GetGoldenPath(c *fiber.Ctx) error {
	id := c.Params("id")
	var gp models.GoldenPath
	if err := db.DB.Where("id = ?", id).First(&gp).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "golden path not found"})
	}
	return c.JSON(gp)
}

func CreateGoldenPath(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	var req struct {
		Name              string `json:"name"`
		Description       string `json:"description"`
		FieldsSchema      string `json:"fields_schema"`
		ResourceLimits    string `json:"resource_limits"`
		AllowedNamespaces string `json:"allowed_namespaces"`
		RequiredLabels    string `json:"required_labels"`
		ApprovalWorkflow  string `json:"approval_workflow"`
		IsActive          *bool  `json:"is_active"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name is required"})
	}
	if req.ApprovalWorkflow == "" {
		req.ApprovalWorkflow = "none"
	}
	isActive := true
	if req.IsActive != nil {
		isActive = *req.IsActive
	}
	gp := models.GoldenPath{
		Name:              req.Name,
		Description:       req.Description,
		FieldsSchema:      req.FieldsSchema,
		ResourceLimits:    req.ResourceLimits,
		AllowedNamespaces: req.AllowedNamespaces,
		RequiredLabels:    req.RequiredLabels,
		ApprovalWorkflow:  req.ApprovalWorkflow,
		IsActive:          isActive,
	}
	if msg := checkGoldenPathConfig(&gp); msg != "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
	}
	if err := db.DB.Create(&gp).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	return c.Status(fiber.StatusCreated).JSON(gp)
}

func UpdateGoldenPath(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	id := c.Params("id")
	var gp models.GoldenPath
	if err := db.DB.Where("id = ?", id).First(&gp).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "golden path not found"})
	}
	// Pointers: an empty string is a value someone may want -- clearing the
	// allowed namespaces -- and must not read as "unchanged".
	var req struct {
		Name              *string `json:"name"`
		Description       *string `json:"description"`
		FieldsSchema      *string `json:"fields_schema"`
		ResourceLimits    *string `json:"resource_limits"`
		AllowedNamespaces *string `json:"allowed_namespaces"`
		RequiredLabels    *string `json:"required_labels"`
		ApprovalWorkflow  *string `json:"approval_workflow"`
		IsActive          *bool   `json:"is_active"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	set := func(dst *string, v *string) {
		if v != nil {
			*dst = strings.TrimSpace(*v)
		}
	}
	set(&gp.Name, req.Name)
	set(&gp.Description, req.Description)
	set(&gp.FieldsSchema, req.FieldsSchema)
	set(&gp.ResourceLimits, req.ResourceLimits)
	set(&gp.AllowedNamespaces, req.AllowedNamespaces)
	set(&gp.RequiredLabels, req.RequiredLabels)
	set(&gp.ApprovalWorkflow, req.ApprovalWorkflow)
	if req.IsActive != nil {
		gp.IsActive = *req.IsActive
	}
	if gp.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name is required"})
	}
	if msg := checkGoldenPathConfig(&gp); msg != "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
	}
	db.DB.Save(&gp)
	return c.JSON(gp)
}

// checkGoldenPathConfig refuses settings the path could never apply.
func checkGoldenPathConfig(gp *models.GoldenPath) string {
	if gp.ApprovalWorkflow != "none" && gp.ApprovalWorkflow != "manual" {
		return "approval_workflow must be none or manual"
	}
	if _, err := parseLimits(gp.ResourceLimits); err != nil {
		return err.Error()
	}
	for _, p := range splitPatterns(gp.AllowedNamespaces) {
		if _, err := path.Match(p, "x"); err != nil {
			return fmt.Sprintf("namespace pattern %q is not valid", p)
		}
	}
	for _, f := range goldenFields(gp) {
		if f.Key == "namespace" {
			return "a field cannot be called namespace: the namespace is asked separately, from the allowed list"
		}
		if f.Validation != "" {
			if _, err := regexp.Compile(f.Validation); err != nil {
				return fmt.Sprintf("the validation of %s is not a valid regex", f.Key)
			}
		}
	}
	return ""
}

func DeleteGoldenPath(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	id := c.Params("id")
	// Its templates go with it: left behind, they would belong to nothing.
	db.DB.Where("golden_path_id = ?", id).Delete(&models.YamlTemplate{})
	db.DB.Where("id = ?", id).Delete(&models.GoldenPath{})
	return c.JSON(fiber.Map{"ok": true})
}

// PreviewGoldenPath renders a path's templates for a sample repository and
// answers, and runs its rules over the result -- what someone would get,
// before anyone creates anything.
func PreviewGoldenPath(c *fiber.Ctx) error {
	var gp models.GoldenPath
	if err := db.DB.First(&gp, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "golden path not found"})
	}
	var req struct {
		Name   string            `json:"name"`
		Inputs map[string]string `json:"inputs"`
	}
	_ = c.BodyParser(&req)
	if req.Name == "" {
		req.Name = "my-service"
	}
	var tmpls []models.YamlTemplate
	db.DB.Where("golden_path_id = ? AND is_active = ?", gp.ID, true).Order("type desc, id asc").Find(&tmpls)
	plan, err := planGoldenPath(&gp, req.Name, req.Inputs, nil, tmpls)
	if err != nil {
		return c.JSON(fiber.Map{"error": err.Error(), "files": fiber.Map{}, "violations": []string{}})
	}
	violations := checkGoldenPolicy(&gp, plan.Namespace, plan.Files)
	if violations == nil {
		violations = []string{}
	}
	return c.JSON(fiber.Map{"files": plan.Files, "namespace": plan.Namespace, "violations": violations})
}

// ListPendingRepositories is the approval queue: repositories requested on
// a golden path that needs a person to say yes.
func ListPendingRepositories(c *fiber.Ctx) error {
	var repos []models.Repository
	db.DB.Where("status = ?", "pending_approval").Order("created_at asc").Find(&repos)
	type row struct {
		Name        string            `json:"name"`
		RequestedAt string            `json:"requested_at"`
		RequestedBy string            `json:"requested_by"`
		GoldenPath  string            `json:"golden_path"`
		Inputs      map[string]string `json:"inputs"`
		ProjectKey  string            `json:"project_key"`
	}
	out := make([]row, 0, len(repos))
	for _, r := range repos {
		var req CreateRepoRequest
		_ = json.Unmarshal([]byte(r.DeferredPayload), &req)
		var u models.User
		db.DB.Select("email").First(&u, r.UserID)
		var gp models.GoldenPath
		if r.GoldenPathID != nil {
			db.DB.Select("name").First(&gp, *r.GoldenPathID)
		}
		out = append(out, row{
			Name: r.Name, RequestedAt: r.CreatedAt.Format("2006-01-02T15:04:05Z07:00"), RequestedBy: u.Email,
			GoldenPath: gp.Name, Inputs: req.GoldenPathInputs, ProjectKey: req.ProjectKey,
		})
	}
	return c.JSON(out)
}

// RejectRepository turns a request down. Nothing was created in the SCM, so
// the pending row is all there is to remove.
func RejectRepository(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	name := c.Params("name")
	var repo models.Repository
	if err := db.DB.Where("name = ? AND status = 'pending_approval'", name).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found or not pending approval"})
	}
	var body struct {
		Reason string `json:"reason"`
	}
	_ = c.BodyParser(&body)
	db.DB.Unscoped().Delete(&repo)
	db.LogAudit(currentUserID(c), "reject_repository", "repository", name, fmt.Sprintf(`{"reason":%q}`, body.Reason), c.IP())
	return c.JSON(fiber.Map{"message": "request rejected"})
}

func ApproveRepository(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "admin only"})
	}
	name := c.Params("name")
	var repo models.Repository
	if err := db.DB.Where("name = ? AND status = 'pending_approval'", name).First(&repo).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository not found or not pending approval"})
	}
	if repo.DeferredPayload == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "no deferred payload found"})
	}

	var req CreateRepoRequest
	if err := json.Unmarshal([]byte(repo.DeferredPayload), &req); err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "failed to deserialise deferred payload"})
	}

	// The path may have changed since the request: check again, now, before
	// anything is created.
	ws, pk := repoScope(&req)
	if _, err := assembleRepoFiles(&req, ws, pk); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "the request no longer passes its golden path: " + err.Error()})
	}

	// provisionRepository replaces the pending row with the created one, so
	// there is nothing left to flip from pending to created afterwards.
	res, err := provisionRepository(repo.UserID, &req, c.IP())
	if err == nil {
		db.LogAudit(currentUserID(c), "approve_repository", "repository", name, "", c.IP())
	}
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": fmt.Sprintf("provisioning failed: %v", err)})
	}

	return c.JSON(res.response("Repository approved and provisioned"))
}

// ValidateGoldenPathInputs is kept for callers that only need a yes or no.
func ValidateGoldenPathInputs(gp models.GoldenPath, inputs map[string]string) string {
	if _, err := resolveGoldenInputs(&gp, inputs); err != nil {
		return err.Error()
	}
	return ""
}
