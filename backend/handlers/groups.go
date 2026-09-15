package handlers

import (
	"strconv"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

type groupMemberItem struct {
	UserID uint   `json:"user_id"`
	Email  string `json:"email"`
}

type groupWorkspaceItem struct {
	WorkspaceID      uint   `json:"workspace_id"`
	Alias            string `json:"alias"`
	WorkspaceIDSlug  string `json:"workspace_id_slug"`
}

type groupResponse struct {
	ID          uint                 `json:"id"`
	Name        string               `json:"name"`
	Description string               `json:"description"`
	Members     []groupMemberItem    `json:"members"`
	Workspaces  []groupWorkspaceItem `json:"workspaces"`
}

func buildGroupResponse(g models.UserGroup) groupResponse {
	// fetch members with emails
	var members []models.UserGroupMember
	db.DB.Where("group_id = ?", g.ID).Find(&members)
	memberItems := make([]groupMemberItem, 0, len(members))
	for _, m := range members {
		var u models.User
		if err := db.DB.First(&u, m.UserID).Error; err == nil {
			memberItems = append(memberItems, groupMemberItem{
				UserID: m.UserID,
				Email:  u.Email,
			})
		}
	}

	// fetch workspaces
	var gwList []models.UserGroupWorkspace
	db.DB.Where("group_id = ?", g.ID).Find(&gwList)
	wsItems := make([]groupWorkspaceItem, 0, len(gwList))
	for _, gw := range gwList {
		var ws models.BitbucketWorkspace
		if err := db.DB.First(&ws, gw.WorkspaceID).Error; err == nil {
			wsItems = append(wsItems, groupWorkspaceItem{
				WorkspaceID:     ws.ID,
				Alias:           ws.Alias,
				WorkspaceIDSlug: ws.WorkspaceID,
			})
		}
	}

	return groupResponse{
		ID:          g.ID,
		Name:        g.Name,
		Description: g.Description,
		Members:     memberItems,
		Workspaces:  wsItems,
	}
}

func ListGroups(c *fiber.Ctx) error {
	var groups []models.UserGroup
	db.DB.Find(&groups)
	out := make([]groupResponse, 0, len(groups))
	for _, g := range groups {
		out = append(out, buildGroupResponse(g))
	}
	return c.JSON(out)
}

func CreateGroup(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can create groups"})
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name is required"})
	}

	g := models.UserGroup{
		Name:        req.Name,
		Description: req.Description,
	}
	if result := db.DB.Create(&g); result.Error != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "group name already exists"})
	}
	return c.Status(fiber.StatusCreated).JSON(buildGroupResponse(g))
}

func UpdateGroup(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can update groups"})
	}

	var g models.UserGroup
	if err := db.DB.First(&g, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "group not found"})
	}

	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid request"})
	}
	if req.Name != "" {
		g.Name = req.Name
	}
	g.Description = req.Description
	db.DB.Save(&g)
	return c.JSON(buildGroupResponse(g))
}

func DeleteGroup(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can delete groups"})
	}

	var g models.UserGroup
	if err := db.DB.First(&g, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "group not found"})
	}

	gID := g.ID
	db.DB.Delete(&g)
	db.DB.Where("group_id = ?", gID).Delete(&models.UserGroupMember{})
	db.DB.Where("group_id = ?", gID).Delete(&models.UserGroupWorkspace{})
	// Same reasoning as deleting a user: a freed id that a future group lands
	// on would inherit these. The cluster RoleBinding is not touched -- it
	// lives in the cluster and removing it is a cluster action, so the UI says
	// so rather than deleting something nobody asked to delete.
	db.DB.Where("subject_type = ? AND subject_id = ?", "group", gID).Delete(&models.PermissionGrant{})
	db.DB.Where("subject_type = ? AND subject_id = ?", "group", gID).Delete(&models.NamespaceScope{})
	return c.JSON(fiber.Map{"message": "group deleted"})
}

func AddGroupMember(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can manage group members"})
	}

	var g models.UserGroup
	if err := db.DB.First(&g, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "group not found"})
	}

	var req struct {
		UserID uint `json:"user_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.UserID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "user_id is required"})
	}

	var u models.User
	if err := db.DB.First(&u, req.UserID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "user not found"})
	}

	// prevent duplicate
	var existing models.UserGroupMember
	if db.DB.Where("group_id = ? AND user_id = ?", g.ID, req.UserID).First(&existing).Error == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "user already in group"})
	}

	member := models.UserGroupMember{GroupID: g.ID, UserID: req.UserID}
	db.DB.Create(&member)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "member added"})
}

func RemoveGroupMember(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can manage group members"})
	}

	groupID := c.Params("id")
	userID, err := strconv.ParseUint(c.Params("user_id"), 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid user_id"})
	}

	result := db.DB.Where("group_id = ? AND user_id = ?", groupID, userID).Delete(&models.UserGroupMember{})
	if result.RowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "member not found in group"})
	}
	return c.JSON(fiber.Map{"message": "member removed"})
}

func AddGroupWorkspace(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can manage group workspaces"})
	}

	var g models.UserGroup
	if err := db.DB.First(&g, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "group not found"})
	}

	var req struct {
		WorkspaceID uint `json:"workspace_id"`
	}
	if err := c.BodyParser(&req); err != nil || req.WorkspaceID == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "workspace_id is required"})
	}

	var ws models.BitbucketWorkspace
	if err := db.DB.First(&ws, req.WorkspaceID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "workspace not found"})
	}

	// prevent duplicate
	var existing models.UserGroupWorkspace
	if db.DB.Where("group_id = ? AND workspace_id = ?", g.ID, req.WorkspaceID).First(&existing).Error == nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "workspace already in group"})
	}

	gw := models.UserGroupWorkspace{GroupID: g.ID, WorkspaceID: req.WorkspaceID}
	db.DB.Create(&gw)
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"message": "workspace added"})
}

func RemoveGroupWorkspace(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can manage group workspaces"})
	}

	groupID := c.Params("id")
	wsID, err := strconv.ParseUint(c.Params("workspace_id"), 10, 64)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid workspace_id"})
	}

	result := db.DB.Where("group_id = ? AND workspace_id = ?", groupID, wsID).Delete(&models.UserGroupWorkspace{})
	if result.RowsAffected == 0 {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "workspace not found in group"})
	}
	return c.JSON(fiber.Map{"message": "workspace removed"})
}
