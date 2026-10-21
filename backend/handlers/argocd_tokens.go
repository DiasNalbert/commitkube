package handlers

import (
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

// ArgoCD is reached with the token of the person acting, never with a token
// shared by everyone. A shared token made every user the same ArgoCD account:
// ArgoCD's RBAC could not tell them apart, its audit log named nobody, and
// rotating one password broke repository creation for the whole team.
//
// An instance therefore says only where ArgoCD is and what to default to.
// Each person adds their own token for it on their profile; without one,
// the ArgoCD steps are skipped with a message that says so.

// argoCredential is the caller's token for an instance, from the
// per-instance table or, for accounts set up before it existed, from the old
// single personal URL and token when that URL is this instance's.
func argoCredential(userID uint, inst models.ArgoCDInstance) (token, username string) {
	var t models.UserArgoCDToken
	if db.DB.Where("user_id = ? AND instance_id = ?", userID, inst.ID).Limit(1).Find(&t); t.ID != 0 {
		return crypto.DecryptField(crypto.MasterKey(), t.Token), t.Username
	}
	var keys models.UserKeys
	if db.DB.Where("user_id = ?", userID).Limit(1).Find(&keys); keys.ID != 0 && keys.ArgoCDAuthToken != "" &&
		normURL(keys.ArgoCDServerURL) == normURL(inst.ServerURL) {
		return crypto.DecryptField(crypto.MasterKey(), keys.ArgoCDAuthToken), ""
	}
	return "", ""
}

func normURL(u string) string { return strings.TrimRight(strings.ToLower(strings.TrimSpace(u)), "/") }

type argoInstanceView struct {
	models.ArgoCDInstance
	HasMyToken     bool   `json:"has_my_token"`
	MyUsername     string `json:"my_username,omitempty"`
	HasSharedToken bool   `json:"has_shared_token,omitempty"` // shown to admins, so the leftover can be removed
}

func ListArgoCDInstances(c *fiber.Ctx) error {
	var instances []models.ArgoCDInstance
	db.DB.Find(&instances)
	userID := currentUserID(c)
	admin := callerIsAdmin(c)
	out := make([]argoInstanceView, 0, len(instances))
	for _, inst := range instances {
		token, username := argoCredential(userID, inst)
		v := argoInstanceView{ArgoCDInstance: inst, HasMyToken: token != "", MyUsername: username}
		if admin {
			v.HasSharedToken = inst.AuthToken != ""
		}
		out = append(out, v)
	}
	return c.JSON(out)
}

func argoInstanceParam(c *fiber.Ctx) (*models.ArgoCDInstance, error) {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return nil, err
	}
	var inst models.ArgoCDInstance
	if err := db.DB.First(&inst, id).Error; err != nil {
		return nil, err
	}
	return &inst, nil
}

// SetMyArgoCDToken saves the caller's own token for an instance, after ArgoCD
// has confirmed it is valid -- a token that fails here would otherwise fail
// later, in the middle of creating a repository.
func SetMyArgoCDToken(c *fiber.Ctx) error {
	inst, err := argoInstanceParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}
	var req struct {
		Token string `json:"token"`
	}
	if err := c.BodyParser(&req); err != nil || strings.TrimSpace(req.Token) == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "token is required"})
	}
	token := strings.TrimSpace(req.Token)
	username, err := services.NewArgoCDClient(inst.ServerURL, token).UserInfo()
	if err != nil {
		return c.Status(fiber.StatusUnprocessableEntity).JSON(fiber.Map{"error": "ArgoCD refused the token: " + err.Error()})
	}

	userID := currentUserID(c)
	row := models.UserArgoCDToken{UserID: userID, InstanceID: inst.ID}
	db.DB.Where("user_id = ? AND instance_id = ?", userID, inst.ID).Limit(1).Find(&row)
	row.UserID, row.InstanceID = userID, inst.ID
	row.Token = crypto.EncryptField(crypto.MasterKey(), token)
	row.Username = username
	if err := db.DB.Save(&row).Error; err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	db.LogAudit(userID, "set_argocd_token", "argocd_instance", inst.Alias, "as "+username, c.IP())
	return c.JSON(fiber.Map{"ok": true, "username": username})
}

func DeleteMyArgoCDToken(c *fiber.Ctx) error {
	inst, err := argoInstanceParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}
	userID := currentUserID(c)
	db.DB.Where("user_id = ? AND instance_id = ?", userID, inst.ID).Delete(&models.UserArgoCDToken{})
	// The legacy personal token for this URL goes too, or it would keep
	// answering for the person after they removed "their token".
	var keys models.UserKeys
	if db.DB.Where("user_id = ?", userID).Limit(1).Find(&keys); keys.ID != 0 && normURL(keys.ArgoCDServerURL) == normURL(inst.ServerURL) {
		db.DB.Model(&keys).Update("argo_cd_auth_token", "")
	}
	db.LogAudit(userID, "delete_argocd_token", "argocd_instance", inst.Alias, "", c.IP())
	return c.JSON(fiber.Map{"ok": true})
}

// DeleteSharedArgoCDToken removes the token an instance still stores from
// before tokens were personal. It is no longer used for anything; keeping it
// only keeps a credential around to leak.
func DeleteSharedArgoCDToken(c *fiber.Ctx) error {
	if !callerIsAdmin(c) {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "Only admins can edit ArgoCD instances"})
	}
	inst, err := argoInstanceParam(c)
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}
	db.DB.Model(inst).Update("auth_token", "")
	db.LogAudit(currentUserID(c), "delete_shared_argocd_token", "argocd_instance", inst.Alias, "", c.IP())
	return c.JSON(fiber.Map{"ok": true})
}
