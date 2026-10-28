package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// A repository connected for GitOps is reached over SSH with a key of its
// own -- one CommitKube generates (only the public half is ever shown) or
// one pasted in. The first successful connection pins the server's host
// key; from then on a different key is refused, not accepted silently.
//
// Each connection also has a push webhook: the provider calls it on every
// push and the applications reading that branch refresh at once, instead of
// on the next poll.

func gitopsRepoFor(c *fiber.Ctx) (*models.GitOpsRepo, error) {
	var r models.GitOpsRepo
	if err := db.DB.First(&r, c.Params("id")).Error; err != nil {
		return nil, c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "repository connection not found"})
	}
	return &r, nil
}

func newWebhookSecret() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

type gitopsRepoView struct {
	models.GitOpsRepo
	Apps int64 `json:"apps"`
}

func viewGitopsRepo(r models.GitOpsRepo) gitopsRepoView {
	var n int64
	db.DB.Model(&models.GitOpsApp{}).Where("gitops_repo_id = ?", r.ID).Count(&n)
	return gitopsRepoView{r, n}
}

func ListGitopsRepos(c *fiber.Ctx) error {
	var repos []models.GitOpsRepo
	db.DB.Order("name asc").Find(&repos)
	out := make([]gitopsRepoView, 0, len(repos))
	for _, r := range repos {
		out = append(out, viewGitopsRepo(r))
	}
	return c.JSON(out)
}

func GetGitopsRepo(c *fiber.Ctx) error {
	r, err := gitopsRepoFor(c)
	if r == nil {
		return err
	}
	return c.JSON(viewGitopsRepo(*r))
}

// CreateGitopsRepo connects a repository. Without a private key, a key pair
// is generated and the connection waits for its public half to be added on
// the provider; with one, the connection is tested at once.
func CreateGitopsRepo(c *fiber.Ctx) error {
	var req struct {
		Name       string `json:"name"`
		URL        string `json:"url"`
		PrivateKey string `json:"private_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	req.Name, req.URL = strings.TrimSpace(req.Name), strings.TrimSpace(req.URL)
	if !dns1123Label.MatchString(req.Name) || len(req.Name) > 63 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name must be lowercase letters, digits and dashes, up to 63 characters"})
	}
	if msg := validGitopsURL(req.URL); msg != "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
	}
	r := models.GitOpsRepo{Name: req.Name, URL: req.URL, Status: "pending", CreatedBy: currentUserID(c),
		WebhookID: uuid.New().String(), WebhookSecret: crypto.EncryptField(crypto.MasterKey(), newWebhookSecret())}
	if err := setRepoKey(&r, req.PrivateKey); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	if err := db.DB.Create(&r).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "a repository connection with this name already exists"})
	}
	db.LogAudit(currentUserID(c), "gitops_repo_create", "gitops_repo", r.Name,
		fmt.Sprintf(`{"url":%q,"key":%q,"fingerprint":%q}`, r.URL, r.KeySource, r.KeyFingerprint), c.IP())
	if r.KeySource == "imported" {
		testGitopsRepo(&r)
	}
	return c.Status(fiber.StatusCreated).JSON(viewGitopsRepo(r))
}

// setRepoKey stores a pasted private key, or generates a pair when none is
// given.
func setRepoKey(r *models.GitOpsRepo, priv string) error {
	if strings.TrimSpace(priv) == "" {
		k, err := generateRepoDeployKey("gitops-" + r.Name)
		if err != nil {
			return err
		}
		r.KeySource, r.SSHPubKey, r.KeyFingerprint = "generated", k.PublicKey, k.Fingerprint
		r.SSHPrivKey = crypto.EncryptField(crypto.MasterKey(), k.PrivateKey)
		return nil
	}
	pub, fp, err := importedKey(priv)
	if err != nil {
		return err
	}
	r.KeySource, r.SSHPubKey, r.KeyFingerprint = "imported", pub, fp
	r.SSHPrivKey = crypto.EncryptField(crypto.MasterKey(), strings.TrimSpace(priv)+"\n")
	return nil
}

// testGitopsRepo lists the remote's branches with the connection's key and
// records the outcome. The first success pins the host key.
func testGitopsRepo(r *models.GitOpsRepo) (gitopsRemote, error) {
	now := time.Now()
	acc, err := connectionAccess(r)
	if err != nil {
		r.Status, r.Message, r.CheckedAt = "failed", err.Error(), &now
		db.DB.Model(r).Updates(map[string]any{"status": r.Status, "message": r.Message, "checked_at": r.CheckedAt})
		return gitopsRemote{}, err
	}
	defer acc.close()
	remote, knownHosts, err := gitopsLsRemote(acc)
	if err != nil {
		r.Status, r.Message, r.CheckedAt = "failed", err.Error(), &now
		db.DB.Model(r).Updates(map[string]any{"status": r.Status, "message": r.Message, "checked_at": r.CheckedAt})
		return remote, err
	}
	updates := map[string]any{"status": "connected", "checked_at": &now, "default_branch": remote.DefaultBranch,
		"message": fmt.Sprintf("%d branch(es) visible", len(remote.Branches))}
	if knownHosts != "" && r.KnownHosts == "" {
		r.KnownHosts, r.HostKey = knownHosts, hostKeyFingerprint(knownHosts)
		updates["known_hosts"], updates["host_key"] = r.KnownHosts, r.HostKey
	}
	db.DB.Model(r).Updates(updates)
	r.Status, r.CheckedAt, r.DefaultBranch, r.Message = "connected", &now, remote.DefaultBranch, updates["message"].(string)
	return remote, nil
}

func TestGitopsRepoConnection(c *fiber.Ctx) error {
	r, err := gitopsRepoFor(c)
	if r == nil {
		return err
	}
	remote, terr := testGitopsRepo(r)
	db.LogAudit(currentUserID(c), "gitops_repo_test", "gitops_repo", r.Name, fmt.Sprintf(`{"status":%q}`, r.Status), c.IP())
	out := fiber.Map{"repo": viewGitopsRepo(*r), "branches": remote.Branches}
	if terr != nil {
		out["error"] = terr.Error()
		return c.Status(fiber.StatusBadGateway).JSON(out)
	}
	return c.JSON(out)
}

// UpdateGitopsRepo changes the URL or the key, rotates the webhook secret,
// or forgets the pinned host key. A new URL may point at another server, so
// it forgets the host key too.
func UpdateGitopsRepo(c *fiber.Ctx) error {
	r, err := gitopsRepoFor(c)
	if r == nil {
		return err
	}
	var req struct {
		URL           *string `json:"url"`
		PrivateKey    *string `json:"private_key"`
		RegenerateKey bool    `json:"regenerate_key"`
		RotateWebhook bool    `json:"rotate_webhook_secret"`
		ForgetHostKey bool    `json:"forget_host_key"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	var changed []string
	if req.URL != nil && strings.TrimSpace(*req.URL) != r.URL {
		u := strings.TrimSpace(*req.URL)
		if msg := validGitopsURL(u); msg != "" {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
		}
		r.URL, req.ForgetHostKey = u, true
		changed = append(changed, "url")
	}
	if req.RegenerateKey || (req.PrivateKey != nil && strings.TrimSpace(*req.PrivateKey) != "") {
		priv := ""
		if req.PrivateKey != nil && !req.RegenerateKey {
			priv = *req.PrivateKey
		}
		if err := setRepoKey(r, priv); err != nil {
			return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
		}
		changed = append(changed, "key")
	}
	if req.ForgetHostKey {
		r.KnownHosts, r.HostKey = "", ""
		changed = append(changed, "host_key")
	}
	if req.RotateWebhook {
		r.WebhookSecret = crypto.EncryptField(crypto.MasterKey(), newWebhookSecret())
		changed = append(changed, "webhook_secret")
	}
	if len(changed) == 0 {
		return c.JSON(viewGitopsRepo(*r))
	}
	// The webhook secret alone does not change how the repository is reached.
	if len(changed) > 1 || changed[0] != "webhook_secret" {
		r.Status, r.Message = "pending", "changed; test the connection again"
	}
	db.DB.Save(r)
	db.LogAudit(currentUserID(c), "gitops_repo_update", "gitops_repo", r.Name,
		fmt.Sprintf(`{"changed":%q,"fingerprint":%q}`, strings.Join(changed, ","), r.KeyFingerprint), c.IP())
	return c.JSON(viewGitopsRepo(*r))
}

func DeleteGitopsRepo(c *fiber.Ctx) error {
	r, err := gitopsRepoFor(c)
	if r == nil {
		return err
	}
	var names []string
	db.DB.Model(&models.GitOpsApp{}).Where("gitops_repo_id = ?", r.ID).Pluck("name", &names)
	if len(names) > 0 {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error": fmt.Sprintf("%d application(s) still read from it (%s); remove them first", len(names), strings.Join(names, ", ")),
		})
	}
	db.DB.Delete(r)
	db.LogAudit(currentUserID(c), "gitops_repo_delete", "gitops_repo", r.Name, fmt.Sprintf(`{"url":%q}`, r.URL), c.IP())
	return c.JSON(fiber.Map{"message": "repository connection removed"})
}

// GetGitopsRepoBranches lists the branches without cloning.
func GetGitopsRepoBranches(c *fiber.Ctx) error {
	r, err := gitopsRepoFor(c)
	if r == nil {
		return err
	}
	acc, err := connectionAccess(r)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	defer acc.close()
	if !acc.pinned {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "test the connection first, so the server's host key is pinned"})
	}
	remote, _, err := gitopsLsRemote(acc)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	branches := remote.Branches
	if branches == nil {
		branches = []string{}
	}
	return c.JSON(fiber.Map{"default_branch": remote.DefaultBranch, "branches": branches})
}

// GetGitopsRepoTree lists a branch's directories and YAML files, with what
// each directory would be read as, so a path is picked rather than typed.
func GetGitopsRepoTree(c *fiber.Ctx) error {
	r, err := gitopsRepoFor(c)
	if r == nil {
		return err
	}
	branch := c.Query("branch", r.DefaultBranch)
	if branch == "" {
		branch = "main"
	}
	acc, err := connectionAccess(r)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	if !acc.pinned {
		acc.close()
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "test the connection first, so the server's host key is pinned"})
	}
	dir, rev, cleanup, err := gitopsCheckout(acc, branch)
	acc.close()
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	defer cleanup()
	entries, truncated := gitopsTree(dir)
	if entries == nil {
		entries = []gitopsTreeEntry{}
	}
	return c.JSON(fiber.Map{"branch": branch, "revision": rev, "root_kind": detectSourceType(dir), "entries": entries, "truncated": truncated})
}

// GetGitopsRepoWebhook reveals where the provider should send pushes and
// the secret it signs them with.
func GetGitopsRepoWebhook(c *fiber.Ctx) error {
	r, err := gitopsRepoFor(c)
	if r == nil {
		return err
	}
	return c.JSON(fiber.Map{
		"path":   "/api/gitops/webhook/" + r.WebhookID,
		"secret": crypto.DecryptField(crypto.MasterKey(), r.WebhookSecret),
	})
}

// ---- the webhook itself ----------------------------------------------------------------

// GitopsWebhook receives a push. It is public -- the provider holds no
// CommitKube session -- so it trusts nothing it was not able to verify:
// GitHub, Gitea and Bitbucket sign the body with the secret
// (X-Hub-Signature-256 / X-Hub-Signature), GitLab sends the secret itself
// (X-Gitlab-Token). An unsigned request is refused.
func GitopsWebhook(c *fiber.Ctx) error {
	var r models.GitOpsRepo
	if err := db.DB.Where("webhook_id = ?", c.Params("id")).First(&r).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "unknown webhook"})
	}
	secret := crypto.DecryptField(crypto.MasterKey(), r.WebhookSecret)
	if secret == "" || !webhookAuthentic(c, secret) {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "the signature does not match this webhook's secret"})
	}
	now := time.Now()
	db.DB.Model(&r).Update("last_push_at", &now)

	branches := pushedBranches(c.Body())
	var apps []models.GitOpsApp
	db.DB.Where("gitops_repo_id = ?", r.ID).Find(&apps)
	queued := 0
	for _, app := range apps {
		if branches != nil && !branches[app.Branch] {
			continue
		}
		enqueueGitopsRefresh(app, "webhook")
		queued++
	}
	return c.Status(fiber.StatusAccepted).JSON(fiber.Map{"queued": queued})
}

// enqueueGitopsRefresh is how the webhook starts a refresh; tests replace it
// to see what a push would refresh without running one.
var enqueueGitopsRefresh = queueGitopsRefresh

func webhookAuthentic(c *fiber.Ctx, secret string) bool {
	sig := c.Get("X-Hub-Signature-256")
	if sig == "" {
		sig = c.Get("X-Hub-Signature")
	}
	if hexSig, ok := strings.CutPrefix(sig, "sha256="); ok {
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write(c.Body())
		want := hex.EncodeToString(mac.Sum(nil))
		return hmac.Equal([]byte(strings.ToLower(hexSig)), []byte(want))
	}
	if tok := c.Get("X-Gitlab-Token"); tok != "" {
		return subtle.ConstantTimeCompare([]byte(tok), []byte(secret)) == 1
	}
	return false
}

// pushedBranches reads which branches a push moved, from the payload shapes
// of GitHub/GitLab/Gitea ("ref"), Bitbucket Cloud (push.changes[].new) and
// Bitbucket Data Center (changes[].ref). nil means it could not tell -- a
// ping, or a provider it does not know -- and every app is refreshed.
func pushedBranches(body []byte) map[string]bool {
	var p struct {
		Ref  string `json:"ref"`
		Push struct {
			Changes []struct {
				New *struct {
					Type string `json:"type"`
					Name string `json:"name"`
				} `json:"new"`
			} `json:"changes"`
		} `json:"push"`
		Changes []struct {
			Ref struct {
				ID        string `json:"id"`
				DisplayID string `json:"displayId"`
				Type      string `json:"type"`
			} `json:"ref"`
		} `json:"changes"`
	}
	if json.Unmarshal(body, &p) != nil {
		return nil
	}
	out := map[string]bool{}
	if b, ok := strings.CutPrefix(p.Ref, "refs/heads/"); ok {
		out[b] = true
	}
	for _, ch := range p.Push.Changes {
		if ch.New != nil && ch.New.Type == "branch" {
			out[ch.New.Name] = true
		}
	}
	for _, ch := range p.Changes {
		if b, ok := strings.CutPrefix(ch.Ref.ID, "refs/heads/"); ok {
			out[b] = true
		}
	}
	if len(out) == 0 {
		if p.Ref != "" {
			return map[string]bool{} // a tag: no branch moved
		}
		return nil
	}
	return out
}
