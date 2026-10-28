package handlers

import (
	"context"
	"fmt"
	"path"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	authnv1 "k8s.io/api/authentication/v1"
	authzv1 "k8s.io/api/authorization/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/restmapper"
	"sigs.k8s.io/yaml"
)

// ---- the cluster, for real -------------------------------------------------------------

type dynamicKube struct {
	dyn    dynamic.Interface
	mapper meta.RESTMapper
}

// Discovery is a dozen API calls; one mapper per cluster is reused for a
// while, and rebuilt when a kind is not found (a CRD installed meanwhile).
var (
	mapperMu    sync.Mutex
	mapperCache = map[uint]struct {
		m  meta.RESTMapper
		at time.Time
	}{}
)

func newDynamicKube(cl *models.Cluster, fresh bool) (*dynamicKube, error) {
	typed, dyn, err := clientsFor(cl)
	if err != nil {
		return nil, err
	}
	mapperMu.Lock()
	defer mapperMu.Unlock()
	if hit, ok := mapperCache[cl.ID]; ok && !fresh && time.Since(hit.at) < 10*time.Minute {
		return &dynamicKube{dyn: dyn, mapper: hit.m}, nil
	}
	groups, err := restmapper.GetAPIGroupResources(typed.Discovery())
	if err != nil {
		return nil, fmt.Errorf("discovery: %w", err)
	}
	m := restmapper.NewDiscoveryRESTMapper(groups)
	mapperCache[cl.ID] = struct {
		m  meta.RESTMapper
		at time.Time
	}{m, time.Now()}
	return &dynamicKube{dyn: dyn, mapper: m}, nil
}

func (k *dynamicKube) Mapping(gvk schema.GroupVersionKind) (schema.GroupVersionResource, bool, error) {
	m, err := k.mapper.RESTMapping(gvk.GroupKind(), gvk.Version)
	if err != nil {
		return schema.GroupVersionResource{}, false, err
	}
	return m.Resource, m.Scope.Name() == meta.RESTScopeNameNamespace, nil
}

func (k *dynamicKube) Get(ctx context.Context, gvr schema.GroupVersionResource, ns, name string) (*unstructured.Unstructured, error) {
	o, err := k.dyn.Resource(gvr).Namespace(ns).Get(ctx, name, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		return nil, nil
	}
	return o, err
}

func (k *dynamicKube) Apply(ctx context.Context, gvr schema.GroupVersionResource, ns string, obj *unstructured.Unstructured, dryRun bool) (*unstructured.Unstructured, error) {
	opts := metav1.ApplyOptions{FieldManager: gitopsFieldManager, Force: true}
	if dryRun {
		opts.DryRun = []string{metav1.DryRunAll}
	}
	return k.dyn.Resource(gvr).Namespace(ns).Apply(ctx, obj.GetName(), obj, opts)
}

func (k *dynamicKube) Delete(ctx context.Context, gvr schema.GroupVersionResource, ns, name string) error {
	bg := metav1.DeletePropagationBackground
	return k.dyn.Resource(gvr).Namespace(ns).Delete(ctx, name, metav1.DeleteOptions{PropagationPolicy: &bg})
}

// ---- refresh and sync --------------------------------------------------------------------

// One operation per application at a time: a sync racing a refresh would
// write the inventory twice.
var (
	gitopsLocksMu sync.Mutex
	gitopsLocks   = map[uint]*sync.Mutex{}
)

func gitopsLock(id uint) *sync.Mutex {
	gitopsLocksMu.Lock()
	defer gitopsLocksMu.Unlock()
	if gitopsLocks[id] == nil {
		gitopsLocks[id] = &sync.Mutex{}
	}
	return gitopsLocks[id]
}

type gitopsWorkspace struct {
	cluster    *models.Cluster
	kube       gitopsKube
	manifests  []gitopsManifest
	revision   string
	renderedAs string
	cleanup    func()
}

// openGitopsWorkspace checks out the app's branch, renders its path, and
// connects to its cluster -- in that order, so a broken chart or overlay is
// reported as such even while the cluster is unreachable. When only the
// cluster fails, the workspace still comes back (without kube) next to the
// error, carrying the commit it read and how it rendered it.
func openGitopsWorkspace(app *models.GitOpsApp) (*gitopsWorkspace, error) {
	var cl models.Cluster
	if err := db.DB.First(&cl, app.ClusterID).Error; err != nil {
		return nil, fmt.Errorf("cluster %d not found", app.ClusterID)
	}
	acc, err := appAccess(app)
	if err != nil {
		return nil, err
	}
	dir, rev, cleanup, err := gitopsCheckout(acc, app.Branch)
	acc.close()
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	manifests, renderedAs, err := renderApp(ctx, app, dir)
	if err != nil {
		cleanup()
		return &gitopsWorkspace{revision: rev, renderedAs: renderedAs, cleanup: func() {}}, err
	}
	ws := &gitopsWorkspace{cluster: &cl, manifests: manifests, revision: rev, renderedAs: renderedAs, cleanup: cleanup}
	kube, err := newDynamicKube(&cl, false)
	if err != nil {
		return ws, fmt.Errorf("cluster %s: %w", cl.Name, err)
	}
	// The mapper is cached for minutes; a kind it does not know may be a
	// CRD installed since. Ask the cluster again before calling it unknown.
	for _, m := range manifests {
		if _, _, err := kube.Mapping(m.Obj.GroupVersionKind()); err != nil {
			if fresh, err := newDynamicKube(&cl, true); err == nil {
				kube = fresh
			}
			break
		}
	}
	ws.kube = kube
	return ws, nil
}

func loadInventory(appID uint) []models.GitOpsResource {
	var inv []models.GitOpsResource
	db.DB.Where("app_id = ?", appID).Find(&inv)
	return inv
}

// storeResults replaces the app's resource rows with a refresh's results.
func storeResults(app *models.GitOpsApp, results []gitopsResult) {
	rows := make([]models.GitOpsResource, 0, len(results))
	for _, r := range results {
		rows = append(rows, models.GitOpsResource{AppID: app.ID, Group: r.Group, Version: r.Version, Kind: r.Kind,
			Namespace: r.Namespace, Name: r.Name, Status: r.Status, Health: r.Health, Message: r.Message, Diff: r.Diff, Applied: r.Applied})
	}
	db.DB.Where("app_id = ?", app.ID).Delete(&models.GitOpsResource{})
	if len(rows) > 0 {
		db.DB.CreateInBatches(&rows, 200)
	}
}

// markUnknown records why an app could not be compared, keeping what was
// learned before it failed: the commit read and how it rendered.
func markUnknown(app *models.GitOpsApp, ws *gitopsWorkspace, err error) {
	now := time.Now()
	updates := map[string]any{"sync_status": "Unknown", "health": GHealthUnknown, "message": err.Error(), "refreshed_at": &now}
	if ws != nil {
		ws.cleanup()
		updates["revision"], updates["rendered_as"] = ws.revision, ws.renderedAs
		app.Revision, app.RenderedAs = ws.revision, ws.renderedAs
	}
	db.DB.Model(app).Updates(updates)
	app.SyncStatus, app.Health, app.Message, app.RefreshedAt = "Unknown", GHealthUnknown, err.Error(), &now
}

// refreshGitopsApp compares the app with the cluster and stores the result.
func refreshGitopsApp(app *models.GitOpsApp) error {
	lock := gitopsLock(app.ID)
	lock.Lock()
	defer lock.Unlock()
	return refreshLocked(app)
}

func refreshLocked(app *models.GitOpsApp) error {
	ws, err := openGitopsWorkspace(app)
	if err != nil {
		markUnknown(app, ws, err)
		return err
	}
	defer ws.cleanup()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	results := compareApp(ctx, app, ws.kube, ws.manifests, loadInventory(app.ID))
	storeResults(app, results)
	sync, health, msg := summarize(results)
	now := time.Now()
	db.DB.Model(app).Updates(map[string]any{"revision": ws.revision, "rendered_as": ws.renderedAs, "sync_status": sync, "health": health, "message": msg, "refreshed_at": &now})
	app.Revision, app.RenderedAs, app.SyncStatus, app.Health, app.Message, app.RefreshedAt = ws.revision, ws.renderedAs, sync, health, msg, &now
	return nil
}

// syncGitopsApp applies the app's branch head and records the run.
func syncGitopsApp(app *models.GitOpsApp, trigger string, userID uint, ip string) (*models.GitOpsSync, error) {
	lock := gitopsLock(app.ID)
	lock.Lock()
	defer lock.Unlock()

	run := models.GitOpsSync{AppID: app.ID, StartedAt: time.Now(), Trigger: trigger, UserID: userID, Phase: "Running"}
	if userID != 0 {
		var u models.User
		db.DB.Select("email").First(&u, userID)
		run.UserEmail = u.Email
	}
	db.DB.Create(&run)
	finish := func(phase, msg string, lines []string) {
		now := time.Now()
		run.FinishedAt, run.Phase, run.Message = &now, phase, msg
		run.Results = strings.Join(lines, "\n")
		db.DB.Save(&run)
	}

	ws, err := openGitopsWorkspace(app)
	if err != nil {
		finish("Failed", err.Error(), nil)
		markUnknown(app, ws, err)
		notifyGitopsFailure(app, err.Error())
		return &run, err
	}
	defer ws.cleanup()
	run.Revision = ws.revision

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	inv := loadInventory(app.ID)
	out := syncApp(ctx, app, ws.kube, ws.manifests, inv)
	// Custom resources whose CRD this same sync installed could not be
	// resolved the first time round. Once the API server serves the new
	// kinds, the whole set is applied again -- applying is idempotent.
	if appliedCRDs(out) && skippedUnknownKinds(out) {
		time.Sleep(3 * time.Second)
		if fresh, err := newDynamicKube(ws.cluster, true); err == nil {
			ws.kube = fresh
			again := syncApp(ctx, app, fresh, ws.manifests, inv)
			again.Lines = append([]string{"CRDs installed; applied again so their custom resources resolve"}, again.Lines...)
			out = again
		}
	}

	// The inventory learns what was applied and forgets what was pruned.
	for _, r := range out.Applied {
		res := db.DB.Model(&models.GitOpsResource{}).
			Where("app_id = ? AND `group` = ? AND kind = ? AND namespace = ? AND name = ?", app.ID, r.Group, r.Kind, r.Namespace, r.Name).
			Updates(map[string]any{"applied": true, "version": r.Version})
		if res.RowsAffected == 0 {
			db.DB.Create(&models.GitOpsResource{AppID: app.ID, Group: r.Group, Version: r.Version, Kind: r.Kind, Namespace: r.Namespace, Name: r.Name, Applied: true, Status: ResSynced})
		}
	}
	for _, r := range out.Pruned {
		db.DB.Where("app_id = ? AND `group` = ? AND kind = ? AND namespace = ? AND name = ?", app.ID, r.Group, r.Kind, r.Namespace, r.Name).Delete(&models.GitOpsResource{})
	}

	phase, msg := "Succeeded", fmt.Sprintf("applied %d object(s)", len(out.Applied))
	if n := countPrefix(out.Lines, "pruned "); n > 0 {
		msg += fmt.Sprintf(", pruned %d", n)
	}
	if out.Failed {
		phase, msg = "Failed", "some objects could not be applied"
	}
	finish(phase, msg, out.Lines)
	now := time.Now()
	db.DB.Model(app).Updates(map[string]any{"synced_revision": ws.revision, "synced_at": &now})
	app.SyncedRevision, app.SyncedAt = ws.revision, &now
	if userID != 0 {
		db.LogAudit(userID, "gitops_sync", "gitops_app", app.Name, fmt.Sprintf(`{"revision":%q,"phase":%q}`, ws.revision, phase), ip)
	}
	if out.Failed {
		notifyGitopsFailure(app, strings.Join(out.Lines, "; "))
	}

	// Read back what the cluster now holds, so the page shows it at once.
	results := compareApp(ctx, app, ws.kube, ws.manifests, loadInventory(app.ID))
	storeResults(app, results)
	st, health, m := summarize(results)
	db.DB.Model(app).Updates(map[string]any{"revision": ws.revision, "sync_status": st, "health": health, "message": m, "refreshed_at": &now})
	return &run, nil
}

func appliedCRDs(out gitopsSyncOutcome) bool {
	for _, r := range out.Applied {
		if r.Kind == "CustomResourceDefinition" {
			return true
		}
	}
	return false
}

func skippedUnknownKinds(out gitopsSyncOutcome) bool {
	for _, l := range out.Lines {
		if strings.HasPrefix(l, "skipped ") && strings.Contains(l, unknownKindHint) {
			return true
		}
	}
	return false
}

func notifyGitopsFailure(app *models.GitOpsApp, detail string) {
	if len(detail) > 600 {
		detail = detail[:600] + "…"
	}
	go SendNotifications("gitops.sync_failed", "GitOps sync failed",
		fmt.Sprintf("%s (%s/%s): %s", app.Name, app.RepoName, app.Branch, detail), app.RepoName, "system")
}

// PollGitOps refreshes every application and, where it is asked to, syncs:
// a new commit with auto-sync, or drift with self-heal. A sync that failed
// on a commit is not retried on the same commit for ten minutes, so a broken
// manifest does not become a loop hammering the API server.
func PollGitOps() {
	var apps []models.GitOpsApp
	db.DB.Find(&apps)
	for i := range apps {
		app := &apps[i]
		if err := refreshGitopsApp(app); err != nil {
			continue
		}
		if !app.AutoSync || app.SyncStatus != ResOutOfSync {
			continue
		}
		trigger := "auto"
		if app.Revision == app.SyncedRevision {
			if !app.SelfHeal {
				continue
			}
			trigger = "self-heal"
		}
		var last models.GitOpsSync
		if db.DB.Where("app_id = ?", app.ID).Order("id desc").First(&last).Error == nil &&
			last.Phase == "Failed" && last.Revision == app.Revision && time.Since(last.StartedAt) < 10*time.Minute {
			continue
		}
		_, _ = syncGitopsApp(app, trigger, 0, "")
	}
}

// RefreshGitopsForRepo is called when CommitKube itself commits to a
// repository, so its applications notice without waiting for the poll.
func RefreshGitopsForRepo(repoName string) {
	var apps []models.GitOpsApp
	db.DB.Where("repo_name = ? AND gitops_repo_id IS NULL", repoName).Find(&apps)
	for i := range apps {
		queueGitopsRefresh(apps[i], "auto")
	}
}

// Pushes come in bursts -- a merge, a tag, a force-push -- and each would
// otherwise queue a clone behind the app's lock. One pending refresh per
// app is enough: whichever runs reads the branch head as it is by then.
var (
	gitopsQueuedMu sync.Mutex
	gitopsQueued   = map[uint]bool{}
)

// queueGitopsRefresh refreshes an app in the background and, when it has
// auto-sync and the branch moved, syncs it.
func queueGitopsRefresh(app models.GitOpsApp, trigger string) {
	gitopsQueuedMu.Lock()
	if gitopsQueued[app.ID] {
		gitopsQueuedMu.Unlock()
		return
	}
	gitopsQueued[app.ID] = true
	gitopsQueuedMu.Unlock()
	go func() {
		lock := gitopsLock(app.ID)
		lock.Lock()
		gitopsQueuedMu.Lock()
		delete(gitopsQueued, app.ID)
		gitopsQueuedMu.Unlock()
		err := refreshLocked(&app)
		lock.Unlock()
		if err == nil && app.AutoSync && app.SyncStatus == ResOutOfSync && app.Revision != app.SyncedRevision {
			_, _ = syncGitopsApp(&app, trigger, 0, "")
		}
	}()
}

// ---- HTTP ------------------------------------------------------------------------------------

var dns1123Label = regexp.MustCompile(`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`)

func gitopsAppFor(c *fiber.Ctx) (*models.GitOpsApp, error) {
	var app models.GitOpsApp
	if err := db.DB.First(&app, c.Params("id")).Error; err != nil {
		return nil, c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "application not found"})
	}
	if !namespaceAllowed(c, app.Namespace) {
		return nil, forbidNamespace(c)
	}
	return &app, nil
}

func ListGitopsApps(c *fiber.Ctx) error {
	var apps []models.GitOpsApp
	db.DB.Order("name asc").Find(&apps)
	type row struct {
		models.GitOpsApp
		Cluster string `json:"cluster"`
		Source  string `json:"source"`
	}
	sources := gitopsSourceNames()
	names := map[uint]string{}
	var clusters []models.Cluster
	db.DB.Select("id", "name").Find(&clusters)
	for _, cl := range clusters {
		names[cl.ID] = cl.Name
	}
	out := []row{}
	for _, a := range apps {
		if namespaceAllowed(c, a.Namespace) {
			out = append(out, row{a, names[a.ClusterID], sourceName(&a, sources)})
		}
	}
	return c.JSON(out)
}

func GetGitopsApp(c *fiber.Ctx) error {
	app, err := gitopsAppFor(c)
	if app == nil {
		return err
	}
	var res []models.GitOpsResource
	db.DB.Where("app_id = ?", app.ID).Find(&res)
	var syncs []models.GitOpsSync
	db.DB.Where("app_id = ?", app.ID).Order("id desc").Limit(20).Find(&syncs)
	var cl models.Cluster
	db.DB.Select("name").First(&cl, app.ClusterID)
	return c.JSON(fiber.Map{"app": app, "cluster": cl.Name, "source": sourceName(app, gitopsSourceNames()), "resources": res, "syncs": syncs})
}

// gitopsSourceNames names every connected repository by id.
func gitopsSourceNames() map[uint]string {
	var repos []models.GitOpsRepo
	db.DB.Select("id", "name").Find(&repos)
	m := map[uint]string{}
	for _, r := range repos {
		m[r.ID] = r.Name
	}
	return m
}

// sourceName is what an application reads from, as people know it.
func sourceName(app *models.GitOpsApp, connected map[uint]string) string {
	if app.GitOpsRepoID != nil {
		return connected[*app.GitOpsRepoID]
	}
	return app.RepoName
}

type gitopsAppInput struct {
	Name            *string `json:"name"`
	ClusterID       *uint   `json:"cluster_id"`
	GitOpsRepoID    *uint   `json:"gitops_repo_id"`
	RepoName        *string `json:"repo_name"`
	Branch          *string `json:"branch"`
	Path            *string `json:"path"`
	Namespace       *string `json:"namespace"`
	SourceType      *string `json:"source_type"`
	Include         *string `json:"include"`
	Exclude         *string `json:"exclude"`
	HelmReleaseName *string `json:"helm_release_name"`
	HelmValueFiles  *string `json:"helm_value_files"`
	HelmValues      *string `json:"helm_values"`
	ClusterScope    *bool   `json:"cluster_scope"`
	AutoSync        *bool   `json:"auto_sync"`
	SelfHeal        *bool   `json:"self_heal"`
	Prune           *bool   `json:"prune"`
}

func (in *gitopsAppInput) apply(app *models.GitOpsApp) {
	str := func(dst *string, v *string) {
		if v != nil {
			*dst = strings.TrimSpace(*v)
		}
	}
	str(&app.Name, in.Name)
	str(&app.RepoName, in.RepoName)
	str(&app.Branch, in.Branch)
	str(&app.Path, in.Path)
	str(&app.Namespace, in.Namespace)
	str(&app.SourceType, in.SourceType)
	str(&app.Include, in.Include)
	str(&app.Exclude, in.Exclude)
	str(&app.HelmReleaseName, in.HelmReleaseName)
	str(&app.HelmValueFiles, in.HelmValueFiles)
	if in.HelmValues != nil {
		app.HelmValues = *in.HelmValues // YAML: indentation is meaning
	}
	if in.GitOpsRepoID != nil {
		app.GitOpsRepoID = in.GitOpsRepoID
		if *in.GitOpsRepoID == 0 {
			app.GitOpsRepoID = nil
		}
	}
	if app.GitOpsRepoID != nil {
		app.RepoName = ""
	}
	if in.ClusterID != nil {
		app.ClusterID = *in.ClusterID
	}
	if in.ClusterScope != nil {
		app.ClusterScope = *in.ClusterScope
	}
	if in.AutoSync != nil {
		app.AutoSync = *in.AutoSync
	}
	if in.SelfHeal != nil {
		app.SelfHeal = *in.SelfHeal
	}
	if in.Prune != nil {
		app.Prune = *in.Prune
	}
}

func validateGitopsApp(app *models.GitOpsApp) string {
	if !dns1123Label.MatchString(app.Name) || len(app.Name) > 63 {
		return "name must be lowercase letters, digits and dashes, up to 63 characters"
	}
	if !dns1123Label.MatchString(app.Namespace) || len(app.Namespace) > 63 {
		return "namespace is not a valid namespace name"
	}
	if app.Branch == "" {
		app.Branch = "main"
	}
	if !validBranch(app.Branch) {
		return "branch is not a valid branch name"
	}
	if strings.Contains(app.Path, "..") {
		return "path cannot contain .."
	}
	if app.SourceType == "" {
		app.SourceType = SourceAuto
	}
	if !gitopsSourceTypes[app.SourceType] {
		return "source type must be auto, directory, kustomize or helm"
	}
	if app.HelmReleaseName != "" && (!dns1123Label.MatchString(app.HelmReleaseName) || len(app.HelmReleaseName) > 53) {
		return "the Helm release name must be lowercase letters, digits and dashes, up to 53 characters"
	}
	if strings.TrimSpace(app.HelmValues) != "" {
		var v map[string]any
		if err := yaml.Unmarshal([]byte(app.HelmValues), &v); err != nil {
			return "the Helm values are not valid YAML: " + err.Error()
		}
	}
	for _, g := range append(splitGlobs(app.Include), splitGlobs(app.Exclude)...) {
		if _, err := path.Match(g, ""); err != nil {
			return fmt.Sprintf("%q is not a valid glob", g)
		}
	}
	var n int64
	if app.GitOpsRepoID != nil {
		db.DB.Model(&models.GitOpsRepo{}).Where("id = ?", *app.GitOpsRepoID).Count(&n)
		if n == 0 {
			return "repository connection not found"
		}
	} else {
		if app.RepoName == "" {
			return "choose a connected repository"
		}
		db.DB.Model(&models.Repository{}).Where("name = ?", app.RepoName).Count(&n)
		if n == 0 {
			return "repository " + app.RepoName + " is not in CommitKube"
		}
	}
	db.DB.Model(&models.Cluster{}).Where("id = ?", app.ClusterID).Count(&n)
	if n == 0 {
		return "cluster not found"
	}
	if app.SelfHeal && !app.AutoSync {
		return "self-heal needs auto-sync"
	}
	return ""
}

// namespaceUnrestricted: the caller is not scoped to a list of namespaces.
// Cluster scope reaches every namespace, so only such a caller may turn it on.
func namespaceUnrestricted(c *fiber.Ctx) bool {
	_, restricted, err := requestNamespaces(c)
	return err == nil && !restricted
}

func forbidClusterScope(c *fiber.Ctx) error {
	return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
		"error": "cluster scope reaches every namespace; your account is scoped to some of them",
	})
}

func CreateGitopsApp(c *fiber.Ctx) error {
	var in gitopsAppInput
	if err := c.BodyParser(&in); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	app := models.GitOpsApp{Branch: "main", SyncStatus: "Unknown", Health: GHealthUnknown, CreatedBy: currentUserID(c)}
	if cl, err := defaultCluster(); err == nil {
		app.ClusterID = cl.ID
	}
	in.apply(&app)
	if msg := validateGitopsApp(&app); msg != "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
	}
	if !namespaceAllowed(c, app.Namespace) {
		return forbidNamespace(c)
	}
	if app.ClusterScope && !namespaceUnrestricted(c) {
		return forbidClusterScope(c)
	}
	if err := db.DB.Create(&app).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "an application with this name already exists"})
	}
	db.LogAudit(currentUserID(c), "gitops_app_create", "gitops_app", app.Name,
		fmt.Sprintf(`{"source":%q,"branch":%q,"path":%q,"type":%q,"namespace":%q,"cluster_scope":%t}`,
			sourceName(&app, gitopsSourceNames()), app.Branch, app.Path, app.SourceType, app.Namespace, app.ClusterScope), c.IP())
	queueGitopsRefresh(app, "auto")
	return c.Status(fiber.StatusCreated).JSON(app)
}

func UpdateGitopsApp(c *fiber.Ctx) error {
	app, err := gitopsAppFor(c)
	if app == nil {
		return err
	}
	var in gitopsAppInput
	if err := c.BodyParser(&in); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	// Renaming would orphan the tracking ids already in the cluster, and
	// moving namespaces would leave everything behind: neither is an edit.
	in.Name, in.Namespace, in.ClusterID = nil, nil, nil
	wasClusterScope := app.ClusterScope
	in.apply(app)
	if app.ClusterScope && !wasClusterScope && !namespaceUnrestricted(c) {
		return forbidClusterScope(c)
	}
	if msg := validateGitopsApp(app); msg != "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": msg})
	}
	db.DB.Save(app)
	db.LogAudit(currentUserID(c), "gitops_app_update", "gitops_app", app.Name,
		fmt.Sprintf(`{"auto_sync":%t,"self_heal":%t,"prune":%t,"cluster_scope":%t,"branch":%q,"path":%q,"type":%q}`,
			app.AutoSync, app.SelfHeal, app.Prune, app.ClusterScope, app.Branch, app.Path, app.SourceType), c.IP())
	queueGitopsRefresh(*app, "auto")
	return c.JSON(app)
}

// DeleteGitopsApp stops managing the application. The objects stay in the
// cluster unless cascade=true, which deletes what the engine applied --
// and only what still carries this app's tracking id.
func DeleteGitopsApp(c *fiber.Ctx) error {
	app, err := gitopsAppFor(c)
	if app == nil {
		return err
	}
	lock := gitopsLock(app.ID)
	lock.Lock()
	defer lock.Unlock()
	deleted := 0
	if c.Query("cascade") == "true" {
		var cl models.Cluster
		if err := db.DB.First(&cl, app.ClusterID).Error; err == nil {
			if kube, err := newDynamicKube(&cl, false); err == nil {
				ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
				defer cancel()
				prune := *app
				prune.Prune = true
				out := syncApp(ctx, &prune, kube, nil, loadInventory(app.ID))
				deleted = len(out.Pruned)
			}
		}
	}
	db.DB.Where("app_id = ?", app.ID).Delete(&models.GitOpsResource{})
	db.DB.Delete(app)
	db.LogAudit(currentUserID(c), "gitops_app_delete", "gitops_app", app.Name, fmt.Sprintf(`{"cascade":%t,"deleted":%d}`, c.Query("cascade") == "true", deleted), c.IP())
	return c.JSON(fiber.Map{"message": "application removed", "deleted_objects": deleted})
}

func RefreshGitopsApp(c *fiber.Ctx) error {
	app, err := gitopsAppFor(c)
	if app == nil {
		return err
	}
	if err := refreshGitopsApp(app); err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	return GetGitopsApp(c)
}

func SyncGitopsApp(c *fiber.Ctx) error {
	app, err := gitopsAppFor(c)
	if app == nil {
		return err
	}
	run, err := syncGitopsApp(app, "manual", currentUserID(c), c.IP())
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error(), "sync": run})
	}
	return c.JSON(fiber.Map{"sync": run})
}

// ---- access ------------------------------------------------------------------------------------

// gitopsDeployerRules is what an application's objects need, written as the
// ClusterRole that is bound per namespace. RBAC objects are left out on
// purpose: a tool that can write RoleBindings can hand itself anything.
var gitopsDeployerRules = []struct {
	Group     string
	Resources []string
}{
	{"", []string{"configmaps", "secrets", "services", "serviceaccounts", "persistentvolumeclaims"}},
	{"apps", []string{"deployments", "statefulsets", "daemonsets"}},
	{"batch", []string{"jobs", "cronjobs"}},
	{"networking.k8s.io", []string{"ingresses", "networkpolicies"}},
	{"autoscaling", []string{"horizontalpodautoscalers"}},
	{"policy", []string{"poddisruptionbudgets"}},
}

// GetGitopsAccess says who CommitKube is on the app's cluster, which of the
// writes it needs in the app's namespace it lacks, and the RBAC that grants
// exactly those -- in that namespace, nowhere else.
func GetGitopsAccess(c *fiber.Ctx) error {
	app, err := gitopsAppFor(c)
	if app == nil {
		return err
	}
	var cl models.Cluster
	if err := db.DB.First(&cl, app.ClusterID).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "cluster not found"})
	}
	typed, _, err := clientsFor(&cl)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	user := ""
	if rev, err := typed.AuthenticationV1().SelfSubjectReviews().Create(ctx, &authnv1.SelfSubjectReview{}, metav1.CreateOptions{}); err == nil {
		user = rev.Status.UserInfo.Username
	}
	subject := "  - kind: ServiceAccount\n    name: <commitkube service account>\n    namespace: <commitkube namespace>"
	if parts := strings.Split(user, ":"); len(parts) == 4 && parts[0] == "system" && parts[1] == "serviceaccount" {
		subject = fmt.Sprintf("  - kind: ServiceAccount\n    name: %s\n    namespace: %s", parts[3], parts[2])
	} else if user != "" {
		subject = fmt.Sprintf("  - kind: User\n    name: %s\n    apiGroup: rbac.authorization.k8s.io", user)
	}
	if app.ClusterScope {
		return c.JSON(clusterScopeAccess(ctx, typed, user, subject))
	}

	var missing []string
	for _, g := range gitopsDeployerRules {
		for _, r := range g.Resources {
			for _, verb := range []string{"get", "patch", "delete"} {
				rev, err := typed.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authzv1.SelfSubjectAccessReview{
					Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authzv1.ResourceAttributes{
						Namespace: app.Namespace, Verb: verb, Group: g.Group, Resource: r,
					}},
				}, metav1.CreateOptions{})
				if err != nil || !rev.Status.Allowed {
					grp := g.Group
					if grp == "" {
						grp = "core"
					}
					missing = append(missing, fmt.Sprintf("%s %s/%s", verb, grp, r))
				}
			}
		}
	}

	var rules strings.Builder
	for _, g := range gitopsDeployerRules {
		fmt.Fprintf(&rules, "  - apiGroups: [%q]\n    resources: [%s]\n    verbs: [get, list, watch, create, update, patch, delete]\n", g.Group, strings.Join(g.Resources, ", "))
	}
	grant := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: commitkube-gitops-deployer
rules:
%s---
# The ClusterRole above grants nothing by itself; this binds it in one
# namespace. Repeat it for each namespace an application deploys to.
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: commitkube-gitops
  namespace: %s
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: commitkube-gitops-deployer
subjects:
%s
`, rules.String(), app.Namespace, subject)

	if missing == nil {
		missing = []string{}
	}
	return c.JSON(fiber.Map{"identity": user, "namespace": app.Namespace, "scope": "namespace", "missing": missing, "grant": grant})
}

// clusterScopeAccess is the access check for an application that may write
// anywhere: every verb it uses, on everything, cluster-wide. There is no
// narrower honest answer -- what such an application writes is decided by
// whoever commits to its repository.
func clusterScopeAccess(ctx context.Context, typed kubernetes.Interface, user, subject string) fiber.Map {
	missing := []string{}
	for _, verb := range []string{"get", "list", "create", "patch", "delete"} {
		rev, err := typed.AuthorizationV1().SelfSubjectAccessReviews().Create(ctx, &authzv1.SelfSubjectAccessReview{
			Spec: authzv1.SelfSubjectAccessReviewSpec{ResourceAttributes: &authzv1.ResourceAttributes{Verb: verb, Group: "*", Resource: "*"}},
		}, metav1.CreateOptions{})
		if err != nil || !rev.Status.Allowed {
			missing = append(missing, verb+" */* (cluster-wide)")
		}
	}
	grant := fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: commitkube-gitops-cluster
rules:
  - apiGroups: ["*"]
    resources: ["*"]
    verbs: [get, list, watch, create, update, patch, delete]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: commitkube-gitops-cluster
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: commitkube-gitops-cluster
subjects:
%s
`, subject)
	return fiber.Map{"identity": user, "namespace": "", "scope": "cluster", "missing": missing, "grant": grant}
}

// createGitopsAppForRepo is how a repository created from CommitKube gets
// deployed by it: one application for its manifest path, syncing on every
// commit. The namespace comes from the request, then the golden path.
func createGitopsAppForRepo(req *CreateRepoRequest, userID uint, manifestPath string, files *repoFiles) (*models.GitOpsApp, error) {
	ns := strings.TrimSpace(req.GitOpsNamespace)
	if ns == "" && files != nil && files.Golden != nil {
		ns = files.Golden.Namespace
	}
	if ns == "" {
		return nil, fmt.Errorf("no namespace to deploy to: choose one, or use a golden path that sets it")
	}
	cl, err := defaultCluster()
	if err != nil {
		return nil, err
	}
	branch := "main"
	if req.ExtraBranch != "" {
		branch = req.ExtraBranch
	}
	name := strings.ToLower(req.Name)
	if len(name) > 63 {
		name = name[:63]
	}
	app := models.GitOpsApp{
		Name: name, ClusterID: cl.ID, RepoName: req.Name, Branch: branch, Path: strings.Trim(manifestPath, "/."),
		Namespace: ns, AutoSync: true, SyncStatus: "Unknown", Health: GHealthUnknown, CreatedBy: userID,
	}
	if msg := validateGitopsApp(&app); msg != "" {
		return nil, fmt.Errorf("%s", msg)
	}
	if err := db.DB.Create(&app).Error; err != nil {
		return nil, fmt.Errorf("an application named %s already exists", app.Name)
	}
	go func() {
		if refreshGitopsApp(&app) == nil && app.SyncStatus == ResOutOfSync {
			_, _ = syncGitopsApp(&app, "auto", 0, "")
		}
	}()
	return &app, nil
}

func countPrefix(lines []string, prefix string) int {
	n := 0
	for _, l := range lines {
		if strings.HasPrefix(l, prefix) {
			n++
		}
	}
	return n
}
