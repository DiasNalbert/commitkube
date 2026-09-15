package handlers

import (
	"context"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// Every cluster call used to resolve to the one credential this process
// happens to hold. This is the seam that replaces it: a handler asks for the
// cluster named in the request, a poller asks for one it is iterating, and
// neither reaches for an ambient identity any more.

var (
	clusterCacheMu sync.Mutex
	clusterCache   = map[uint]*cachedClients{}
)

type cachedClients struct {
	typed     *kubernetes.Clientset
	dynamic   dynamic.Interface
	builtFrom time.Time // the cluster row's UpdatedAt the clients were built from
}

// ambientRestConfig is the credential the process itself holds: the pod's
// ServiceAccount in-cluster, or KUBECONFIG outside it.
func ambientRestConfig() (*rest.Config, error) {
	cfg, err := rest.InClusterConfig()
	if err == nil {
		return cfg, nil
	}
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		kubeconfig = os.Getenv("HOME") + "/.kube/config"
	}
	cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	if err != nil {
		return nil, fmt.Errorf("not running in-cluster and no usable KUBECONFIG: %w", err)
	}
	return cfg, nil
}

func clusterRestConfig(cl *models.Cluster) (*rest.Config, error) {
	if cl.Local {
		return ambientRestConfig()
	}
	if cl.APIServer == "" {
		return nil, fmt.Errorf("cluster %q has no API server address", cl.Name)
	}
	cfg := &rest.Config{
		Host:        cl.APIServer,
		BearerToken: crypto.DecryptField(crypto.MasterKey(), cl.ServiceToken),
	}
	if cl.InsecureTLS {
		cfg.TLSClientConfig = rest.TLSClientConfig{Insecure: true}
	} else if cl.CACert != "" {
		cfg.TLSClientConfig = rest.TLSClientConfig{CAData: []byte(cl.CACert)}
	}
	return cfg, nil
}

// clientsFor returns the typed and dynamic clients for one cluster, rebuilding
// them when the row changed so an edited endpoint or a rotated token takes
// effect without a restart.
func clientsFor(cl *models.Cluster) (*kubernetes.Clientset, dynamic.Interface, error) {
	clusterCacheMu.Lock()
	defer clusterCacheMu.Unlock()

	if hit, ok := clusterCache[cl.ID]; ok && hit.builtFrom.Equal(cl.UpdatedAt) {
		return hit.typed, hit.dynamic, nil
	}

	cfg, err := clusterRestConfig(cl)
	if err != nil {
		return nil, nil, err
	}
	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}

	clusterCache[cl.ID] = &cachedClients{typed: typed, dynamic: dyn, builtFrom: cl.UpdatedAt}
	return typed, dyn, nil
}

// EnsureDefaultCluster registers the ambient credential as a cluster row the
// first time the process starts. Without it an existing install would come up
// with no clusters and every Kubernetes page would go blank -- the migration
// has to be invisible.
func EnsureDefaultCluster() {
	var count int64
	db.DB.Model(&models.Cluster{}).Count(&count)
	if count > 0 {
		return
	}
	name := os.Getenv("DEFAULT_CLUSTER_NAME")
	if name == "" {
		name = "in-cluster"
	}
	cl := models.Cluster{Name: name, Local: true, IsDefault: true}
	if err := db.DB.Create(&cl).Error; err != nil {
		fmt.Printf("could not register the default cluster: %v\n", err)
		return
	}
	fmt.Printf("registered %q as the default cluster, using this process's own credential\n", name)
}

// defaultCluster is what a request without an explicit cluster gets, and what
// the pollers collect from.
func defaultCluster() (*models.Cluster, error) {
	var cl models.Cluster
	if err := db.DB.Where("is_default = ?", true).First(&cl).Error; err == nil {
		return &cl, nil
	}
	if err := db.DB.Order("id asc").First(&cl).Error; err != nil {
		return nil, fmt.Errorf("no cluster is configured")
	}
	return &cl, nil
}

// clusterFromRequest resolves ?cluster=<id|name>, falling back to the default
// so every existing caller keeps working untouched.
func clusterFromRequest(c *fiber.Ctx) (*models.Cluster, error) {
	ref := c.Query("cluster")
	if ref == "" {
		return defaultCluster()
	}
	var cl models.Cluster
	q := db.DB.Where("name = ?", ref)
	if id := c.QueryInt("cluster", 0); id > 0 {
		q = db.DB.Where("id = ?", id)
	}
	if err := q.First(&cl).Error; err != nil {
		return nil, fmt.Errorf("unknown cluster %q", ref)
	}
	return &cl, nil
}

// requestClients is what a Fiber handler calls instead of building its own.
//
// With impersonation on, every live call a request makes -- listing pods,
// reading a manifest, tailing a log, deleting something -- carries the
// caller's identity, and the cluster decides. With it off, this is the
// collector, exactly as before.
//
// What this cannot cover is the data the pollers already collected. That was
// read with the collector's credential before any request existed, so Triage,
// the service map and the stored history are protected by CommitKube's
// namespace filter and nothing else. The two guarantees are different and the
// UI says so.
func requestClients(c *fiber.Ctx) (*kubernetes.Clientset, dynamic.Interface, error) {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return nil, nil, err
	}
	if !cl.Impersonate {
		return clientsFor(cl)
	}

	cfg, err := clusterRestConfig(cl)
	if err != nil {
		return nil, nil, err
	}
	imp, err := impersonationFor(c)
	if err != nil {
		return nil, nil, err
	}
	// Built per request, never cached: the identity is part of the config, and
	// a cached client would carry the previous caller's. The underlying
	// connection pool is still shared, keyed on the TLS config.
	cfg = rest.CopyConfig(cfg)
	cfg.Impersonate = imp

	typed, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	dyn, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, nil, err
	}
	return typed, dyn, nil
}

// requestClusterID is what a read of collected data scopes itself by. Every
// query against a collector table must carry it: the rows of a second cluster
// are in the same tables, and without the filter they surface on the first
// cluster's page.
func requestClusterID(c *fiber.Ctx) (uint, error) {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return 0, err
	}
	return cl.ID, nil
}

// listNamespaces says which namespaces a listing should actually query.
//
// A cluster-wide List is a cluster-scoped permission. A RoleBinding in one
// namespace permits Pods("apis").List() and nothing wider, so once
// impersonation is on, the old "list everything, then filter" stops working
// for exactly the people it was meant to protect. Querying the scoped
// namespaces one at a time is both what the cluster will allow and what makes
// the two policies agree: the scope decides what we ask for, the cluster
// decides whether we may have it.
//
// The empty string means one cluster-wide call, which is right for an
// unscoped account and for every cluster that is not impersonating.
func listNamespaces(c *fiber.Ctx) ([]string, error) {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return nil, err
	}
	if !cl.Impersonate {
		return []string{""}, nil
	}
	allowed, restricted, err := requestNamespaces(c)
	if err != nil {
		return nil, err
	}
	if !restricted {
		return []string{""}, nil
	}
	return allowed, nil
}

// requestTyped is requestClients for the handlers that only need the typed
// client, which is most of them.
func requestTyped(c *fiber.Ctx) (*kubernetes.Clientset, error) {
	typed, _, err := requestClients(c)
	return typed, err
}

// collectorClients is what a background poller calls: no request, no user,
// the cluster's own service identity.
func collectorClients(cl *models.Cluster) (*kubernetes.Clientset, dynamic.Interface, error) {
	return clientsFor(cl)
}

// allClusters is the iteration a poller does; today they collect from the
// default cluster only, and this is where that widens.
func allClusters() []models.Cluster {
	var list []models.Cluster
	db.DB.Order("id asc").Find(&list)
	return list
}

func clusterUnreachable(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
}

// ---- HTTP -----------------------------------------------------------------

// ListClusters powers the cluster selector. It reports reachability so a
// misconfigured cluster is visible as such instead of as an empty page.
func ListClusters(c *fiber.Ctx) error {
	list := allClusters()
	out := make([]fiber.Map, 0, len(list))
	for i := range list {
		cl := &list[i]
		row := fiber.Map{
			"id": cl.ID, "name": cl.Name, "local": cl.Local,
			"api_server": cl.APIServer, "is_default": cl.IsDefault,
			"impersonate":     cl.Impersonate,
			"can_manage_rbac": cl.CanManageRBAC,
		}
		if typed, _, err := clientsFor(cl); err != nil {
			row["reachable"], row["error"] = false, err.Error()
		} else if v, err := typed.Discovery().ServerVersion(); err != nil {
			row["reachable"], row["error"] = false, err.Error()
		} else {
			row["reachable"], row["version"] = true, v.GitVersion
		}
		out = append(out, row)
	}
	return c.JSON(fiber.Map{"clusters": out})
}

// CreateCluster imports a cluster. The token given here is the collector
// identity, so it needs read across the cluster and nothing more.
func CreateCluster(c *fiber.Ctx) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	var req struct {
		Name        string `json:"name"`
		APIServer   string `json:"api_server"`
		CACert      string `json:"ca_cert"`
		Token       string `json:"token"`
		InsecureTLS bool   `json:"insecure_tls"`
	}
	if err := c.BodyParser(&req); err != nil || req.Name == "" || req.APIServer == "" || req.Token == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "name, api_server and token are required",
		})
	}

	cl := models.Cluster{
		Name:         req.Name,
		APIServer:    req.APIServer,
		CACert:       req.CACert,
		ServiceToken: crypto.EncryptField(crypto.MasterKey(), req.Token),
		InsecureTLS:  req.InsecureTLS,
		CreatedBy:    currentUserID(c),
	}

	// Reject a cluster that cannot be reached: storing it would turn one bad
	// paste into a page that fails much later, far from the cause.
	typed, _, err := func() (*kubernetes.Clientset, dynamic.Interface, error) {
		cfg, err := clusterRestConfig(&cl)
		if err != nil {
			return nil, nil, err
		}
		t, err := kubernetes.NewForConfig(cfg)
		return t, nil, err
	}()
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := typed.CoreV1().Namespaces().List(ctx, metav1.ListOptions{Limit: 1}); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "could not read the cluster with that token: " + err.Error(),
		})
	}

	if err := db.DB.Create(&cl).Error; err != nil {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{"error": "a cluster with that name already exists"})
	}
	db.LogAudit(currentUserID(c), "create_cluster", "cluster", cl.Name, "", c.IP())
	return c.Status(fiber.StatusCreated).JSON(fiber.Map{"id": cl.ID, "name": cl.Name})
}

func DeleteCluster(c *fiber.Ctx) error {
	if err := requireAdmin(c); err != nil {
		return err
	}
	var cl models.Cluster
	if err := db.DB.First(&cl, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "cluster not found"})
	}
	if cl.Local {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "the local cluster is this process's own credential and cannot be removed",
		})
	}
	db.DB.Delete(&cl)

	clusterCacheMu.Lock()
	delete(clusterCache, cl.ID)
	clusterCacheMu.Unlock()

	db.LogAudit(currentUserID(c), "delete_cluster", "cluster", cl.Name, "", c.IP())
	return c.JSON(fiber.Map{"message": "cluster removed"})
}

// ---- impersonation --------------------------------------------------------

// Reads run as the collector, which is the Dynatrace-shaped half of this
// design: one identity gathers everything and CommitKube decides who sees
// what. Writes cannot work that way. A delete that runs as the collector is
// attributed to the collector in the cluster's audit log, and its blast radius
// is the collector's, not the person's. Impersonation fixes both without a
// credential per user: the API server evaluates RBAC against the impersonated
// identity, and records who did the impersonating.

// ImpersonationName is the cluster identity for one CommitKube user. The email
// is used verbatim so a cluster audit entry names a person rather than a row
// id that only this database can resolve.
func ImpersonationName(email string) string { return "ck:" + email }

// ImpersonationGroup is the cluster identity for a CommitKube group, and the
// thing RoleBindings actually name -- binding per group keeps the number of
// cluster objects fixed as people come and go.
func ImpersonationGroup(name string) string { return "ck:group:" + name }

// impersonationFor builds the identity a request should act as.
func impersonationFor(c *fiber.Ctx) (rest.ImpersonationConfig, error) {
	var user models.User
	if err := db.DB.First(&user, currentUserID(c)).Error; err != nil {
		return rest.ImpersonationConfig{}, fmt.Errorf("cannot resolve the calling user")
	}

	var groupNames []string
	db.DB.Model(&models.UserGroup{}).
		Where("id IN (?)", db.DB.Model(&models.UserGroupMember{}).
			Select("group_id").Where("user_id = ?", user.ID)).
		Pluck("name", &groupNames)

	groups := make([]string, 0, len(groupNames))
	for _, g := range groupNames {
		groups = append(groups, ImpersonationGroup(g))
	}
	return rest.ImpersonationConfig{UserName: ImpersonationName(user.Email), Groups: groups}, nil
}

// writeClients is requestClients for the mutating handlers. Kept as its own
// name because a reader scanning a delete wants to see that the identity was
// considered, not have to know that requestClients handles it.
func writeClients(c *fiber.Ctx) (*kubernetes.Clientset, error) {
	typed, _, err := requestClients(c)
	return typed, err
}

// UpdateClusterFlags toggles the two switches that change how much this
// product is trusted with. Behind iam.manage, so only root reaches them.
func UpdateClusterFlags(c *fiber.Ctx) error {
	var cl models.Cluster
	if err := db.DB.First(&cl, c.Params("id")).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "cluster not found"})
	}
	var req struct {
		Impersonate   *bool `json:"impersonate"`
		CanManageRBAC *bool `json:"can_manage_rbac"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}

	updates := map[string]interface{}{}
	if req.Impersonate != nil {
		updates["impersonate"] = *req.Impersonate
	}
	if req.CanManageRBAC != nil {
		updates["can_manage_rbac"] = *req.CanManageRBAC
	}
	if len(updates) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "nothing to change"})
	}
	db.DB.Model(&cl).Updates(updates)

	// Both switches widen what the product may do, so they are worth an audit
	// entry naming who flipped them.
	db.LogAudit(currentUserID(c), "update_cluster_flags", "cluster", cl.Name,
		fmt.Sprintf("%v", updates), c.IP())
	return c.JSON(fiber.Map{"message": "cluster updated"})
}
