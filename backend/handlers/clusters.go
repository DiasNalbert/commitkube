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
func requestClients(c *fiber.Ctx) (*kubernetes.Clientset, dynamic.Interface, error) {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return nil, nil, err
	}
	return clientsFor(cl)
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
