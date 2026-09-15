package handlers

import (
	"context"
	"fmt"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"golang.org/x/crypto/bcrypt"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var externalSecretGVR = schema.GroupVersionResource{
	Group:    "external-secrets.io",
	Version:  "v1beta1",
	Resource: "externalsecrets",
}

type ExternalSecretItem struct {
	Name      string   `json:"name"`
	Namespace string   `json:"namespace"`
	Store     string   `json:"store"`
	Keys      []string `json:"keys"`
}

type K8sSecretItem struct {
	Name      string            `json:"name"`
	Namespace string            `json:"namespace"`
	Type      string            `json:"type"`
	Keys      []string          `json:"keys"`
	Values    map[string]string `json:"values"`
}

type SecretsListResponse struct {
	ExternalSecrets      []ExternalSecretItem `json:"external_secrets"`
	KubernetesSecrets    []K8sSecretItem      `json:"kubernetes_secrets"`
	ExternalSecretsError string               `json:"external_secrets_error,omitempty"`
}

// buildK8sClients is the pre-multicluster entry point, kept for callers that
// have no request to resolve a cluster from -- the background pollers. It now
// goes through the default cluster row rather than reaching for the ambient
// credential directly. A handler serving a user should call requestClients
// instead, so ?cluster= is honoured.
func buildK8sClients() (kubernetes.Interface, dynamic.Interface, error) {
	cl, err := defaultCluster()
	if err != nil {
		return nil, nil, err
	}
	return clientsFor(cl)
}

func verifyCurrentUserPassword(c *fiber.Ctx, password string) (*models.User, error) {
	userID := uint(c.Locals("user_id").(float64))
	var user models.User
	if err := db.DB.First(&user, userID).Error; err != nil {
		return nil, err
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		return nil, fiber.NewError(fiber.StatusUnauthorized, "invalid password")
	}
	return &user, nil
}

func ListSecrets(c *fiber.Ctx) error {
	var req struct {
		Password  string `json:"password"`
		Namespace string `json:"namespace"`
	}
	if err := c.BodyParser(&req); err != nil || req.Password == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "password required"})
	}

	if _, err := verifyCurrentUserPassword(c, req.Password); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid password"})
	}

	typed, dyn, err := requestClients(c)
	if err != nil {
		return c.Status(503).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}

	ns := req.Namespace

	// list ExternalSecrets
	var extItems []ExternalSecretItem
	var extSecretsErr string
	esList, esErr := dyn.Resource(externalSecretGVR).Namespace(ns).List(context.Background(), metav1.ListOptions{})
	if esErr != nil {
		extSecretsErr = esErr.Error()
	} else {
		for _, obj := range esList.Items {
			meta := obj.Object["metadata"].(map[string]interface{})
			spec, _ := obj.Object["spec"].(map[string]interface{})

			name, _ := meta["name"].(string)
			namespace, _ := meta["namespace"].(string)

			store := ""
			if ss, ok := spec["secretStoreRef"].(map[string]interface{}); ok {
				store, _ = ss["name"].(string)
			}

			var keys []string
			if dataArr, ok := spec["data"].([]interface{}); ok {
				for _, d := range dataArr {
					dm, _ := d.(map[string]interface{})
					if k, ok := dm["secretKey"].(string); ok {
						keys = append(keys, k)
					}
				}
			}
			if dataFrom, ok := spec["dataFrom"].([]interface{}); ok && len(dataFrom) > 0 {
				keys = append(keys, "*")
			}
			if keys == nil {
				keys = []string{}
			}

			extItems = append(extItems, ExternalSecretItem{
				Name:      name,
				Namespace: namespace,
				Store:     store,
				Keys:      keys,
			})
		}
	}
	if extItems == nil {
		extItems = []ExternalSecretItem{}
	}

	// list Kubernetes Secrets
	var k8sItems []K8sSecretItem
	secretList, err := typed.CoreV1().Secrets(ns).List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"error": "failed to list secrets: " + err.Error()})
	}

	scopedNS, restricted, scopeErr := requestNamespaces(c)
	if scopeErr != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": scopeErr.Error()})
	}
	permitted := map[string]bool{}
	for _, ns := range scopedNS {
		permitted[ns] = true
	}

	for _, s := range secretList.Items {
		if restricted && !permitted[s.Namespace] {
			continue
		}
		var keys []string
		values := make(map[string]string)
		for k := range s.Data {
			keys = append(keys, k)
			values[k] = "••••••••"
		}
		if keys == nil {
			keys = []string{}
		}
		k8sItems = append(k8sItems, K8sSecretItem{
			Name:      s.Name,
			Namespace: s.Namespace,
			Type:      string(s.Type),
			Keys:      keys,
			Values:    values,
		})
	}
	if k8sItems == nil {
		k8sItems = []K8sSecretItem{}
	}

	return c.JSON(SecretsListResponse{
		ExternalSecrets:      extItems,
		KubernetesSecrets:    k8sItems,
		ExternalSecretsError: extSecretsErr,
	})
}

func RevealSecretValue(c *fiber.Ctx) error {
	role, _ := c.Locals("role").(string)
	if role != "root" && role != "admin" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{"error": "only admins can reveal secret values"})
	}

	var req struct {
		Password  string `json:"password"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Key       string `json:"key"`
	}
	if err := c.BodyParser(&req); err != nil || req.Password == "" || req.Namespace == "" || req.Name == "" || req.Key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "password, namespace, name and key required"})
	}

	if _, err := verifyCurrentUserPassword(c, req.Password); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid password"})
	}

	if !namespaceAllowed(c, req.Namespace) {
		return forbidNamespace(c)
	}

	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(503).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}

	secret, err := typed.CoreV1().Secrets(req.Namespace).Get(context.Background(), req.Name, metav1.GetOptions{})
	if err != nil {
		return c.Status(404).JSON(fiber.Map{"error": "secret not found"})
	}

	data, ok := secret.Data[req.Key]
	if !ok {
		return c.Status(404).JSON(fiber.Map{"error": "key not found in secret"})
	}

	return c.JSON(fiber.Map{"value": string(data)})
}

// systemSecretTypes are the Secrets Kubernetes maintains for itself. Editing a
// ServiceAccount token by hand does not rotate anything -- it breaks the thing
// that was using it, in a way that surfaces much later as a confusing auth
// error somewhere else entirely.
var systemSecretTypes = map[corev1.SecretType]bool{
	corev1.SecretTypeServiceAccountToken: true,
	"bootstrap.kubernetes.io/token":      true,
	"helm.sh/release.v1":                 true,
}

// externalSecretOwner reports whether something else is the source of truth for
// this Secret. External Secrets Operator rewrites the Secret on every refresh,
// so an edit made here is reverted on a schedule nobody remembers -- the change
// looks like it worked and undoes itself hours later.
func externalSecretOwner(secret *corev1.Secret) string {
	for _, ref := range secret.OwnerReferences {
		if ref.Kind == "ExternalSecret" {
			return ref.Name
		}
	}
	if v, ok := secret.Annotations["reconcile.external-secrets.io/managed"]; ok && v == "true" {
		return secret.Name
	}
	return ""
}

// UpdateSecretValue changes one key of one Secret.
//
// Gated like the reveal and then some: the permission, the caller's password
// again, and the namespace scope. Writing a credential into a running cluster
// is the most consequential thing this product can do -- every other write
// changes what runs, this changes what it can reach.
func UpdateSecretValue(c *fiber.Ctx) error {
	var req struct {
		Password  string `json:"password"`
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Key       string `json:"key"`
		Value     string `json:"value"`
		// AcknowledgeManaged is the caller saying they know an operator owns
		// this Secret and will overwrite the change.
		AcknowledgeManaged bool `json:"acknowledge_managed"`
		// AllowNewKey separates adding from editing. Without it a mistyped key
		// silently becomes a new one that looks right in the listing and is
		// read by nothing.
		AllowNewKey bool `json:"allow_new_key"`
	}
	if err := c.BodyParser(&req); err != nil ||
		req.Password == "" || req.Namespace == "" || req.Name == "" || req.Key == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "password, namespace, name and key are required",
		})
	}

	if _, err := verifyCurrentUserPassword(c, req.Password); err != nil {
		return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{"error": "invalid password"})
	}
	if !namespaceAllowed(c, req.Namespace) {
		return forbidNamespace(c)
	}

	// Writes go as the caller when the cluster is deciding, so this is refused
	// twice on a cluster with impersonation on: here, and by Kubernetes.
	typed, err := writeClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}

	ctx := context.Background()
	secret, err := typed.CoreV1().Secrets(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
	if err != nil {
		return k8sError(c, err)
	}

	if systemSecretTypes[secret.Type] {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("this Secret is of type %s, which Kubernetes maintains itself; editing it breaks the thing using it rather than rotating anything", secret.Type),
		})
	}
	if owner := externalSecretOwner(secret); owner != "" && !req.AcknowledgeManaged {
		return c.Status(fiber.StatusConflict).JSON(fiber.Map{
			"error":         fmt.Sprintf("this Secret is managed by the ExternalSecret %q, which rewrites it on every refresh; the change would be reverted", owner),
			"managed_by":    owner,
			"needs_consent": true,
		})
	}
	_, existing := secret.Data[req.Key]
	if !existing && !req.AllowNewKey {
		// Refusing by default turns a typo into an error instead of into a
		// second key that looks right in a list and is read by nothing.
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": fmt.Sprintf("there is no key %q in this Secret", req.Key),
		})
	}

	if secret.Data == nil {
		secret.Data = map[string][]byte{}
	}
	secret.Data[req.Key] = []byte(req.Value)

	if _, err := typed.CoreV1().Secrets(req.Namespace).Update(ctx, secret, metav1.UpdateOptions{}); err != nil {
		return k8sError(c, err)
	}

	// The value is never logged, only that it changed and by whom. A value in
	// an audit row is the credential in a second place.
	action := "update_secret"
	if !existing {
		action = "add_secret_key"
	}
	db.LogAudit(currentUserID(c), action, "secret", req.Namespace+"/"+req.Name,
		fmt.Sprintf(`{"key":"%s"}`, req.Key), c.IP())

	message := "value updated"
	if !existing {
		message = "key added"
	}
	return c.JSON(fiber.Map{
		"message": message,
		// Pods do not reload a Secret they already mounted as env vars, and
		// saying so here saves the hour spent wondering why nothing changed.
		"note": "workloads that read this Secret as environment variables keep the old value until their pods restart",
	})
}
