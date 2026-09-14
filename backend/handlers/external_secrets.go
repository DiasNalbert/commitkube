package handlers

import (
	"context"
	"os"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"golang.org/x/crypto/bcrypt"
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

func buildK8sClients() (kubernetes.Interface, dynamic.Interface, error) {
	cfg, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := os.Getenv("KUBECONFIG")
		if kubeconfig == "" {
			kubeconfig = os.Getenv("HOME") + "/.kube/config"
		}
		cfg, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			return nil, nil, err
		}
	}
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

	typed, dyn, err := buildK8sClients()
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

	for _, s := range secretList.Items {
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

	typed, _, err := buildK8sClients()
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
