package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/gofiber/fiber/v2"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/yaml"
)

// ResourceRow is the normalized shape every Kubernetes resource list returns,
// so a single frontend component can render any of them. Kind-specific columns
// go in Fields, keyed by the column id the frontend expects.
type ResourceRow struct {
	Name       string            `json:"name"`
	Namespace  string            `json:"namespace"`
	Age        string            `json:"age"`
	Status     string            `json:"status"`      // healthy | warning | critical | unknown
	StatusText string            `json:"status_text"` // human readable, e.g. "3/3 ready"
	Fields     map[string]string `json:"fields"`
}

// kindGVR maps the frontend's kind slug to the API resource, and records
// whether it is namespaced. Only kinds listed here can be browsed or have their
// manifest read -- an unknown kind is rejected rather than guessed.
var kindGVR = map[string]struct {
	GVR        schema.GroupVersionResource
	Namespaced bool
}{
	"namespaces":             {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "namespaces"}, false},
	"pods":                   {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "pods"}, true},
	"persistentvolumeclaims": {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "persistentvolumeclaims"}, true},
	"ingresses":              {schema.GroupVersionResource{Group: "networking.k8s.io", Version: "v1", Resource: "ingresses"}, true},
	"services":               {schema.GroupVersionResource{Group: "", Version: "v1", Resource: "services"}, true},
	"deployments":            {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "deployments"}, true},
	"replicasets":            {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "replicasets"}, true},
	"daemonsets":             {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "daemonsets"}, true},
	"statefulsets":           {schema.GroupVersionResource{Group: "apps", Version: "v1", Resource: "statefulsets"}, true},
}

// secretLikeKinds must never be served by the generic manifest endpoint: their
// manifests carry the very values that the Secrets page gates behind a password
// re-check. Serving them here would be a way around that gate.
var secretLikeKinds = map[string]bool{
	"secrets":         true,
	"externalsecrets": true,
	"serviceaccounts": true,
}

// podImage summarises a pod template's containers for a table cell: the first
// container's image, noting how many others there are rather than listing all.
func podImage(containers []corev1.Container) string {
	if len(containers) == 0 {
		return ""
	}
	img := containers[0].Image
	if n := len(containers) - 1; n > 0 {
		img += fmt.Sprintf(" (+%d)", n)
	}
	return img
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func readyStatus(ready, desired int64) (string, string) {
	text := fmt.Sprintf("%d/%d ready", ready, desired)
	switch {
	case desired == 0:
		return "unknown", text
	case ready == desired:
		return "healthy", text
	case ready == 0:
		return "critical", text
	default:
		return "warning", text
	}
}

// ListK8sResources returns a normalized list of one resource kind.
func ListK8sResources(c *fiber.Ctx) error {
	kind := strings.ToLower(c.Params("kind"))
	namespace := c.Query("namespace")

	entry, ok := kindGVR[kind]
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("unsupported resource kind %q", kind),
		})
	}
	if !entry.Namespaced {
		namespace = ""
	}

	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}

	ctx := context.Background()
	opts := metav1.ListOptions{}
	rows := []ResourceRow{}

	switch kind {
	case "namespaces":
		list, err := typed.CoreV1().Namespaces().List(ctx, opts)
		if err != nil {
			return k8sError(c, err)
		}
		// Pod counts make the namespace list actionable rather than decorative.
		podsByNS := map[string]int{}
		if pods, err := typed.CoreV1().Pods("").List(ctx, opts); err == nil {
			for i := range pods.Items {
				podsByNS[pods.Items[i].Namespace]++
			}
		}
		for i := range list.Items {
			ns := &list.Items[i]
			phase := string(ns.Status.Phase)
			status := "healthy"
			if phase != "Active" {
				status = "warning"
			}
			rows = append(rows, ResourceRow{
				Name: ns.Name, Age: shortAge(ns.CreationTimestamp.Time),
				Status: status, StatusText: phase,
				Fields: map[string]string{
					"phase": phase,
					"pods":  fmt.Sprintf("%d", podsByNS[ns.Name]),
				},
			})
		}

	case "ingresses":
		list, err := typed.NetworkingV1().Ingresses(namespace).List(ctx, opts)
		if err != nil {
			return k8sError(c, err)
		}
		for i := range list.Items {
			ing := &list.Items[i]

			hosts := []string{}
			backends := map[string]bool{}
			paths := 0
			for _, rule := range ing.Spec.Rules {
				if rule.Host != "" {
					hosts = append(hosts, rule.Host)
				}
				if rule.HTTP == nil {
					continue
				}
				for _, pth := range rule.HTTP.Paths {
					paths++
					if pth.Backend.Service != nil {
						backends[pth.Backend.Service.Name] = true
					}
				}
			}

			// The address is filled in by the ingress controller once it has
			// actually programmed the load balancer, so its absence is the
			// signal that an Ingress exists but is not serving yet.
			addresses := []string{}
			for _, lb := range ing.Status.LoadBalancer.Ingress {
				if lb.IP != "" {
					addresses = append(addresses, lb.IP)
				} else if lb.Hostname != "" {
					addresses = append(addresses, lb.Hostname)
				}
			}

			tlsHosts := 0
			for _, t := range ing.Spec.TLS {
				tlsHosts += len(t.Hosts)
			}

			class := ""
			if ing.Spec.IngressClassName != nil {
				class = *ing.Spec.IngressClassName
			} else if v, ok := ing.Annotations["kubernetes.io/ingress.class"]; ok {
				class = v + " (annotation)"
			}

			status, statusText := "healthy", "Serving"
			if len(addresses) == 0 {
				status, statusText = "warning", "No address assigned"
			}
			if paths == 0 {
				status, statusText = "warning", "No backend paths"
			}

			tls := "no"
			if len(ing.Spec.TLS) > 0 {
				tls = fmt.Sprintf("yes (%d host%s)", tlsHosts, plural(tlsHosts))
			}

			rows = append(rows, ResourceRow{
				Name: ing.Name, Namespace: ing.Namespace, Age: shortAge(ing.CreationTimestamp.Time),
				Status: status, StatusText: statusText,
				Fields: map[string]string{
					"class":    class,
					"hosts":    strings.Join(hosts, ", "),
					"paths":    strconv.Itoa(paths),
					"backends": strings.Join(sortedKeys(backends), ", "),
					"tls":      tls,
					"address":  strings.Join(addresses, ", "),
				},
			})
		}

	case "services":
		list, err := typed.CoreV1().Services(namespace).List(ctx, opts)
		if err != nil {
			return k8sError(c, err)
		}
		for i := range list.Items {
			svc := &list.Items[i]

			ports := []string{}
			for _, p := range svc.Spec.Ports {
				entry := strconv.Itoa(int(p.Port))
				if p.NodePort > 0 {
					entry += ":" + strconv.Itoa(int(p.NodePort))
				}
				ports = append(ports, entry+"/"+string(p.Protocol))
			}

			external := []string{}
			for _, lb := range svc.Status.LoadBalancer.Ingress {
				if lb.IP != "" {
					external = append(external, lb.IP)
				} else if lb.Hostname != "" {
					external = append(external, lb.Hostname)
				}
			}

			// A LoadBalancer with no external address is still being
			// provisioned; every other type is ready as soon as it exists.
			status, statusText := "healthy", string(svc.Spec.Type)
			if svc.Spec.Type == corev1.ServiceTypeLoadBalancer && len(external) == 0 {
				status, statusText = "warning", "LoadBalancer pending"
			}

			rows = append(rows, ResourceRow{
				Name: svc.Name, Namespace: svc.Namespace, Age: shortAge(svc.CreationTimestamp.Time),
				Status: status, StatusText: statusText,
				Fields: map[string]string{
					"type":       string(svc.Spec.Type),
					"clusterIP":  svc.Spec.ClusterIP,
					"externalIP": strings.Join(external, ", "),
					"ports":      strings.Join(ports, ", "),
				},
			})
		}

	case "deployments":
		list, err := typed.AppsV1().Deployments(namespace).List(ctx, opts)
		if err != nil {
			return k8sError(c, err)
		}
		for i := range list.Items {
			d := &list.Items[i]
			desired := int64(1)
			if d.Spec.Replicas != nil {
				desired = int64(*d.Spec.Replicas)
			}
			status, text := readyStatus(int64(d.Status.ReadyReplicas), desired)
			rows = append(rows, ResourceRow{
				Name: d.Name, Namespace: d.Namespace, Age: shortAge(d.CreationTimestamp.Time),
				Status: status, StatusText: text,
				Fields: map[string]string{
					"ready":     fmt.Sprintf("%d/%d", d.Status.ReadyReplicas, desired),
					"upToDate":  fmt.Sprintf("%d", d.Status.UpdatedReplicas),
					"available": fmt.Sprintf("%d", d.Status.AvailableReplicas),
					"image":     podImage((d.Spec.Template.Spec.Containers)),
				},
			})
		}

	case "replicasets":
		list, err := typed.AppsV1().ReplicaSets(namespace).List(ctx, opts)
		if err != nil {
			return k8sError(c, err)
		}
		for i := range list.Items {
			r := &list.Items[i]
			desired := int64(0)
			if r.Spec.Replicas != nil {
				desired = int64(*r.Spec.Replicas)
			}
			status, text := readyStatus(int64(r.Status.ReadyReplicas), desired)
			// A scaled-to-zero ReplicaSet is the normal resting state of a
			// superseded revision, not a problem.
			if desired == 0 {
				status, text = "unknown", "scaled to zero"
			}
			owner := ""
			if len(r.OwnerReferences) > 0 {
				owner = r.OwnerReferences[0].Name
			}
			rows = append(rows, ResourceRow{
				Name: r.Name, Namespace: r.Namespace, Age: shortAge(r.CreationTimestamp.Time),
				Status: status, StatusText: text,
				Fields: map[string]string{
					"desired": fmt.Sprintf("%d", desired),
					"current": fmt.Sprintf("%d", r.Status.Replicas),
					"ready":   fmt.Sprintf("%d", r.Status.ReadyReplicas),
					"owner":   owner,
					"image":   podImage((r.Spec.Template.Spec.Containers)),
				},
			})
		}

	case "daemonsets":
		list, err := typed.AppsV1().DaemonSets(namespace).List(ctx, opts)
		if err != nil {
			return k8sError(c, err)
		}
		for i := range list.Items {
			d := &list.Items[i]
			status, text := readyStatus(int64(d.Status.NumberReady), int64(d.Status.DesiredNumberScheduled))
			rows = append(rows, ResourceRow{
				Name: d.Name, Namespace: d.Namespace, Age: shortAge(d.CreationTimestamp.Time),
				Status: status, StatusText: text,
				Fields: map[string]string{
					"desired":   fmt.Sprintf("%d", d.Status.DesiredNumberScheduled),
					"current":   fmt.Sprintf("%d", d.Status.CurrentNumberScheduled),
					"ready":     fmt.Sprintf("%d", d.Status.NumberReady),
					"upToDate":  fmt.Sprintf("%d", d.Status.UpdatedNumberScheduled),
					"available": fmt.Sprintf("%d", d.Status.NumberAvailable),
					"image":     podImage((d.Spec.Template.Spec.Containers)),
				},
			})
		}

	case "statefulsets":
		list, err := typed.AppsV1().StatefulSets(namespace).List(ctx, opts)
		if err != nil {
			return k8sError(c, err)
		}
		for i := range list.Items {
			s := &list.Items[i]
			desired := int64(1)
			if s.Spec.Replicas != nil {
				desired = int64(*s.Spec.Replicas)
			}
			status, text := readyStatus(int64(s.Status.ReadyReplicas), desired)
			rows = append(rows, ResourceRow{
				Name: s.Name, Namespace: s.Namespace, Age: shortAge(s.CreationTimestamp.Time),
				Status: status, StatusText: text,
				Fields: map[string]string{
					"ready":   fmt.Sprintf("%d/%d", s.Status.ReadyReplicas, desired),
					"current": fmt.Sprintf("%d", s.Status.CurrentReplicas),
					"service": s.Spec.ServiceName,
					"image":   podImage((s.Spec.Template.Spec.Containers)),
				},
			})
		}

	case "persistentvolumeclaims":
		list, err := typed.CoreV1().PersistentVolumeClaims(namespace).List(ctx, opts)
		if err != nil {
			return k8sError(c, err)
		}
		for i := range list.Items {
			p := &list.Items[i]
			phase := string(p.Status.Phase)
			status := "unknown"
			switch phase {
			case "Bound":
				status = "healthy"
			case "Pending":
				status = "warning"
			case "Lost":
				status = "critical"
			}
			capacity := ""
			if q, ok := p.Status.Capacity["storage"]; ok {
				capacity = q.String()
			} else if q, ok := p.Spec.Resources.Requests["storage"]; ok {
				capacity = q.String() + " (requested)"
			}
			modes := make([]string, 0, len(p.Spec.AccessModes))
			for _, m := range p.Spec.AccessModes {
				modes = append(modes, string(m))
			}
			sc := ""
			if p.Spec.StorageClassName != nil {
				sc = *p.Spec.StorageClassName
			}
			rows = append(rows, ResourceRow{
				Name: p.Name, Namespace: p.Namespace, Age: shortAge(p.CreationTimestamp.Time),
				Status: status, StatusText: phase,
				Fields: map[string]string{
					"phase":        phase,
					"capacity":     capacity,
					"accessModes":  strings.Join(modes, ","),
					"storageClass": sc,
					"volume":       p.Spec.VolumeName,
				},
			})
		}

	default:
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("kind %q is registered but has no list implementation", kind),
		})
	}

	// Worst first, then by name, so problems surface without sorting.
	rank := map[string]int{"critical": 0, "warning": 1, "unknown": 2, "healthy": 3}
	sort.SliceStable(rows, func(i, j int) bool {
		ri, rj := rank[rows[i].Status], rank[rows[j].Status]
		if ri != rj {
			return ri < rj
		}
		if rows[i].Namespace != rows[j].Namespace {
			return rows[i].Namespace < rows[j].Namespace
		}
		return rows[i].Name < rows[j].Name
	})

	totals := map[string]int{"total": len(rows), "critical": 0, "warning": 0, "healthy": 0, "unknown": 0}
	for _, r := range rows {
		totals[r.Status]++
	}

	return c.JSON(fiber.Map{"kind": kind, "items": rows, "totals": totals})
}

// GetK8sManifest returns one resource as YAML, for the manifest viewer.
func GetK8sManifest(c *fiber.Ctx) error {
	kind := strings.ToLower(c.Params("kind"))
	name := c.Params("name")
	namespace := c.Query("namespace")

	if secretLikeKinds[kind] {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "manifests of secret-bearing resources are not served here; use the Secrets page, which re-checks your password",
		})
	}

	entry, ok := kindGVR[kind]
	if !ok {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": fmt.Sprintf("unsupported resource kind %q", kind),
		})
	}
	if name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "name is required"})
	}
	if entry.Namespaced && namespace == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace is required for " + kind})
	}
	if !entry.Namespaced {
		namespace = ""
	}

	_, dyn, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}

	// The dynamic client keeps apiVersion/kind on the object, which the typed
	// clients drop -- that matters for something presented as a manifest.
	obj, err := dyn.Resource(entry.GVR).Namespace(namespace).
		Get(context.Background(), name, metav1.GetOptions{})
	if err != nil {
		return k8sError(c, err)
	}

	// managedFields is server-side-apply bookkeeping: often larger than the
	// manifest itself and meaningless to a reader.
	if meta, ok := obj.Object["metadata"].(map[string]interface{}); ok {
		delete(meta, "managedFields")
	}

	raw, err := json.Marshal(obj.Object)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}
	out, err := yaml.JSONToYAML(raw)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": err.Error()})
	}

	return c.JSON(fiber.Map{
		"kind":      kind,
		"name":      name,
		"namespace": namespace,
		"manifest":  string(out),
	})
}

// ListK8sNamespaceNames is a lightweight list for populating namespace filters.
func ListK8sNamespaceNames(c *fiber.Ctx) error {
	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": "cannot connect to cluster: " + err.Error()})
	}
	list, err := typed.CoreV1().Namespaces().List(context.Background(), metav1.ListOptions{})
	if err != nil {
		return k8sError(c, err)
	}
	names := make([]string, 0, len(list.Items))
	for i := range list.Items {
		names = append(names, list.Items[i].Name)
	}
	sort.Strings(names)
	return c.JSON(fiber.Map{"namespaces": names})
}

// k8sError forwards an API error with a status the frontend can act on: a
// permissions problem needs a different message than an unreachable cluster.
func k8sError(c *fiber.Ctx, err error) error {
	msg := err.Error()
	status := fiber.StatusBadGateway
	if strings.Contains(msg, "is forbidden") {
		status = fiber.StatusForbidden
	} else if strings.Contains(msg, "not found") {
		status = fiber.StatusNotFound
	}
	return c.Status(status).JSON(fiber.Map{"error": msg})
}
