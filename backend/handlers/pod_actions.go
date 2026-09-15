package handlers

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// requireAdmin gates the mutating pod actions. Deleting or scaling a workload
// is not something a read-only user should reach through the UI.
func requireAdmin(c *fiber.Ctx) error {
	role, _ := c.Locals("role").(string)
	if role != "root" && role != "admin" {
		return c.Status(fiber.StatusForbidden).JSON(fiber.Map{
			"error": "only admins can perform this action",
		})
	}
	return nil
}

func currentUserID(c *fiber.Ctx) uint {
	if v, ok := c.Locals("user_id").(float64); ok {
		return uint(v)
	}
	return 0
}

func podLogOptions(c *fiber.Ctx, follow bool) *corev1.PodLogOptions {
	tail := int64(c.QueryInt("tail", 200))
	opts := &corev1.PodLogOptions{
		Container:  c.Query("container"),
		Follow:     follow,
		Timestamps: true,
		TailLines:  &tail,
	}
	// Reading the previous container's log is the only way to see why a pod in
	// CrashLoopBackOff died, since the current container may not be up yet.
	if c.Query("previous") == "true" {
		opts.Previous = true
		opts.Follow = false
	}
	return opts
}

// GetPodLogs returns a fixed slice of a pod's log, read from the kubelet via
// the API server rather than through ArgoCD.
func GetPodLogs(c *fiber.Ctx) error {
	namespace := c.Query("namespace")
	if !namespaceAllowed(c, namespace) {
		return forbidNamespace(c)
	}
	name := c.Query("pod")
	if namespace == "" || name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace and pod are required"})
	}

	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	raw, err := typed.CoreV1().Pods(namespace).
		GetLogs(name, podLogOptions(c, false)).
		DoRaw(context.Background())
	if err != nil {
		return k8sError(c, err)
	}

	return c.JSON(fiber.Map{"logs": string(raw)})
}

// StreamPodLogs follows a pod's log and relays it as Server-Sent Events, so the
// UI shows new lines as the container writes them.
func StreamPodLogs(c *fiber.Ctx) error {
	namespace := c.Query("namespace")
	if !namespaceAllowed(c, namespace) {
		return forbidNamespace(c)
	}
	name := c.Query("pod")
	if namespace == "" || name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace and pod are required"})
	}

	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	stream, err := typed.CoreV1().Pods(namespace).
		GetLogs(name, podLogOptions(c, true)).
		Stream(context.Background())
	if err != nil {
		return k8sError(c, err)
	}

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no") // nginx would otherwise buffer the stream

	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer stream.Close()

		lines := make(chan string, 256)
		done := make(chan struct{})
		defer close(done)

		go func() {
			defer close(lines)
			scanner := bufio.NewScanner(stream)
			scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
			for scanner.Scan() {
				select {
				case lines <- scanner.Text():
				case <-done:
					return // writer gave up; do not block on the send
				}
			}
		}()

		// nginx drops an idle proxied response after proxy_read_timeout (300s in
		// nginx.conf), which would silently kill the stream of any pod that logs
		// less than once every five minutes. An SSE comment frame keeps the
		// connection alive and is ignored by the client parser.
		keepalive := time.NewTicker(25 * time.Second)
		defer keepalive.Stop()

		for {
			select {
			case line, ok := <-lines:
				if !ok {
					fmt.Fprintf(w, "event: done\ndata: {}\n\n")
					w.Flush()
					return
				}
				if strings.TrimSpace(line) == "" {
					continue
				}
				// The kubelet prefixes an RFC3339 timestamp when Timestamps is
				// set; split it out so the UI can style it apart from the message.
				ts, msg := "", line
				if i := strings.IndexByte(line, ' '); i > 0 {
					if _, err := time.Parse(time.RFC3339Nano, line[:i]); err == nil {
						ts, msg = line[:i], line[i+1:]
					}
				}
				data, _ := json.Marshal(map[string]string{"timestamp": ts, "content": msg})
				if _, err := fmt.Fprintf(w, "data: %s\n\n", data); err != nil {
					return // client disconnected
				}
				if err := w.Flush(); err != nil {
					return
				}

			case <-keepalive.C:
				if _, err := fmt.Fprint(w, ": keepalive\n\n"); err != nil {
					return
				}
				if err := w.Flush(); err != nil {
					return
				}
			}
		}
	})
	return nil
}

// DeletePod removes a single pod. A pod owned by a controller is recreated
// automatically; a bare pod is gone for good, which the response makes explicit
// so the UI can say which of the two happened.
func DeletePod(c *fiber.Ctx) error {
	if err := requireAdmin(c); err != nil {
		return err
	}

	namespace := c.Query("namespace")
	if !namespaceAllowed(c, namespace) {
		return forbidNamespace(c)
	}
	name := c.Query("pod")
	if namespace == "" || name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace and pod are required"})
	}

	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	ctx := context.Background()
	pod, err := typed.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return k8sError(c, err)
	}
	managed := len(pod.OwnerReferences) > 0

	if err := typed.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return k8sError(c, err)
	}

	db.LogAudit(currentUserID(c), "delete_pod", "pod", namespace+"/"+name,
		fmt.Sprintf("managed=%t", managed), c.IP())

	msg := fmt.Sprintf("Pod %s deleted", name)
	if managed {
		msg += " — its controller will recreate it"
	} else {
		msg += " — it had no controller, so it will not come back"
	}
	return c.JSON(fiber.Map{"message": msg, "managed": managed})
}

// RestartPod deletes the pod so its controller recreates it. Kubernetes has no
// restart verb for a pod: this is what `kubectl delete pod` achieves, and the
// endpoint is named for the intent rather than the mechanism.
func RestartPod(c *fiber.Ctx) error {
	if err := requireAdmin(c); err != nil {
		return err
	}

	namespace := c.Query("namespace")
	if !namespaceAllowed(c, namespace) {
		return forbidNamespace(c)
	}
	name := c.Query("pod")
	if namespace == "" || name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace and pod are required"})
	}

	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	ctx := context.Background()
	pod, err := typed.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return k8sError(c, err)
	}
	// Without a controller nothing would recreate the pod, so a "restart" would
	// silently be a deletion. Refuse instead of destroying the workload.
	if len(pod.OwnerReferences) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"error": "this pod has no controller, so deleting it would not restart it; use Delete if that is what you intend",
		})
	}

	if err := typed.CoreV1().Pods(namespace).Delete(ctx, name, metav1.DeleteOptions{}); err != nil {
		return k8sError(c, err)
	}

	db.LogAudit(currentUserID(c), "restart_pod", "pod", namespace+"/"+name, "", c.IP())
	return c.JSON(fiber.Map{"message": fmt.Sprintf("Pod %s is restarting", name)})
}

// resolveScalable walks a pod's ownership chain to the workload that actually
// carries a replica count. A pod is never scaled directly.
func resolveScalable(ctx context.Context, typed kubernetes.Interface, namespace string, pod *corev1.Pod) (kind, name string, err error) {
	if len(pod.OwnerReferences) == 0 {
		return "", "", fmt.Errorf("pod has no controller, so there is nothing to scale")
	}
	owner := pod.OwnerReferences[0]

	switch owner.Kind {
	case "ReplicaSet":
		rs, err := typed.AppsV1().ReplicaSets(namespace).Get(ctx, owner.Name, metav1.GetOptions{})
		if err != nil {
			return "", "", err
		}
		// A ReplicaSet is normally itself owned by a Deployment; scaling the
		// ReplicaSet directly would be undone by the Deployment controller.
		if len(rs.OwnerReferences) > 0 && rs.OwnerReferences[0].Kind == "Deployment" {
			return "Deployment", rs.OwnerReferences[0].Name, nil
		}
		return "ReplicaSet", owner.Name, nil
	case "StatefulSet":
		return "StatefulSet", owner.Name, nil
	case "DaemonSet":
		return "", "", fmt.Errorf("a DaemonSet runs one pod per node and cannot be scaled by replica count")
	case "Job", "CronJob":
		return "", "", fmt.Errorf("%s pods are not scaled by replica count", owner.Kind)
	default:
		return "", "", fmt.Errorf("owner kind %s is not scalable from here", owner.Kind)
	}
}

// ScalePodWorkload sets the replica count of the workload owning a pod.
func ScalePodWorkload(c *fiber.Ctx) error {
	if err := requireAdmin(c); err != nil {
		return err
	}

	var req struct {
		Namespace string `json:"namespace"`
		Pod       string `json:"pod"`
		Replicas  *int32 `json:"replicas"`
	}
	if err := c.BodyParser(&req); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body"})
	}
	if req.Namespace == "" || req.Pod == "" || req.Replicas == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace, pod and replicas are required"})
	}
	if *req.Replicas < 0 || *req.Replicas > 100 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "replicas must be between 0 and 100"})
	}

	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	ctx := context.Background()
	if !namespaceAllowed(c, req.Namespace) {
		return forbidNamespace(c)
	}

	pod, err := typed.CoreV1().Pods(req.Namespace).Get(ctx, req.Pod, metav1.GetOptions{})
	if err != nil {
		return k8sError(c, err)
	}

	kind, name, err := resolveScalable(ctx, typed, req.Namespace, pod)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}

	scale := &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: req.Namespace},
		Spec:       autoscalingv1.ScaleSpec{Replicas: *req.Replicas},
	}

	var previous int32
	switch kind {
	case "Deployment":
		cur, err := typed.AppsV1().Deployments(req.Namespace).GetScale(ctx, name, metav1.GetOptions{})
		if err != nil {
			return k8sError(c, err)
		}
		previous = cur.Spec.Replicas
		if _, err := typed.AppsV1().Deployments(req.Namespace).UpdateScale(ctx, name, scale, metav1.UpdateOptions{}); err != nil {
			return k8sError(c, err)
		}
	case "StatefulSet":
		cur, err := typed.AppsV1().StatefulSets(req.Namespace).GetScale(ctx, name, metav1.GetOptions{})
		if err != nil {
			return k8sError(c, err)
		}
		previous = cur.Spec.Replicas
		if _, err := typed.AppsV1().StatefulSets(req.Namespace).UpdateScale(ctx, name, scale, metav1.UpdateOptions{}); err != nil {
			return k8sError(c, err)
		}
	case "ReplicaSet":
		cur, err := typed.AppsV1().ReplicaSets(req.Namespace).GetScale(ctx, name, metav1.GetOptions{})
		if err != nil {
			return k8sError(c, err)
		}
		previous = cur.Spec.Replicas
		if _, err := typed.AppsV1().ReplicaSets(req.Namespace).UpdateScale(ctx, name, scale, metav1.UpdateOptions{}); err != nil {
			return k8sError(c, err)
		}
	}

	db.LogAudit(currentUserID(c), "scale_workload", strings.ToLower(kind), req.Namespace+"/"+name,
		fmt.Sprintf("%d -> %d", previous, *req.Replicas), c.IP())

	return c.JSON(fiber.Map{
		"message":  fmt.Sprintf("%s %s scaled from %d to %d replicas", kind, name, previous, *req.Replicas),
		"kind":     kind,
		"name":     name,
		"previous": previous,
		"replicas": *req.Replicas,
	})
}

// GetPodScaleTarget tells the UI which workload a pod belongs to and its
// current replica count, so the scale dialog opens with real values.
func GetPodScaleTarget(c *fiber.Ctx) error {
	namespace := c.Query("namespace")
	name := c.Query("pod")
	if namespace == "" || name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace and pod are required"})
	}

	typed, _, err := requestClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	ctx := context.Background()
	pod, err := typed.CoreV1().Pods(namespace).Get(ctx, name, metav1.GetOptions{})
	if err != nil {
		return k8sError(c, err)
	}

	kind, target, err := resolveScalable(ctx, typed, namespace, pod)
	if err != nil {
		return c.JSON(fiber.Map{"scalable": false, "reason": err.Error()})
	}

	var replicas int32
	switch kind {
	case "Deployment":
		s, err := typed.AppsV1().Deployments(namespace).GetScale(ctx, target, metav1.GetOptions{})
		if err != nil {
			return k8sError(c, err)
		}
		replicas = s.Spec.Replicas
	case "StatefulSet":
		s, err := typed.AppsV1().StatefulSets(namespace).GetScale(ctx, target, metav1.GetOptions{})
		if err != nil {
			return k8sError(c, err)
		}
		replicas = s.Spec.Replicas
	case "ReplicaSet":
		s, err := typed.AppsV1().ReplicaSets(namespace).GetScale(ctx, target, metav1.GetOptions{})
		if err != nil {
			return k8sError(c, err)
		}
		replicas = s.Spec.Replicas
	}

	return c.JSON(fiber.Map{
		"scalable": true,
		"kind":     kind,
		"name":     target,
		"replicas": replicas,
	})
}
