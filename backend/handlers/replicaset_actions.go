package handlers

import (
	"context"
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	appsv1 "k8s.io/api/apps/v1"
	autoscalingv1 "k8s.io/api/autoscaling/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// A ReplicaSet is rarely what someone means to act on: most belong to a
// Deployment, which decides how many pods each one runs. So each action
// says what it will really do before doing it -- and refuses the version of
// it that would silently not stick or would take a service down by
// surprise.

const revisionAnnotation = "deployment.kubernetes.io/revision"

// replicaSetRole classifies one ReplicaSet for the person about to act on it.
type replicaSetRole struct {
	// Kind is "retired" (an old revision of a Deployment, scaled to zero),
	// "current" (the revision a Deployment runs now), "standalone" (no
	// Deployment owns it).
	Kind       string
	Deployment string
	Replicas   int32
}

func classifyReplicaSet(ctx context.Context, typed kubernetes.Interface, rs *appsv1.ReplicaSet) replicaSetRole {
	owner := owningDeployment(rs)
	if owner == "" {
		return roleOf(rs, nil)
	}
	d, err := typed.AppsV1().Deployments(rs.Namespace).Get(ctx, owner, metav1.GetOptions{})
	if err != nil {
		return roleOf(rs, nil)
	}
	return roleOf(rs, d)
}

func owningDeployment(rs *appsv1.ReplicaSet) string {
	for _, o := range rs.OwnerReferences {
		if o.Kind == "Deployment" {
			return o.Name
		}
	}
	return ""
}

// roleOf classifies a ReplicaSet against the Deployment that owns it (nil
// when none does, or it is gone: then nothing will recreate it). The list
// and the delete use this same rule, so what the page calls retired is
// exactly what a delete removes without question.
func roleOf(rs *appsv1.ReplicaSet, d *appsv1.Deployment) replicaSetRole {
	role := replicaSetRole{Kind: "standalone"}
	if rs.Spec.Replicas != nil {
		role.Replicas = *rs.Spec.Replicas
	}
	if d == nil {
		return role
	}
	role.Deployment, role.Kind = d.Name, "retired"
	if rev := rs.Annotations[revisionAnnotation]; rev != "" && rev == d.Annotations[revisionAnnotation] {
		role.Kind = "current"
	} else if role.Replicas > 0 {
		// Mid-rollout: an old revision still running pods.
		role.Kind = "current"
	}
	return role
}

// DeleteReplicaSets deletes a batch. Retired revisions go without question
// (they only cost a line in the rollout history). A ReplicaSet that runs
// pods -- a Deployment's current revision, or a standalone one -- takes its
// pods with it, so it needs allow_running.
func DeleteReplicaSets(c *fiber.Ctx) error {
	var req struct {
		Items []struct {
			Namespace string `json:"namespace"`
			Name      string `json:"name"`
		} `json:"items"`
		AllowRunning bool `json:"allow_running"`
	}
	if err := c.BodyParser(&req); err != nil || len(req.Items) == 0 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "items are required"})
	}
	if len(req.Items) > 200 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "at most 200 at a time"})
	}
	typed, err := writeClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	ctx := context.Background()

	type result struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Outcome   string `json:"outcome"` // deleted | skipped | failed
		Message   string `json:"message"`
	}
	results := make([]result, 0, len(req.Items))
	deleted := 0
	for _, it := range req.Items {
		r := result{Namespace: it.Namespace, Name: it.Name}
		if !namespaceAllowed(c, it.Namespace) {
			r.Outcome, r.Message = "failed", "outside your namespaces"
			results = append(results, r)
			continue
		}
		rs, err := typed.AppsV1().ReplicaSets(it.Namespace).Get(ctx, it.Name, metav1.GetOptions{})
		if err != nil {
			r.Outcome, r.Message = "failed", err.Error()
			results = append(results, r)
			continue
		}
		role := classifyReplicaSet(ctx, typed, rs)
		// The current revision of a Deployment scaled to zero runs nothing,
		// but deleting it is not cleanup: the Deployment controller makes
		// it again at once, under the same name. Never worth doing.
		if role.Kind == "current" && role.Replicas == 0 {
			r.Outcome = "skipped"
			r.Message = fmt.Sprintf("current revision of Deployment %s, which is scaled to zero: Kubernetes would recreate it at once. Delete the Deployment to remove it", role.Deployment)
			results = append(results, r)
			continue
		}
		running := role.Kind == "current" || (role.Kind == "standalone" && role.Replicas > 0)
		if running && !req.AllowRunning {
			r.Outcome = "skipped"
			if role.Kind == "current" {
				r.Message = fmt.Sprintf("current revision of Deployment %s: deleting it kills its %d pod(s) and the Deployment recreates them", role.Deployment, role.Replicas)
			} else {
				r.Message = fmt.Sprintf("runs %d pod(s) that would be deleted with it, and nothing recreates them", role.Replicas)
			}
			results = append(results, r)
			continue
		}
		bg := metav1.DeletePropagationBackground
		if err := typed.AppsV1().ReplicaSets(it.Namespace).Delete(ctx, it.Name, metav1.DeleteOptions{PropagationPolicy: &bg}); err != nil {
			r.Outcome, r.Message = "failed", err.Error()
			results = append(results, r)
			continue
		}
		r.Outcome = "deleted"
		switch role.Kind {
		case "retired":
			r.Message = "retired revision removed from " + role.Deployment + "'s rollout history"
		case "current":
			r.Message = fmt.Sprintf("Deployment %s is recreating its pods", role.Deployment)
		default:
			r.Message = "deleted with its pods"
		}
		deleted++
		db.LogAudit(currentUserID(c), "delete_replicaset", "replicaset", it.Namespace+"/"+it.Name,
			fmt.Sprintf(`{"role":%q,"deployment":%q,"replicas":%d}`, role.Kind, role.Deployment, role.Replicas), c.IP())
		results = append(results, r)
	}
	return c.JSON(fiber.Map{"deleted": deleted, "results": results})
}

// ScaleReplicaSet sets a replica count. A ReplicaSet owned by a Deployment
// cannot keep a count of its own -- the Deployment controller undoes it in
// seconds -- so the Deployment is scaled instead, and the answer says so.
func ScaleReplicaSet(c *fiber.Ctx) error {
	var req struct {
		Namespace string `json:"namespace"`
		Name      string `json:"name"`
		Replicas  *int32 `json:"replicas"`
	}
	if err := c.BodyParser(&req); err != nil || req.Namespace == "" || req.Name == "" || req.Replicas == nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace, name and replicas are required"})
	}
	if *req.Replicas < 0 || *req.Replicas > 100 {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "replicas must be between 0 and 100"})
	}
	if !namespaceAllowed(c, req.Namespace) {
		return forbidNamespace(c)
	}
	typed, err := writeClients(c)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	ctx := context.Background()
	rs, err := typed.AppsV1().ReplicaSets(req.Namespace).Get(ctx, req.Name, metav1.GetOptions{})
	if err != nil {
		return k8sError(c, err)
	}
	role := classifyReplicaSet(ctx, typed, rs)
	scale := &autoscalingv1.Scale{
		ObjectMeta: metav1.ObjectMeta{Namespace: req.Namespace},
		Spec:       autoscalingv1.ScaleSpec{Replicas: *req.Replicas},
	}

	kind, name := "ReplicaSet", req.Name
	var previous int32
	if role.Deployment != "" {
		kind, name = "Deployment", role.Deployment
		cur, err := typed.AppsV1().Deployments(req.Namespace).GetScale(ctx, name, metav1.GetOptions{})
		if err != nil {
			return k8sError(c, err)
		}
		previous = cur.Spec.Replicas
		scale.Name = name
		if _, err := typed.AppsV1().Deployments(req.Namespace).UpdateScale(ctx, name, scale, metav1.UpdateOptions{}); err != nil {
			return k8sError(c, err)
		}
	} else {
		cur, err := typed.AppsV1().ReplicaSets(req.Namespace).GetScale(ctx, name, metav1.GetOptions{})
		if err != nil {
			return k8sError(c, err)
		}
		previous = cur.Spec.Replicas
		scale.Name = name
		if _, err := typed.AppsV1().ReplicaSets(req.Namespace).UpdateScale(ctx, name, scale, metav1.UpdateOptions{}); err != nil {
			return k8sError(c, err)
		}
	}
	db.LogAudit(currentUserID(c), "scale_workload", strings.ToLower(kind), req.Namespace+"/"+name,
		fmt.Sprintf("%d -> %d (from replicaset %s)", previous, *req.Replicas, req.Name), c.IP())
	msg := fmt.Sprintf("%s %s scaled from %d to %d", kind, name, previous, *req.Replicas)
	if kind == "Deployment" {
		msg += " -- a ReplicaSet owned by a Deployment follows the Deployment's count"
	}
	return c.JSON(fiber.Map{"message": msg, "kind": kind, "name": name, "previous": previous, "replicas": *req.Replicas})
}
