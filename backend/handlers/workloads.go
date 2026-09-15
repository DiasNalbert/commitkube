package handlers

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// workloadState is one workload as read from the cluster, before it is stored.
type workloadState struct {
	Namespace string
	Kind      string
	Name      string
	Desired   int32
	Ready     int32
	Updated   int32
	Available int32
	Image     string
	Status    string
}

// deriveStatus classifies a workload's replica state. A workload deliberately
// scaled to zero is not "down" -- it is off, which is why it gets its own
// status and is excluded from uptime rather than counted as downtime.
func deriveStatus(desired, ready int32) string {
	switch {
	case desired == 0:
		return "scaled_zero"
	case ready == desired:
		return "healthy"
	case ready == 0:
		return "degraded"
	default:
		return "progressing"
	}
}

func collectWorkloads(ctx context.Context, cl *models.Cluster) ([]workloadState, error) {
	typed, _, err := collectorClients(cl)
	if err != nil {
		return nil, err
	}

	opts := metav1.ListOptions{}
	out := []workloadState{}

	deploys, err := typed.AppsV1().Deployments("").List(ctx, opts)
	if err != nil {
		return nil, err
	}
	for i := range deploys.Items {
		d := &deploys.Items[i]
		desired := int32(1)
		if d.Spec.Replicas != nil {
			desired = *d.Spec.Replicas
		}
		out = append(out, workloadState{
			Namespace: d.Namespace, Kind: "Deployment", Name: d.Name,
			Desired: desired, Ready: d.Status.ReadyReplicas,
			Updated: d.Status.UpdatedReplicas, Available: d.Status.AvailableReplicas,
			Image:  primaryImage(d.Spec.Template.Spec.Containers),
			Status: deriveStatus(desired, d.Status.ReadyReplicas),
		})
	}

	sts, err := typed.AppsV1().StatefulSets("").List(ctx, opts)
	if err == nil {
		for i := range sts.Items {
			s := &sts.Items[i]
			desired := int32(1)
			if s.Spec.Replicas != nil {
				desired = *s.Spec.Replicas
			}
			out = append(out, workloadState{
				Namespace: s.Namespace, Kind: "StatefulSet", Name: s.Name,
				Desired: desired, Ready: s.Status.ReadyReplicas,
				Updated: s.Status.UpdatedReplicas, Available: s.Status.ReadyReplicas,
				Image:  primaryImage(s.Spec.Template.Spec.Containers),
				Status: deriveStatus(desired, s.Status.ReadyReplicas),
			})
		}
	}

	ds, err := typed.AppsV1().DaemonSets("").List(ctx, opts)
	if err == nil {
		for i := range ds.Items {
			d := &ds.Items[i]
			// A DaemonSet's "desired" is however many nodes it should land on.
			desired := d.Status.DesiredNumberScheduled
			out = append(out, workloadState{
				Namespace: d.Namespace, Kind: "DaemonSet", Name: d.Name,
				Desired: desired, Ready: d.Status.NumberReady,
				Updated: d.Status.UpdatedNumberScheduled, Available: d.Status.NumberAvailable,
				Image:  primaryImage(d.Spec.Template.Spec.Containers),
				Status: deriveStatus(desired, d.Status.NumberReady),
			})
		}
	}

	return out, nil
}

// primaryImage returns the image of the first container, which is the one that
// identifies the workload for scanning and for change history.
func primaryImage(containers []corev1.Container) string {
	if len(containers) == 0 {
		return ""
	}
	return containers[0].Image
}

// PollWorkloads samples every workload and records the transitions between
// samples, which together give uptime and a change history without ArgoCD.
func PollWorkloads() {
	retentionDays := 30
	if v := os.Getenv("WORKLOAD_RETENTION_DAYS"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			retentionDays = d
		}
	}
	cutoff := time.Now().AddDate(0, 0, -retentionDays)
	db.DB.Where("recorded_at < ?", cutoff).Delete(&models.WorkloadSnapshot{})
	db.DB.Where("recorded_at < ?", cutoff).Delete(&models.WorkloadEvent{})

	for _, cl := range allClusters() {
		pollWorkloadsFor(&cl)
	}
}

func pollWorkloadsFor(cl *models.Cluster) {
	states, err := collectWorkloads(context.Background(), cl)
	if err != nil {
		fmt.Printf("Workload monitoring: cluster %s: %v\n", cl.Name, err)
		return
	}

	now := time.Now()

	// One query for the previous sample of every workload, instead of one per
	// workload: at a few hundred workloads the difference is the whole poll.
	var previous []models.WorkloadSnapshot
	db.DB.Raw(`
		SELECT * FROM workload_snapshots
		WHERE cluster_id = ?
		  AND id IN (SELECT MAX(id) FROM workload_snapshots WHERE cluster_id = ? GROUP BY namespace, kind, name)
	`, cl.ID, cl.ID).Scan(&previous)
	prevByKey := map[string]models.WorkloadSnapshot{}
	for _, p := range previous {
		prevByKey[p.Namespace+"/"+p.Kind+"/"+p.Name] = p
	}

	for _, w := range states {
		key := w.Namespace + "/" + w.Kind + "/" + w.Name

		if prev, ok := prevByKey[key]; ok {
			addEvent := func(eventType, oldV, newV string) {
				db.DB.Create(&models.WorkloadEvent{
					ClusterID:  cl.ID,
					RecordedAt: now, Namespace: w.Namespace, Kind: w.Kind, Name: w.Name,
					EventType: eventType, OldValue: oldV, NewValue: newV,
				})
			}
			if prev.Status != w.Status {
				addEvent("status_change", prev.Status, w.Status)
				if w.Status == "degraded" {
					go SendNotifications("workload.degraded", "Workload Degraded",
						fmt.Sprintf("%s %s in namespace %s has 0/%d replicas ready",
							w.Kind, w.Name, w.Namespace, w.Desired),
						w.Name, "system")
				}
			}
			if prev.Desired != w.Desired {
				addEvent("replicas_change",
					strconv.Itoa(int(prev.Desired)), strconv.Itoa(int(w.Desired)))
			}
			if w.Image != "" && prev.Image != w.Image {
				addEvent("image_change", prev.Image, w.Image)
			}
		}

		db.DB.Create(&models.WorkloadSnapshot{
			ClusterID:  cl.ID,
			RecordedAt: now, Namespace: w.Namespace, Kind: w.Kind, Name: w.Name,
			Desired: w.Desired, Ready: w.Ready, Updated: w.Updated,
			Available: w.Available, Image: w.Image, Status: w.Status,
		})
	}
}

type WorkloadSummary struct {
	Namespace   string   `json:"namespace"`
	Kind        string   `json:"kind"`
	Name        string   `json:"name"`
	Desired     int32    `json:"desired"`
	Ready       int32    `json:"ready"`
	Updated     int32    `json:"updated"`
	Available   int32    `json:"available"`
	Image       string   `json:"image"`
	Status      string   `json:"status"`
	UptimePct   float64  `json:"uptime_pct"`
	SampleCount int      `json:"sample_count"`
	MiniHistory []string `json:"mini_history"`
}

// GetWorkloads lists every workload with its live state plus the uptime and
// mini timeline computed from stored samples.
func GetWorkloads(c *fiber.Ctx) error {
	cl, err := clusterFromRequest(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	states, err := collectWorkloads(context.Background(), cl)
	if err != nil {
		return k8sError(c, err)
	}

	// Uptime excludes samples where the workload was scaled to zero: being
	// switched off on purpose is not downtime.
	type uptimeRow struct {
		Namespace string
		Kind      string
		Name      string
		Healthy   int
		Counted   int
	}
	var uptimeRows []uptimeRow
	db.DB.Raw(`
		SELECT namespace, kind, name,
			SUM(CASE WHEN status = 'healthy' THEN 1 ELSE 0 END) AS healthy,
			SUM(CASE WHEN status != 'scaled_zero' THEN 1 ELSE 0 END) AS counted
		FROM workload_snapshots
		WHERE cluster_id = ?
		GROUP BY namespace, kind, name
	`, cl.ID).Scan(&uptimeRows)
	uptimeByKey := map[string]uptimeRow{}
	for _, r := range uptimeRows {
		uptimeByKey[r.Namespace+"/"+r.Kind+"/"+r.Name] = r
	}

	type miniRow struct {
		Namespace string
		Kind      string
		Name      string
		Status    string
	}
	var miniRows []miniRow
	db.DB.Raw(`
		SELECT namespace, kind, name, status FROM (
			SELECT namespace, kind, name, status,
				ROW_NUMBER() OVER (PARTITION BY namespace, kind, name ORDER BY recorded_at DESC) AS rn
			FROM workload_snapshots
			WHERE cluster_id = ?
		) WHERE rn <= 90
		ORDER BY namespace, kind, name, rn DESC
	`, cl.ID).Scan(&miniRows)
	miniByKey := map[string][]string{}
	for _, r := range miniRows {
		k := r.Namespace + "/" + r.Kind + "/" + r.Name
		miniByKey[k] = append(miniByKey[k], r.Status)
	}

	totals := map[string]int{"total": 0, "healthy": 0, "degraded": 0, "progressing": 0, "scaled_zero": 0}
	items := make([]WorkloadSummary, 0, len(states))

	for _, w := range states {
		key := w.Namespace + "/" + w.Kind + "/" + w.Name
		u := uptimeByKey[key]
		uptime := 0.0
		if u.Counted > 0 {
			uptime = float64(u.Healthy) / float64(u.Counted) * 100
		}
		items = append(items, WorkloadSummary{
			Namespace: w.Namespace, Kind: w.Kind, Name: w.Name,
			Desired: w.Desired, Ready: w.Ready, Updated: w.Updated,
			Available: w.Available, Image: w.Image, Status: w.Status,
			UptimePct: uptime, SampleCount: u.Counted,
			MiniHistory: miniByKey[key],
		})
		totals["total"]++
		totals[w.Status]++
	}

	return c.JSON(fiber.Map{"items": items, "totals": totals})
}

// GetWorkloadHistory returns the stored samples and change history for one
// workload -- the uptime detail view.
func GetWorkloadHistory(c *fiber.Ctx) error {
	namespace := c.Query("namespace")
	name := c.Query("name")
	kind := c.Query("kind")
	if namespace == "" || name == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "namespace and name are required"})
	}

	clusterID, err := requestClusterID(c)
	if err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": err.Error()})
	}
	sq := db.DB.Where("cluster_id = ? AND namespace = ? AND name = ?", clusterID, namespace, name)
	eq := db.DB.Where("cluster_id = ? AND namespace = ? AND name = ?", clusterID, namespace, name)
	if kind != "" {
		sq = sq.Where("kind = ?", kind)
		eq = eq.Where("kind = ?", kind)
	}

	var snapshots []models.WorkloadSnapshot
	sq.Order("recorded_at desc").Limit(3000).Find(&snapshots)

	var events []models.WorkloadEvent
	eq.Order("recorded_at desc").Limit(300).Find(&events)

	healthy, counted := 0, 0
	for _, s := range snapshots {
		if s.Status == "scaled_zero" {
			continue
		}
		counted++
		if s.Status == "healthy" {
			healthy++
		}
	}
	uptime := 0.0
	if counted > 0 {
		uptime = float64(healthy) / float64(counted) * 100
	}

	if snapshots == nil {
		snapshots = []models.WorkloadSnapshot{}
	}
	if events == nil {
		events = []models.WorkloadEvent{}
	}

	return c.JSON(fiber.Map{
		"snapshots":  snapshots,
		"events":     events,
		"uptime_pct": uptime,
		"samples":    counted,
	})
}

// latestWorkloadImage finds the image a workload is currently running, by name.
// It replaces the ArgoCD snapshot lookup the image scanner used to depend on.
//
// Deliberately not scoped to one cluster: the caller is the vulnerability
// scanner, which has no request and no cluster in hand. A repository deployed
// in any cluster has an image worth scanning, so the most recent sample from
// anywhere wins.
func latestWorkloadImage(name string) (string, error) {
	var snap models.WorkloadSnapshot
	err := db.DB.Where("name = ? AND image != ''", name).
		Order("recorded_at desc").First(&snap).Error
	if err == nil && snap.Image != "" {
		return snap.Image, nil
	}

	// No sample yet (the poller may not have run since this workload appeared),
	// so ask the clusters directly.
	var lastErr error
	for _, cl := range allClusters() {
		states, cErr := collectWorkloads(context.Background(), &cl)
		if cErr != nil {
			lastErr = cErr
			continue
		}
		for _, w := range states {
			if w.Name == name && w.Image != "" {
				return w.Image, nil
			}
		}
	}
	if lastErr != nil {
		return "", fmt.Errorf("no stored sample for %s and no cluster could be read: %v", name, lastErr)
	}
	return "", fmt.Errorf("no running workload named %s was found in any cluster", name)
}
