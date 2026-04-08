package handlers

import (
	"bufio"
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/crypto"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"github.com/kubecommit/backend/services"
)

func PollMonitoring() {
	cutoff := time.Now().AddDate(0, 0, -7)
	db.DB.Where("recorded_at < ?", cutoff).Delete(&models.ServiceSnapshot{})
	db.DB.Where("recorded_at < ?", cutoff).Delete(&models.ServiceEvent{})

	var instances []models.ArgoCDInstance
	db.DB.Find(&instances)

	encKey := crypto.MasterKey()
	for _, inst := range instances {
		token := crypto.DecryptField(encKey, inst.AuthToken)
		client := services.NewArgoCDClient(inst.ServerURL, token)
		var promClient *services.PrometheusClient
		if inst.PrometheusURL != "" {
			promClient = services.NewPrometheusClient(inst.PrometheusURL)
		}
		apps, err := client.ListApplications()
		if err != nil {
			fmt.Printf("Monitoring: instance %d (%s) error: %v\n", inst.ID, inst.Alias, err)
			continue
		}

		for _, app := range apps {
			appStats := client.GetApplicationStats(app.Name)
			app.Replicas = appStats.Replicas
			app.ReadyReplicas = appStats.ReadyReplicas

			var latest models.ServiceSnapshot
			hasLatest := db.DB.Where("argocd_instance_id = ? AND app_name = ?", inst.ID, app.Name).
				Order("recorded_at desc").First(&latest).Error == nil

			now := time.Now()

			if hasLatest {
				if latest.HealthStatus != app.HealthStatus {
					db.DB.Create(&models.ServiceEvent{
						RecordedAt: now, ArgoCDInstanceID: inst.ID,
						AppName: app.Name, Namespace: app.Namespace,
						EventType: "health_change", OldValue: latest.HealthStatus, NewValue: app.HealthStatus,
					})
					DispatchWebhook(services.WebhookEvent{
						Event: "deploy.status_changed",
						Payload: map[string]interface{}{
							"app_name":    app.Name,
							"namespace":   app.Namespace,
							"event_type":  "health_change",
							"old_value":   latest.HealthStatus,
							"new_value":   app.HealthStatus,
							"recorded_at": now,
						},
					})
				}
				if latest.SyncStatus != app.SyncStatus {
					db.DB.Create(&models.ServiceEvent{
						RecordedAt: now, ArgoCDInstanceID: inst.ID,
						AppName: app.Name, Namespace: app.Namespace,
						EventType: "sync_change", OldValue: latest.SyncStatus, NewValue: app.SyncStatus,
					})
					DispatchWebhook(services.WebhookEvent{
						Event: "deploy.status_changed",
						Payload: map[string]interface{}{
							"app_name":    app.Name,
							"namespace":   app.Namespace,
							"event_type":  "sync_change",
							"old_value":   latest.SyncStatus,
							"new_value":   app.SyncStatus,
							"recorded_at": now,
						},
					})
				}
				if app.Image != "" && latest.Image != app.Image {
					db.DB.Create(&models.ServiceEvent{
						RecordedAt: now, ArgoCDInstanceID: inst.ID,
						AppName: app.Name, Namespace: app.Namespace,
						EventType: "image_change", OldValue: latest.Image, NewValue: app.Image,
					})
				}
				if app.Replicas > 0 && latest.Replicas != app.Replicas {
					db.DB.Create(&models.ServiceEvent{
						RecordedAt: now, ArgoCDInstanceID: inst.ID,
						AppName: app.Name, Namespace: app.Namespace,
						EventType: "replicas_change",
						OldValue:  fmt.Sprintf("%d", latest.Replicas),
						NewValue:  fmt.Sprintf("%d", app.Replicas),
					})
				}
				if appStats.MaxRestartCount > latest.MaxRestartCount+5 {
					db.DB.Create(&models.ServiceEvent{
						RecordedAt: now, ArgoCDInstanceID: inst.ID,
						AppName: app.Name, Namespace: app.Namespace,
						EventType: "restart_spike",
						OldValue:  fmt.Sprintf("%d", latest.MaxRestartCount),
						NewValue:  fmt.Sprintf("%d", appStats.MaxRestartCount),
					})
				}
			}

			snap := models.ServiceSnapshot{
				RecordedAt:       now,
				ArgoCDInstanceID: inst.ID,
				AppName:          app.Name,
				Namespace:        app.Namespace,
				HealthStatus:     app.HealthStatus,
				SyncStatus:       app.SyncStatus,
				Replicas:         app.Replicas,
				ReadyReplicas:    app.ReadyReplicas,
				Image:            app.Image,
				MaxRestartCount:  appStats.MaxRestartCount,
				RestartingPods:   appStats.RestartingPods,
			}
			if promClient != nil {
				m := promClient.GetAppMetrics(app.Name, app.Namespace)
				snap.CPUCores = m.CPUCores
				snap.MemoryBytes = int64(m.MemoryBytes)
				snap.NetRxBytesPerSec = m.NetRxBytes
				snap.NetTxBytesPerSec = m.NetTxBytes
			}
			db.DB.Create(&snap)
		}
	}
}

type AppSummary struct {
	AppName         string                `json:"app_name"`
	Namespace       string                `json:"namespace"`
	InstanceID      uint                  `json:"argocd_instance_id"`
	InstanceAlias   string                `json:"argocd_instance_alias"`
	HealthStatus    string                `json:"health_status"`
	SyncStatus      string                `json:"sync_status"`
	Replicas        int                   `json:"replicas"`
	ReadyReplicas   int                   `json:"ready_replicas"`
	Image           string                `json:"image"`
	LastSeen        time.Time             `json:"last_seen"`
	StatusSince     time.Time             `json:"status_since"`
	RecentEvents    []models.ServiceEvent `json:"recent_events"`
	MiniHistory     []string              `json:"mini_history"`
}

type appKey struct {
	InstanceID uint
	AppName    string
}

func GetMonitoringDashboard(c *fiber.Ctx) error {
	var latestSnapshots []models.ServiceSnapshot
	db.DB.Raw(`
		SELECT * FROM service_snapshots
		WHERE id IN (
			SELECT MAX(id) FROM service_snapshots GROUP BY argocd_instance_id, app_name
		)
	`).Scan(&latestSnapshots)

	var instances []models.ArgoCDInstance
	db.DB.Find(&instances)
	instanceMap := map[uint]string{}
	for _, inst := range instances {
		instanceMap[inst.ID] = inst.Alias
	}

	var allEvents []models.ServiceEvent
	db.DB.Where("recorded_at > ?", time.Now().AddDate(0, 0, -7)).
		Order("recorded_at desc").
		Find(&allEvents)
	eventsByApp := map[appKey][]models.ServiceEvent{}
	for _, e := range allEvents {
		k := appKey{e.ArgoCDInstanceID, e.AppName}
		if len(eventsByApp[k]) < 20 {
			eventsByApp[k] = append(eventsByApp[k], e)
		}
	}

	type miniRow struct {
		ArgoCDInstanceID uint   `gorm:"column:argocd_instance_id"`
		AppName          string `gorm:"column:app_name"`
		HealthStatus     string `gorm:"column:health_status"`
	}
	var miniRows []miniRow
	db.DB.Raw(`
		SELECT argocd_instance_id, app_name, health_status FROM (
			SELECT argocd_instance_id, app_name, health_status,
				ROW_NUMBER() OVER (PARTITION BY argocd_instance_id, app_name ORDER BY recorded_at DESC) as rn
			FROM service_snapshots
		) WHERE rn <= 90
		ORDER BY argocd_instance_id, app_name, rn DESC
	`).Scan(&miniRows)
	miniByApp := map[appKey][]string{}
	for _, r := range miniRows {
		k := appKey{r.ArgoCDInstanceID, r.AppName}
		miniByApp[k] = append(miniByApp[k], r.HealthStatus)
	}

	totals := map[string]int{"healthy": 0, "degraded": 0, "missing": 0, "unknown": 0, "total": 0}
	namespaces := map[string][]AppSummary{}

	for _, snap := range latestSnapshots {
		if _, exists := instanceMap[snap.ArgoCDInstanceID]; !exists {
			continue
		}

		k := appKey{snap.ArgoCDInstanceID, snap.AppName}
		events := eventsByApp[k]

		statusSince := snap.RecordedAt
		for _, e := range events {
			if e.EventType == "health_change" && e.NewValue == snap.HealthStatus {
				statusSince = e.RecordedAt
				break
			}
		}

		summary := AppSummary{
			AppName:       snap.AppName,
			Namespace:     snap.Namespace,
			InstanceID:    snap.ArgoCDInstanceID,
			InstanceAlias: instanceMap[snap.ArgoCDInstanceID],
			HealthStatus:  snap.HealthStatus,
			SyncStatus:    snap.SyncStatus,
			Replicas:      snap.Replicas,
			ReadyReplicas: snap.ReadyReplicas,
			Image:         snap.Image,
			LastSeen:      snap.RecordedAt,
			StatusSince:   statusSince,
			RecentEvents:  events,
			MiniHistory:   miniByApp[k],
		}

		switch strings.ToLower(snap.HealthStatus) {
		case "healthy":
			totals["healthy"]++
		case "degraded":
			totals["degraded"]++
		case "missing":
			totals["missing"]++
		default:
			totals["unknown"]++
		}
		totals["total"]++

		namespaces[snap.Namespace] = append(namespaces[snap.Namespace], summary)
	}

	return c.JSON(fiber.Map{"namespaces": namespaces, "totals": totals})
}

func GetAppHistory(c *fiber.Ctx) error {
	appName := c.Query("app")
	namespace := c.Query("namespace")

	q := db.DB.Where("app_name = ?", appName)
	if namespace != "" {
		q = q.Where("namespace = ?", namespace)
	}

	var snapshots []models.ServiceSnapshot
	q.Order("recorded_at desc").Limit(2000).Find(&snapshots)

	eq := db.DB.Where("app_name = ?", appName)
	if namespace != "" {
		eq = eq.Where("namespace = ?", namespace)
	}
	var events []models.ServiceEvent
	eq.Order("recorded_at desc").Limit(500).Find(&events)

	var total int64
	healthy := 0
	db.DB.Model(&models.ServiceSnapshot{}).Where("app_name = ?", appName).Count(&total)
	db.DB.Model(&models.ServiceSnapshot{}).Where("app_name = ? AND health_status = 'Healthy'", appName).
		Select("COUNT(*)").Scan(&healthy)

	uptime := 0.0
	if total > 0 {
		uptime = float64(healthy) / float64(total) * 100
	}

	return c.JSON(fiber.Map{
		"snapshots":       snapshots,
		"events":          events,
		"uptime_pct":      uptime,
		"total_snapshots": total,
	})
}

func RestartApplication(c *fiber.Ctx) error {
	appName := c.Query("app")
	namespace := c.Query("namespace")
	instanceID := c.QueryInt("argocd_instance_id", 0)

	if appName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "app is required"})
	}

	var inst models.ArgoCDInstance
	q := db.DB
	if instanceID > 0 {
		q = q.Where("id = ?", instanceID)
	}
	if err := q.First(&inst).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}

	client := services.NewArgoCDClient(inst.ServerURL, crypto.DecryptField(crypto.MasterKey(), inst.AuthToken))
	if err := client.RestartApplication(appName, namespace); err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	return c.JSON(fiber.Map{"message": "Restart triggered for " + appName})
}


func GetApplicationLogs(c *fiber.Ctx) error {
	appName := c.Query("app")
	namespace := c.Query("namespace")
	instanceID := c.QueryInt("argocd_instance_id", 0)
	tailLines := c.QueryInt("tail", 200)

	if appName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "app is required"})
	}

	var inst models.ArgoCDInstance
	q := db.DB
	if instanceID > 0 {
		q = q.Where("id = ?", instanceID)
	}
	if err := q.First(&inst).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}

	client := services.NewArgoCDClient(inst.ServerURL, crypto.DecryptField(crypto.MasterKey(), inst.AuthToken))
	lines, err := client.GetApplicationLogs(appName, namespace, tailLines)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}
	if lines == nil {
		lines = []services.LogLine{}
	}
	return c.JSON(fiber.Map{"logs": lines})
}

func StreamApplicationLogs(c *fiber.Ctx) error {
	appName := c.Query("app")
	namespace := c.Query("namespace")
	instanceID := c.QueryInt("argocd_instance_id", 0)
	tailLines := c.QueryInt("tail", 100)

	if appName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "app is required"})
	}

	var inst models.ArgoCDInstance
	q := db.DB
	if instanceID > 0 {
		q = q.Where("id = ?", instanceID)
	}
	if err := q.First(&inst).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}

	client := services.NewArgoCDClient(inst.ServerURL, crypto.DecryptField(crypto.MasterKey(), inst.AuthToken))
	resp, err := client.StreamApplicationLogs(appName, namespace, tailLines)
	if err != nil {
		return c.Status(fiber.StatusBadGateway).JSON(fiber.Map{"error": err.Error()})
	}

	c.Set("Content-Type", "text/event-stream")
	c.Set("Cache-Control", "no-cache")
	c.Set("Connection", "keep-alive")
	c.Set("X-Accel-Buffering", "no")

	c.Context().SetBodyStreamWriter(func(w *bufio.Writer) {
		defer resp.Body.Close()
		scanner := bufio.NewScanner(resp.Body)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := bytes.TrimSpace(scanner.Bytes())
			if len(line) == 0 {
				continue
			}
			var wrapper struct {
				Result struct {
					Content   string `json:"content"`
					Timestamp string `json:"timeStamp"`
					PodName   string `json:"podName"`
				} `json:"result"`
			}
			if err := json.Unmarshal(line, &wrapper); err != nil || wrapper.Result.Content == "" {
				continue
			}
			data, _ := json.Marshal(map[string]string{
				"content":   wrapper.Result.Content,
				"timestamp": wrapper.Result.Timestamp,
				"pod_name":  wrapper.Result.PodName,
			})
			fmt.Fprintf(w, "data: %s\n\n", data)
			w.Flush()
		}
		fmt.Fprintf(w, "event: done\ndata: {}\n\n")
		w.Flush()
	})
	return nil
}

func GetAppMetrics(c *fiber.Ctx) error {
	appName := c.Query("app")
	namespace := c.Query("namespace")
	instanceID := c.QueryInt("argocd_instance_id", 0)

	if appName == "" {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "app and namespace are required"})
	}

	var inst models.ArgoCDInstance
	q := db.DB
	if instanceID > 0 {
		q = q.Where("id = ?", instanceID)
	}
	if err := q.First(&inst).Error; err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "argocd instance not found"})
	}

	if inst.PrometheusURL == "" {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{"error": "no prometheus_url configured for this instance"})
	}

	promClient := services.NewPrometheusClient(inst.PrometheusURL)
	metrics := promClient.GetAppMetrics(appName, namespace)
	return c.JSON(metrics)
}

func ClearMonitoringHistory(c *fiber.Ctx) error {
	before := c.Query("before")

	q1 := db.DB.Where("1 = 1")
	q2 := db.DB.Where("1 = 1")
	if before != "" {
		if t, err := time.Parse(time.RFC3339, before); err == nil {
			q1 = q1.Where("recorded_at < ?", t)
			q2 = q2.Where("recorded_at < ?", t)
		}
	}

	q1.Delete(&models.ServiceSnapshot{})
	q2.Delete(&models.ServiceEvent{})

	return c.JSON(fiber.Map{"message": "History cleared"})
}

func ExportMonitoringHistory(c *fiber.Ctx) error {
	format := c.Query("format", "json")
	appName := c.Query("app")
	namespace := c.Query("namespace")

	q := db.DB.Model(&models.ServiceSnapshot{})
	if appName != "" {
		q = q.Where("app_name = ?", appName)
	}
	if namespace != "" {
		q = q.Where("namespace = ?", namespace)
	}

	var snapshots []models.ServiceSnapshot
	q.Order("recorded_at desc").Find(&snapshots)

	if format == "csv" {
		c.Set("Content-Type", "text/csv")
		c.Set("Content-Disposition", "attachment; filename=monitoring-history.csv")
		var buf strings.Builder
		w := csv.NewWriter(&buf)
		w.Write([]string{"recorded_at", "app_name", "namespace", "health_status", "sync_status", "replicas", "ready_replicas", "image"})
		for _, s := range snapshots {
			w.Write([]string{
				s.RecordedAt.Format(time.RFC3339),
				s.AppName, s.Namespace,
				s.HealthStatus, s.SyncStatus,
				fmt.Sprintf("%d", s.Replicas),
				fmt.Sprintf("%d", s.ReadyReplicas),
				s.Image,
			})
		}
		w.Flush()
		return c.SendString(buf.String())
	}

	c.Set("Content-Type", "application/json")
	c.Set("Content-Disposition", "attachment; filename=monitoring-history.json")
	data, _ := json.Marshal(snapshots)
	return c.Send(data)
}
