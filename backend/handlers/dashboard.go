package handlers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func GetDashboardSummary(c *fiber.Ctx) error {
	wsID := c.QueryInt("workspace_id", 0)
	argoInstanceID := c.QueryInt("argocd_instance_id", 0)

	repoQ := db.DB.Model(&models.Repository{})
	if wsID > 0 {
		repoQ = repoQ.Where("workspace_id = ?", wsID)
	}
	var repoCount int64
	repoQ.Count(&repoCount)

	scanQ := db.DB
	if wsID > 0 {
		scanQ = scanQ.Where("repo_name IN (SELECT name FROM repositories WHERE workspace_id = ?)", wsID)
	}
	var scanResults []models.ScanResult
	scanQ.Find(&scanResults)
	secTotals := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for _, r := range scanResults {
		secTotals["critical"] += r.Critical + r.ImageCritical
		secTotals["high"] += r.High + r.ImageHigh
		secTotals["medium"] += r.Medium + r.ImageMedium
		secTotals["low"] += r.Low + r.ImageLow
	}

	var instances []models.ArgoCDInstance
	db.DB.Find(&instances)
	activeInstances := map[uint]bool{}
	for _, inst := range instances {
		activeInstances[inst.ID] = true
	}

	snapshotQ := db.DB.Raw(`
		SELECT * FROM service_snapshots
		WHERE id IN (
			SELECT MAX(id) FROM service_snapshots GROUP BY argocd_instance_id, app_name
		)
	`)

	var latestSnapshots []models.ServiceSnapshot
	snapshotQ.Scan(&latestSnapshots)

	monTotals := map[string]int{"healthy": 0, "degraded": 0, "unknown": 0, "total": 0}
	podTotals := map[string]int{"total": 0, "ready": 0, "unhealthy_apps": 0}

	for _, snap := range latestSnapshots {
		if !activeInstances[snap.ArgoCDInstanceID] {
			continue
		}
		if argoInstanceID > 0 && int(snap.ArgoCDInstanceID) != argoInstanceID {
			continue
		}
		switch strings.ToLower(snap.HealthStatus) {
		case "healthy":
			monTotals["healthy"]++
		case "degraded":
			monTotals["degraded"]++
		default:
			monTotals["unknown"]++
		}
		monTotals["total"]++

		podTotals["total"] += snap.Replicas
		podTotals["ready"] += snap.ReadyReplicas
		if snap.Replicas > 0 && snap.ReadyReplicas < snap.Replicas {
			podTotals["unhealthy_apps"]++
		}
	}

	return c.JSON(fiber.Map{
		"repos":      repoCount,
		"security":   secTotals,
		"monitoring": monTotals,
		"pods":       podTotals,
	})
}
