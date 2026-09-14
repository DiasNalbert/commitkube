package handlers

import (
	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func GetDashboardSummary(c *fiber.Ctx) error {
	wsSlug := c.Query("workspace_slug", "")
	projectKey := c.Query("project_key", "")

	var wsIDs []uint
	if wsSlug != "" {
		db.DB.Model(&models.BitbucketWorkspace{}).
			Where("workspace_id = ?", wsSlug).
			Pluck("id", &wsIDs)
	}

	repoQ := db.DB.Model(&models.Repository{})
	if len(wsIDs) > 0 {
		repoQ = repoQ.Where("workspace_id IN ?", wsIDs)
		if projectKey != "" {
			repoQ = repoQ.Where("project_key = ?", projectKey)
		}
	}
	var repoCount int64
	repoQ.Count(&repoCount)

	scanQ := db.DB
	if len(wsIDs) > 0 {
		if projectKey != "" {
			scanQ = scanQ.Where("repo_name IN (SELECT name FROM repositories WHERE workspace_id IN ? AND project_key = ?)", wsIDs, projectKey)
		} else {
			scanQ = scanQ.Where("repo_name IN (SELECT name FROM repositories WHERE workspace_id IN ?)", wsIDs)
		}
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

	// Health now comes from workload samples read from the Kubernetes API, not
	// from ArgoCD: ArgoCD is only used to deploy applications.
	var latestSnapshots []models.WorkloadSnapshot
	db.DB.Raw(`
		SELECT * FROM workload_snapshots
		WHERE id IN (SELECT MAX(id) FROM workload_snapshots GROUP BY namespace, kind, name)
	`).Scan(&latestSnapshots)

	monTotals := map[string]int{"healthy": 0, "degraded": 0, "unknown": 0, "total": 0}
	podTotals := map[string]int{"total": 0, "ready": 0, "unhealthy_apps": 0}

	for _, snap := range latestSnapshots {
		switch snap.Status {
		case "healthy":
			monTotals["healthy"]++
		case "degraded":
			monTotals["degraded"]++
		default:
			monTotals["unknown"]++
		}
		monTotals["total"]++

		podTotals["total"] += int(snap.Desired)
		podTotals["ready"] += int(snap.Ready)
		if snap.Desired > 0 && snap.Ready < snap.Desired {
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
