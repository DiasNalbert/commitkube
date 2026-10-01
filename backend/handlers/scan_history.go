package handlers

import (
	"fmt"
	"log"
	"sort"
	"time"
	_ "time/tzdata" // the timeline buckets by the viewer's day; the image may ship without zoneinfo

	"github.com/gofiber/fiber/v2"
	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func GetScanHistory(c *fiber.Ctx) error {
	repoName := c.Params("name")
	limit := c.QueryInt("limit", 10)
	if limit < 1 || limit > 50 {
		limit = 10
	}

	var history []models.ScanHistory
	db.DB.Where("repo_name = ?", repoName).
		Order("created_at desc").
		Limit(limit).
		Find(&history)

	return c.JSON(history)
}

// recordScanHistory appends one point to a repository's history. Every pass
// that changes the stored counts has to call it -- the full scan and the
// image-only rescan alike -- or the timeline shows a flat line where the
// numbers actually moved.
func recordScanHistory(r models.ScanResult) {
	db.DB.Create(&models.ScanHistory{
		RepoName:      r.RepoName,
		Critical:      r.Critical,
		High:          r.High,
		Medium:        r.Medium,
		Low:           r.Low,
		ImageCritical: r.ImageCritical,
		ImageHigh:     r.ImageHigh,
		ImageMedium:   r.ImageMedium,
		ImageLow:      r.ImageLow,
	})
}

// GetScanStatus is what the dashboards poll to stay live: a version that
// changes whenever any scan result is written, and nothing else. It is two
// index lookups, so polling it every few seconds costs nothing, and the
// dashboard only refetches the expensive endpoints when it moves.
func GetScanStatus(c *fiber.Ctx) error {
	var row struct {
		LastScan  string
		Results   int64
		HistoryID uint
	}
	db.DB.Model(&models.ScanResult{}).Select("COALESCE(MAX(updated_at), '') AS last_scan, COUNT(*) AS results").Scan(&row)
	_ = db.DB.Model(&models.ScanHistory{}).Select("COALESCE(MAX(id), 0)").Row().Scan(&row.HistoryID)
	return c.JSON(fiber.Map{
		"version":      fmt.Sprintf("%s|%d|%d", row.LastScan, row.Results, row.HistoryID),
		"last_scan_at": row.LastScan,
	})
}

// ReconcileScanHistory gives every repository a history point matching its
// current result, wherever the newest point disagrees with it. Until the
// image-only rescan recorded history, it changed the stored counts without
// leaving a trace, so the trend's last day and the dashboard's totals drifted
// apart. Safe to run on every start: a repository already in step is left
// alone.
func ReconcileScanHistory() {
	var results []models.ScanResult
	db.DB.Select("id", "updated_at", "repo_name", "critical", "high", "medium", "low",
		"image_critical", "image_high", "image_medium", "image_low").Find(&results)
	if len(results) == 0 {
		return
	}
	var latest []models.ScanHistory
	db.DB.Where("id IN (?)", db.DB.Model(&models.ScanHistory{}).Select("MAX(id)").Group("repo_name")).Find(&latest)
	last := make(map[string]models.ScanHistory, len(latest))
	for _, h := range latest {
		last[h.RepoName] = h
	}

	var missing []models.ScanHistory
	for _, r := range results {
		h, ok := last[r.RepoName]
		if ok && h.Critical == r.Critical && h.High == r.High && h.Medium == r.Medium && h.Low == r.Low &&
			h.ImageCritical == r.ImageCritical && h.ImageHigh == r.ImageHigh &&
			h.ImageMedium == r.ImageMedium && h.ImageLow == r.ImageLow {
			continue
		}
		// Dated when the result was last written, which is when those numbers
		// became true -- never before the point it corrects.
		at := r.UpdatedAt
		if ok && !at.After(h.CreatedAt) {
			at = h.CreatedAt.Add(time.Second)
		}
		missing = append(missing, models.ScanHistory{
			CreatedAt: at, RepoName: r.RepoName,
			Critical: r.Critical, High: r.High, Medium: r.Medium, Low: r.Low,
			ImageCritical: r.ImageCritical, ImageHigh: r.ImageHigh,
			ImageMedium: r.ImageMedium, ImageLow: r.ImageLow,
		})
	}
	if len(missing) > 0 {
		if err := db.DB.CreateInBatches(&missing, 200).Error; err != nil {
			log.Printf("Scan history reconcile failed: %v", err)
			return
		}
		log.Printf("Scan history reconciled for %d repositories", len(missing))
	}
}

type severityCounts struct {
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
}

func (s severityCounts) add(o severityCounts) severityCounts {
	return severityCounts{s.Critical + o.Critical, s.High + o.High, s.Medium + o.Medium, s.Low + o.Low}
}

func countsFor(h models.ScanHistory, domain string) severityCounts {
	if domain == "container" {
		return severityCounts{h.ImageCritical, h.ImageHigh, h.ImageMedium, h.ImageLow}
	}
	return severityCounts{h.Critical, h.High, h.Medium, h.Low}
}

type timelinePoint struct {
	Date  string `json:"date"`
	Repos int    `json:"repos"` // repositories with at least one scan by that day
	severityCounts
}

type timelineMover struct {
	Repo  string         `json:"repo"`
	From  severityCounts `json:"from"`
	To    severityCounts `json:"to"`
	Delta severityCounts `json:"delta"`
}

// timelineSplit separates the change that is work from the change that is
// onboarding. A repository scanned for the first time halfway through the
// period lifts the total by everything it already had, which on the chart
// looks exactly like a regression. Baseline compares the repositories that
// were tracked on the first day with themselves; Added is what arrived with
// the ones that started being scanned later.
type timelineSplit struct {
	BaselineRepos int            `json:"baseline_repos"`
	BaselineFrom  severityCounts `json:"baseline_from"`
	BaselineTo    severityCounts `json:"baseline_to"`
	AddedRepos    int            `json:"added_repos"`
	Added         severityCounts `json:"added"`
}

// buildScanTimeline turns individual scans into one point per day: the sum,
// across repositories, of each one's most recent scan as of the end of that
// day. A repository scanned on Monday still counts on Thursday with Monday's
// numbers -- its vulnerabilities did not go anywhere just because nobody
// looked -- which is what makes the line a measure of the work and not of how
// often the scanner ran.
//
// before holds each repository's last scan prior to the window, so a
// repository scanned only before it starts is not missing from day one.
func buildScanTimeline(before, within []models.ScanHistory, domain string, start time.Time, days int, loc *time.Location) ([]timelinePoint, []timelineMover, timelineSplit) {
	sort.Slice(within, func(i, j int) bool { return within[i].CreatedAt.Before(within[j].CreatedAt) })

	current := map[string]severityCounts{}
	for _, h := range before {
		current[h.RepoName] = countsFor(h, domain)
	}
	first := map[string]severityCounts{}
	for k, v := range current {
		first[k] = v
	}

	points := make([]timelinePoint, 0, days)
	var baseline map[string]severityCounts // as of the first day anything was tracked
	i := 0
	for d := 0; d < days; d++ {
		dayStart := start.AddDate(0, 0, d)
		dayEnd := dayStart.AddDate(0, 0, 1)
		for i < len(within) && within[i].CreatedAt.Before(dayEnd) {
			h := within[i]
			c := countsFor(h, domain)
			if _, seen := first[h.RepoName]; !seen {
				first[h.RepoName] = c
			}
			current[h.RepoName] = c
			i++
		}
		var sum severityCounts
		for _, c := range current {
			sum = sum.add(c)
		}
		if baseline == nil && len(current) > 0 {
			baseline = make(map[string]severityCounts, len(current))
			for k, v := range current {
				baseline[k] = v
			}
		}
		points = append(points, timelinePoint{Date: dayStart.In(loc).Format("2006-01-02"), Repos: len(current), severityCounts: sum})
	}

	var split timelineSplit
	for repo, to := range current {
		if from, ok := baseline[repo]; ok {
			split.BaselineRepos++
			split.BaselineFrom = split.BaselineFrom.add(from)
			split.BaselineTo = split.BaselineTo.add(to)
		} else {
			split.AddedRepos++
			split.Added = split.Added.add(to)
		}
	}

	movers := make([]timelineMover, 0, len(current))
	for repo, to := range current {
		from := first[repo]
		delta := severityCounts{to.Critical - from.Critical, to.High - from.High, to.Medium - from.Medium, to.Low - from.Low}
		if delta == (severityCounts{}) {
			continue
		}
		movers = append(movers, timelineMover{Repo: repo, From: from, To: to, Delta: delta})
	}
	// Most improved first: critical counts before high, high before the rest.
	sort.Slice(movers, func(a, b int) bool {
		x, y := movers[a].Delta, movers[b].Delta
		if x.Critical != y.Critical {
			return x.Critical < y.Critical
		}
		if x.High != y.High {
			return x.High < y.High
		}
		return x.Medium+x.Low < y.Medium+y.Low
	})
	return points, movers, split
}

// GetScanTimeline answers "how much did the vulnerability count go down",
// for the same repositories the dashboard shows.
func GetScanTimeline(c *fiber.Ctx) error {
	domain := c.Query("domain", "code")
	if domain != "container" {
		domain = "code"
	}
	days := c.QueryInt("days", 90)
	if days < 7 || days > 365 {
		days = 90
	}
	loc, err := time.LoadLocation(c.Query("tz", "UTC"))
	if err != nil {
		loc = time.UTC
	}

	repoNames := scanScopeRepoNames(c.QueryInt("workspace_id", 0), c.Query("project_key", ""), c.Query("search", ""))

	now := time.Now().In(loc)
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	start := today.AddDate(0, 0, -(days - 1))

	var before, within []models.ScanHistory
	if len(repoNames) > 0 {
		db.DB.Where("id IN (?)",
			db.DB.Model(&models.ScanHistory{}).Select("MAX(id)").
				Where("repo_name IN ? AND created_at < ?", repoNames, start).
				Group("repo_name"),
		).Find(&before)
		db.DB.Where("repo_name IN ? AND created_at >= ?", repoNames, start).Find(&within)
	}

	points, movers, split := buildScanTimeline(before, within, domain, start, days, loc)

	improved := []timelineMover{}
	regressed := []timelineMover{}
	for _, m := range movers {
		if m.Delta.Critical < 0 || (m.Delta.Critical == 0 && m.Delta.High < 0) ||
			(m.Delta.Critical == 0 && m.Delta.High == 0 && m.Delta.Medium+m.Delta.Low < 0) {
			if len(improved) < 8 {
				improved = append(improved, m)
			}
		}
	}
	for i := len(movers) - 1; i >= 0 && len(regressed) < 8; i-- {
		m := movers[i]
		if m.Delta.Critical > 0 || (m.Delta.Critical == 0 && m.Delta.High > 0) ||
			(m.Delta.Critical == 0 && m.Delta.High == 0 && m.Delta.Medium+m.Delta.Low > 0) {
			regressed = append(regressed, m)
		}
	}

	return c.JSON(fiber.Map{
		"domain":    domain,
		"days":      days,
		"points":    points,
		"improved":  improved,
		"regressed": regressed,
		"split":     split,
		"scans":     len(within),
	})
}
