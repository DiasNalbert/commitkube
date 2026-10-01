package handlers

import (
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

// buildScanTimeline turns individual scans into one point per day: the sum,
// across repositories, of each one's most recent scan as of the end of that
// day. A repository scanned on Monday still counts on Thursday with Monday's
// numbers -- its vulnerabilities did not go anywhere just because nobody
// looked -- which is what makes the line a measure of the work and not of how
// often the scanner ran.
//
// before holds each repository's last scan prior to the window, so a
// repository scanned only before it starts is not missing from day one.
func buildScanTimeline(before, within []models.ScanHistory, domain string, start time.Time, days int, loc *time.Location) ([]timelinePoint, []timelineMover) {
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
		points = append(points, timelinePoint{Date: dayStart.In(loc).Format("2006-01-02"), Repos: len(current), severityCounts: sum})
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
	return points, movers
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

	points, movers := buildScanTimeline(before, within, domain, start, days, loc)

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
		"scans":     len(within),
	})
}
