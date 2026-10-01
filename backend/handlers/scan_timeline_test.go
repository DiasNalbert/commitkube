package handlers

import (
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

func TestScanTimelineCarriesLastScanForward(t *testing.T) {
	loc := time.UTC
	start := time.Date(2026, 9, 1, 0, 0, 0, 0, loc)
	at := func(day, hour int) time.Time { return start.AddDate(0, 0, day).Add(time.Duration(hour) * time.Hour) }

	before := []models.ScanHistory{
		{RepoName: "a", CreatedAt: start.Add(-48 * time.Hour), Critical: 10, High: 5},
	}
	within := []models.ScanHistory{
		{RepoName: "b", CreatedAt: at(1, 9), Critical: 2},
		{RepoName: "a", CreatedAt: at(2, 9), Critical: 4, High: 5},
		{RepoName: "a", CreatedAt: at(2, 23), Critical: 3, High: 5, ImageCritical: 7},
	}

	points, movers, split, changes := buildScanTimeline(before, within, "code", start, 4, 24, loc)
	want := []int{10, 12, 5, 5}
	for i, p := range points {
		if p.Critical != want[i] {
			t.Fatalf("day %d: critical = %d, want %d (%+v)", i, p.Critical, want[i], points)
		}
	}
	if points[0].Repos != 1 || points[1].Repos != 2 {
		t.Fatalf("repo counts = %d, %d", points[0].Repos, points[1].Repos)
	}
	if points[0].Date != "2026-09-01" {
		t.Fatalf("date = %s", points[0].Date)
	}
	if len(movers) != 1 || movers[0].Repo != "a" || movers[0].Delta.Critical != -7 {
		t.Fatalf("movers = %+v", movers)
	}

	// a was tracked from day one (10 -> 3 critical); b arrived on day 1 with 2.
	if split.BaselineRepos != 1 || split.BaselineFrom.Critical != 10 || split.BaselineTo.Critical != 3 {
		t.Fatalf("baseline = %+v", split)
	}
	if split.AddedRepos != 1 || split.Added.Critical != 2 {
		t.Fatalf("added = %+v", split)
	}

	// b's first scan is onboarding; a's two rescans are the changes, newest first.
	if len(changes) != 2 || changes[0].Repo != "a" || changes[0].Delta.Critical != -1 || changes[1].Delta.Critical != -6 {
		t.Fatalf("changes = %+v", changes)
	}

	img, _, _, _ := buildScanTimeline(before, within, "container", start, 4, 24, loc)
	if img[3].Critical != 7 {
		t.Fatalf("container day 3 critical = %d, want 7", img[3].Critical)
	}
}

func TestReconcileScanHistoryCatchesUpWithResults(t *testing.T) {
	usePostureDB(t)
	if err := db.DB.AutoMigrate(&models.ScanResult{}, &models.ScanHistory{}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	// a: history is stale (an image-only rescan moved it). b: in step. c: no history at all.
	db.DB.Create(&models.ScanHistory{RepoName: "a", CreatedAt: old, ImageCritical: 9})
	db.DB.Create(&models.ScanHistory{RepoName: "b", CreatedAt: old, ImageCritical: 4})
	db.DB.Create(&models.ScanResult{RepoName: "a", ImageCritical: 5})
	db.DB.Create(&models.ScanResult{RepoName: "b", ImageCritical: 4})
	db.DB.Create(&models.ScanResult{RepoName: "c", Critical: 1})

	ReconcileScanHistory()
	ReconcileScanHistory() // idempotent

	var n int64
	db.DB.Model(&models.ScanHistory{}).Count(&n)
	if n != 4 {
		t.Fatalf("history rows = %d, want 4 (one added for a, one for c)", n)
	}
	var a models.ScanHistory
	db.DB.Where("repo_name = ?", "a").Order("id desc").First(&a)
	if a.ImageCritical != 5 || !a.CreatedAt.After(old) {
		t.Fatalf("a not reconciled: %+v", a)
	}
}

// Two moves on the same day -- a catch-up that raised the count and a fix
// that lowered it -- are one point on a daily chart and two on an hourly one.
func TestScanTimelineHourlyBucketsSeparateSameDayMoves(t *testing.T) {
	loc := time.UTC
	start := time.Date(2026, 10, 1, 0, 0, 0, 0, loc)
	before := []models.ScanHistory{{RepoName: "a", CreatedAt: start.Add(-time.Hour), Medium: 100}}
	within := []models.ScanHistory{
		{RepoName: "a", CreatedAt: start.Add(5 * time.Hour), Medium: 900},  // catch-up at 05:00
		{RepoName: "a", CreatedAt: start.Add(13 * time.Hour), Medium: 300}, // fix at 13:00
	}
	daily, _, _, _ := buildScanTimeline(before, within, "code", start, 1, 24, loc)
	if len(daily) != 1 || daily[0].Medium != 300 {
		t.Fatalf("daily = %+v", daily)
	}
	hourly, _, _, _ := buildScanTimeline(before, within, "code", start, 24, 1, loc)
	if hourly[4].Medium != 100 || hourly[5].Medium != 900 || hourly[13].Medium != 300 {
		t.Fatalf("hourly = %v / %v / %v", hourly[4].Medium, hourly[5].Medium, hourly[13].Medium)
	}
	if hourly[13].Date != "2026-10-01T13:00" {
		t.Fatalf("label = %s", hourly[13].Date)
	}
}

func TestPickWorkloadImagePrefersTheRunningDeployment(t *testing.T) {
	got := pickWorkloadImage([]workloadState{
		{Namespace: "old", Kind: "Deployment", Name: "api", Desired: 0, Image: "api:old"},
		{Namespace: "jobs", Kind: "CronJob", Name: "api", Desired: 1, Image: "api:cron"},
		{Namespace: "prod", Kind: "Deployment", Name: "api", Desired: 3, Image: "api:new"},
	})
	if got != "api:new" {
		t.Fatalf("picked %s, want api:new", got)
	}
}
