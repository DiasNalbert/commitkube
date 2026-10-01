package handlers

import (
	"testing"
	"time"

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

	points, movers := buildScanTimeline(before, within, "code", start, 4, loc)
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

	img, _ := buildScanTimeline(before, within, "container", start, 4, loc)
	if img[3].Critical != 7 {
		t.Fatalf("container day 3 critical = %d, want 7", img[3].Critical)
	}
}
