package handlers

import (
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// The daily image-only pass rewrites the result row, so staleness of the
// code half must be read from its own clock. Before it had one, a
// repository whose image was rescanned every day never had its code -- its
// dependencies, its secrets -- scanned again.
func TestRescanSchedulesTheCodeByItsOwnClock(t *testing.T) {
	prev := db.DB
	t.Cleanup(func() { db.DB = prev })
	gdb, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "scan.db")), &gorm.Config{})
	if err != nil {
		t.Fatal(err)
	}
	gdb.AutoMigrate(&models.Repository{}, &models.ScanResult{})
	db.DB = gdb

	now := time.Now()
	ago := func(d time.Duration) *time.Time { t := now.Add(-d); return &t }
	day := 24 * time.Hour
	rows := []struct {
		repo    string
		updated time.Duration
		code    *time.Time
		scanned bool
	}{
		{"rescan-image-fresh-code-old", time.Hour, ago(8 * day), true}, // the bug: image yesterday, code a week+ ago
		{"rescan-both-fresh", time.Hour, ago(time.Hour), true},         // nothing due
		{"rescan-image-stale", 25 * time.Hour, ago(2 * day), true},     // image due only
		{"rescan-before-the-clock", time.Hour, nil, true},              // never had a scheduled code pass
		{"rescan-never-scanned", 0, nil, false},                        // nothing stored yet
	}
	for _, r := range rows {
		gdb.Create(&models.Repository{Name: r.repo})
		if r.scanned {
			gdb.Create(&models.ScanResult{RepoName: r.repo, CreatedAt: now.Add(-30 * day), UpdatedAt: now.Add(-r.updated), CodeScannedAt: r.code})
		}
	}

	var got []string
	prevEnqueue := enqueueRescan
	enqueueRescan = func(repo string, mode ScanMode) { got = append(got, repo+"="+string(mode)) }
	t.Cleanup(func() { enqueueRescan = prevEnqueue })

	PollRescans()
	sort.Strings(got)
	want := []string{"rescan-before-the-clock=full", "rescan-image-fresh-code-old=full", "rescan-image-stale=image", "rescan-never-scanned=full"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("queued %v\nwant   %v", got, want)
	}
}

func TestTrivyDoesNotSeeTheAPISecrets(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "k")
	t.Setenv("JWT_SECRET", "j")
	t.Setenv("ADMIN_PASSWORD", "p")
	t.Setenv("TRIVY_DB_REPOSITORY", "mirror.local/trivy-db")
	t.Setenv("HTTPS_PROXY", "http://proxy:3128")
	t.Setenv("AWS_ROLE_ARN", "arn:aws:iam::1:role/ecr")
	env := strings.Join(trivyEnv("TRIVY_USERNAME=u"), "\n")
	for _, secret := range []string{"ENCRYPTION_KEY=", "JWT_SECRET=", "ADMIN_PASSWORD="} {
		if strings.Contains(env, secret) {
			t.Errorf("%s reaches Trivy", secret)
		}
	}
	for _, needed := range []string{"PATH=", "TRIVY_DB_REPOSITORY=", "HTTPS_PROXY=", "AWS_ROLE_ARN=", "TRIVY_USERNAME=u"} {
		if !strings.Contains(env, needed) {
			t.Errorf("%s does not reach Trivy", needed)
		}
	}
}
