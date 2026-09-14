package handlers

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/kubecommit/backend/db"
	"github.com/kubecommit/backend/models"
)

// Scans used to be fired as a bare goroutine each. Importing a workspace calls
// that once per repository, so connecting a hundred repositories started a
// hundred concurrent clones, Trivy runs and vulnerability-database downloads
// thirty seconds later. A queue with a small worker pool is what makes any
// scheduled rescan possible at all: without it, every rescan cycle would be
// the same stampede on a timer.

// ScanMode says how much of a repository to look at. An image-only pass skips
// the clone entirely, which is most of the cost, and is the pass worth running
// often: new CVEs land against a base image that has not changed, while the
// code findings only move when someone pushes.
type ScanMode string

const (
	ScanFull  ScanMode = "full"  // clone + filesystem scan + image scan
	ScanImage ScanMode = "image" // image scan only
)

type scanJob struct {
	Repo string
	Mode ScanMode
}

var (
	scanQueue   chan scanJob
	queuedMu    sync.Mutex
	queued      = map[string]bool{}
	scanWorkers int

	// trivyDBReady gates --skip-db-update: passing it before any database has
	// been downloaded makes every scan fail instead of merely being slow.
	trivyDBMu    sync.RWMutex
	trivyDBReady bool
)

// TrivyCacheDir is where Trivy keeps the vulnerability database between runs.
// It defaults next to the SQLite file, which is already the one path the
// deployment guarantees is persistent -- a cache on an ephemeral filesystem is
// re-downloaded on every restart, which is the problem it exists to solve.
func TrivyCacheDir() string {
	if v := os.Getenv("TRIVY_CACHE_DIR"); v != "" {
		return v
	}
	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(dbPath), "trivy-cache")
}

// trivyCacheArgs returns the flags every Trivy invocation shares: a shared
// cache, and -- once the database has been fetched at least once -- a promise
// not to fetch it again mid-scan.
func trivyCacheArgs() []string {
	args := []string{}
	if dir := TrivyCacheDir(); dir != "" {
		args = append(args, "--cache-dir", dir)
		trivyDBMu.RLock()
		ready := trivyDBReady
		trivyDBMu.RUnlock()
		if ready {
			args = append(args, "--skip-db-update", "--skip-java-db-update")
		}
	}
	return args
}

// EnqueueScan schedules a scan, collapsing duplicates: a repository already
// waiting is not queued twice, so ten pushes in a minute cost one scan.
func EnqueueScan(repoName string, mode ScanMode) {
	if repoName == "" {
		return
	}
	key := repoName + "|" + string(mode)

	queuedMu.Lock()
	if queued[key] {
		queuedMu.Unlock()
		return
	}
	queued[key] = true
	queuedMu.Unlock()

	select {
	case scanQueue <- scanJob{Repo: repoName, Mode: mode}:
	default:
		// A full queue means the workers are far behind; dropping is better
		// than blocking the HTTP handler that asked for the scan.
		queuedMu.Lock()
		delete(queued, key)
		queuedMu.Unlock()
		fmt.Printf("scan queue full, dropped %s (%s)\n", repoName, mode)
	}
}

// TriggerScanBackground keeps the name every caller already uses, but now only
// puts the repository in line.
func TriggerScanBackground(repoName string) {
	EnqueueScan(repoName, ScanFull)
}

// StartScanWorkers boots the pool. Called once from main.
func StartScanWorkers() {
	scanWorkers = 2
	if v := os.Getenv("SCAN_WORKERS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			scanWorkers = n
		}
	}
	depth := 500
	if v := os.Getenv("SCAN_QUEUE_DEPTH"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			depth = n
		}
	}
	scanQueue = make(chan scanJob, depth)

	for i := 0; i < scanWorkers; i++ {
		go func(worker int) {
			for job := range scanQueue {
				queuedMu.Lock()
				delete(queued, job.Repo+"|"+string(job.Mode))
				queuedMu.Unlock()

				var err error
				switch job.Mode {
				case ScanImage:
					err = runImageOnlyScan(job.Repo)
				default:
					err = runScanAndSave(job.Repo, "")
				}
				if err != nil {
					fmt.Printf("scan worker %d: %s (%s) failed: %v\n", worker, job.Repo, job.Mode, err)
				}
			}
		}(i)
	}
	fmt.Printf("scan queue started: %d workers, depth %d\n", scanWorkers, depth)
}

// UpdateTrivyDB fetches the vulnerability database into the shared cache. It
// runs on its own schedule so that a scan never pays for the download, and so
// that a rescan actually reflects CVEs published since the last pass -- which
// is the whole point of rescanning code nobody has touched.
func UpdateTrivyDB() {
	dir := TrivyCacheDir()
	if dir == "" {
		return // no persistent cache configured; scans update the DB themselves
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		fmt.Printf("trivy cache dir unavailable (%s): %v\n", dir, err)
		return
	}

	cmd := exec.Command("trivy", "image", "--cache-dir", dir, "--download-db-only", "--no-progress")
	if out, err := cmd.CombinedOutput(); err != nil {
		fmt.Printf("trivy database update failed: %s\n", string(out))
		return
	}

	trivyDBMu.Lock()
	first := !trivyDBReady
	trivyDBReady = true
	trivyDBMu.Unlock()
	if first {
		fmt.Printf("trivy vulnerability database ready in %s\n", dir)
	}
}

// PollRescans enqueues the repositories whose findings have gone stale. Both
// cadences exist because the two passes cost very different amounts: an image
// pass pulls a manifest, a full pass clones a repository.
func PollRescans() {
	imageAge := durationEnv("RESCAN_IMAGE_AGE", 24*time.Hour)
	fullAge := durationEnv("RESCAN_FULL_AGE", 7*24*time.Hour)

	var repos []models.Repository
	db.DB.Find(&repos)

	now := time.Now()
	full, image := 0, 0
	for _, repo := range repos {
		var last models.ScanResult
		err := db.DB.Where("repo_name = ?", repo.Name).Order("created_at desc").First(&last).Error
		if err != nil {
			// Never scanned: a full pass is the only one that can produce
			// anything, since there is nothing to rescan yet.
			EnqueueScan(repo.Name, ScanFull)
			full++
			continue
		}
		switch {
		case now.Sub(last.CreatedAt) >= fullAge:
			EnqueueScan(repo.Name, ScanFull)
			full++
		case now.Sub(last.CreatedAt) >= imageAge:
			EnqueueScan(repo.Name, ScanImage)
			image++
		}
	}
	if full+image > 0 {
		fmt.Printf("rescan queued: %d full, %d image-only\n", full, image)
	}
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	if v := os.Getenv(name); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return fallback
}
